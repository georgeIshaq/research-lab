"""What each tool does, independent of MCP so it can be tested directly.

Safety rules enforced here:
- Only instances whose name starts with the configured prefix are ever listed,
  touched over SSH or terminated. George's other Lambda instances are invisible.
- A launch is refused if price x (max_hours + one reaper interval) is over
  MAX_EXPERIMENT_USD, because the reaper can be up to one interval late.
- Every launch and termination goes into the spend log.
"""

from __future__ import annotations

import base64
import re
import shlex
import time
from datetime import datetime, timezone
from typing import Any, Callable

from .config import Settings
from .lambda_api import LambdaAPIError, LambdaClient
from .ssh import Runner, SSHError
from .store import Store

GONE_STATUSES = {"terminated", "terminating"}
MAX_NAME_LEN = 64
DEFAULT_MAX_OUTPUT = 50_000
MAX_READ_BYTES = 5_000_000
MAX_WRITE_BYTES = 5_000_000


class LabError(Exception):
    """An error whose message is safe and useful to show to Claude."""


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="microseconds")


def _usd(x: float) -> float:
    return round(x, 2)


def _home_relative(path: str) -> str:
    # Commands and SFTP both start in the home directory, so "~/x" means "x".
    if path == "~":
        return "."
    if path.startswith("~/"):
        return path[2:]
    return path


class LabService:
    def __init__(
        self,
        settings: Settings,
        lam: LambdaClient,
        store: Store,
        runner: Runner,
        public_key: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.s = settings
        self.lam = lam
        self.store = store
        self.runner = runner
        self.public_key = public_key
        self.clock = clock

    # ---------- Lambda helpers ----------

    async def _call(self, coro):
        try:
            return await coro
        except LambdaAPIError as exc:
            raise LabError(str(exc)) from None

    async def _types(self) -> dict[str, Any]:
        return await self._call(self.lam.instance_types())

    async def _price_per_hour(self, instance_type: str) -> tuple[float, list[str]]:
        types = await self._types()
        entry = types.get(instance_type)
        if not entry:
            raise LabError(f"Unknown instance type {instance_type!r}. Use list_instance_types to see valid names.")
        cents = entry["instance_type"]["price_cents_per_hour"]
        regions = [r["name"] for r in entry.get("regions_with_capacity_available", [])]
        return cents / 100.0, regions

    def _owns(self, inst: dict[str, Any]) -> bool:
        return (inst.get("name") or "").startswith(self.s.instance_prefix)

    def _deadline_from_name(self, name: str) -> float | None:
        m = re.search(r"-(\d{9,11})$", name or "")
        return float(m.group(1)) if m else None

    async def _owned_instance(self, instance_id: str) -> dict[str, Any]:
        try:
            inst = await self.lam.get_instance(instance_id)
        except LambdaAPIError as exc:
            if exc.status == 404:
                raise LabError(f"No instance {instance_id} on the Lambda account") from None
            raise LabError(str(exc)) from None
        if not self._owns(inst):
            raise LabError(f"Instance {instance_id} was not launched by this connector, so it won't touch it")
        return inst

    async def _record(self, instance_id: str) -> dict[str, Any] | None:
        return await self.store.get(f"instances/{instance_id}.json")

    async def _save_record(self, rec: dict[str, Any]) -> None:
        await self.store.put(f"instances/{rec['id']}.json", rec)

    async def _log_spend(self, event: str, rec: dict[str, Any], **extra: Any) -> None:
        now = self.clock()
        doc = {
            "at": _iso(now),
            "event": event,
            "instance_id": rec["id"],
            "name": rec.get("name"),
            "instance_type": rec.get("instance_type"),
            "price_per_hour_usd": rec.get("price_per_hour_usd"),
            **extra,
        }
        await self.store.put(f"spend/{_iso(now)}-{event}-{rec['id']}.json", doc)

    def _accrued(self, rec: dict[str, Any], until: float | None = None) -> tuple[float, float]:
        end = until if until is not None else self.clock()
        hours = max(0.0, end - rec["launched_at"]) / 3600.0
        return hours, hours * rec["price_per_hour_usd"]

    async def _ensure_ssh_key(self) -> None:
        keys = await self._call(self.lam.list_ssh_keys())
        for k in keys:
            if k.get("name") == self.s.ssh_key_name:
                existing = " ".join((k.get("public_key") or "").split()[:2])
                if existing and existing != " ".join(self.public_key.split()[:2]):
                    raise LabError(
                        f"Lambda already has an SSH key named {self.s.ssh_key_name!r} that doesn't match the "
                        "connector's key. Delete it in the Lambda dashboard or set SSH_KEY_NAME to another name."
                    )
                return
        await self._call(self.lam.add_ssh_key(self.s.ssh_key_name, self.public_key))

    # ---------- catalogue and cost ----------

    async def list_instance_types(self, only_available: bool = True) -> list[dict[str, Any]]:
        types = await self._types()
        rows = []
        for name, entry in types.items():
            it = entry["instance_type"]
            regions = [r["name"] for r in entry.get("regions_with_capacity_available", [])]
            if only_available and not regions:
                continue
            rows.append(
                {
                    "name": name,
                    "description": it.get("description"),
                    "gpu_description": it.get("gpu_description"),
                    "price_per_hour_usd": it["price_cents_per_hour"] / 100.0,
                    "specs": it.get("specs"),
                    "regions_with_capacity": regions,
                    "max_hours_within_cap": _usd(self._max_hours_for(it["price_cents_per_hour"] / 100.0)),
                }
            )
        rows.sort(key=lambda r: r["price_per_hour_usd"])
        return rows

    def _grace_hours(self) -> float:
        return self.s.reaper_interval_minutes / 60.0

    def _max_hours_for(self, price: float) -> float:
        if price <= 0:
            return self.s.max_hours_limit
        return max(0.0, min(self.s.max_hours_limit, self.s.max_experiment_usd / price - self._grace_hours()))

    async def estimate_cost(self, instance_type: str, hours: float) -> dict[str, Any]:
        if hours <= 0:
            raise LabError("hours must be positive")
        price, regions = await self._price_per_hour(instance_type)
        worst = price * (hours + self._grace_hours())
        return {
            "instance_type": instance_type,
            "price_per_hour_usd": price,
            "hours": hours,
            "estimated_usd": _usd(price * hours),
            "worst_case_usd": _usd(worst),
            "worst_case_note": f"Includes up to {self.s.reaper_interval_minutes} minutes before the reaper stops it.",
            "cap_usd": self.s.max_experiment_usd,
            "within_cap": worst <= self.s.max_experiment_usd and hours <= self.s.max_hours_limit,
            "max_hours_within_cap": _usd(self._max_hours_for(price)),
            "regions_with_capacity": regions,
        }

    # ---------- lifecycle ----------

    async def launch_instance(self, instance_type: str, region: str, max_hours: float, name: str) -> dict[str, Any]:
        if not (max_hours > 0):
            raise LabError("max_hours must be positive")
        if max_hours > self.s.max_hours_limit:
            raise LabError(f"max_hours {max_hours} is over the limit of {self.s.max_hours_limit} hours")
        price, regions = await self._price_per_hour(instance_type)
        worst = price * (max_hours + self._grace_hours())
        if worst > self.s.max_experiment_usd:
            raise LabError(
                f"Refused: {instance_type} at ${price:.2f}/h for {max_hours} h could cost up to ${worst:.2f} "
                f"(with {self.s.reaper_interval_minutes} min reaper margin), over the ${self.s.max_experiment_usd:.2f} cap. "
                f"Max hours for this type is {self._max_hours_for(price):.2f}."
            )
        if region not in regions:
            raise LabError(
                f"No {instance_type} capacity in {region!r} right now. Regions with capacity: {regions or 'none'}"
            )
        running = [i for i in await self._call(self.lam.list_instances()) if self._owns(i) and i.get("status") not in GONE_STATUSES]
        if len(running) >= self.s.max_concurrent_instances:
            raise LabError(
                f"Refused: {len(running)} connector instances already running (limit {self.s.max_concurrent_instances}). "
                "Terminate one first."
            )
        await self._ensure_ssh_key()

        now = self.clock()
        deadline = int(now + max_hours * 3600)
        label = re.sub(r"[^a-z0-9-]+", "-", (name or "run").lower()).strip("-") or "run"
        room = MAX_NAME_LEN - len(self.s.instance_prefix) - len(str(deadline)) - 1
        label = label[: max(1, room)].strip("-") or "run"
        full_name = f"{self.s.instance_prefix}{label}-{deadline}"

        ids = await self._call(self.lam.launch(region, instance_type, self.s.ssh_key_name, full_name))
        if not ids:
            raise LabError("Lambda accepted the launch but returned no instance id")
        rec = {
            "id": ids[0],
            "name": full_name,
            "instance_type": instance_type,
            "region": region,
            "price_per_hour_usd": price,
            "max_hours": max_hours,
            "launched_at": now,
            "deadline": float(deadline),
            "status": "running",
            "host_key": None,
        }
        await self._save_record(rec)
        await self._log_spend("launch", rec, max_hours=max_hours, budget_usd=_usd(price * max_hours))
        return {
            "instance_id": rec["id"],
            "name": full_name,
            "instance_type": instance_type,
            "region": region,
            "price_per_hour_usd": price,
            "max_hours": max_hours,
            "auto_terminate_at": _iso(deadline),
            "budget_usd": _usd(price * max_hours),
            "note": "Booting usually takes a few minutes; list_instances shows the IP once it's active.",
        }

    async def list_instances(self) -> list[dict[str, Any]]:
        out = []
        now = self.clock()
        for inst in await self._call(self.lam.list_instances()):
            if not self._owns(inst):
                continue
            rec = await self._record(inst["id"])
            deadline = (rec or {}).get("deadline") or self._deadline_from_name(inst.get("name", ""))
            row = {
                "instance_id": inst["id"],
                "name": inst.get("name"),
                "status": inst.get("status"),
                "ip": inst.get("ip"),
                "instance_type": (inst.get("instance_type") or {}).get("name"),
                "region": (inst.get("region") or {}).get("name"),
                "auto_terminate_at": _iso(deadline) if deadline else None,
                "hours_left": _usd(max(0.0, (deadline - now) / 3600.0)) if deadline else None,
            }
            if rec:
                hours, cost = self._accrued(rec)
                row["hours_running"] = _usd(hours)
                row["cost_so_far_usd"] = _usd(cost)
            out.append(row)
        return out

    async def _finish(self, inst: dict[str, Any], reason: str) -> dict[str, Any]:
        await self._call(self.lam.terminate([inst["id"]]))
        now = self.clock()
        rec = await self._record(inst["id"])
        if rec is None:
            # Tagged but no record (e.g. the record write failed). Price from the live instance.
            it = inst.get("instance_type") or {}
            rec = {
                "id": inst["id"],
                "name": inst.get("name"),
                "instance_type": it.get("name"),
                "price_per_hour_usd": (it.get("price_cents_per_hour") or 0) / 100.0,
                "launched_at": now,
                "status": "running",
            }
        hours, cost = self._accrued(rec, now)
        rec.update(status="terminated", terminated_at=now, cost_usd=_usd(cost), terminate_reason=reason)
        await self._save_record(rec)
        await self._log_spend("terminate", rec, reason=reason, hours=_usd(hours), cost_usd=_usd(cost))
        return {"instance_id": inst["id"], "name": rec.get("name"), "hours": _usd(hours), "cost_usd": _usd(cost), "reason": reason}

    async def terminate_instance(self, instance_id: str) -> dict[str, Any]:
        inst = await self._owned_instance(instance_id)
        if inst.get("status") in GONE_STATUSES:
            raise LabError(f"Instance {instance_id} is already {inst.get('status')}")
        return await self._finish(inst, "requested")

    async def reap(self) -> dict[str, Any]:
        """Terminate connector instances past their deadline. Called by Cloud Scheduler."""
        now = self.clock()
        live = await self._call(self.lam.list_instances())
        reaped, errors = [], []
        live_ids = set()
        for inst in live:
            if not self._owns(inst):
                continue
            live_ids.add(inst["id"])
            if inst.get("status") in GONE_STATUSES:
                continue
            rec = await self._record(inst["id"])
            deadline = (rec or {}).get("deadline") or self._deadline_from_name(inst.get("name", ""))
            if deadline is None or now >= deadline:
                # No known deadline on a tagged instance means we can't vouch for its cost: stop it.
                try:
                    reaped.append(await self._finish(inst, "max_hours reached" if deadline else "no deadline found"))
                except LabError as exc:
                    errors.append({"instance_id": inst["id"], "error": str(exc)})
        # Records still marked running but gone from Lambda were stopped elsewhere; close them out.
        closed = []
        for rec in await self.store.list("instances/"):
            # The 15 minute wait covers a fresh launch that the list doesn't show yet.
            if rec.get("status") == "running" and rec["id"] not in live_ids and now - rec["launched_at"] > 900:
                hours, cost = self._accrued(rec, min(now, rec.get("deadline", now)))
                rec.update(status="terminated", terminated_at=now, cost_usd=_usd(cost), terminate_reason="gone from Lambda")
                await self._save_record(rec)
                await self._log_spend("terminate", rec, reason="gone from Lambda (estimated)", hours=_usd(hours), cost_usd=_usd(cost))
                closed.append(rec["id"])
        return {"reaped": reaped, "closed_out": closed, "errors": errors}

    async def spend_log(self, limit: int = 50) -> dict[str, Any]:
        events = await self.store.list("spend/")
        spent = sum(e.get("cost_usd", 0.0) for e in events if e["event"] == "terminate")
        accruing = 0.0
        for rec in await self.store.list("instances/"):
            if rec.get("status") == "running":
                accruing += self._accrued(rec)[1]
        return {
            "total_terminated_usd": _usd(spent),
            "running_accrued_usd": _usd(accruing),
            "total_usd": _usd(spent + accruing),
            "note": "Costs are estimates from list price x time since launch; Lambda's invoice is the source of truth.",
            "events": events[-limit:] if limit > 0 else events,
        }

    # ---------- on-instance work ----------

    async def _ssh_target(self, instance_id: str) -> tuple[str, dict[str, Any]]:
        inst = await self._owned_instance(instance_id)
        status = inst.get("status")
        if status != "active" or not inst.get("ip"):
            raise LabError(f"Instance {instance_id} is {status}, not active yet; try again shortly")
        rec = await self._record(instance_id) or {
            "id": instance_id,
            "name": inst.get("name"),
            "instance_type": (inst.get("instance_type") or {}).get("name"),
            "price_per_hour_usd": ((inst.get("instance_type") or {}).get("price_cents_per_hour") or 0) / 100.0,
            "launched_at": self.clock(),
            "deadline": self._deadline_from_name(inst.get("name", "")),
            "status": "running",
            "host_key": None,
        }
        return inst["ip"], rec

    async def _remember_host_key(self, rec: dict[str, Any], host_key: str) -> None:
        if host_key and not rec.get("host_key"):
            rec["host_key"] = host_key
            await self._save_record(rec)

    async def run_command(
        self,
        instance_id: str,
        command: str,
        timeout_seconds: float = 120,
        background: bool = False,
        log_path: str | None = None,
    ) -> dict[str, Any]:
        ip, rec = await self._ssh_target(instance_id)
        timeout_seconds = max(1.0, min(float(timeout_seconds), 3000.0))
        if background:
            log = _home_relative(log_path or f"claude-lab-logs/{int(self.clock())}.log")
            log_dir = log.rsplit("/", 1)[0] if "/" in log else "."
            wrapped = (
                f"mkdir -p {shlex.quote(log_dir)}; "
                f"nohup setsid bash -lc {shlex.quote(command)} > {shlex.quote(log)} 2>&1 < /dev/null & echo $!"
            )
            res = await self._ssh(self.runner.run(ip, rec.get("host_key"), wrapped, 30.0, DEFAULT_MAX_OUTPUT))
            await self._remember_host_key(rec, res.host_key)
            return {
                "started": res.exit_code == 0,
                "pid": res.stdout.strip() or None,
                "log_path": log,
                "stderr": res.stderr,
                "hint": "Use tail_log with this log_path to watch it.",
            }
        res = await self._ssh(self.runner.run(ip, rec.get("host_key"), command, timeout_seconds, DEFAULT_MAX_OUTPUT))
        await self._remember_host_key(rec, res.host_key)
        return {
            "exit_code": res.exit_code,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "timed_out": res.timed_out,
            "output_truncated_to_last_bytes": DEFAULT_MAX_OUTPUT if res.truncated else None,
        }

    async def _ssh(self, coro):
        try:
            return await coro
        except SSHError as exc:
            raise LabError(str(exc)) from None

    async def tail_log(self, instance_id: str, path: str, lines: int = 100) -> dict[str, Any]:
        lines = max(1, min(int(lines), 5000))
        cmd = f"tail -n {lines} -- {shlex.quote(_home_relative(path))}"
        res = await self.run_command(instance_id, cmd, timeout_seconds=30)
        if res["exit_code"] != 0:
            raise LabError(f"tail failed: {res['stderr'].strip() or 'exit ' + str(res['exit_code'])}")
        return {"path": path, "lines": lines, "text": res["stdout"]}

    async def gpu_status(self, instance_id: str) -> dict[str, Any]:
        cmd = (
            "nvidia-smi --query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw "
            "--format=csv,noheader,nounits && echo '---' && "
            "nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader,nounits"
        )
        res = await self.run_command(instance_id, cmd, timeout_seconds=30)
        if res["exit_code"] != 0:
            raise LabError(f"nvidia-smi failed: {res['stderr'].strip()}")
        gpu_part, _, proc_part = res["stdout"].partition("---")
        gpus = []
        for line in gpu_part.strip().splitlines():
            f = [x.strip() for x in line.split(",")]
            if len(f) >= 7:
                gpus.append(
                    {"index": f[0], "name": f[1], "util_pct": f[2], "mem_used_mib": f[3], "mem_total_mib": f[4], "temp_c": f[5], "power_w": f[6]}
                )
        procs = []
        for line in proc_part.strip().splitlines():
            f = [x.strip() for x in line.split(",")]
            if len(f) >= 3:
                procs.append({"pid": f[0], "process": f[1], "mem_used_mib": f[2]})
        return {"gpus": gpus, "processes": procs}

    async def read_file(self, instance_id: str, path: str, offset: int = 0, max_bytes: int = 1_000_000, as_base64: bool = False) -> dict[str, Any]:
        max_bytes = max(1, min(int(max_bytes), MAX_READ_BYTES))
        ip, rec = await self._ssh_target(instance_id)
        res = await self._ssh(self.runner.read_file(ip, rec.get("host_key"), _home_relative(path), max(0, int(offset)), max_bytes))
        await self._remember_host_key(rec, res.host_key)
        out: dict[str, Any] = {
            "path": path,
            "offset": offset,
            "bytes_read": len(res.data),
            "file_size": res.size,
            "more": offset + len(res.data) < res.size,
        }
        if as_base64:
            out["content_base64"] = base64.b64encode(res.data).decode()
        else:
            out["content"] = res.data.decode("utf-8", errors="replace")
        return out

    async def write_file(self, instance_id: str, path: str, content: str, is_base64: bool = False, append: bool = False) -> dict[str, Any]:
        try:
            data = base64.b64decode(content, validate=True) if is_base64 else content.encode("utf-8")
        except ValueError:
            raise LabError("content is not valid base64") from None
        if len(data) > MAX_WRITE_BYTES:
            raise LabError(f"content is {len(data)} bytes, over the {MAX_WRITE_BYTES} byte limit")
        ip, rec = await self._ssh_target(instance_id)
        host_key = await self._ssh(self.runner.write_file(ip, rec.get("host_key"), _home_relative(path), data, append))
        await self._remember_host_key(rec, host_key)
        return {"path": path, "bytes_written": len(data), "appended": append}
