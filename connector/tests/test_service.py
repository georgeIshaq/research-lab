import asyncio

import httpx
import pytest

from lambda_connector.service import LabError
from lambda_connector.ssh import CommandResult

from conftest import API_KEY, PUBLIC_KEY, FakeRunner


def run(coro):
    return asyncio.run(coro)


def test_instance_types_sorted_with_prices_and_cap(service):
    rows = run(service.list_instance_types())
    assert [r["name"] for r in rows] == ["gpu_1x_a10", "gpu_8x_h100_sxm5"]  # gh200 has no capacity
    assert rows[0]["price_per_hour_usd"] == 0.75
    # $500 / $23.92 = 20.90 h, minus the 10 minute reaper margin.
    assert rows[1]["max_hours_within_cap"] == pytest.approx(20.74, abs=0.01)
    all_rows = run(service.list_instance_types(only_available=False))
    assert "gpu_1x_gh200" in [r["name"] for r in all_rows]


def test_estimate_cost(service):
    est = run(service.estimate_cost("gpu_8x_h100_sxm5", 10))
    assert est["estimated_usd"] == 239.2
    assert est["within_cap"] is True
    over = run(service.estimate_cost("gpu_8x_h100_sxm5", 21))
    assert over["within_cap"] is False
    with pytest.raises(LabError, match="Unknown instance type"):
        run(service.estimate_cost("gpu_nope", 1))


def test_launch_refused_over_cap(service, fake_lambda):
    with pytest.raises(LabError, match="over the \\$500.00 cap"):
        run(service.launch_instance("gpu_8x_h100_sxm5", "us-west-1", 21, "big"))
    # Exactly at the price limit is still refused because of the reaper margin.
    with pytest.raises(LabError, match="cap"):
        run(service.launch_instance("gpu_8x_h100_sxm5", "us-west-1", 500 / 23.92, "edge"))
    assert not fake_lambda.instances


def test_launch_refused_without_capacity_or_bad_hours(service):
    with pytest.raises(LabError, match="No gpu_1x_a10 capacity in 'us-west-1'"):
        run(service.launch_instance("gpu_1x_a10", "us-west-1", 2, "x"))
    with pytest.raises(LabError, match="positive"):
        run(service.launch_instance("gpu_1x_a10", "us-east-1", 0, "x"))
    with pytest.raises(LabError, match="over the limit"):
        run(service.launch_instance("gpu_1x_a10", "us-east-1", 100, "x"))


def test_launch_tags_registers_key_and_logs(service, fake_lambda, store, clock):
    out = run(service.launch_instance("gpu_1x_a10", "us-east-1", 4, "LoRA sweep #1!"))
    iid = out["instance_id"]
    inst = fake_lambda.instances[iid]
    assert inst["name"] == f"claude-lab-lora-sweep-1-{int(clock() + 4 * 3600)}"
    assert len(inst["name"]) <= 64
    assert inst["ssh_key_names"] == ["claude-lab-connector"]
    assert fake_lambda.ssh_keys == [{"id": "k0", "name": "claude-lab-connector", "public_key": PUBLIC_KEY}]
    assert out["budget_usd"] == 3.0
    rec = run(store.get(f"instances/{iid}.json"))
    assert rec["deadline"] == clock() + 4 * 3600
    events = run(store.list("spend/"))
    assert [e["event"] for e in events] == ["launch"]
    # A second launch reuses the registered key.
    run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "two"))
    assert len(fake_lambda.ssh_keys) == 1


def test_long_name_is_truncated(service, fake_lambda):
    out = run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "x" * 200))
    assert len(fake_lambda.instances[out["instance_id"]]["name"]) == 64


def test_mismatched_existing_ssh_key_is_refused(service, fake_lambda):
    fake_lambda.ssh_keys.append({"id": "k9", "name": "claude-lab-connector", "public_key": "ssh-ed25519 AAAAOTHER x"})
    with pytest.raises(LabError, match="doesn't match"):
        run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "x"))
    assert not fake_lambda.instances


def test_concurrency_limit(service):
    for i in range(3):
        run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, f"r{i}"))
    with pytest.raises(LabError, match="already running"):
        run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "r4"))


def test_foreign_instances_are_invisible_and_untouchable(service, fake_lambda):
    foreign = fake_lambda.add_foreign_instance()
    run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "mine"))
    assert [i["name"].startswith("claude-lab-") for i in run(service.list_instances())] == [True]
    for call in (
        service.terminate_instance(foreign),
        service.run_command(foreign, "ls"),
        service.read_file(foreign, "x"),
        service.write_file(foreign, "x", "y"),
        service.gpu_status(foreign),
    ):
        with pytest.raises(LabError, match="not launched by this connector"):
            run(call)
    assert fake_lambda.instances[foreign]["status"] == "active"


def test_terminate_records_cost(service, fake_lambda, store, clock):
    iid = run(service.launch_instance("gpu_8x_h100_sxm5", "us-west-1", 5, "h100"))["instance_id"]
    clock.advance(2 * 3600)
    out = run(service.terminate_instance(iid))
    assert out["cost_usd"] == pytest.approx(47.84)
    assert fake_lambda.instances[iid]["status"] == "terminated"
    log = run(service.spend_log())
    assert [e["event"] for e in log["events"]] == ["launch", "terminate"]
    assert log["total_usd"] == pytest.approx(47.84)
    with pytest.raises(LabError, match="already terminated"):
        run(service.terminate_instance(iid))


def test_ssh_requires_active_instance(service, fake_lambda):
    iid = run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "x"))["instance_id"]
    with pytest.raises(LabError, match="booting, not active"):
        run(service.run_command(iid, "nvidia-smi"))
    fake_lambda.activate(iid)
    assert run(service.run_command(iid, "echo hi"))["exit_code"] == 0


def test_host_key_is_pinned_on_first_use(service, fake_lambda, runner, store):
    iid = run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "x"))["instance_id"]
    fake_lambda.activate(iid)
    run(service.run_command(iid, "true"))
    assert run(store.get(f"instances/{iid}.json"))["host_key"] == FakeRunner.HOST_KEY
    run(service.run_command(iid, "true"))
    assert runner.commands[-1][1] == FakeRunner.HOST_KEY
    runner.host_key = "ssh-ed25519 AAAAEVIL"
    with pytest.raises(LabError, match="Host key changed"):
        run(service.run_command(iid, "true"))


def test_background_command_is_detached_and_quoted(service, fake_lambda, runner):
    iid = run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "x"))["instance_id"]
    fake_lambda.activate(iid)
    runner.next_result = CommandResult(0, "4242\n", "", False, False, runner.host_key)
    out = run(service.run_command(iid, "python train.py --name 'a b'", background=True, log_path="~/logs/run 1.log"))
    assert out == {"started": True, "pid": "4242", "log_path": "logs/run 1.log", "stderr": "", "hint": "Use tail_log with this log_path to watch it."}
    cmd = runner.commands[-1][2]
    assert cmd.startswith("mkdir -p logs; nohup setsid bash -lc ")
    assert "> 'logs/run 1.log' 2>&1 < /dev/null & echo $!" in cmd
    assert "'python train.py --name '\"'\"'a b'\"'\"''" in cmd


def test_tail_log_and_gpu_status(service, fake_lambda, runner):
    iid = run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "x"))["instance_id"]
    fake_lambda.activate(iid)
    runner.next_result = CommandResult(0, "step 10 loss 1.2\n", "", False, False, runner.host_key)
    out = run(service.tail_log(iid, "~/train.log; rm -rf /", 20))
    assert out["text"] == "step 10 loss 1.2\n"
    assert runner.commands[-1][2] == "tail -n 20 -- 'train.log; rm -rf /'"
    runner.next_result = CommandResult(1, "", "tail: cannot open", False, False, runner.host_key)
    with pytest.raises(LabError, match="tail failed"):
        run(service.tail_log(iid, "nope.log"))
    runner.next_result = CommandResult(
        0, "0, NVIDIA A10, 97, 20000, 23028, 61, 140.5\n---\n1234, python, 19800\n", "", False, False, runner.host_key
    )
    gpu = run(service.gpu_status(iid))
    assert gpu["gpus"][0]["util_pct"] == "97"
    assert gpu["processes"] == [{"pid": "1234", "process": "python", "mem_used_mib": "19800"}]


def test_read_and_write_files(service, fake_lambda, runner):
    iid = run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "x"))["instance_id"]
    fake_lambda.activate(iid)
    run(service.write_file(iid, "~/cfg.yaml", "lr: 1e-4\n"))
    run(service.write_file(iid, "cfg.yaml", "bs: 8\n", append=True))
    assert runner.files["cfg.yaml"] == b"lr: 1e-4\nbs: 8\n"
    out = run(service.read_file(iid, "cfg.yaml", offset=0, max_bytes=4))
    assert out["content"] == "lr: " and out["more"] is True and out["file_size"] == 15
    run(service.write_file(iid, "w.bin", "AAEC", is_base64=True))
    assert run(service.read_file(iid, "w.bin", as_base64=True))["content_base64"] == "AAEC"
    with pytest.raises(LabError, match="base64"):
        run(service.write_file(iid, "w.bin", "!!notbase64", is_base64=True))
    with pytest.raises(LabError, match="No such file"):
        run(service.read_file(iid, "missing"))


def test_reaper_terminates_only_overdue_connector_instances(service, fake_lambda, clock):
    foreign = fake_lambda.add_foreign_instance()
    short = run(service.launch_instance("gpu_1x_a10", "us-east-1", 1, "short"))["instance_id"]
    long = run(service.launch_instance("gpu_1x_a10", "us-east-1", 5, "long"))["instance_id"]
    clock.advance(3600 + 60)
    result = run(service.reap())
    assert [r["instance_id"] for r in result["reaped"]] == [short]
    assert result["reaped"][0]["reason"] == "max_hours reached"
    assert fake_lambda.instances[short]["status"] == "terminated"
    assert fake_lambda.instances[long]["status"] == "booting"
    assert fake_lambda.instances[foreign]["status"] == "active"
    # Running again does nothing new.
    assert run(service.reap())["reaped"] == []


def test_reaper_uses_deadline_in_name_when_record_is_missing(service, fake_lambda, store, clock):
    iid = run(service.launch_instance("gpu_1x_a10", "us-east-1", 2, "x"))["instance_id"]
    store._docs.pop(f"instances/{iid}.json")
    clock.advance(3600)
    assert run(service.reap())["reaped"] == []
    clock.advance(3600 + 1)
    assert [r["instance_id"] for r in run(service.reap())["reaped"]] == [iid]


def test_reaper_closes_out_instances_terminated_elsewhere(service, fake_lambda, store, clock):
    iid = run(service.launch_instance("gpu_1x_a10", "us-east-1", 4, "x"))["instance_id"]
    del fake_lambda.instances[iid]
    assert run(service.reap())["closed_out"] == []  # too fresh to judge
    clock.advance(3600)
    assert run(service.reap())["closed_out"] == [iid]
    assert run(store.get(f"instances/{iid}.json"))["status"] == "terminated"


def test_lambda_errors_are_reported_without_the_key(service):
    def broken(request):
        return httpx.Response(500, json={"error": {"code": "global/unknown", "message": "boom"}})

    service.lam._client._transport = httpx.MockTransport(broken)
    with pytest.raises(LabError) as exc:
        run(service.list_instance_types())
    assert "boom" in str(exc.value)
    assert API_KEY not in str(exc.value)
