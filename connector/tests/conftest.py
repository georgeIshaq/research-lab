"""Fakes for Lambda's API and for SSH, so tests never touch the network."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from lambda_connector.config import Settings  # noqa: E402
from lambda_connector.lambda_api import LambdaClient  # noqa: E402
from lambda_connector.service import LabService  # noqa: E402
from lambda_connector.ssh import CommandResult, FileRead, SSHError  # noqa: E402
from lambda_connector.store import MemoryStore  # noqa: E402

API_KEY = "secret_lambda_key_for_tests_only"
PUBLIC_KEY = "ssh-ed25519 AAAATESTKEY claude-lab-connector"


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class FakeLambda:
    """In-memory stand-in for the parts of the Lambda Cloud API the connector uses."""

    def __init__(self) -> None:
        self.types = {
            "gpu_1x_a10": {
                "instance_type": {
                    "name": "gpu_1x_a10",
                    "description": "1x A10 (24 GB PCIe)",
                    "gpu_description": "A10 (24 GB PCIe)",
                    "price_cents_per_hour": 75,
                    "specs": {"vcpus": 30, "memory_gib": 200, "storage_gib": 1400, "gpus": 1},
                },
                "regions_with_capacity_available": [{"name": "us-east-1", "description": "Virginia"}],
            },
            "gpu_8x_h100_sxm5": {
                "instance_type": {
                    "name": "gpu_8x_h100_sxm5",
                    "description": "8x H100 (80 GB SXM5)",
                    "gpu_description": "H100 (80 GB SXM5)",
                    "price_cents_per_hour": 2392,
                    "specs": {"vcpus": 208, "memory_gib": 1800, "storage_gib": 24780, "gpus": 8},
                },
                "regions_with_capacity_available": [{"name": "us-west-1", "description": "California"}],
            },
            "gpu_1x_gh200": {
                "instance_type": {"name": "gpu_1x_gh200", "description": "GH200", "price_cents_per_hour": 149, "specs": {}},
                "regions_with_capacity_available": [],
            },
        }
        self.instances: dict[str, dict[str, Any]] = {}
        self.ssh_keys: list[dict[str, Any]] = []
        self.requests: list[httpx.Request] = []
        self._n = 0

    def add_foreign_instance(self, name: str = "georges-own-box") -> str:
        iid = f"foreign{len(self.instances)}"
        self.instances[iid] = {
            "id": iid,
            "name": name,
            "status": "active",
            "ip": "10.0.0.99",
            "instance_type": self.types["gpu_1x_a10"]["instance_type"],
            "region": {"name": "us-east-1"},
            "ssh_key_names": ["george"],
            "file_system_names": [],
        }
        return iid

    def activate(self, iid: str, ip: str = "203.0.113.10") -> None:
        self.instances[iid].update(status="active", ip=ip)

    def _ok(self, data: Any) -> httpx.Response:
        return httpx.Response(200, json={"data": data})

    def _err(self, status: int, code: str, message: str) -> httpx.Response:
        return httpx.Response(status, json={"error": {"code": code, "message": message}})

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.headers.get("authorization") != f"Bearer {API_KEY}":
            return self._err(401, "global/invalid-api-key", "API key was invalid")
        path = request.url.path.removeprefix("/api/v1")
        body = json.loads(request.content) if request.content else {}
        if request.method == "GET" and path == "/instance-types":
            return self._ok(self.types)
        if request.method == "GET" and path == "/instances":
            return self._ok(list(self.instances.values()))
        if request.method == "GET" and path.startswith("/instances/"):
            iid = path.rsplit("/", 1)[1]
            if iid not in self.instances:
                return self._err(404, "global/object-does-not-exist", "Instance not found")
            return self._ok(self.instances[iid])
        if request.method == "GET" and path == "/ssh-keys":
            return self._ok(self.ssh_keys)
        if request.method == "POST" and path == "/ssh-keys":
            key = {"id": f"k{len(self.ssh_keys)}", "name": body["name"], "public_key": body["public_key"]}
            self.ssh_keys.append(key)
            return self._ok(key)
        if request.method == "POST" and path == "/instance-operations/launch":
            t = self.types.get(body["instance_type_name"])
            if not t:
                return self._err(400, "instance-operations/launch/invalid-instance-type", "Unknown type")
            self._n += 1
            iid = f"inst{self._n:04d}"
            self.instances[iid] = {
                "id": iid,
                "name": body.get("name"),
                "status": "booting",
                "ip": None,
                "instance_type": t["instance_type"],
                "region": {"name": body["region_name"]},
                "ssh_key_names": body["ssh_key_names"],
                "file_system_names": [],
            }
            return self._ok({"instance_ids": [iid]})
        if request.method == "POST" and path == "/instance-operations/terminate":
            out = []
            for iid in body["instance_ids"]:
                inst = self.instances[iid]
                inst["status"] = "terminated"
                out.append(inst)
            return self._ok({"terminated_instances": out})
        return self._err(404, "not-found", f"No route {request.method} {path}")


class FakeRunner:
    """Records SSH calls and answers from a script."""

    HOST_KEY = "ssh-ed25519 AAAAHOSTKEY"

    def __init__(self) -> None:
        self.commands: list[tuple[str, str | None, str]] = []
        self.files: dict[str, bytes] = {}
        self.next_result: CommandResult | None = None
        self.host_key = self.HOST_KEY

    def _check(self, known: str | None) -> None:
        if known and known != self.host_key:
            raise SSHError("Host key changed since first connection; refusing to connect")

    async def run(self, host, known_host_key, command, timeout, max_output):
        self._check(known_host_key)
        self.commands.append((host, known_host_key, command))
        res = self.next_result or CommandResult(0, "ok\n", "", False, False, self.host_key)
        self.next_result = None
        return res

    async def read_file(self, host, known_host_key, path, offset, max_bytes):
        self._check(known_host_key)
        if path not in self.files:
            raise SSHError(f"No such file on the instance: {path}")
        data = self.files[path]
        return FileRead(data[offset : offset + max_bytes], len(data), self.host_key)

    async def write_file(self, host, known_host_key, path, data, append):
        self._check(known_host_key)
        self.files[path] = (self.files.get(path, b"") if append else b"") + data
        return self.host_key


def make_settings(**overrides: Any) -> Settings:
    base = dict(
        public_url="https://lab.example.run.app",
        lambda_api_key=API_KEY,
        ssh_private_key="unused-in-tests",
        oauth_signing_key="k" * 48,
        owner_passphrase="correct horse battery staple",
        state_bucket=None,
        lambda_api_base="https://cloud.lambda.ai/api/v1",
        reaper_service_account="reaper@proj.iam.gserviceaccount.com",
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def fake_lambda() -> FakeLambda:
    return FakeLambda()


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def store() -> MemoryStore:
    return MemoryStore()


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture
def service(settings, fake_lambda, store, runner, clock) -> LabService:
    client = LambdaClient(API_KEY, settings.lambda_api_base, transport=httpx.MockTransport(fake_lambda.handler))
    return LabService(settings, client, store, runner, PUBLIC_KEY, clock=clock)
