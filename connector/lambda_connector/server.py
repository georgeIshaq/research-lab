"""MCP server wiring: tools, OAuth routes, reaper endpoint, and the ASGI app."""

from __future__ import annotations

import functools
import logging
import os
from typing import Any, Awaitable, Callable

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import Settings
from .lambda_api import LambdaClient
from .oauth import BearerGate, OAuthServer
from .service import LabError, LabService
from .ssh import ParamikoRunner, load_private_key, public_key_line
from .store import GCSStore, MemoryStore, Store

log = logging.getLogger("lambda_connector")

INSTRUCTIONS = """\
Drive GPU instances on the owner's Lambda Cloud account for research experiments.
Typical flow: list_instance_types -> estimate_cost -> launch_instance -> list_instances until
status is active -> run_command (background=true for training) -> tail_log / gpu_status ->
read_file to pull results -> terminate_instance as soon as the work is done.
Every instance has a hard max_hours after which it is terminated automatically, and launches
over the spending cap are refused. Only instances this connector launched are visible.
"""

ReaperVerifier = Callable[[str], bool]


def google_oidc_verifier(settings: Settings) -> ReaperVerifier:
    """Accept only Cloud Scheduler's OIDC token for the reaper's service account."""

    def verify(token: str) -> bool:
        if not settings.reaper_service_account:
            return False
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token

        try:
            claims = id_token.verify_oauth2_token(token, google_requests.Request(), audience=settings.reaper_url)
        except ValueError:
            return False
        return claims.get("email") == settings.reaper_service_account and bool(claims.get("email_verified"))

    return verify


def _tool_errors(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
    # The SDK hides the text of unexpected exceptions from the client; LabError
    # messages are written for Claude, so pass them through as ToolError.
    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return await fn(*args, **kwargs)
        except LabError as exc:
            raise ToolError(str(exc)) from None

    return wrapper


def build_mcp(service: LabService, oauth: OAuthServer, reaper_verifier: ReaperVerifier) -> MCPServer:
    mcp = MCPServer(name="lambda-gpu-lab", instructions=INSTRUCTIONS)
    read_only = ToolAnnotations(read_only_hint=True, open_world_hint=True)
    acts = ToolAnnotations(read_only_hint=False, destructive_hint=False, open_world_hint=True)
    destroys = ToolAnnotations(read_only_hint=False, destructive_hint=True, open_world_hint=True)

    @mcp.tool(annotations=read_only)
    @_tool_errors
    async def list_instance_types(only_available: bool = True) -> list[dict[str, Any]]:
        """List Lambda instance types with hourly price (USD), specs, regions that have capacity now,
        and the most hours each can run within the spending cap. Set only_available=false to include
        types with no capacity anywhere."""
        return await service.list_instance_types(only_available)

    @mcp.tool(annotations=read_only)
    @_tool_errors
    async def estimate_cost(instance_type: str, hours: float) -> dict[str, Any]:
        """Estimate the cost of running an instance type for some hours, and whether it fits the cap."""
        return await service.estimate_cost(instance_type, hours)

    @mcp.tool(annotations=acts)
    @_tool_errors
    async def launch_instance(instance_type: str, region: str, max_hours: float, name: str) -> dict[str, Any]:
        """Launch one instance. It is terminated automatically after max_hours. Refused if
        price x max_hours (plus a reaper margin) is over the cap. name is a short label for the run."""
        return await service.launch_instance(instance_type, region, max_hours, name)

    @mcp.tool(annotations=read_only)
    @_tool_errors
    async def list_instances() -> list[dict[str, Any]]:
        """List instances this connector launched: status, IP, time left before auto-termination
        and cost so far."""
        return await service.list_instances()

    @mcp.tool(annotations=destroys)
    @_tool_errors
    async def terminate_instance(instance_id: str) -> dict[str, Any]:
        """Terminate an instance this connector launched. Everything on its disk is lost, so pull
        results with read_file first."""
        return await service.terminate_instance(instance_id)

    @mcp.tool(annotations=destroys)
    @_tool_errors
    async def run_command(
        instance_id: str,
        command: str,
        timeout_seconds: float = 120,
        background: bool = False,
        log_path: str | None = None,
    ) -> dict[str, Any]:
        """Run a shell command on an instance as the ubuntu user, from the home directory.
        For anything long (installs, training) set background=true: it runs detached with output
        written to log_path (default claude-lab-logs/<time>.log), and returns the pid at once.
        Foreground output keeps the last 50 KB of stdout and stderr."""
        return await service.run_command(instance_id, command, timeout_seconds, background, log_path)

    @mcp.tool(annotations=read_only)
    @_tool_errors
    async def tail_log(instance_id: str, path: str, lines: int = 100) -> dict[str, Any]:
        """Show the last lines of a file on an instance, such as a training log."""
        return await service.tail_log(instance_id, path, lines)

    @mcp.tool(annotations=read_only)
    @_tool_errors
    async def gpu_status(instance_id: str) -> dict[str, Any]:
        """GPU utilisation, memory, temperature and power, plus the processes using the GPUs."""
        return await service.gpu_status(instance_id)

    @mcp.tool(annotations=read_only)
    @_tool_errors
    async def read_file(
        instance_id: str, path: str, offset: int = 0, max_bytes: int = 1_000_000, as_base64: bool = False
    ) -> dict[str, Any]:
        """Read part of a file on an instance (up to 5 MB per call; use offset to page through).
        Set as_base64=true for binary files."""
        return await service.read_file(instance_id, path, offset, max_bytes, as_base64)

    @mcp.tool(annotations=destroys)
    @_tool_errors
    async def write_file(
        instance_id: str, path: str, content: str, is_base64: bool = False, append: bool = False
    ) -> dict[str, Any]:
        """Write (or append to) a file on an instance, up to 5 MB. Overwrites by default."""
        return await service.write_file(instance_id, path, content, is_base64, append)

    @mcp.tool(annotations=read_only)
    @_tool_errors
    async def spend_log(limit: int = 50) -> dict[str, Any]:
        """Spend so far: every launch and termination with its estimated cost, plus totals."""
        return await service.spend_log(limit)

    for route in oauth.routes():
        mcp.custom_route(route.path, methods=sorted(m for m in route.methods if m != "HEAD"))(route.endpoint)

    @mcp.custom_route("/tasks/reap", methods=["POST"])
    async def reap(request: Request) -> Response:
        auth = request.headers.get("authorization", "")
        token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
        if not token or not reaper_verifier(token):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            result = await service.reap()
        except LabError as exc:
            log.error("reaper failed: %s", exc)
            return JSONResponse({"error": str(exc)}, status_code=502)
        if result["reaped"] or result["errors"] or result["closed_out"]:
            log.info("reaper: %s", result)
        return JSONResponse(result, status_code=500 if result["errors"] else 200)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> Response:
        return JSONResponse({"ok": True})

    return mcp


def build_app(
    settings: Settings,
    service: LabService,
    store: Store,
    reaper_verifier: ReaperVerifier | None = None,
) -> BearerGate:
    oauth = OAuthServer(settings, store, clock=service.clock)
    mcp = build_mcp(service, oauth, reaper_verifier or google_oidc_verifier(settings))
    # Stateless JSON mode: no server-side sessions, so any Cloud Run instance can answer any request.
    inner = mcp.streamable_http_app(stateless_http=True, json_response=True, host="0.0.0.0")
    return BearerGate(inner, oauth)


def create_app() -> BearerGate:
    """Entry point for uvicorn on Cloud Run (`--factory lambda_connector.server:create_app`)."""
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    settings = Settings.from_env()
    store: Store = GCSStore(settings.state_bucket) if settings.state_bucket else MemoryStore()
    if not settings.state_bucket:
        log.warning("STATE_BUCKET is not set: records and spend log live in memory and vanish on restart")
    key = load_private_key(settings.ssh_private_key)
    service = LabService(
        settings,
        LambdaClient(settings.lambda_api_key, settings.lambda_api_base),
        store,
        ParamikoRunner(key, settings.ssh_user),
        public_key_line(key, settings.ssh_key_name),
    )
    return build_app(settings, service, store)
