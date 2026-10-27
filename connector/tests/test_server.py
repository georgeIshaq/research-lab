"""End-to-end: Claude's OAuth sign-in, then MCP calls, through the real ASGI app."""

import base64
import hashlib
import json
import re
import secrets
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from starlette.testclient import TestClient

from lambda_connector.server import build_app

from conftest import API_KEY

BASE = "https://lab.example.run.app"
CALLBACK = "https://claude.ai/api/mcp/auth_callback"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def client(settings, service, store, monkeypatch):
    # Skip the 1 second penalty after a wrong passphrase.
    async def no_sleep(_):
        return None

    monkeypatch.setattr("lambda_connector.oauth.asyncio.sleep", no_sleep)
    app = build_app(settings, service, store, reaper_verifier=lambda t: t == "scheduler-token")
    with TestClient(app, base_url=BASE, follow_redirects=False) as c:
        yield c


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def register(c, uris=(CALLBACK,)):
    r = c.post("/register", json={"client_name": "Claude", "redirect_uris": list(uris), "token_endpoint_auth_method": "none"})
    return r


def authorize(c, client_id, challenge, redirect=CALLBACK, passphrase="correct horse battery staple"):
    r = c.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st4te",
            "scope": "lab",
            "resource": f"{BASE}/mcp",
        },
    )
    assert r.status_code == 200, r.text
    assert urlsplit(redirect).hostname in r.text
    req = re.search(r'name="req" value="([^"]+)"', r.text).group(1)
    return c.post("/authorize", data={"req": req, "passphrase": passphrase, "action": "approve"})


def sign_in(c):
    client_id = register(c).json()["client_id"]
    verifier, challenge = pkce()
    r = authorize(c, client_id, challenge)
    assert r.status_code == 302
    q = parse_qs(urlsplit(r.headers["location"]).query)
    tok = c.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": q["code"][0],
            "redirect_uri": CALLBACK,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    assert tok.status_code == 200, tok.text
    return client_id, tok.json()


def mcp_call(c, token, method, params=None, id_=1):
    body = {"jsonrpc": "2.0", "id": id_, "method": method}
    if params is not None:
        body["params"] = params
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {token}", "mcp-protocol-version": "2025-06-18"}
    return c.post("/mcp", json=body, headers=headers)


def tool(c, token, tool_name, **args):
    r = mcp_call(c, token, "tools/call", {"name": tool_name, "arguments": args})
    assert r.status_code == 200, r.text
    return r.json()["result"]


def test_discovery_metadata(client):
    r = client.post("/mcp", json={}, headers=MCP_HEADERS)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == (
        f'Bearer resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp", scope="lab"'
    )
    prm = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert prm["resource"] == f"{BASE}/mcp"
    assert prm["authorization_servers"] == [BASE]
    asm = client.get("/.well-known/oauth-authorization-server").json()
    assert asm["issuer"] == BASE
    assert asm["registration_endpoint"] == f"{BASE}/register"
    assert asm["code_challenge_methods_supported"] == ["S256"]
    assert asm["token_endpoint_auth_methods_supported"] == ["none"]


def test_full_sign_in_then_tools(client, fake_lambda):
    _, tokens = sign_in(client)
    assert tokens["token_type"] == "Bearer" and tokens["refresh_token"]
    init = mcp_call(
        client,
        tokens["access_token"],
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}},
    )
    assert init.status_code == 200 and "Lambda" in init.json()["result"]["instructions"]
    names = [t["name"] for t in mcp_call(client, tokens["access_token"], "tools/list").json()["result"]["tools"]]
    assert set(names) == {
        "list_instance_types", "estimate_cost", "launch_instance", "list_instances", "terminate_instance",
        "run_command", "tail_log", "gpu_status", "read_file", "write_file", "spend_log",
    }
    launched = tool(client, tokens["access_token"], "launch_instance", instance_type="gpu_1x_a10", region="us-east-1", max_hours=2, name="smoke")
    assert launched["isError"] is False
    iid = launched["structuredContent"]["instance_id"]
    refused = tool(client, tokens["access_token"], "launch_instance", instance_type="gpu_8x_h100_sxm5", region="us-west-1", max_hours=30, name="big")
    assert refused["isError"] is True and "cap" in refused["content"][0]["text"]
    fake_lambda.activate(iid)
    out = tool(client, tokens["access_token"], "run_command", instance_id=iid, command="echo hi")
    assert out["structuredContent"]["exit_code"] == 0
    done = tool(client, tokens["access_token"], "terminate_instance", instance_id=iid)
    assert done["isError"] is False
    spend = tool(client, tokens["access_token"], "spend_log")
    assert [e["event"] for e in spend["structuredContent"]["events"]] == ["launch", "terminate"]
    # The Lambda key never leaves the server.
    for r in fake_lambda.requests:
        assert r.headers["authorization"] == f"Bearer {API_KEY}"
    assert API_KEY not in json.dumps(spend)


def test_wrong_passphrase_is_refused_and_locks_out(client):
    client_id = register(client).json()["client_id"]
    _, challenge = pkce()
    r = authorize(client, client_id, challenge, passphrase="nope")
    assert r.status_code == 401 and "That passphrase isn" in r.text
    for _ in range(9):
        authorize(client, client_id, challenge, passphrase="nope")
    r = authorize(client, client_id, challenge)  # right passphrase, but locked out now
    assert r.status_code == 429


def test_deny_redirects_with_access_denied(client):
    client_id = register(client).json()["client_id"]
    _, challenge = pkce()
    r = client.get(
        "/authorize",
        params={"response_type": "code", "client_id": client_id, "redirect_uri": CALLBACK, "code_challenge": challenge, "code_challenge_method": "S256", "state": "s"},
    )
    req = re.search(r'name="req" value="([^"]+)"', r.text).group(1)
    r = client.post("/authorize", data={"req": req, "action": "deny"})
    assert r.status_code == 302 and "error=access_denied" in r.headers["location"]


def test_registration_only_accepts_claude_callbacks(client):
    assert register(client, ["https://evil.example/cb"]).status_code == 400
    assert register(client, [CALLBACK, "https://evil.example/cb"]).status_code == 400
    assert register(client, ["http://localhost/callback"]).status_code == 201
    r = client.post("/register", json={"redirect_uris": [CALLBACK], "token_endpoint_auth_method": "client_secret_basic"})
    assert r.status_code == 400


def test_loopback_redirect_matches_any_port(client):
    client_id = register(client, ["http://localhost/callback"]).json()["client_id"]
    _, challenge = pkce()
    r = authorize(client, client_id, challenge, redirect="http://localhost:53122/callback")
    assert r.status_code == 302 and r.headers["location"].startswith("http://localhost:53122/callback?code=")


def test_authorize_rejects_unregistered_redirect_and_forged_client(client):
    client_id = register(client).json()["client_id"]
    _, challenge = pkce()
    r = client.get("/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": "https://evil.example/cb", "code_challenge": challenge, "code_challenge_method": "S256"})
    assert r.status_code == 400
    r = client.get("/authorize", params={"response_type": "code", "client_id": "made-up", "redirect_uri": CALLBACK, "code_challenge": challenge, "code_challenge_method": "S256"})
    assert r.status_code == 400
    r = client.get("/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": CALLBACK})
    assert r.status_code == 302 and "error=invalid_request" in r.headers["location"]


def test_code_needs_pkce_and_works_once(client):
    client_id = register(client).json()["client_id"]
    verifier, challenge = pkce()
    loc = authorize(client, client_id, challenge).headers["location"]
    code = parse_qs(urlsplit(loc).query)["code"][0]
    base = {"grant_type": "authorization_code", "code": code, "redirect_uri": CALLBACK, "client_id": client_id}
    assert client.post("/token", data={**base, "code_verifier": "wrong"}).json()["error"] == "invalid_grant"
    other = register(client).json()["client_id"]
    assert client.post("/token", data={**base, "client_id": other, "code_verifier": verifier}).json()["error"] == "invalid_grant"
    assert client.post("/token", data={**base, "code_verifier": verifier}).status_code == 200
    assert client.post("/token", data={**base, "code_verifier": verifier}).json()["error"] == "invalid_grant"


def test_code_expires(client, clock):
    client_id = register(client).json()["client_id"]
    verifier, challenge = pkce()
    code = parse_qs(urlsplit(authorize(client, client_id, challenge).headers["location"]).query)["code"][0]
    clock.advance(301)
    r = client.post("/token", data={"grant_type": "authorization_code", "code": code, "client_id": client_id, "code_verifier": verifier})
    assert r.json()["error"] == "invalid_grant"


def test_refresh_rotates_and_reuse_revokes_family(client, clock):
    client_id, tokens = sign_in(client)
    r1 = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"], "client_id": client_id})
    assert r1.status_code == 200
    new = r1.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    # Replaying the old refresh token is treated as theft: it and the new one stop working.
    replay = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    again = client.post("/token", data={"grant_type": "refresh_token", "refresh_token": new["refresh_token"]})
    assert again.json()["error"] == "invalid_grant"


def test_access_token_expiry_and_tampering(client, clock):
    _, tokens = sign_in(client)
    access = tokens["access_token"]
    assert mcp_call(client, access, "tools/list").status_code == 200
    head, body, sig = access.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["sub"] = "someone-else"
    forged = head + "." + base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode() + "." + sig
    assert mcp_call(client, forged, "tools/list").status_code == 401
    # A refresh token can't be used as an access token.
    assert mcp_call(client, tokens["refresh_token"], "tools/list").status_code == 401
    clock.advance(3601)
    r = mcp_call(client, access, "tools/list")
    assert r.status_code == 401 and 'error="invalid_token"' in r.headers["www-authenticate"]


def test_tokens_from_another_signing_key_are_rejected(client, settings, service, store):
    from lambda_connector.oauth import OAuthServer

    from conftest import make_settings

    other = OAuthServer(make_settings(oauth_signing_key="z" * 48), store, clock=service.clock)
    token = other._issue_tokens("fam", "cid")["access_token"]
    assert mcp_call(client, token, "tools/list").status_code == 401


def test_reaper_endpoint_requires_scheduler_token(client, fake_lambda, clock):
    _, tokens = sign_in(client)
    tool(client, tokens["access_token"], "launch_instance", instance_type="gpu_1x_a10", region="us-east-1", max_hours=1, name="r")
    assert client.post("/tasks/reap").status_code == 401
    assert client.post("/tasks/reap", headers={"Authorization": "Bearer nope"}).status_code == 401
    # An MCP access token is not a scheduler token.
    assert client.post("/tasks/reap", headers={"Authorization": f"Bearer {tokens['access_token']}"}).status_code == 401
    clock.advance(3601)
    r = client.post("/tasks/reap", headers={"Authorization": "Bearer scheduler-token"})
    assert r.status_code == 200 and len(r.json()["reaped"]) == 1


def test_healthz_is_open(client):
    assert client.get("/healthz").json() == {"ok": True}
