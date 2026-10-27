"""A one-user OAuth 2.1 authorization server, plus the bearer check on /mcp.

Claude custom connectors sign in with OAuth: Claude registers itself (dynamic
client registration), sends the browser to /authorize with a PKCE challenge,
then trades the code for tokens at /token. Here the "sign in" page asks for
the owner passphrase, so only someone holding it can connect a Claude account.

Everything is stateless except two kinds of tiny marker in the store: used
codes / refresh tokens (so each works once) and revoked refresh-token families.
Client ids, codes and tokens are HS256 JWTs signed with OAUTH_SIGNING_KEY;
rotating that secret logs every connected client out.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import secrets
import time
from collections import deque
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit

import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import Settings
from .store import Store

SCOPE = "lab"
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 24 * 3600
CODE_TTL = 300
AUTHREQ_TTL = 600
HOSTED_CALLBACKS = {
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1"}
FAILURE_WINDOW = 900
MAX_FAILURES = 10

_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _b64url_sha256(text: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).rstrip(b"=").decode()


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:32]


class OAuthServer:
    def __init__(self, settings: Settings, store: Store, clock: Callable[[], float] = time.time) -> None:
        self.s = settings
        self.store = store
        self.clock = clock
        self._key = hmac.new(settings.oauth_signing_key.encode(), b"lambda-connector-oauth-v1", hashlib.sha256).digest()
        self._failures: deque[float] = deque()

    # ---------- signing ----------

    def _sign(self, typ: str, claims: dict[str, Any], ttl: int | None) -> str:
        now = int(self.clock())
        body = {"typ": typ, "iss": self.s.public_url, "iat": now, **claims}
        if ttl is not None:
            body["exp"] = now + ttl
        return jwt.encode(body, self._key, algorithm="HS256")

    def _verify(self, token: str, typ: str, audience: str | None = None) -> dict[str, Any] | None:
        try:
            claims = jwt.decode(
                token,
                self._key,
                algorithms=["HS256"],
                issuer=self.s.public_url,
                audience=audience,
                # Expiry is checked below against the injectable clock, not by PyJWT.
                options={"verify_aud": audience is not None, "verify_exp": False, "verify_iat": False, "verify_nbf": False},
            )
        except jwt.PyJWTError:
            return None
        if claims.get("typ") != typ:
            return None
        exp = claims.get("exp")
        if exp is not None and self.clock() >= exp:
            return None
        return claims

    # ---------- redirect URIs ----------

    def _allowed_redirect(self, uri: str) -> bool:
        if uri in HOSTED_CALLBACKS:
            return True
        if not self.s.allow_loopback_redirects:
            return False
        parts = urlsplit(uri)
        return parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS and not parts.fragment

    @staticmethod
    def _redirect_matches(registered: str, requested: str) -> bool:
        if registered == requested:
            return True
        a, b = urlsplit(registered), urlsplit(requested)
        # RFC 8252: loopback redirects match whatever port the native client picked.
        return (
            a.scheme == b.scheme == "http"
            and a.hostname in LOOPBACK_HOSTS
            and a.hostname == b.hostname
            and a.path == b.path
            and a.query == b.query
        )

    # ---------- access tokens ----------

    def verify_access_token(self, token: str) -> dict[str, Any] | None:
        claims = self._verify(token, "access", audience=self.s.mcp_url)
        if claims and SCOPE in str(claims.get("scope", "")).split():
            return claims
        return None

    def _issue_tokens(self, family: str, client_digest: str) -> dict[str, Any]:
        access = self._sign(
            "access", {"aud": self.s.mcp_url, "sub": "owner", "scope": SCOPE, "fam": family, "jti": secrets.token_hex(8)}, ACCESS_TTL
        )
        refresh = self._sign("refresh", {"fam": family, "cid": client_digest, "jti": secrets.token_hex(16)}, REFRESH_TTL)
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL,
            "refresh_token": refresh,
            "scope": SCOPE,
        }

    # ---------- metadata ----------

    def protected_resource_metadata(self) -> dict[str, Any]:
        return {
            "resource": self.s.mcp_url,
            "authorization_servers": [self.s.public_url],
            "scopes_supported": [SCOPE],
            "bearer_methods_supported": ["header"],
            "resource_name": "Lambda GPU lab",
        }

    def authorization_server_metadata(self) -> dict[str, Any]:
        base = self.s.public_url
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SCOPE],
            "authorization_response_iss_parameter_supported": True,
        }

    async def _prm(self, request: Request) -> Response:
        return JSONResponse(self.protected_resource_metadata())

    async def _asm(self, request: Request) -> Response:
        return JSONResponse(self.authorization_server_metadata())

    # ---------- registration ----------

    async def _register(self, request: Request) -> Response:
        try:
            body = await request.json()
        except (ValueError, json.JSONDecodeError):
            return JSONResponse({"error": "invalid_client_metadata", "error_description": "Body must be JSON"}, 400)
        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            return JSONResponse({"error": "invalid_redirect_uri", "error_description": "redirect_uris is required"}, 400)
        bad = [u for u in uris if not self._allowed_redirect(u)]
        if bad:
            return JSONResponse(
                {"error": "invalid_redirect_uri", "error_description": "This server only accepts Claude's callback URLs"}, 400
            )
        auth_method = body.get("token_endpoint_auth_method", "none")
        if auth_method != "none":
            return JSONResponse(
                {"error": "invalid_client_metadata", "error_description": "Only public clients (auth method none) are supported"}, 400
            )
        name = str(body.get("client_name") or "MCP client")[:100]
        client_id = self._sign("client", {"ru": uris, "name": name, "jti": secrets.token_hex(8)}, None)
        return JSONResponse(
            {
                "client_id": client_id,
                "client_id_issued_at": int(self.clock()),
                "client_name": name,
                "redirect_uris": uris,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": SCOPE,
            },
            status_code=201,
        )

    # ---------- authorization ----------

    def _error_page(self, message: str, status: int = 400) -> Response:
        page = f"<!doctype html><title>Can't connect</title><body style='font-family:system-ui;max-width:32rem;margin:4rem auto'><h1>Can't connect</h1><p>{html.escape(message)}</p></body>"
        return HTMLResponse(page, status_code=status, headers=_SECURITY_HEADERS)

    @staticmethod
    def _redirect_with(uri: str, params: dict[str, str]) -> Response:
        sep = "&" if urlsplit(uri).query else "?"
        return RedirectResponse(uri + sep + urlencode({k: v for k, v in params.items() if v is not None}), status_code=302)

    def _consent_page(self, req_token: str, redirect_uri: str, client_name: str, error: str | None = None, status: int = 200) -> Response:
        host = urlsplit(redirect_uri).hostname or redirect_uri
        warn = ""
        if host in LOOPBACK_HOSTS:
            warn = "<p style='color:#a40'>This sends the sign-in to a program on your own computer (a local address). Only continue if you just started Claude Code.</p>"
        err = f"<p style='color:#b00'>{html.escape(error)}</p>" if error else ""
        page = f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Lambda GPU lab</title></head>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">
<h1>Connect Lambda GPU lab</h1>
<p><b>{html.escape(client_name)}</b> wants to launch, run commands on and terminate GPU instances in your Lambda account, within this connector's spending cap.</p>
<p>It will be sent back to <b>{html.escape(host)}</b>.</p>
{warn}{err}
<form method="post" action="/authorize">
<input type="hidden" name="req" value="{html.escape(req_token)}">
<label>Owner passphrase<br><input type="password" name="passphrase" autocomplete="current-password" required style="width:100%;padding:.5rem"></label>
<p><button type="submit" name="action" value="approve">Allow</button>
<button type="submit" name="action" value="deny" formnovalidate>Deny</button></p>
</form></body></html>"""
        return HTMLResponse(page, status_code=status, headers=_SECURITY_HEADERS)

    async def _authorize(self, request: Request) -> Response:
        if request.method == "POST":
            return await self._authorize_post(request)
        q = request.query_params
        client = self._verify(q.get("client_id", ""), "client")
        if not client:
            return self._error_page("Unknown client. Remove the connector in Claude and add it again.")
        registered: list[str] = client["ru"]
        redirect_uri = q.get("redirect_uri")
        if not redirect_uri:
            if len(registered) != 1:
                return self._error_page("redirect_uri is required.")
            redirect_uri = registered[0]
        if not any(self._redirect_matches(r, redirect_uri) for r in registered):
            return self._error_page("redirect_uri doesn't match the registered client.")
        state = q.get("state")
        if q.get("response_type") != "code":
            return self._redirect_with(redirect_uri, {"error": "unsupported_response_type", "state": state})
        if not q.get("code_challenge") or q.get("code_challenge_method") != "S256":
            return self._redirect_with(
                redirect_uri, {"error": "invalid_request", "error_description": "PKCE S256 is required", "state": state}
            )
        resource = q.get("resource")
        if resource and resource.rstrip("/") not in (self.s.mcp_url, self.s.public_url):
            return self._redirect_with(redirect_uri, {"error": "invalid_target", "state": state})
        req = self._sign(
            "authreq",
            {
                "cid": _digest(q["client_id"]),
                "ru": redirect_uri,
                "cc": q["code_challenge"],
                "state": state,
                "name": client.get("name", "MCP client"),
            },
            AUTHREQ_TTL,
        )
        return self._consent_page(req, redirect_uri, client.get("name", "MCP client"))

    def _locked_out(self) -> bool:
        now = self.clock()
        while self._failures and now - self._failures[0] > FAILURE_WINDOW:
            self._failures.popleft()
        return len(self._failures) >= MAX_FAILURES

    async def _authorize_post(self, request: Request) -> Response:
        form = await request.form()
        req = self._verify(str(form.get("req", "")), "authreq")
        if not req:
            return self._error_page("This sign-in page expired. Start connecting again from Claude.")
        redirect_uri = req["ru"]
        if form.get("action") == "deny":
            return self._redirect_with(redirect_uri, {"error": "access_denied", "state": req.get("state"), "iss": self.s.public_url})
        if self._locked_out():
            return self._consent_page(str(form["req"]), redirect_uri, req["name"], "Too many wrong passphrases. Try again in 15 minutes.", 429)
        given = str(form.get("passphrase", ""))
        if not hmac.compare_digest(given.encode(), self.s.owner_passphrase.encode()):
            self._failures.append(self.clock())
            await asyncio.sleep(1.0)
            return self._consent_page(str(form["req"]), redirect_uri, req["name"], "That passphrase isn't right.", 401)
        code = self._sign(
            "code", {"cid": req["cid"], "ru": redirect_uri, "cc": req["cc"], "jti": secrets.token_hex(16)}, CODE_TTL
        )
        return self._redirect_with(redirect_uri, {"code": code, "state": req.get("state"), "iss": self.s.public_url})

    # ---------- token ----------

    @staticmethod
    def _token_error(error: str, description: str, status: int = 400) -> Response:
        return JSONResponse({"error": error, "error_description": description}, status_code=status, headers={"Cache-Control": "no-store"})

    async def _token(self, request: Request) -> Response:
        ctype = request.headers.get("content-type", "")
        if "application/json" in ctype:
            try:
                data = {k: str(v) for k, v in (await request.json()).items()}
            except (ValueError, AttributeError):
                return self._token_error("invalid_request", "Malformed body")
        else:
            data = {k: str(v) for k, v in (await request.form()).items()}
        grant = data.get("grant_type")
        if grant == "authorization_code":
            return await self._grant_code(data)
        if grant == "refresh_token":
            return await self._grant_refresh(data)
        return self._token_error("unsupported_grant_type", "Use authorization_code or refresh_token")

    async def _grant_code(self, data: dict[str, str]) -> Response:
        code = self._verify(data.get("code", ""), "code")
        if not code:
            return self._token_error("invalid_grant", "Code is invalid or expired")
        client_id = data.get("client_id", "")
        if not client_id or _digest(client_id) != code["cid"] or not self._verify(client_id, "client"):
            return self._token_error("invalid_grant", "Code was issued to another client")
        if data.get("redirect_uri") and data["redirect_uri"] != code["ru"]:
            return self._token_error("invalid_grant", "redirect_uri doesn't match")
        verifier = data.get("code_verifier", "")
        if not verifier or not hmac.compare_digest(_b64url_sha256(verifier), code["cc"]):
            return self._token_error("invalid_grant", "PKCE verification failed")
        if not await self.store.create(f"oauth/used/{code['jti']}.json", {"at": self.clock(), "kind": "code"}):
            return self._token_error("invalid_grant", "Code was already used")
        return JSONResponse(self._issue_tokens(secrets.token_hex(12), code["cid"]), headers={"Cache-Control": "no-store"})

    async def _grant_refresh(self, data: dict[str, str]) -> Response:
        tok = self._verify(data.get("refresh_token", ""), "refresh")
        if not tok:
            return self._token_error("invalid_grant", "Refresh token is invalid or expired")
        client_id = data.get("client_id")
        if client_id and _digest(client_id) != tok["cid"]:
            return self._token_error("invalid_grant", "Refresh token was issued to another client")
        family = tok["fam"]
        if await self.store.get(f"oauth/revoked/{family}.json"):
            return self._token_error("invalid_grant", "This sign-in was revoked; connect again")
        if not await self.store.create(f"oauth/used/{tok['jti']}.json", {"at": self.clock(), "kind": "refresh", "fam": family}):
            # A rotated refresh token came back: someone may have copied it. Kill the whole family.
            await self.store.put(f"oauth/revoked/{family}.json", {"at": self.clock(), "reason": "refresh token reuse"})
            return self._token_error("invalid_grant", "Refresh token was already used; connect again")
        return JSONResponse(self._issue_tokens(family, tok["cid"]), headers={"Cache-Control": "no-store"})

    # ---------- wiring ----------

    def routes(self) -> list[Route]:
        return [
            Route("/.well-known/oauth-protected-resource", self._prm, methods=["GET"]),
            Route("/.well-known/oauth-protected-resource/mcp", self._prm, methods=["GET"]),
            Route("/.well-known/oauth-authorization-server", self._asm, methods=["GET"]),
            Route("/.well-known/oauth-authorization-server/mcp", self._asm, methods=["GET"]),
            Route("/register", self._register, methods=["POST"]),
            Route("/authorize", self._authorize, methods=["GET", "POST"]),
            Route("/token", self._token, methods=["POST"]),
        ]


class BearerGate:
    """ASGI wrapper: requests to /mcp need a valid access token, everything else passes."""

    def __init__(self, app: ASGIApp, oauth: OAuthServer) -> None:
        self.app = app
        self.oauth = oauth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and (scope["path"] == "/mcp" or scope["path"].startswith("/mcp/")):
            auth = ""
            for k, v in scope.get("headers", []):
                if k == b"authorization":
                    auth = v.decode("latin-1")
                    break
            token = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
            if not token or not self.oauth.verify_access_token(token):
                meta = f"{self.oauth.s.public_url}/.well-known/oauth-protected-resource/mcp"
                challenge = f'Bearer resource_metadata="{meta}", scope="{SCOPE}"'
                if token:
                    challenge += ', error="invalid_token"'
                resp = JSONResponse(
                    {"error": "invalid_token" if token else "unauthorized"},
                    status_code=401,
                    headers={"WWW-Authenticate": challenge},
                )
                await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)
