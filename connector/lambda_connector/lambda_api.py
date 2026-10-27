"""Thin async client for the Lambda Cloud API (v1).

Written against Lambda's public docs (docs.lambda.ai/api/cloud): base URL
https://cloud.lambda.ai/api/v1, Bearer auth, responses wrapped in {"data": ...},
errors as {"error": {"code", "message", "suggestion"}}.
"""

from __future__ import annotations

from typing import Any

import httpx


class LambdaAPIError(Exception):
    def __init__(self, status: int, code: str, message: str, suggestion: str | None = None) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.suggestion = suggestion
        text = f"Lambda API error {status} {code}: {message}"
        if suggestion:
            text += f" ({suggestion})"
        super().__init__(text)


class LambdaClient:
    def __init__(self, api_key: str, base_url: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=httpx.Timeout(30.0),
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, json: dict[str, Any] | None = None) -> Any:
        try:
            resp = await self._client.request(method, path, json=json)
        except httpx.HTTPError as exc:
            # The exception text never includes request headers, so the key stays out of it.
            raise LambdaAPIError(0, "network-error", f"{type(exc).__name__}: {exc}") from None
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code >= 400 or (isinstance(body, dict) and "error" in body):
            err = (body or {}).get("error", {}) if isinstance(body, dict) else {}
            raise LambdaAPIError(
                resp.status_code,
                str(err.get("code", "unknown")),
                str(err.get("message", resp.reason_phrase)),
                err.get("suggestion"),
            )
        if not isinstance(body, dict) or "data" not in body:
            raise LambdaAPIError(resp.status_code, "bad-response", "Response had no data field")
        return body["data"]

    async def instance_types(self) -> dict[str, Any]:
        """{type_name: {"instance_type": {...,"price_cents_per_hour"}, "regions_with_capacity_available": [...]}}"""
        return await self._request("GET", "/instance-types")

    async def list_instances(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/instances")

    async def get_instance(self, instance_id: str) -> dict[str, Any]:
        return await self._request("GET", f"/instances/{instance_id}")

    async def launch(self, region: str, instance_type: str, ssh_key_name: str, name: str) -> list[str]:
        data = await self._request(
            "POST",
            "/instance-operations/launch",
            json={
                "region_name": region,
                "instance_type_name": instance_type,
                "ssh_key_names": [ssh_key_name],
                "quantity": 1,
                "name": name,
            },
        )
        return list(data.get("instance_ids", []))

    async def terminate(self, instance_ids: list[str]) -> list[dict[str, Any]]:
        data = await self._request("POST", "/instance-operations/terminate", json={"instance_ids": instance_ids})
        return list(data.get("terminated_instances", []))

    async def list_ssh_keys(self) -> list[dict[str, Any]]:
        return await self._request("GET", "/ssh-keys")

    async def add_ssh_key(self, name: str, public_key: str) -> dict[str, Any]:
        return await self._request("POST", "/ssh-keys", json={"name": name, "public_key": public_key})
