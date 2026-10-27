"""Small JSON document store.

Cloud Run keeps nothing between requests, so anything that must last (which
instances we launched, the spend log, used one-time OAuth codes) lives here.
`GCSStore` keeps one JSON object per key in a Cloud Storage bucket;
`MemoryStore` is for tests and local runs.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import Any, Protocol


class Store(Protocol):
    async def get(self, key: str) -> dict[str, Any] | None: ...

    async def put(self, key: str, doc: dict[str, Any]) -> None: ...

    async def create(self, key: str, doc: dict[str, Any]) -> bool:
        """Write `doc` only if `key` doesn't exist yet. Returns False if it did."""
        ...

    async def list(self, prefix: str) -> list[dict[str, Any]]: ...


class MemoryStore:
    def __init__(self) -> None:
        self._docs: dict[str, str] = {}
        self._lock = threading.Lock()

    async def get(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            raw = self._docs.get(key)
        return json.loads(raw) if raw is not None else None

    async def put(self, key: str, doc: dict[str, Any]) -> None:
        with self._lock:
            self._docs[key] = json.dumps(doc)

    async def create(self, key: str, doc: dict[str, Any]) -> bool:
        with self._lock:
            if key in self._docs:
                return False
            self._docs[key] = json.dumps(doc)
            return True

    async def list(self, prefix: str) -> list[dict[str, Any]]:
        with self._lock:
            items = sorted((k, v) for k, v in self._docs.items() if k.startswith(prefix))
        return [json.loads(v) for _, v in items]


class GCSStore:
    def __init__(self, bucket_name: str, client: Any = None) -> None:
        from google.cloud import storage  # imported lazily so tests don't need credentials

        self._client = client or storage.Client()
        self._bucket = self._client.bucket(bucket_name)

    async def get(self, key: str) -> dict[str, Any] | None:
        from google.api_core.exceptions import NotFound

        def _get() -> dict[str, Any] | None:
            try:
                return json.loads(self._bucket.blob(key).download_as_bytes())
            except NotFound:
                return None

        return await asyncio.to_thread(_get)

    async def put(self, key: str, doc: dict[str, Any]) -> None:
        await asyncio.to_thread(
            self._bucket.blob(key).upload_from_string, json.dumps(doc), content_type="application/json"
        )

    async def create(self, key: str, doc: dict[str, Any]) -> bool:
        from google.api_core.exceptions import PreconditionFailed

        def _create() -> bool:
            try:
                # if_generation_match=0 makes the write fail if the object exists,
                # which gives an atomic "use once" marker.
                self._bucket.blob(key).upload_from_string(
                    json.dumps(doc), content_type="application/json", if_generation_match=0
                )
                return True
            except PreconditionFailed:
                return False

        return await asyncio.to_thread(_create)

    async def list(self, prefix: str) -> list[dict[str, Any]]:
        def _list() -> list[dict[str, Any]]:
            blobs = sorted(self._client.list_blobs(self._bucket, prefix=prefix), key=lambda b: b.name)
            return [json.loads(b.download_as_bytes()) for b in blobs]

        return await asyncio.to_thread(_list)
