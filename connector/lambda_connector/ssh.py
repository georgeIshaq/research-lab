"""SSH and SFTP to instances, using the connector's private key.

Host keys are trust-on-first-use: the first key an instance shows is saved in
the instance record, and a different key on a later connection is refused.
"""

from __future__ import annotations

import asyncio
import io
import time
from dataclasses import dataclass
from typing import Protocol

import paramiko


class SSHError(Exception):
    pass


@dataclass
class CommandResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    host_key: str


@dataclass
class FileRead:
    data: bytes
    size: int
    host_key: str


class Runner(Protocol):
    async def run(self, host: str, known_host_key: str | None, command: str, timeout: float, max_output: int) -> CommandResult: ...

    async def read_file(self, host: str, known_host_key: str | None, path: str, offset: int, max_bytes: int) -> FileRead: ...

    async def write_file(self, host: str, known_host_key: str | None, path: str, data: bytes, append: bool) -> str: ...


def load_private_key(text: str) -> paramiko.PKey:
    text = text.strip() + "\n"
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text))
        except (paramiko.SSHException, ValueError):
            continue
    raise SSHError("SSH_PRIVATE_KEY is not an unencrypted Ed25519, ECDSA or RSA private key")


def public_key_line(key: paramiko.PKey, comment: str) -> str:
    return f"{key.get_name()} {key.get_base64()} {comment}"


class _TofuPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected: str | None) -> None:
        self.expected = expected
        self.observed: str | None = None

    def missing_host_key(self, client, hostname, key) -> None:  # noqa: ANN001 (paramiko signature)
        observed = f"{key.get_name()} {key.get_base64()}"
        if self.expected and observed != self.expected:
            raise SSHError(
                f"Host key for {hostname} changed since first connection; refusing to connect"
            )
        self.observed = observed


class _TailBuffer:
    """Keeps the last `limit` bytes, which is the useful end of a training log."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.buf = bytearray()
        self.truncated = False

    def add(self, chunk: bytes) -> None:
        self.buf += chunk
        if len(self.buf) > self.limit:
            del self.buf[: len(self.buf) - self.limit]
            self.truncated = True

    def text(self) -> str:
        return self.buf.decode("utf-8", errors="replace")


class ParamikoRunner:
    def __init__(self, private_key: paramiko.PKey, username: str, connect_timeout: float = 15.0, port: int = 22) -> None:
        self._key = private_key
        self._user = username
        self._connect_timeout = connect_timeout
        self._port = port

    def _connect(self, host: str, known_host_key: str | None) -> tuple[paramiko.SSHClient, str]:
        client = paramiko.SSHClient()
        policy = _TofuPolicy(known_host_key)
        client.set_missing_host_key_policy(policy)
        try:
            client.connect(
                host,
                port=self._port,
                username=self._user,
                pkey=self._key,
                timeout=self._connect_timeout,
                banner_timeout=self._connect_timeout,
                auth_timeout=self._connect_timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        except SSHError:
            client.close()
            raise
        except (paramiko.SSHException, OSError) as exc:
            client.close()
            raise SSHError(f"Could not connect to {host}: {exc}") from None
        return client, policy.observed or known_host_key or ""

    def _run(self, host: str, known: str | None, command: str, timeout: float, max_output: int) -> CommandResult:
        client, host_key = self._connect(host, known)
        try:
            chan = client.get_transport().open_session()
            chan.exec_command(command)
            out, err = _TailBuffer(max_output), _TailBuffer(max_output)
            deadline = time.monotonic() + timeout
            timed_out = False
            while True:
                busy = False
                while chan.recv_ready():
                    out.add(chan.recv(65536))
                    busy = True
                while chan.recv_stderr_ready():
                    err.add(chan.recv_stderr(65536))
                    busy = True
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                if not busy:
                    time.sleep(0.05)
            exit_code = None if timed_out else chan.recv_exit_status()
            chan.close()
            return CommandResult(exit_code, out.text(), err.text(), timed_out, out.truncated or err.truncated, host_key)
        finally:
            client.close()

    def _read(self, host: str, known: str | None, path: str, offset: int, max_bytes: int) -> FileRead:
        client, host_key = self._connect(host, known)
        try:
            sftp = client.open_sftp()
            try:
                size = sftp.stat(path).st_size or 0
                with sftp.open(path, "rb") as f:
                    f.seek(offset)
                    data = f.read(max_bytes)
            except FileNotFoundError:
                raise SSHError(f"No such file on the instance: {path}") from None
            except OSError as exc:
                raise SSHError(f"Could not read {path}: {exc}") from None
            return FileRead(data, size, host_key)
        finally:
            client.close()

    def _write(self, host: str, known: str | None, path: str, data: bytes, append: bool) -> str:
        client, host_key = self._connect(host, known)
        try:
            sftp = client.open_sftp()
            try:
                with sftp.open(path, "ab" if append else "wb") as f:
                    f.write(data)
            except OSError as exc:
                raise SSHError(f"Could not write {path}: {exc}") from None
            return host_key
        finally:
            client.close()

    async def run(self, host: str, known_host_key: str | None, command: str, timeout: float, max_output: int) -> CommandResult:
        return await asyncio.to_thread(self._run, host, known_host_key, command, timeout, max_output)

    async def read_file(self, host: str, known_host_key: str | None, path: str, offset: int, max_bytes: int) -> FileRead:
        return await asyncio.to_thread(self._read, host, known_host_key, path, offset, max_bytes)

    async def write_file(self, host: str, known_host_key: str | None, path: str, data: bytes, append: bool) -> str:
        return await asyncio.to_thread(self._write, host, known_host_key, path, data, append)
