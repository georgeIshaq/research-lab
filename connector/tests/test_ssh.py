"""ParamikoRunner against a real SSH server running in-process on localhost."""

import asyncio
import io
import os
import socket
import subprocess
import threading

import paramiko
import pytest

from lambda_connector.ssh import ParamikoRunner, SSHError, load_private_key, public_key_line


class _Server(paramiko.ServerInterface):
    def __init__(self, allowed: paramiko.PKey) -> None:
        self.allowed = allowed
        self.command: bytes | None = None
        self.event = threading.Event()

    def check_auth_publickey(self, username, key):
        ok = username == "ubuntu" and key.get_base64() == self.allowed.get_base64()
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        self.command = command
        self.event.set()
        return True


class _SFTPHandle(paramiko.SFTPHandle):
    pass


class _SFTP(paramiko.SFTPServerInterface):
    root = "/"

    def _real(self, path):
        return os.path.join(self.root, path.lstrip("/"))

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(self._real(path)))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    lstat = stat

    def open(self, path, flags, attr):
        real = self._real(path)
        try:
            fd = os.open(real, flags, 0o644)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        if flags & os.O_WRONLY:
            mode = "ab" if flags & os.O_APPEND else "wb"
        elif flags & os.O_RDWR:
            mode = "a+b" if flags & os.O_APPEND else "r+b"
        else:
            mode = "rb"
        f = os.fdopen(fd, mode)
        h = _SFTPHandle(flags)
        h.filename = real
        h.readfile = f
        h.writefile = f
        return h


@pytest.fixture
def sshd(tmp_path):
    client_key = paramiko.Ed25519Key.from_private_key(io.StringIO(_gen_ed25519()))
    host_key = paramiko.RSAKey.generate(2048)
    _SFTP.root = str(tmp_path)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    def handle(conn):
        try:
            _handle(conn)
        except (paramiko.SSHException, OSError, EOFError):
            pass  # a client the test meant to reject hung up

    def _handle(conn):
        t = paramiko.Transport(conn)
        t.add_server_key(host_key)
        t.set_subsystem_handler("sftp", paramiko.SFTPServer, _SFTP)
        server = _Server(client_key)
        t.start_server(server=server)
        chan = t.accept(10)
        if chan is None:
            return
        if server.event.wait(2) and server.command is not None:
            proc = subprocess.run(["bash", "-c", server.command.decode()], capture_output=True, cwd=tmp_path, timeout=10)
            chan.sendall(proc.stdout)
            chan.sendall_stderr(proc.stderr)
            chan.send_exit_status(proc.returncode)
            chan.close()
        else:
            while t.is_active():
                t.join(0.1)

    threading.Thread(target=serve, daemon=True).start()
    yield port, client_key, host_key, tmp_path
    stop.set()
    sock.close()


def _gen_ed25519() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return (
        Ed25519PrivateKey.generate()
        .private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        .decode()
    )


def test_load_private_key_and_public_line():
    key = load_private_key(_gen_ed25519())
    line = public_key_line(key, "claude-lab-connector")
    assert line.startswith("ssh-ed25519 ") and line.endswith(" claude-lab-connector")
    with pytest.raises(SSHError):
        load_private_key("not a key")


def test_run_read_write_and_host_key_pinning(sshd):
    port, client_key, host_key, root = sshd
    runner = ParamikoRunner(client_key, "ubuntu", connect_timeout=5, port=port)
    res = asyncio.run(runner.run("127.0.0.1", None, "echo out; echo err >&2; exit 3", 10, 50_000))
    assert (res.exit_code, res.stdout, res.stderr, res.timed_out) == (3, "out\n", "err\n", False)
    pinned = res.host_key
    assert pinned == f"{host_key.get_name()} {host_key.get_base64()}"

    # Output beyond the limit keeps the tail.
    res = asyncio.run(runner.run("127.0.0.1", pinned, "seq 1 2000", 10, 100))
    assert res.truncated and res.stdout.endswith("2000\n") and len(res.stdout) == 100

    asyncio.run(runner.write_file("127.0.0.1", pinned, "notes.txt", b"hello ", False))
    asyncio.run(runner.write_file("127.0.0.1", pinned, "notes.txt", b"world", True))
    assert (root / "notes.txt").read_bytes() == b"hello world"
    fr = asyncio.run(runner.read_file("127.0.0.1", pinned, "notes.txt", 6, 100))
    assert (fr.data, fr.size) == (b"world", 11)
    with pytest.raises(SSHError, match="No such file"):
        asyncio.run(runner.read_file("127.0.0.1", pinned, "missing.txt", 0, 10))

    with pytest.raises(SSHError, match="Host key"):
        asyncio.run(runner.run("127.0.0.1", "ssh-rsa AAAAWRONG", "true", 5, 100))


def test_wrong_client_key_is_rejected(sshd):
    port, *_ = sshd
    stranger = paramiko.Ed25519Key.from_private_key(io.StringIO(_gen_ed25519()))
    runner = ParamikoRunner(stranger, "ubuntu", connect_timeout=5, port=port)
    with pytest.raises(SSHError, match="Could not connect"):
        asyncio.run(runner.run("127.0.0.1", None, "true", 5, 100))
