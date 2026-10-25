"""K5 at unit level: the gateway passes only what it was told to pass.

Runs net/gateway.js with the host's node against local TCP servers only —
no traffic leaves the machine.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import pytest

GATEWAY = Path(__file__).resolve().parents[2] / "net" / "gateway.js"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not on PATH")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EchoServer:
    """Answers every connection with b'ECHO:' + first chunk received."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                data = c.recv(1024)
                c.sendall(b"ECHO:" + data)

    def close(self):
        self.sock.close()


@pytest.fixture
def echo():
    s = EchoServer()
    yield s
    s.close()


def start_gateway(env: dict[str, str]) -> subprocess.Popen:
    p = subprocess.Popen(
        [NODE, str(GATEWAY)],
        env={**os.environ, "ACR_BIND": "127.0.0.1", **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    line = p.stdout.readline()
    if not line:
        p.wait(timeout=5)
        return p
    assert json.loads(line)["event"] == "ready"
    return p


def stop(p: subprocess.Popen) -> str:
    p.terminate()
    _, err = p.communicate(timeout=5)
    return err


def talk(port: int, payload: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(payload)
        chunks = []
        while True:
            try:
                b = s.recv(4096)
            except TimeoutError:
                break
            if not b:
                break
            chunks.append(b)
            if b"ECHO:" in b"".join(chunks):
                break
        return b"".join(chunks)


def test_forward_reaches_only_its_target(echo):
    lp = free_port()
    gw = start_gateway({"ACR_FORWARDS": f"{lp}=127.0.0.1:{echo.port}"})
    try:
        assert talk(lp, b"hello") == b"ECHO:hello"
    finally:
        err = stop(gw)
    assert '"event":"forward"' in err


def test_connect_proxy_allows_the_listed_target_and_refuses_others(echo):
    cp = free_port()
    gw = start_gateway({"ACR_CONNECT_PORT": str(cp), "ACR_CONNECT_ALLOW": f"127.0.0.1:{echo.port}"})
    try:
        ok = talk(cp, f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: x\r\n\r\nping".encode())
        assert ok.startswith(b"HTTP/1.1 200") and ok.endswith(b"ECHO:ping")
        denied = talk(cp, b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert denied.startswith(b"HTTP/1.1 403")
        other_port = talk(cp, f"CONNECT 127.0.0.1:{echo.port + 1} HTTP/1.1\r\n\r\n".encode())
        assert other_port.startswith(b"HTTP/1.1 403")
        plain = talk(cp, b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert plain.startswith(b"HTTP/1.1 405")
    finally:
        err = stop(gw)
    decisions = [json.loads(x) for x in err.splitlines() if '"event":"connect"' in x]
    assert [d["allowed"] for d in decisions] == [True, False, False, False]
    assert all("Host" not in json.dumps(d) for d in decisions)  # headers are never logged


def test_proxy_auth_header_is_not_logged(echo):
    cp = free_port()
    gw = start_gateway({"ACR_CONNECT_PORT": str(cp), "ACR_CONNECT_ALLOW": f"127.0.0.1:{echo.port}"})
    try:
        talk(cp, b"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic U0VDUkVUOnNlY3JldA==\r\n\r\n")
    finally:
        err = stop(gw)
    assert "U0VDUkVU" not in err


@pytest.mark.parametrize(
    "env",
    [
        {},  # nothing to do
        {"ACR_FORWARDS": "abc"},  # malformed
        {"ACR_FORWARDS": "70000=127.0.0.1:1"},  # port out of range
        {"ACR_CONNECT_PORT": "3128", "ACR_CONNECT_ALLOW": "no-port"},
    ],
)
def test_bad_configuration_is_fatal(env):
    gw = start_gateway(env)
    gw.wait(timeout=5)
    assert gw.returncode == 2
    assert '"event":"fatal"' in gw.stderr.read()
