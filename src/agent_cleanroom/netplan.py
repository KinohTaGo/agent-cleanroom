"""Network plan: the single way out of a run's internal network.

The agent container joins a Docker network created with ``--internal`` (no
route anywhere). A gateway container on that network and on a normal one
passes on only what the plan allows:

* ``forward`` — the backend runs on the host (Ollama, llama-server, a mock).
  The gateway listens on the backend's port and pipes it to the host alias.
  The agent sees ``http://gateway:<port>``; nothing else is reachable.
* ``connect-proxy`` — the backend is a remote HTTPS API. The gateway runs an
  HTTP CONNECT proxy that accepts exactly ``<host>:<port>`` of that API.
* ``none`` — no backend at all: the gateway is not started, the agent has no
  way out.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

GATEWAY_ALIAS = "gateway"
HOST_ALIAS = "host.docker.internal"
CONNECT_PORT = 3128
LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", HOST_ALIAS})


class NetPlanError(ValueError):
    pass


@dataclass(frozen=True)
class Forward:
    listen: int
    host: str
    port: int

    def spec(self) -> str:
        return f"{self.listen}={self.host}:{self.port}"


@dataclass(frozen=True)
class NetworkPlan:
    mode: str  # "forward" | "connect-proxy" | "none"
    container_base_url: str | None
    forwards: tuple[Forward, ...] = ()
    connect_port: int | None = None
    connect_allow: tuple[str, ...] = ()
    proxy_url: str | None = None
    notes: tuple[str, ...] = field(default=())

    @property
    def needs_gateway(self) -> bool:
        return self.mode != "none"

    def gateway_env(self) -> dict[str, str]:
        env: dict[str, str] = {}
        if self.forwards:
            env["ACR_FORWARDS"] = ",".join(f.spec() for f in self.forwards)
        if self.connect_port:
            env["ACR_CONNECT_PORT"] = str(self.connect_port)
            env["ACR_CONNECT_ALLOW"] = ",".join(self.connect_allow)
        return env

    def describe(self) -> dict:
        return {
            "mode": self.mode,
            "internal_network": True,
            "gateway": self.needs_gateway,
            "container_base_url": self.container_base_url,
            "forwards": [f"gateway:{f.listen} -> {f.host}:{f.port}" for f in self.forwards],
            "connect_allow": list(self.connect_allow),
            "proxy": self.proxy_url,
        }


def plan_for(url: str | None) -> NetworkPlan:
    """Work out the gateway for a backend URL as the host sees it."""
    if url is None:
        return NetworkPlan(mode="none", container_base_url=None)
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        raise NetPlanError(f"backend URL must be http(s)://host[:port], got {url!r}")
    if parts.username or parts.password:
        raise NetPlanError("backend URL must not carry credentials; use --auth-env-file")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise NetPlanError("backend URL must be scheme://host[:port] only (no path or query)")
    port = parts.port or (443 if scheme == "https" else 80)
    if host in LOCAL_HOSTS:
        if scheme != "http":
            raise NetPlanError("a backend on the host must be plain http (the gateway forwards TCP)")
        return NetworkPlan(
            mode="forward",
            container_base_url=f"http://{GATEWAY_ALIAS}:{port}",
            forwards=(Forward(listen=port, host=HOST_ALIAS, port=port),),
        )
    if scheme != "https":
        raise NetPlanError("a remote backend must be https (plain http leaves the machine unencrypted)")
    netloc_host = f"[{host}]" if ":" in host else host
    return NetworkPlan(
        mode="connect-proxy",
        container_base_url=f"https://{netloc_host}" + (f":{port}" if port != 443 else ""),
        connect_port=CONNECT_PORT,
        connect_allow=(f"{netloc_host}:{port}",),
        proxy_url=f"http://{GATEWAY_ALIAS}:{CONNECT_PORT}",
    )
