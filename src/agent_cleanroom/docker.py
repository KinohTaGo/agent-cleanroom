"""Docker plumbing: the hardened `docker run` argv and the run's network.

The argv builders are pure functions so the hardening can be tested without
Docker. ``DockerExecutor`` is the only place that runs the docker CLI.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from agent_cleanroom.netplan import GATEWAY_ALIAS, HOST_ALIAS, NetworkPlan

LABEL = "io.github.agent-cleanroom.run"
CLEANROOM_USER = "10001:10001"
GATEWAY_SCRIPT = "/usr/local/lib/agent-cleanroom/gateway.js"
TINI = "/usr/bin/tini"


class DockerError(RuntimeError):
    pass


@dataclass(frozen=True)
class Hardening:
    memory: str = "4g"
    pids_limit: int = 512
    tmpfs_size: str = "1g"

    def args(self) -> list[str]:
        return [
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--user",
            CLEANROOM_USER,
            "--memory",
            self.memory,
            "--memory-swap",
            self.memory,
            "--pids-limit",
            str(self.pids_limit),
        ]

    def describe(self) -> dict:
        return {
            "cap_drop": ["ALL"],
            "no_new_privileges": True,
            "read_only_root": True,
            "user": CLEANROOM_USER,
            "memory": self.memory,
            "pids_limit": self.pids_limit,
            "tmpfs": ["/cleanroom", "/tmp"],
        }


@dataclass
class ContainerSpec:
    image: str
    command: list[str]
    name: str
    network: str
    env: dict[str, str] = field(default_factory=dict)  # values on argv: never secrets
    pass_env: list[str] = field(default_factory=list)  # names; docker reads the values
    env_file: Path | None = None  # the user's auth file; docker reads it
    workdir: Path | None = None  # mounted at /work
    outdir: Path | None = None  # mounted at /out
    hardening: Hardening = field(default_factory=Hardening)
    labels: dict[str, str] = field(default_factory=dict)


def agent_run_argv(spec: ContainerSpec, docker: str = "docker") -> list[str]:
    tmpfs_opts = f"rw,nosuid,nodev,size={spec.hardening.tmpfs_size},mode=1777"
    argv = [docker, "run", "--rm", "--name", spec.name, "--network", spec.network]
    argv += spec.hardening.args()
    argv += ["--tmpfs", f"/cleanroom:{tmpfs_opts}", "--tmpfs", f"/tmp:{tmpfs_opts}"]
    for k, v in sorted(spec.labels.items()):
        argv += ["--label", f"{k}={v}"]
    if spec.workdir is not None:
        argv += ["-v", f"{spec.workdir}:/work:rw"]
    if spec.outdir is not None:
        argv += ["-v", f"{spec.outdir}:/out:rw"]
    argv += ["-w", "/work"]
    for k, v in sorted(spec.env.items()):
        argv += ["-e", f"{k}={v}"]
    for name in sorted(set(spec.pass_env)):
        argv += ["-e", name]
    if spec.env_file is not None:
        argv += ["--env-file", str(spec.env_file)]
    argv += [spec.image, TINI, "-s", "--", *spec.command]
    return argv


def gateway_run_argv(
    plan: NetworkPlan, name: str, image: str, labels: dict[str, str], docker: str = "docker"
) -> list[str]:
    argv = [docker, "run", "-d", "--rm", "--name", name, "--network", "bridge"]
    argv += ["--add-host", f"{HOST_ALIAS}:host-gateway"]
    argv += Hardening(memory="128m", pids_limit=64).args()
    for k, v in sorted(labels.items()):
        argv += ["--label", f"{k}={v}"]
    for k, v in sorted(plan.gateway_env().items()):
        argv += ["-e", f"{k}={v}"]
    argv += [image, "node", GATEWAY_SCRIPT]
    return argv


@dataclass
class ExecResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


class DockerExecutor:
    """Runs containers for real. One instance per run."""

    def __init__(self, docker: str | None = None):
        self.docker = docker or os.environ.get("AGENT_CLEANROOM_DOCKER", "docker")
        self.gateway_log = b""

    def _call(self, args: list[str], timeout: float = 120) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(args, capture_output=True, timeout=timeout, check=False)
        except FileNotFoundError as e:
            raise DockerError(f"docker CLI not found ({self.docker})") from e
        except subprocess.TimeoutExpired as e:
            raise DockerError(f"docker did not answer within {timeout}s: {' '.join(args[:3])}") from e

    def _ok(self, args: list[str], what: str, timeout: float = 120) -> bytes:
        r = self._call(args, timeout)
        if r.returncode != 0:
            msg = r.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
            raise DockerError(f"{what} failed (rc={r.returncode}): {msg[0]}")
        return r.stdout

    def check(self) -> None:
        self._ok([self.docker, "version", "--format", "{{.Server.Version}}"], "docker version", 30)

    def image_id(self, ref: str) -> str:
        out = self._ok(
            [self.docker, "image", "inspect", "--format", "{{.Id}}", ref], f"image inspect {ref} (build it first)", 30
        )
        return out.decode().strip()

    @contextmanager
    def network(self, plan: NetworkPlan, run_id: str, gateway_image: str) -> Iterator[str]:
        net = f"acr-{run_id}"
        gw = f"acr-{run_id}-gw"
        labels = {LABEL: run_id}
        self._ok(
            [self.docker, "network", "create", "--internal", "--label", f"{LABEL}={run_id}", net], "network create"
        )
        try:
            if plan.needs_gateway:
                self._ok(gateway_run_argv(plan, gw, gateway_image, labels, self.docker), "gateway start")
                self._ok([self.docker, "network", "connect", "--alias", GATEWAY_ALIAS, net, gw], "gateway connect")
                self._wait_ready(gw)
            yield net
        finally:
            if plan.needs_gateway:
                r = self._call([self.docker, "logs", gw], 30)
                self.gateway_log = r.stderr if r.returncode == 0 else b""
                self._call([self.docker, "rm", "-f", gw], 60)
            self._call([self.docker, "network", "rm", net], 60)

    def _wait_ready(self, gw: str, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            r = self._call([self.docker, "logs", gw], 30)
            if b'"event":"ready"' in r.stdout:
                return
            if b'"event":"fatal"' in r.stderr:
                raise DockerError("gateway refused its configuration: " + r.stderr.decode()[-300:])
            time.sleep(0.3)
        raise DockerError(f"gateway was not ready within {timeout}s")

    def run(self, spec: ContainerSpec, timeout: float) -> ExecResult:
        argv = agent_run_argv(spec, self.docker)
        try:
            r = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
            return ExecResult(r.returncode, r.stdout, r.stderr)
        except subprocess.TimeoutExpired as e:
            self._call([self.docker, "rm", "-f", spec.name], 60)
            return ExecResult(124, e.stdout or b"", e.stderr or b"", timed_out=True)
        except FileNotFoundError as e:
            raise DockerError(f"docker CLI not found ({self.docker})") from e
        finally:
            self._call([self.docker, "rm", "-f", spec.name], 60)
