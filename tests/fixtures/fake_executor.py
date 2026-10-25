"""Docker-free stand-in for DockerExecutor (tests only).

``FakeExecutor`` runs the *real* verifier (verifier/verify.sh) against a fake
root with stub tools — the same trick the bats tests use — with the
environment the runner built for the container, then runs the agent command
on the host in the copied working directory. Everything the runner does
around the container (identity, env, redaction, diff, bundle, sums) is
exercised for real; only the container boundary is simulated.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from contextlib import contextmanager
from pathlib import Path

from agent_cleanroom.docker import ContainerSpec, ExecResult
from agent_cleanroom.redact import parse_env_file

REPO = Path(__file__).resolve().parents[2]
VERIFY = REPO / "verifier" / "verify.sh"
PIN = "2.1.308"


def _stub(bindir: Path, name: str, body: str) -> None:
    p = bindir / name
    p.write_text("#!/bin/sh\n" + body + "\n")
    p.chmod(0o755)


class FakeExecutor:
    """Docker-free stand-in. Knobs: dirty_home, hardening_ok, http_code."""

    def __init__(self, root: Path, *, dirty_home: bool = False, hardening_ok: bool = True, http_code: str = "200"):
        self.root = root
        self.dirty_home = dirty_home
        self.hardening_ok = hardening_ok
        self.http_code = http_code
        self.gateway_log = b""
        self.specs: list[ContainerSpec] = []
        self.networks: list[str] = []

    def check(self) -> None:
        pass

    def image_id(self, ref: str) -> str:
        return "sha256:" + "f" * 64

    @contextmanager
    def network(self, plan, run_id, gateway_image):
        self.networks.append(plan.mode)
        yield f"acr-{run_id}"
        self.gateway_log = b'{"event":"forward","listen":1,"to":"host.docker.internal:1"}\n'

    def _sysroot(self) -> tuple[Path, Path]:
        root = self.root / "sysroot"
        if root.exists():
            shutil.rmtree(root)
        for d in ("cleanroom/.config", "cleanroom/.local/share", "cleanroom/.cache", "etc", "proc/self"):
            (root / d).mkdir(parents=True)
        (root / "etc/cleanroom-claude-version").write_text(f"{PIN} (Claude Code)\n")
        if self.dirty_home:
            (root / "cleanroom/CLAUDE.md").write_text("be terse\n")
        cap, nnp, ro = ("0000000000000000", "1", "ro") if self.hardening_ok else ("a80425fb", "0", "rw")
        (root / "proc/self/status").write_text(f"CapBnd:\t{cap}\nNoNewPrivs:\t{nnp}\n")
        (root / "proc/self/mountinfo").write_text(f"1 0 0:1 / / {ro},relatime - overlay overlay rw\n")
        bindir = self.root / "stubbin"
        if bindir.exists():
            shutil.rmtree(bindir)
        bindir.mkdir()
        _stub(bindir, "claude", f'echo "{PIN} (Claude Code)"')
        _stub(bindir, "node", 'echo "v24.22.1"')
        _stub(bindir, "npm", 'echo "11.6.2"')
        _stub(
            bindir,
            "curl",
            'for a in "$@"; do [ "$a" = "-w" ] && { printf "%s" "${STUB_HTTP_CODE:-200}"; '
            'exit 0; }; done; echo "curl 8.14.1"',
        )
        jq = shutil.which("jq")
        if jq:
            os.symlink(jq, bindir / "jq")
        return root, bindir

    def _env(self, spec: ContainerSpec) -> dict[str, str]:
        env = dict(spec.env)
        for n in spec.pass_env:
            if n in os.environ:
                env[n] = os.environ[n]
        if spec.env_file is not None:
            env.update(parse_env_file(spec.env_file))
        return env

    def run(self, spec: ContainerSpec, timeout: float) -> ExecResult:
        self.specs.append(spec)
        root, bindir = self._sysroot()
        base = {
            "PATH": f"{bindir}:/usr/bin:/bin",
            "HOME": str(root / "cleanroom"),
            "CLAUDE_CONFIG_DIR": str(root / "cleanroom/.claude"),
            "CLAUDE_CLI_VERSION": PIN,
            "DISABLE_AUTOUPDATER": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "ACR_VERIFY_SYSROOT": str(root),
            "STUB_HTTP_CODE": self.http_code,
        }
        env = {**base, **self._env(spec)}
        cwd = spec.workdir or self.root
        v = subprocess.run(["bash", str(VERIFY)], cwd=cwd, env=env, capture_output=True, timeout=60)
        if spec.command == ["verify.sh"]:
            return ExecResult(v.returncode, v.stdout, v.stderr)
        assert spec.command[:4][0] == "bash" and spec.command[3] == "acr"
        assert spec.outdir is not None
        (spec.outdir / "env.json").write_bytes(v.stdout)
        if v.returncode != 0:
            (spec.outdir / "verify.stderr").write_bytes(v.stderr)
            return ExecResult(97, b"", b"")
        user_cmd = spec.command[4:]
        try:
            r = subprocess.run(
                user_cmd, cwd=cwd, env={**os.environ, **self._env(spec)}, capture_output=True, timeout=timeout
            )
        except subprocess.TimeoutExpired as e:
            return ExecResult(124, e.stdout or b"", e.stderr or b"", timed_out=True)
        return ExecResult(r.returncode, r.stdout, r.stderr)
