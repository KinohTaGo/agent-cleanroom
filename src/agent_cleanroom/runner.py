"""The `verify` and `run` pipelines.

Both start the same container the same way (internal network, gateway,
hardening flags, backend declared to the verifier). `verify` stops after the
verifier; `run` then executes the agent and writes a bundle.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import stat
import tempfile
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from agent_cleanroom import BACKEND_SCHEMA, MANIFEST_SCHEMA, __version__, bundle, redact, workdiff
from agent_cleanroom.backends import Backend
from agent_cleanroom.docker import ContainerSpec, ExecResult, Hardening
from agent_cleanroom.identify import Identity, identify
from agent_cleanroom.netplan import NetworkPlan, plan_for

VERIFY_THEN_EXEC = 'verify.sh > /out/env.json 2> /out/verify.stderr || exit 97; exec "$@"'
EXIT = {"ok": 0, "verify-failed": 1, "agent-failed": 3, "timeout": 3, "secret-found": 4}


class RunError(RuntimeError):
    """Infrastructure or usage problem: nothing was run (exit 2)."""


class Executor(Protocol):
    gateway_log: bytes

    def check(self) -> None: ...
    def image_id(self, ref: str) -> str: ...
    def network(self, plan: NetworkPlan, run_id: str, gateway_image: str) -> AbstractContextManager[str]: ...
    def run(self, spec: ContainerSpec, timeout: float) -> ExecResult: ...


@dataclass
class Options:
    backend: Backend | None
    model: str | None = None
    image: str = "agent-cleanroom/claude-code:local"
    gateway_image: str = "agent-cleanroom/base:local"
    workdir: Path | None = None
    runs_dir: Path = Path("runs")
    command: list[str] = field(default_factory=list)
    prompt: str | None = None
    auth_env_file: Path | None = None
    pass_env: list[str] = field(default_factory=list)
    allow_project_inputs: bool = False
    timeout: float = 1800.0
    hardening: Hardening = field(default_factory=Hardening)


@dataclass
class Outcome:
    status: str
    exit_code: int
    bundle_dir: Path | None
    verify_json: bytes = b""


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def check_auth_file(path: Path) -> None:
    try:
        st = path.stat()
    except OSError as e:
        raise RunError(f"cannot read --auth-env-file: {e.strerror}") from e
    if not stat.S_ISREG(st.st_mode):
        raise RunError("--auth-env-file must be a regular file")
    if st.st_mode & 0o077:
        raise RunError(
            f"--auth-env-file is readable by group/other (mode {stat.S_IMODE(st.st_mode):o}); run: chmod 600 <file>"
        )


def known_secrets(opts: Options) -> list[bytes]:
    values: list[str] = []
    if opts.auth_env_file is not None:
        values += list(redact.parse_env_file(opts.auth_env_file).values())
    values += [os.environ.get(n, "") for n in opts.pass_env]
    return redact.secret_values(values)


def container_env(opts: Options, plan: NetworkPlan, ident: Identity | None) -> dict[str, str]:
    env = {
        "ACR_REQUIRE_HARDENING": "1",
        "ACR_VERIFY_PROBE": "1" if plan.needs_gateway else "0",
    }
    if opts.allow_project_inputs:
        env["ACR_ALLOW_PROJECT_INPUTS"] = "1"
    b = opts.backend
    if b is None or ident is None:
        return env
    env.update(
        {
            "ACR_BACKEND": b.name,
            "ACR_BACKEND_ENDPOINT": plan.container_base_url or "",
            "ANTHROPIC_BASE_URL": plan.container_base_url or "",
            "ACR_BACKEND_RUNTIME": ident.runtime,
            "ACR_SEED_FIXED": "0",
        }
    )
    if ident.runtime_version:
        env["ACR_BACKEND_RUNTIME_VERSION"] = ident.runtime_version
    if ident.model_digest:
        env["ACR_MODEL_DIGEST"] = ident.model_digest
    if opts.model:
        env["ACR_MODEL"] = opts.model
        env["ANTHROPIC_MODEL"] = opts.model
        if b.kind == "ollama":
            # A local server has only the model it was given: point every
            # role Claude Code may pick (small/fast, subagents) at it.
            for k in (
                "ANTHROPIC_DEFAULT_OPUS_MODEL",
                "ANTHROPIC_DEFAULT_SONNET_MODEL",
                "ANTHROPIC_DEFAULT_HAIKU_MODEL",
                "ANTHROPIC_SMALL_FAST_MODEL",
                "CLAUDE_CODE_SUBAGENT_MODEL",
            ):
                env[k] = opts.model
    if b.auth_mode == "placeholder" and b.placeholder:
        env["ANTHROPIC_AUTH_TOKEN"] = b.placeholder
        env["ANTHROPIC_API_KEY"] = ""
    if plan.proxy_url:
        env["HTTPS_PROXY"] = plan.proxy_url
        env["https_proxy"] = plan.proxy_url
    return env


def _prepare(opts: Options) -> tuple[NetworkPlan, Identity | None, list[bytes]]:
    if opts.auth_env_file is not None:
        check_auth_file(opts.auth_env_file)
    if opts.backend is not None and opts.backend.auth_mode == "env-file" and opts.auth_env_file is None:
        raise RunError(f"backend {opts.backend.name!r} needs --auth-env-file (your own key or token)")
    plan = plan_for(opts.backend.url if opts.backend else None)
    ident = identify(opts.backend, opts.model) if opts.backend else None
    return plan, ident, known_secrets(opts)


def _spec(
    opts: Options, run_id: str, net: str, env: dict[str, str], work: Path | None, out: Path | None, command: list[str]
) -> ContainerSpec:
    return ContainerSpec(
        image=opts.image,
        command=command,
        name=f"acr-{run_id}-agent",
        network=net,
        env=env,
        pass_env=list(opts.pass_env),
        env_file=opts.auth_env_file,
        workdir=work,
        outdir=out,
        hardening=opts.hardening,
        labels={"io.github.agent-cleanroom.run": run_id},
    )


def verify_only(opts: Options, ex: Executor) -> Outcome:
    plan, ident, known = _prepare(opts)
    ex.check()
    ex.image_id(opts.image)
    run_id = new_run_id()
    tmp = Path(tempfile.mkdtemp(prefix="acr-verify-"))
    try:
        work = tmp / "work"
        workdiff.copy_tree(opts.workdir, work)
        workdiff.make_writable_for_container(work)
        env = container_env(opts, plan, ident)
        with ex.network(plan, run_id, opts.gateway_image) as net:
            res = ex.run(_spec(opts, run_id, net, env, work, None, ["verify.sh"]), timeout=120)
        out, _ = redact.redact(res.stdout, known)
        if res.returncode not in (0, 1):
            raise RunError(
                f"verifier did not run (rc={res.returncode}): "
                + redact.redact(res.stderr, known)[0].decode("utf-8", "replace")[-300:]
            )
        status = "ok" if res.returncode == 0 else "verify-failed"
        return Outcome(status=status, exit_code=res.returncode, bundle_dir=None, verify_json=out)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def backend_record(opts: Options, plan: NetworkPlan, ident: Identity) -> dict:
    b = opts.backend
    assert b is not None
    return {
        "schema": BACKEND_SCHEMA,
        "name": b.name,
        "kind": b.kind,
        "profile": b.source,
        "endpoint": {"host": b.url, "container": plan.container_base_url},
        "runtime": {"name": ident.runtime, "version": ident.runtime_version},
        "model": {"name": ident.model, "digest": ident.model_digest, "digest_source": ident.digest_source},
        "sampling": {
            "fixed_by_agent_cleanroom": False,
            "note": "temperature/top_p/top_k/max_tokens are chosen by the agent CLI, not fixed here",
        },
        "seed": {"fixed": False, "value": None, "note": b.seed_note},
        "auth": {"mode": b.auth_mode, "env_file_given": opts.auth_env_file is not None},
    }


def run(opts: Options, ex: Executor) -> Outcome:
    if not opts.command:
        raise RunError("nothing to run: give --prompt or a command after --")
    plan, ident, known = _prepare(opts)
    if opts.backend is None or ident is None:
        raise RunError("run needs a backend (--backend)")
    ex.check()
    image_id = ex.image_id(opts.image)
    gw_id = ex.image_id(opts.gateway_image) if plan.needs_gateway else None

    run_id = new_run_id()
    bdir = opts.runs_dir / run_id
    bdir.mkdir(parents=True, exist_ok=False)
    tmp = Path(tempfile.mkdtemp(prefix="acr-run-"))
    started, t0 = utc_now(), time.monotonic()
    try:
        before, after, out = tmp / "before", tmp / "after", tmp / "out"
        exclude = opts.runs_dir if opts.workdir is not None else None
        info = workdiff.copy_tree(opts.workdir, before, exclude=exclude)
        workdiff.copy_tree(opts.workdir, after, exclude=exclude)
        workdiff.make_writable_for_container(after)
        out.mkdir()
        os.chmod(out, 0o777)

        env = container_env(opts, plan, ident)
        command = ["bash", "-c", VERIFY_THEN_EXEC, "acr", *opts.command]
        with ex.network(plan, run_id, opts.gateway_image) as net:
            res = ex.run(_spec(opts, run_id, net, env, after, out, command), timeout=opts.timeout)

        env_raw = (out / "env.json").read_bytes() if (out / "env.json").is_file() else b""
        try:
            passed = bool(json.loads(env_raw).get("verification_passed"))
        except ValueError:
            passed = False
        if res.timed_out:
            status = "timeout"
        elif not passed:
            status = "verify-failed"
        elif res.returncode != 0:
            status = "agent-failed"
        else:
            status = "ok"

        diff, changes = workdiff.diff_trees(before, after) if passed else (b"", {})
        redactions = 0
        stdout = res.stdout
        stderr = res.stderr
        if not passed and (out / "verify.stderr").is_file():
            stderr = stderr + (out / "verify.stderr").read_bytes()
        for name, data in (
            ("env.json", env_raw),
            ("stdout", stdout),
            ("stderr", stderr),
            ("workdir.diff", diff),
            ("gateway.log", ex.gateway_log),
        ):
            clean, n = redact.redact(data, known)
            redactions += n
            (bdir / name).write_bytes(clean)
        bundle.write_json(bdir / "backend.json", backend_record(opts, plan, ident))

        findings = redact.scan_dir(bdir, known)
        safe_cmd = [redact.redact(c.encode(), known)[0].decode() for c in opts.command]
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "run_id": run_id,
            "tool": {"name": "agent-cleanroom", "version": __version__},
            "started_utc": started,
            "finished_utc": utc_now(),
            "duration_seconds": round(time.monotonic() - t0, 3),
            "status": "secret-found" if findings else status,
            "verification_passed": passed,
            "agent_exit_code": None if (not passed or res.timed_out) else res.returncode,
            "image": {"ref": opts.image, "id": image_id},
            "gateway_image": {"ref": opts.gateway_image, "id": gw_id} if gw_id else None,
            "command": safe_cmd,
            "prompt_sha256": hashlib.sha256(opts.prompt.encode()).hexdigest() if opts.prompt else None,
            "workdir": {
                "source": "given" if opts.workdir is not None else "empty",
                "files": info["files"],
                "bytes": info["bytes"],
                "project_inputs_allowed": opts.allow_project_inputs,
                "changes": changes,
            },
            "network": plan.describe(),
            "hardening": opts.hardening.describe(),
            "env_names": sorted(
                set(env)
                | set(opts.pass_env)
                | (set(redact.parse_env_file(opts.auth_env_file)) if opts.auth_env_file else set())
            ),
            "secret_scan": {
                "values_checked": len(known),
                "redactions": redactions,
                "clean": not findings,
                "findings": findings,
            },
            "files": sorted([*(p.name for p in bdir.iterdir()), "manifest.json", bundle.SUMS]),
        }
        bundle.write_json(bdir / "manifest.json", manifest)
        late = [f for f in redact.scan_dir(bdir, known) if f["file"] == "manifest.json"]
        if late:
            raise RunError("manifest.json would carry a secret; bundle left unsummed")
        bundle.write_sums(bdir)
        final = manifest["status"]
        return Outcome(status=final, exit_code=EXIT[final], bundle_dir=bdir, verify_json=env_raw)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
