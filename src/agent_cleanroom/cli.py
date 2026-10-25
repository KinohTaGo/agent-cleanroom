"""Command line: `agent-cleanroom verify | run | bundle verify`.

Exit codes
  0  verify: clean room / run: agent finished with 0 / bundle verify: intact
  1  the clean-room verifier failed (the agent was not started), or the bundle
     failed verification
  2  usage or infrastructure error (nothing ran)
  3  run: the agent exited non-zero or timed out (bundle written)
  4  run: a secret-shaped string survived redaction (bundle written, flagged)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_cleanroom import __version__, bundle, runner
from agent_cleanroom.backends import BackendError, builtin_names, load_backend, with_url
from agent_cleanroom.docker import DockerError, DockerExecutor, Hardening
from agent_cleanroom.identify import IdentifyError
from agent_cleanroom.netplan import NetPlanError


def _common(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("backend")
    g.add_argument(
        "--backend", default=None, help=f"built-in profile ({', '.join(builtin_names())}) or 'none' (no network at all)"
    )
    g.add_argument("--backend-file", type=Path, help="a backend profile TOML file instead of --backend")
    g.add_argument("--backend-url", help="override the profile's URL as the host sees it")
    g.add_argument("--model", help="model name (required for ollama)")
    g.add_argument(
        "--auth-env-file", type=Path, help="your own NAME=value file (mode 600) with an API key or setup-token token"
    )
    c = p.add_argument_group("container")
    c.add_argument("--image", default="agent-cleanroom/claude-code:local")
    c.add_argument("--gateway-image", default="agent-cleanroom/base:local")
    c.add_argument("--workdir", type=Path, help="directory to copy into /work (default: empty)")
    c.add_argument(
        "--allow-project-inputs",
        action="store_true",
        help="declare CLAUDE.md/.mcp.json/.claude settings in the workdir (recorded by sha256)",
    )
    c.add_argument(
        "--pass-env",
        action="append",
        default=[],
        metavar="NAME",
        help="pass a host environment variable into the container (value scrubbed from the record)",
    )
    c.add_argument("--memory", default="4g")
    c.add_argument("--pids-limit", type=int, default=512)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-cleanroom",
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n", 1)[1],
    )
    p.add_argument("--version", action="version", version=f"agent-cleanroom {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="start the clean room and run only the verifier")
    _common(v)

    r = sub.add_parser("run", help="verify, run the agent, write a run record")
    _common(r)
    r.add_argument("--prompt", help="prompt for the default agent command (claude -p)")
    r.add_argument("--prompt-file", type=Path)
    r.add_argument(
        "--skip-permissions",
        action="store_true",
        help="pass --dangerously-skip-permissions to claude (the container is the sandbox)",
    )
    r.add_argument("--runs-dir", type=Path, default=Path("runs"))
    r.add_argument("--timeout", type=float, default=1800.0, help="seconds (default 1800)")
    r.add_argument(
        "command", nargs=argparse.REMAINDER, help="-- CMD ... : run this instead of the default claude command"
    )

    b = sub.add_parser("bundle", help="work with run records")
    bsub = b.add_subparsers(dest="bundle_cmd", required=True)
    bv = bsub.add_parser("verify", help="check a run record's sums, schemas and secret scan")
    bv.add_argument("path", type=Path)
    return p


def _backend(args: argparse.Namespace):
    if args.backend_file is not None and args.backend is not None:
        raise BackendError("give --backend or --backend-file, not both")
    if args.backend_file is not None:
        return with_url(load_backend(path=args.backend_file), args.backend_url)
    if args.backend in (None, "none"):
        if args.backend_url:
            raise BackendError("--backend-url needs a backend")
        return None
    return with_url(load_backend(name=args.backend), args.backend_url)


def _options(args: argparse.Namespace) -> runner.Options:
    opts = runner.Options(
        backend=_backend(args),
        model=args.model,
        image=args.image,
        gateway_image=args.gateway_image,
        workdir=args.workdir,
        auth_env_file=args.auth_env_file,
        pass_env=args.pass_env,
        allow_project_inputs=args.allow_project_inputs,
        hardening=Hardening(memory=args.memory, pids_limit=args.pids_limit),
    )
    if opts.workdir is not None and not opts.workdir.is_dir():
        raise runner.RunError("--workdir must be a directory")
    return opts


def _agent_command(args: argparse.Namespace) -> tuple[list[str], str | None]:
    cmd = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    prompt = args.prompt
    if args.prompt_file is not None:
        if prompt is not None:
            raise runner.RunError("give --prompt or --prompt-file, not both")
        prompt = args.prompt_file.read_text(encoding="utf-8")
    if cmd:
        if prompt is not None:
            raise runner.RunError("give a prompt or a command after --, not both")
        return cmd, None
    if prompt is None:
        raise runner.RunError("nothing to run: give --prompt/--prompt-file or a command after --")
    cmd = ["claude", "-p", prompt]
    if args.model:
        cmd += ["--model", args.model]
    if args.skip_permissions:
        cmd.append("--dangerously-skip-permissions")
    return cmd, prompt


def main(argv: list[str] | None = None, executor: runner.Executor | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "bundle":
            report = bundle.verify_bundle(args.path)
            print(json.dumps(report, indent=2, sort_keys=True))
            if not args.path.is_dir():
                return 2
            return 0 if report["ok"] else 1
        opts = _options(args)
        ex = executor or DockerExecutor()
        if args.cmd == "verify":
            out = runner.verify_only(opts, ex)
            sys.stdout.write(out.verify_json.decode("utf-8", "replace"))
            return out.exit_code
        opts.command, opts.prompt = _agent_command(args)
        opts.runs_dir = args.runs_dir
        opts.timeout = args.timeout
        out = runner.run(opts, ex)
        print(f"[agent-cleanroom] {out.status}: {out.bundle_dir}", file=sys.stderr)
        print(str(out.bundle_dir))
        return out.exit_code
    except (BackendError, NetPlanError, IdentifyError, DockerError, runner.RunError) as e:
        print(f"[agent-cleanroom] error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
