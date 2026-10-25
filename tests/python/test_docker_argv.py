"""A6: every agent container gets the hardening flags; secrets never reach argv."""

from pathlib import Path

from agent_cleanroom.docker import ContainerSpec, Hardening, agent_run_argv, gateway_run_argv
from agent_cleanroom.netplan import plan_for


def _spec(**kw) -> ContainerSpec:
    base = dict(image="img", command=["verify.sh"], name="acr-x-agent", network="acr-x")
    base.update(kw)
    return ContainerSpec(**base)


def _pairs(argv: list[str]) -> set[tuple[str, str]]:
    return set(zip(argv, argv[1:], strict=False))


def test_agent_argv_has_every_hardening_flag():
    argv = agent_run_argv(_spec())
    pairs = _pairs(argv)
    for flag in [
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--user", "10001:10001"),
        ("--memory", "4g"),
        ("--memory-swap", "4g"),
        ("--pids-limit", "512"),
        ("--network", "acr-x"),
    ]:
        assert flag in pairs, flag
    assert "--read-only" in argv
    tmpfs = [b for a, b in pairs if a == "--tmpfs"]
    assert sorted(t.split(":")[0] for t in tmpfs) == ["/cleanroom", "/tmp"]
    assert all("nosuid" in t and "nodev" in t for t in tmpfs)
    # the command runs under tini, after the image
    i = argv.index("img")
    assert argv[i + 1 :] == ["/usr/bin/tini", "-s", "--", "verify.sh"]


def test_hardening_limits_are_configurable():
    argv = agent_run_argv(_spec(hardening=Hardening(memory="2g", pids_limit=128)))
    assert ("--memory", "2g") in _pairs(argv) and ("--pids-limit", "128") in _pairs(argv)


def test_secret_values_never_appear_in_argv(tmp_path: Path):
    auth = tmp_path / "auth.env"
    auth.write_text("ANTHROPIC_API_KEY=" + "-".join(["sk", "ant", "api03", "SECRET" * 4]) + "\n")
    argv = agent_run_argv(_spec(env={"ACR_BACKEND": "anthropic"}, pass_env=["MY_TOKEN"], env_file=auth))
    joined = "\0".join(argv)
    assert "SECRET" not in joined
    assert ("-e", "MY_TOKEN") in _pairs(argv)  # name only: docker reads the value
    assert ("--env-file", str(auth)) in _pairs(argv)  # path only: docker reads the file


def test_mounts_are_work_and_out_only(tmp_path: Path):
    argv = agent_run_argv(_spec(workdir=tmp_path / "w", outdir=tmp_path / "o"))
    vols = [b for a, b in zip(argv, argv[1:], strict=False) if a == "-v"]
    assert vols == [f"{tmp_path / 'w'}:/work:rw", f"{tmp_path / 'o'}:/out:rw"]
    assert ("-w", "/work") in _pairs(argv)


def test_gateway_argv_is_hardened_and_carries_only_the_plan():
    plan = plan_for("http://127.0.0.1:11500")
    argv = gateway_run_argv(plan, "acr-x-gw", "base", {"io.github.agent-cleanroom.run": "x"})
    pairs = _pairs(argv)
    assert ("--cap-drop", "ALL") in pairs and "--read-only" in argv
    assert ("--add-host", "host.docker.internal:host-gateway") in pairs
    assert ("-e", "ACR_FORWARDS=11500=host.docker.internal:11500") in pairs
    assert argv[-3:] == ["base", "node", "/usr/local/lib/agent-cleanroom/gateway.js"]
