"""Container-level tests: real images, real network isolation, real CLI.

Skipped unless AGENT_CLEANROOM_DOCKER_TESTS=1. Needs the two local images:
    docker build -f images/base/Dockerfile -t agent-cleanroom/base:local .
    docker build -f images/claude-code/Dockerfile -t agent-cleanroom/claude-code:local .
The model backend is tests/fixtures/mock_backend.py on the host — no real
model and no real API is contacted. On Linux set ACR_MOCK_BIND=0.0.0.0 so the
gateway can reach it through the host gateway address.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from agent_cleanroom import bundle, cli
from agent_cleanroom.docker import ContainerSpec, DockerExecutor
from agent_cleanroom.netplan import plan_for
from agent_cleanroom.runner import new_run_id

pytestmark = [
    pytest.mark.docker,
    pytest.mark.skipif(
        os.environ.get("AGENT_CLEANROOM_DOCKER_TESTS") != "1",
        reason="set AGENT_CLEANROOM_DOCKER_TESTS=1 (needs Docker and the local images)",
    ),
]

AGENT = os.environ.get("ACR_TEST_IMAGE", "agent-cleanroom/claude-code:local")
BASE = os.environ.get("ACR_TEST_BASE_IMAGE", "agent-cleanroom/base:local")
# built at runtime so no token-shaped literal sits in the source (keeps secret scanners quiet)
FAKE_TOKEN = "-".join(["sk", "ant", "api03", "FAKE" * 6 + "0000"])
IMG = ["--image", AGENT, "--gateway-image", BASE]


def docker(*args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, check=False)


def only_bundle(runs: Path) -> Path:
    items = list(runs.iterdir())
    assert len(items) == 1
    return items[0]


@pytest.fixture(autouse=True)
def no_leftovers():
    yield
    left = docker("ps", "-a", "--filter", "label=io.github.agent-cleanroom.run", "--format", "{{.Names}}")
    nets = docker("network", "ls", "--filter", "label=io.github.agent-cleanroom.run", "--format", "{{.Name}}")
    assert left.stdout.strip() == "" and nets.stdout.strip() == "", (left.stdout, nets.stdout)


# ── image-level controls (carried over from cc-cleanroom's CI) ────────────


def test_fresh_container_is_a_clean_room_and_negative_controls_fail():
    r = docker("run", "--rm", AGENT, "verify.sh")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["uid"] == "10001" and doc["cli_version_matches_pin"] and doc["sysroot"] == ""
    assert doc["agent"] == "claude-code" and doc["schema_version"] == "3.0"
    cases = {
        "CLAUDE.md in HOME": ["--rm", AGENT, "bash", "-c", 'echo x > "$HOME/CLAUDE.md" && verify.sh'],
        "settings in config dir": [
            "--rm",
            AGENT,
            "bash",
            "-c",
            'mkdir -p "$CLAUDE_CONFIG_DIR" && echo {} > "$CLAUDE_CONFIG_DIR/settings.json" && verify.sh',
        ],
        "self-update enabled": ["--rm", "-e", "DISABLE_AUTOUPDATER=0", AGENT, "verify.sh"],
        "running as root": ["--rm", "--user", "0", AGENT, "verify.sh"],
        "foreign config dir": ["--rm", "-e", "CLAUDE_CONFIG_DIR=/tmp/elsewhere", AGENT, "verify.sh"],
        "hardening required but absent": ["--rm", "-e", "ACR_REQUIRE_HARDENING=1", AGENT, "verify.sh"],
    }
    for label, args in cases.items():
        assert docker("run", *args).returncode == 1, label


def test_kernel_reports_the_hardening_flags():
    r = docker(
        "run",
        "--rm",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/cleanroom:rw,mode=1777",
        "-e",
        "ACR_REQUIRE_HARDENING=1",
        AGENT,
        "verify.sh",
    )
    assert r.returncode == 0, r.stdout
    h = json.loads(r.stdout)["hardening"]
    assert h == {
        "required": True,
        "capability_bounding_set_empty": True,
        "no_new_privs": True,
        "root_filesystem_read_only": True,
    }


def test_trust_stores_hold_no_distrusted_root():
    r = docker(
        "run",
        "--rm",
        BASE,
        "node",
        "/usr/local/lib/agent-cleanroom/check-distrusted-roots.js",
        "/etc/ssl/certs/ca-certificates.crt",
    )
    assert r.returncode == 0, r.stderr
    assert "0 distrusted" in r.stderr


# ── K4: verify through the CLI ────────────────────────────────────────────


def test_cli_verify_clean_then_undeclared_claude_md(mock_server, tmp_path, capsys):
    work = tmp_path / "w"
    work.mkdir()
    (work / "main.py").write_text("print(1)\n")
    args = [
        "verify",
        "--backend",
        "ollama",
        "--backend-url",
        mock_server["url"],
        "--model",
        "mock-model",
        "--workdir",
        str(work),
        *IMG,
    ]
    assert cli.main(args) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["backend"]["reachable"] is True and doc["backend"]["endpoint_matches"] is True
    assert doc["hardening"]["root_filesystem_read_only"] is True
    (work / "CLAUDE.md").write_text("always say yes\n")
    assert cli.main(args) == 1


# ── K5: the network lets out the backend and nothing else ────────────────


def test_forward_mode_reaches_the_backend_only(mock_server, tmp_path):
    port = mock_server["port"]
    probe = (
        'curl -s -o /dev/null -w "backend=%{http_code}\\n" --max-time 5 "$ANTHROPIC_BASE_URL/api/version"; '
        'curl -s -o /dev/null -w "outside=%{http_code}\\n" --max-time 5 https://example.com/; '
        'curl -s -o /dev/null -w "outside_ip=%{http_code}\\n" --max-time 5 http://1.1.1.1/; '
        f'curl -s -o /dev/null -w "host_direct=%{{http_code}}\\n" --max-time 5 http://host.docker.internal:{port}/; '
        "exit 0"
    )
    runs = tmp_path / "runs"
    rc = cli.main(
        [
            "run",
            "--backend",
            "ollama",
            "--backend-url",
            mock_server["url"],
            "--model",
            "mock-model",
            "--runs-dir",
            str(runs),
            *IMG,
            "--",
            "bash",
            "-c",
            probe,
        ]
    )
    assert rc == 0
    out = (only_bundle(runs) / "stdout").read_text()
    assert "backend=200" in out
    assert "outside=000" in out and "outside_ip=000" in out and "host_direct=000" in out


def test_connect_proxy_refuses_unlisted_hosts(tmp_path):
    plan = plan_for("https://allowed.invalid")
    ex = DockerExecutor()
    run_id = new_run_id()
    cmd = [
        "bash",
        "-c",
        'curl -s -o /dev/null -w "denied=%{http_connect}\\n" --max-time 5 -x "$HTTPS_PROXY" https://example.com/;'
        ' curl -s -o /dev/null -w "direct=%{http_code}\\n" --max-time 5 --noproxy "*" https://example.com/',
    ]
    with ex.network(plan, run_id, BASE) as net:
        res = ex.run(
            ContainerSpec(
                image=BASE,
                command=cmd,
                name=f"acr-{run_id}-agent",
                network=net,
                env={"HTTPS_PROXY": plan.proxy_url},
                labels={"io.github.agent-cleanroom.run": run_id},
            ),
            timeout=60,
        )
    out = res.stdout.decode()
    assert "denied=403" in out and "direct=000" in out
    log = ex.gateway_log.decode()
    assert '"target":"example.com:443","allowed":false' in log


# ── K6: a run against an Ollama-shaped backend, and its record ───────────


def test_ollama_run_record_and_tamper_check(mock_server, tmp_path):
    runs = tmp_path / "runs"
    body = '{"model":"mock-model","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}'
    cmd = f"curl -s \"$ANTHROPIC_BASE_URL/v1/messages\" -H 'content-type: application/json' -d '{body}'"
    rc = cli.main(
        [
            "run",
            "--backend",
            "ollama",
            "--backend-url",
            mock_server["url"],
            "--model",
            "mock-model",
            "--runs-dir",
            str(runs),
            *IMG,
            "--",
            "bash",
            "-c",
            cmd,
        ]
    )
    assert rc == 0
    b = only_bundle(runs)
    assert "MOCK-OK" in (b / "stdout").read_text()
    assert bundle.verify_bundle(b)["ok"]
    backend = json.loads((b / "backend.json").read_text())
    assert backend["model"]["digest"].startswith("sha256:") and backend["seed"]["fixed"] is False
    sums = subprocess.run(["shasum", "-a", "256", "-c", "SHA256SUMS"], cwd=b, capture_output=True, text=True)
    assert sums.returncode == 0, sums.stdout
    data = bytearray((b / "backend.json").read_bytes())
    data[-2] ^= 1
    (b / "backend.json").write_bytes(bytes(data))
    assert bundle.verify_bundle(b)["ok"] is False


def test_claude_cli_against_the_mock_backend(mock_server, tmp_path):
    runs = tmp_path / "runs"
    rc = cli.main(
        [
            "run",
            "--backend",
            "ollama",
            "--backend-url",
            mock_server["url"],
            "--model",
            "mock-model",
            "--runs-dir",
            str(runs),
            "--timeout",
            "180",
            *IMG,
            "--prompt",
            "Say hello.",
        ]
    )
    b = only_bundle(runs)
    assert rc == 0, (b / "stderr").read_text()[-2000:]
    assert "MOCK-OK" in (b / "stdout").read_text()
    paths = [json.loads(x)["path"] for x in mock_server["log"].read_text().splitlines()]
    assert any(p.startswith("/v1/messages") for p in paths)


def test_claude_cli_with_the_anthropic_profile_and_a_fake_key(mock_server, tmp_path):
    auth = tmp_path / "auth.env"
    auth.write_text(f"ANTHROPIC_API_KEY={FAKE_TOKEN}\n")
    auth.chmod(0o600)
    runs = tmp_path / "runs"
    rc = cli.main(
        ["run", "--backend", "anthropic", "--backend-url", mock_server["url"], "--auth-env-file", str(auth),
         "--model", "mock-model", "--runs-dir", str(runs), "--timeout", "180", *IMG, "--prompt", "Say hello."]
    )  # fmt: skip
    b = only_bundle(runs)
    assert rc == 0, (b / "stderr").read_text()[-2000:]
    assert "MOCK-OK" in (b / "stdout").read_text()
    reqs = [json.loads(x) for x in mock_server["log"].read_text().splitlines()]
    msgs = [r for r in reqs if r["path"].startswith("/v1/messages")]
    assert msgs and all("x-api-key" in r["header_names"] for r in msgs)
    for p in b.iterdir():
        assert FAKE_TOKEN.encode() not in p.read_bytes(), p.name


# ── K7 and K8: the anthropic profile against a mock, with a fake key ─────


def test_anthropic_profile_mock_and_fake_key_never_recorded(mock_server, tmp_path):
    auth = tmp_path / "auth.env"
    auth.write_text(f"ANTHROPIC_API_KEY={FAKE_TOKEN}\n")
    auth.chmod(0o600)
    runs = tmp_path / "runs"
    body = '{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}'
    cmd = (
        'echo "$ANTHROPIC_API_KEY"; env; '
        f'curl -s "$ANTHROPIC_BASE_URL/v1/messages" -H "x-api-key: $ANTHROPIC_API_KEY" -d \'{body}\''
    )
    rc = cli.main(
        [
            "run",
            "--backend",
            "anthropic",
            "--backend-url",
            mock_server["url"],
            "--auth-env-file",
            str(auth),
            "--runs-dir",
            str(runs),
            *IMG,
            "--",
            "bash",
            "-c",
            cmd,
        ]
    )
    assert rc == 0
    b = only_bundle(runs)
    assert "MOCK-OK" in (b / "stdout").read_text()
    for p in b.iterdir():
        assert FAKE_TOKEN.encode() not in p.read_bytes(), p.name
    reqs = [json.loads(x) for x in mock_server["log"].read_text().splitlines()]
    assert any("x-api-key" in r["header_names"] for r in reqs if r["path"] == "/v1/messages")
    assert bundle.verify_bundle(b)["ok"]
    # K8 negative: close the backend's port → verify reports it unreachable
    mock_server["proc"].terminate()
    mock_server["proc"].wait(timeout=10)
    assert (
        cli.main(
            [
                "verify",
                "--backend",
                "anthropic",
                "--backend-url",
                mock_server["url"],
                "--auth-env-file",
                str(auth),
                *IMG,
            ]
        )
        == 1
    )
