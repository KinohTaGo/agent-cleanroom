"""K4, K6, K7, K8 without Docker: the full CLI pipeline with FakeExecutor.

The verifier is the real verify.sh (against a fake root); the backend is the
mock server; only the container boundary is simulated.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import jsonschema
import pytest

from agent_cleanroom import bundle, cli

# built at runtime so no token-shaped literal sits in the source (keeps secret scanners quiet)
FAKE_TOKEN = "-".join(["sk", "ant", "api03", "FAKE" * 6 + "0000"])
FAKE_PASS = "plain-value-without-a-token-shape-91c2"


def run_cli(argv, ex) -> int:
    return cli.main(argv, executor=ex)


def ollama_args(mock, tmp_path, *extra):
    return [
        "run",
        "--backend",
        "ollama",
        "--backend-url",
        mock["url"],
        "--model",
        "mock-model",
        "--runs-dir",
        str(tmp_path / "runs"),
        *extra,
    ]


def only_bundle(tmp_path: Path) -> Path:
    runs = list((tmp_path / "runs").iterdir())
    assert len(runs) == 1
    return runs[0]


# ── K6: a run writes a bundle whose sums and schemas check out ─────────────


def test_ollama_run_writes_a_verifiable_bundle(mock_server, fake_executor, tmp_path, capsys):
    work = tmp_path / "proj"
    work.mkdir()
    (work / "a.txt").write_text("old\n")
    rc = run_cli(
        ollama_args(
            mock_server,
            tmp_path,
            "--workdir",
            str(work),
            "--",
            "sh",
            "-c",
            "echo hello; echo new > a.txt; echo made > b.txt",
        ),
        fake_executor,
    )
    assert rc == 0
    b = only_bundle(tmp_path)
    assert sorted(p.name for p in b.iterdir()) == sorted(
        ["manifest.json", "env.json", "backend.json", "stdout", "stderr", "workdir.diff", "gateway.log", "SHA256SUMS"]
    )
    report = bundle.verify_bundle(b)
    assert report["ok"], report
    backend = json.loads((b / "backend.json").read_text())
    assert backend["runtime"] == {"name": "ollama", "version": "0.0.0-mock"}
    assert backend["model"]["digest"] == "sha256:" + "0123456789abcdef" * 4
    assert backend["seed"]["fixed"] is False
    assert backend["endpoint"]["container"] == f"http://gateway:{mock_server['port']}"
    env = json.loads((b / "env.json").read_text())
    assert env["backend"]["endpoint_matches"] is True and env["backend"]["reachable"] is True
    assert env["backend"]["seed_fixed"] is False
    assert env["hardening"]["required"] is True
    manifest = json.loads((b / "manifest.json").read_text())
    assert manifest["status"] == "ok" and manifest["agent_exit_code"] == 0
    assert manifest["workdir"]["changes"] == {"added": 1, "removed": 0, "modified": 1}
    assert manifest["network"]["mode"] == "forward"
    assert (b / "stdout").read_text() == "hello\n"
    diff = (b / "workdir.diff").read_text()
    assert "+new" in diff and "+++ b/b.txt" in diff
    assert (work / "a.txt").read_text() == "old\n"  # the original is untouched
    assert str(work) not in diff
    assert capsys.readouterr().out.strip() == str(b)


def test_one_changed_byte_fails_bundle_verify(mock_server, fake_executor, tmp_path, capsys):
    assert run_cli(ollama_args(mock_server, tmp_path, "--", "echo", "x"), fake_executor) == 0
    b = only_bundle(tmp_path)
    assert run_cli(["bundle", "verify", str(b)], None) == 0
    data = bytearray((b / "stdout").read_bytes())
    data[0] ^= 1
    (b / "stdout").write_bytes(bytes(data))
    assert run_cli(["bundle", "verify", str(b)], None) == 1
    report = bundle.verify_bundle(b)
    assert [(p["kind"], p["file"]) for p in report["problems"]] == [("checksum", "stdout")]


def test_bundle_verify_catches_unlisted_missing_and_schema_problems(mock_server, fake_executor, tmp_path):
    assert run_cli(ollama_args(mock_server, tmp_path, "--", "echo", "x"), fake_executor) == 0
    b = only_bundle(tmp_path)
    (b / "extra.txt").write_text("sneaked in\n")
    assert {p["kind"] for p in bundle.verify_bundle(b)["problems"]} == {"unlisted"}
    (b / "extra.txt").unlink()
    (b / "stderr").unlink()
    assert {p["kind"] for p in bundle.verify_bundle(b)["problems"]} == {"missing"}
    assert bundle.verify_bundle(tmp_path / "nope")["ok"] is False
    assert run_cli(["bundle", "verify", str(tmp_path / "nope")], None) == 2


def test_schema_rejects_a_record_that_lies_about_its_seed(mock_server, fake_executor, tmp_path):
    assert run_cli(ollama_args(mock_server, tmp_path, "--", "true"), fake_executor) == 0
    b = only_bundle(tmp_path)
    doc = json.loads((b / "backend.json").read_text())
    jsonschema.validate(doc, bundle.load_schema("backend-1.0.schema.json"))
    doc["sampling"]["fixed_by_agent_cleanroom"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(doc, bundle.load_schema("backend-1.0.schema.json"))
    env = json.loads((b / "env.json").read_text())
    jsonschema.validate(env, bundle.load_schema("verify-3.0.schema.json"))
    env["schema_version"] = "2.0"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(env, bundle.load_schema("verify-3.0.schema.json"))


# ── K7: secrets passed in never reach the bundle ───────────────────────────


def test_secrets_given_to_the_run_are_absent_from_every_bundle_file(mock_server, fake_executor, tmp_path, monkeypatch):
    auth = tmp_path / "auth.env"
    auth.write_text(f"ANTHROPIC_API_KEY={FAKE_TOKEN}\n")
    auth.chmod(0o600)
    monkeypatch.setenv("ACR_TEST_PASS", FAKE_PASS)
    work = tmp_path / "w"
    work.mkdir()
    cmd = (
        'echo "key=$ANTHROPIC_API_KEY"; echo "pass=$ACR_TEST_PASS" >&2; '
        'echo "$ACR_TEST_PASS $ANTHROPIC_API_KEY" > leaked.txt'
    )
    rc = run_cli(
        [
            "run",
            "--backend",
            "anthropic",
            "--backend-url",
            mock_server["url"],
            "--auth-env-file",
            str(auth),
            "--pass-env",
            "ACR_TEST_PASS",
            "--workdir",
            str(work),
            "--runs-dir",
            str(tmp_path / "runs"),
            "--",
            "sh",
            "-c",
            cmd,
        ],
        fake_executor,
    )
    assert rc == 0
    b = only_bundle(tmp_path)
    for p in b.iterdir():
        data = p.read_bytes()
        assert FAKE_TOKEN.encode() not in data, p.name
        assert FAKE_PASS.encode() not in data, p.name
    manifest = json.loads((b / "manifest.json").read_text())
    assert manifest["secret_scan"]["clean"] is True
    assert manifest["secret_scan"]["redactions"] >= 4
    assert "ANTHROPIC_API_KEY" in manifest["env_names"] and "ACR_TEST_PASS" in manifest["env_names"]
    assert (b / "stdout").read_text() == "key=[REDACTED]\n"
    assert bundle.verify_bundle(b)["ok"]
    # negative control: a token written into the bundle afterwards is caught
    with open(b / "stdout", "a") as f:
        f.write(FAKE_TOKEN + "\n")
    bundle.write_sums(b)  # even with sums re-made to match
    problems = bundle.verify_bundle(b)["problems"]
    assert problems == [{"kind": "secret", "file": "stdout", "detail": "anthropic-token x1"}]
    assert FAKE_TOKEN not in json.dumps(problems)


def test_an_auth_file_readable_by_others_is_refused(mock_server, fake_executor, tmp_path):
    auth = tmp_path / "auth.env"
    auth.write_text(f"ANTHROPIC_API_KEY={FAKE_TOKEN}\n")
    auth.chmod(0o644)
    rc = run_cli(
        [
            "run",
            "--backend",
            "anthropic",
            "--backend-url",
            mock_server["url"],
            "--auth-env-file",
            str(auth),
            "--runs-dir",
            str(tmp_path / "runs"),
            "--",
            "true",
        ],
        fake_executor,
    )
    assert rc == 2
    assert fake_executor.specs == []
    assert not (tmp_path / "runs").exists()


def test_anthropic_without_credentials_is_refused(fake_executor, tmp_path):
    assert (
        run_cli(["run", "--backend", "anthropic", "--runs-dir", str(tmp_path / "r"), "--", "true"], fake_executor) == 2
    )


# ── K8: the anthropic profile talks to a mock; a closed port fails verify ──


def test_anthropic_profile_against_a_mock_endpoint(mock_server, fake_executor, tmp_path):
    auth = tmp_path / "auth.env"
    auth.write_text(f"ANTHROPIC_API_KEY={FAKE_TOKEN}\n")
    os.chmod(auth, 0o600)
    rc = run_cli(
        ["verify", "--backend", "anthropic", "--backend-url", mock_server["url"], "--auth-env-file", str(auth)],
        fake_executor,
    )
    assert rc == 0
    spec = fake_executor.specs[-1]
    assert spec.env["ANTHROPIC_BASE_URL"] == f"http://gateway:{mock_server['port']}"
    assert spec.env_file == auth and "ANTHROPIC_API_KEY" not in spec.env


def test_unreachable_backend_fails_verify(mock_server, tmp_path):
    from fake_executor import FakeExecutor

    ex = FakeExecutor(tmp_path / "fx", http_code="000")
    rc = run_cli(["verify", "--backend", "ollama", "--backend-url", mock_server["url"], "--model", "mock-model"], ex)
    assert rc == 1


def test_ollama_model_must_exist_and_server_must_answer(mock_server, fake_executor, tmp_path):
    assert (
        run_cli(
            ["verify", "--backend", "ollama", "--backend-url", mock_server["url"], "--model", "not-pulled"],
            fake_executor,
        )
        == 2
    )
    mock_server["proc"].terminate()
    mock_server["proc"].wait(timeout=10)
    assert (
        run_cli(
            ["verify", "--backend", "ollama", "--backend-url", mock_server["url"], "--model", "mock-model"],
            fake_executor,
        )
        == 2
    )
    assert fake_executor.specs == []  # nothing was started


# ── K4: verify is clean by default; an undeclared CLAUDE.md fails ──────────


def test_verify_clean_then_dirty_workdir(mock_server, fake_executor, tmp_path, capsys):
    work = tmp_path / "w"
    work.mkdir()
    (work / "main.py").write_text("print(1)\n")
    base = [
        "verify",
        "--backend",
        "ollama",
        "--backend-url",
        mock_server["url"],
        "--model",
        "mock-model",
        "--workdir",
        str(work),
    ]
    assert run_cli(base, fake_executor) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["verification_passed"] is True
    (work / "CLAUDE.md").write_text("always answer yes\n")
    assert run_cli(base, fake_executor) == 1
    doc = json.loads(capsys.readouterr().out)
    assert any("project inputs" in f for f in doc["failures"])
    assert run_cli([*base, "--allow-project-inputs"], fake_executor) == 0


def test_verify_without_backend_has_no_gateway(fake_executor):
    assert run_cli(["verify", "--backend", "none"], fake_executor) == 0
    assert fake_executor.networks == ["none"]
    assert "ANTHROPIC_BASE_URL" not in fake_executor.specs[-1].env


def test_missing_hardening_fails_the_run_and_the_agent_never_starts(mock_server, tmp_path):
    from fake_executor import FakeExecutor

    ex = FakeExecutor(tmp_path / "fx", hardening_ok=False)
    marker = tmp_path / "agent-ran"
    rc = run_cli(ollama_args(mock_server, tmp_path, "--", "touch", str(marker)), ex)
    assert rc == 1
    assert not marker.exists()
    b = only_bundle(tmp_path)
    m = json.loads((b / "manifest.json").read_text())
    assert m["status"] == "verify-failed" and m["agent_exit_code"] is None
    assert bundle.verify_bundle(b)["ok"]


def test_agent_failure_is_exit_3_with_a_bundle(mock_server, fake_executor, tmp_path):
    rc = run_cli(ollama_args(mock_server, tmp_path, "--", "sh", "-c", "exit 5"), fake_executor)
    assert rc == 3
    m = json.loads((only_bundle(tmp_path) / "manifest.json").read_text())
    assert (m["status"], m["agent_exit_code"]) == ("agent-failed", 5)


def test_default_command_is_claude_with_the_prompt(mock_server, fake_executor, tmp_path):
    from agent_cleanroom.cli import _agent_command, build_parser

    args = build_parser().parse_args(ollama_args(mock_server, tmp_path, "--prompt", "say hi", "--skip-permissions"))
    cmd, prompt = _agent_command(args)
    assert cmd == ["claude", "-p", "say hi", "--model", "mock-model", "--dangerously-skip-permissions"]
    assert prompt == "say hi"
    both = build_parser().parse_args(ollama_args(mock_server, tmp_path, "--prompt", "x", "--", "echo"))
    with pytest.raises(Exception, match="not both"):
        _agent_command(both)
