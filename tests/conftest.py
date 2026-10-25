"""Shared test fixtures: the mock model server and the Docker-free executor."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))

from fake_executor import FakeExecutor  # noqa: E402

MOCK = Path(__file__).resolve().parent / "fixtures" / "mock_backend.py"


@pytest.fixture
def mock_server(tmp_path):
    log = tmp_path / "requests.jsonl"
    proc = subprocess.Popen(
        [sys.executable, str(MOCK), "--port", "0", "--log", str(log)], stdout=subprocess.PIPE, text=True
    )
    port = int(proc.stdout.readline().strip())
    try:
        yield {"url": f"http://127.0.0.1:{port}", "port": port, "log": log, "proc": proc}
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture
def fake_executor(tmp_path):
    return FakeExecutor(tmp_path / "fake")
