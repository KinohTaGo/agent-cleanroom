"""Identify the backend before a run: runtime version and model digest.

Only the host talks to the backend here, and only for Ollama (a local
server). For a remote API nothing is sent before the run — there is no
version or weight digest to ask for, and probing a paid API is not free.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from agent_cleanroom.backends import Backend

TIMEOUT = 5.0


class IdentifyError(RuntimeError):
    pass


@dataclass(frozen=True)
class Identity:
    runtime: str
    runtime_version: str | None
    model: str | None
    model_digest: str | None
    digest_source: str | None


def _get_json(url: str) -> dict:
    # No proxies: the host must reach its own local server directly.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise IdentifyError(f"cannot read {url}: {e}") from e


def _match_model(models: list[dict], wanted: str) -> dict | None:
    names = {wanted} if ":" in wanted else {wanted, f"{wanted}:latest"}
    for m in models:
        if m.get("name") in names or m.get("model") in names:
            return m
    return None


def identify(backend: Backend, model: str | None) -> Identity:
    if backend.kind == "ollama":
        if not model:
            raise IdentifyError("--model is required for the ollama backend")
        version = _get_json(f"{backend.url}/api/version").get("version")
        tags = _get_json(f"{backend.url}/api/tags").get("models") or []
        found = _match_model(tags, model)
        if found is None:
            raise IdentifyError(
                f"model {model!r} is not present on the Ollama server; "
                "agent-cleanroom does not pull models (pull it yourself, then re-run)"
            )
        digest = found.get("digest")
        if digest and not str(digest).startswith("sha256:"):
            digest = f"sha256:{digest}"
        return Identity(
            runtime="ollama",
            runtime_version=str(version) if version else None,
            model=model,
            model_digest=digest,
            digest_source="ollama /api/tags",
        )
    return Identity(
        runtime="anthropic-messages-api",
        runtime_version=None,
        model=model,
        model_digest=None,
        digest_source=None,
    )
