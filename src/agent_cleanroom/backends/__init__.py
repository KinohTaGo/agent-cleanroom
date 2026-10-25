"""Backend profiles: which model server a run talks to, and how."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

PROFILE_SCHEMA = "agent-cleanroom/backend-profile/1"
KINDS = ("ollama", "anthropic")
AUTH_MODES = ("placeholder", "env-file")


class BackendError(ValueError):
    """A backend profile is missing, malformed or used wrongly."""


@dataclass(frozen=True)
class Backend:
    name: str
    kind: str
    description: str
    url: str
    auth_mode: str
    placeholder: str | None
    seed_supported: bool
    seed_note: str
    source: str  # "builtin:<name>" or "file:<basename>" (no host paths)


def builtin_names() -> list[str]:
    pkg = resources.files(__package__)
    return sorted(p.name[: -len(".toml")] for p in pkg.iterdir() if p.name.endswith(".toml"))


def _parse(data: dict, source: str) -> Backend:
    if data.get("schema") != PROFILE_SCHEMA:
        raise BackendError(f"{source}: schema must be {PROFILE_SCHEMA!r}")
    kind = data.get("kind")
    if kind not in KINDS:
        raise BackendError(f"{source}: kind must be one of {KINDS}, got {kind!r}")
    endpoint = data.get("endpoint") or {}
    auth = data.get("auth") or {}
    seed = data.get("seed") or {}
    url = endpoint.get("url")
    if not isinstance(url, str) or "://" not in url:
        raise BackendError(f"{source}: endpoint.url must be an absolute URL")
    mode = auth.get("mode")
    if mode not in AUTH_MODES:
        raise BackendError(f"{source}: auth.mode must be one of {AUTH_MODES}, got {mode!r}")
    placeholder = auth.get("placeholder")
    if mode == "placeholder" and not isinstance(placeholder, str):
        raise BackendError(f"{source}: auth.placeholder is required for mode 'placeholder'")
    return Backend(
        name=str(data.get("name") or kind),
        kind=kind,
        description=str(data.get("description") or ""),
        url=url.rstrip("/"),
        auth_mode=mode,
        placeholder=placeholder if mode == "placeholder" else None,
        seed_supported=bool(seed.get("supported", False)),
        seed_note=str(seed.get("note") or ""),
        source=source,
    )


def load_backend(name: str | None = None, path: Path | None = None) -> Backend:
    """Load a built-in profile by name, or a profile file by path."""
    if (name is None) == (path is None):
        raise BackendError("give exactly one of a backend name or a backend file")
    if path is not None:
        try:
            data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as e:
            raise BackendError(f"cannot read backend file {Path(path).name}: {e}") from e
        return _parse(data, f"file:{Path(path).name}")
    if name not in builtin_names():
        raise BackendError(f"unknown backend {name!r}; built-in: {', '.join(builtin_names())}")
    text = resources.files(__package__).joinpath(f"{name}.toml").read_text(encoding="utf-8")
    return _parse(tomllib.loads(text), f"builtin:{name}")


def with_url(backend: Backend, url: str | None) -> Backend:
    """Return the profile with its endpoint URL overridden (if given)."""
    if not url:
        return backend
    if "://" not in url:
        raise BackendError(f"--backend-url must be an absolute URL, got {url!r}")
    return Backend(**{**backend.__dict__, "url": url.rstrip("/")})
