"""Keep secrets out of run records.

Two layers, both applied to every file of a bundle:

1. *Known values* — the values of the user's auth file and of every
   environment variable passed into the container — are replaced wherever
   they appear.
2. *Token shapes* — strings that look like credentials (Anthropic keys and
   OAuth tokens, GitHub tokens, AWS access keys, private-key headers) are
   replaced even when the value was not known in advance.

Findings are reported by rule name and count only — never the value.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

REDACTED = b"[REDACTED]"
MIN_SECRET_LEN = 8

TOKEN_RULES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("anthropic-token", re.compile(rb"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("github-token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("github-pat", re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{30,}")),
    ("aws-access-key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("private-key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)


def parse_env_file(path: Path) -> dict[str, str]:
    """Read NAME=value lines the way `docker run --env-file` does."""
    out: dict[str, str] = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        out[name.strip()] = value
    return out


def secret_values(values: Iterable[str]) -> list[bytes]:
    """Distinct values long enough to redact safely, longest first."""
    keep = {v.encode("utf-8") for v in values if v and len(v) >= MIN_SECRET_LEN}
    return sorted(keep, key=len, reverse=True)


def redact(data: bytes, known: list[bytes]) -> tuple[bytes, int]:
    count = 0
    for v in known:
        n = data.count(v)
        if n:
            data = data.replace(v, REDACTED)
            count += n
    for _rule, pat in TOKEN_RULES:
        data, n = pat.subn(REDACTED, data)
        count += n
    return data, count


def scan(data: bytes, known: list[bytes]) -> dict[str, int]:
    found: dict[str, int] = {}
    hits = sum(data.count(v) for v in known)
    if hits:
        found["known-value"] = hits
    for rule, pat in TOKEN_RULES:
        n = len(pat.findall(data))
        if n:
            found[rule] = n
    return found


def scan_dir(root: Path, known: list[bytes]) -> list[dict]:
    """Scan every regular file under root; return [{file, rule, count}]."""
    findings: list[dict] = []
    for p in sorted(Path(root).rglob("*")):
        if p.is_file() and not p.is_symlink():
            for rule, n in sorted(scan(p.read_bytes(), known).items()):
                findings.append({"file": p.relative_to(root).as_posix(), "rule": rule, "count": n})
    return findings
