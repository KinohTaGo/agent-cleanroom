"""Run records ("bundles"): write them, sum them, verify them.

A bundle is a directory ``runs/<id>/`` with:

    manifest.json   what ran, where, with which limits, and the outcome
    env.json        the verifier's record of the container (schema 3.0)
    backend.json    the backend: runtime and version, model and digest, seed
    stdout, stderr  the agent's output streams
    workdir.diff    changes the agent made to (a copy of) the working dir
    gateway.log     the gateway's allow/deny decisions (targets only)
    SHA256SUMS      sha256 of every other file, `sha256sum -c` compatible

``verify_bundle`` checks that every file is listed and matches, that nothing
unlisted was added, that the JSON files match their schemas, and that no
file contains a credential-shaped string.
"""

from __future__ import annotations

import hashlib
import json
from importlib import resources
from pathlib import Path

import jsonschema

from agent_cleanroom import redact

SUMS = "SHA256SUMS"
REQUIRED = ("manifest.json", "env.json", "backend.json", "stdout", "stderr", "workdir.diff")
OPTIONAL = ("gateway.log",)
SCHEMAS = {
    "manifest.json": "manifest-1.0.schema.json",
    "env.json": "verify-3.0.schema.json",
    "backend.json": "backend-1.0.schema.json",
}


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(p: Path, obj: object) -> None:
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def write_sums(root: Path) -> list[str]:
    names = sorted(p.name for p in root.iterdir() if p.is_file() and p.name != SUMS)
    lines = [f"{sha256_file(root / n)}  {n}\n" for n in names]
    (root / SUMS).write_text("".join(lines), encoding="ascii")
    return names


def load_schema(name: str) -> dict:
    return json.loads(resources.files("agent_cleanroom.schemas").joinpath(name).read_text("utf-8"))


def _problem(kind: str, file: str, detail: str) -> dict:
    return {"kind": kind, "file": file, "detail": detail}


def verify_bundle(root: Path) -> dict:
    """Return {"ok": bool, "problems": [...], "files": n}. Never raises on bad content."""
    root = Path(root)
    problems: list[dict] = []
    sums_path = root / SUMS
    if not sums_path.is_file():
        return {"ok": False, "files": 0, "problems": [_problem("missing", SUMS, "no checksum list")]}

    listed: dict[str, str] = {}
    for i, line in enumerate(sums_path.read_text("ascii", errors="replace").splitlines(), 1):
        parts = line.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64 or "/" in parts[1] or parts[1] in ("", ".", ".."):
            problems.append(_problem("malformed", SUMS, f"line {i}"))
            continue
        listed[parts[1]] = parts[0]

    present = {p.name for p in root.iterdir() if p.name != SUMS}
    for name in sorted(present - set(listed)):
        problems.append(_problem("unlisted", name, "file is not in SHA256SUMS"))
    for name, digest in sorted(listed.items()):
        p = root / name
        if not p.is_file() or p.is_symlink():
            problems.append(_problem("missing", name, "listed but not a regular file"))
        elif sha256_file(p) != digest:
            problems.append(_problem("checksum", name, "sha256 does not match SHA256SUMS"))
    for name in REQUIRED:
        if name not in listed:
            problems.append(_problem("missing", name, "required file not in bundle"))

    for name, schema_file in SCHEMAS.items():
        p = root / name
        if not p.is_file():
            continue
        try:
            doc = json.loads(p.read_text("utf-8"))
            jsonschema.validate(doc, load_schema(schema_file))
        except (ValueError, jsonschema.ValidationError) as e:
            msg = e.message if isinstance(e, jsonschema.ValidationError) else str(e)
            problems.append(_problem("schema", name, msg[:200]))

    for f in redact.scan_dir(root, known=[]):
        problems.append(_problem("secret", f["file"], f"{f['rule']} x{f['count']}"))

    return {"ok": not problems, "files": len(listed), "problems": problems}
