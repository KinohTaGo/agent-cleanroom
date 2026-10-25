"""Working-directory snapshot and diff.

The agent never touches the user's directory: it works on a copy, and the
run record keeps a diff of that copy against a second, untouched copy. Paths
in the diff are relative (``a/<path>``, ``b/<path>``), so the record carries
no host paths. ``.git`` directories are left out of the diff (their contents
churn on any commit); the verifier records the git HEAD instead.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import shutil
from pathlib import Path

SKIP_DIRS = frozenset({".git"})


def copy_tree(src: Path | None, dst: Path, exclude: Path | None = None) -> dict:
    """Copy src to dst (symlinks kept as links). Returns {files, bytes}."""
    dst.mkdir(parents=True, exist_ok=False)
    files = size = 0
    if src is None:
        return {"files": 0, "bytes": 0}
    src = src.resolve()
    excl = exclude.resolve() if exclude is not None else None
    for root, dirs, names in os.walk(src):
        r = Path(root)
        if excl is not None:
            dirs[:] = [d for d in dirs if (r / d).resolve() != excl]
        rel = r.relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for d in dirs:
            p = r / d
            if p.is_symlink():
                os.symlink(os.readlink(p), dst / rel / d)
        dirs[:] = [d for d in dirs if not (r / d).is_symlink()]
        for n in names:
            p = r / n
            q = dst / rel / n
            if p.is_symlink():
                os.symlink(os.readlink(p), q)
            else:
                shutil.copy2(p, q)
                files += 1
                size += p.stat().st_size
    return {"files": files, "bytes": size}


def make_writable_for_container(root: Path) -> None:
    """Let the container's unprivileged uid write the copy (Linux hosts)."""
    for dirpath, _dirnames, filenames in os.walk(root):
        os.chmod(dirpath, 0o777)
        for n in filenames:
            p = Path(dirpath) / n
            if not p.is_symlink():
                os.chmod(p, 0o666 | (p.stat().st_mode & 0o111))


def _files(root: Path) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for n in filenames:
            p = Path(dirpath) / n
            out[p.relative_to(root).as_posix()] = p
        for d in list(dirnames):
            p = Path(dirpath) / d
            if p.is_symlink():
                out[p.relative_to(root).as_posix()] = p
    return out


def _read(p: Path | None) -> bytes | None:
    if p is None:
        return None
    if p.is_symlink():
        return b"symlink -> " + os.readlink(p).encode("utf-8", "surrogateescape") + b"\n"
    return p.read_bytes()


def _sha(b: bytes | None) -> str:
    return "absent" if b is None else hashlib.sha256(b).hexdigest()


def _text(b: bytes | None) -> list[str] | None:
    if b is None:
        return []
    if b"\0" in b:
        return None
    try:
        return b.decode("utf-8").splitlines(keepends=True)
    except UnicodeDecodeError:
        return None


def diff_trees(before: Path, after: Path) -> tuple[bytes, dict]:
    """Unified diff of two trees. Returns (diff bytes, {added, removed, modified})."""
    a, b = _files(before), _files(after)
    out: list[str] = []
    stats = {"added": 0, "removed": 0, "modified": 0}
    for rel in sorted(set(a) | set(b)):
        da, db = _read(a.get(rel)), _read(b.get(rel))
        if da == db:
            continue
        kind = "added" if da is None else "removed" if db is None else "modified"
        stats[kind] += 1
        ta, tb = _text(da), _text(db)
        if ta is None or tb is None:
            out.append(f"Binary file {rel} {kind}: {_sha(da)} -> {_sha(db)}\n")
            continue
        fa = "/dev/null" if da is None else f"a/{rel}"
        fb = "/dev/null" if db is None else f"b/{rel}"
        lines = list(difflib.unified_diff(ta, tb, fromfile=fa, tofile=fb))
        for line in lines:
            out.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    return "".join(out).encode("utf-8"), stats
