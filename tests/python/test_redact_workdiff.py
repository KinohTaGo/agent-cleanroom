"""K7 at unit level: secrets are scrubbed and a second scan finds nothing."""

from pathlib import Path

from agent_cleanroom import redact, workdiff

# built at runtime so no token-shaped literal sits in the source (keeps secret scanners quiet)
FAKE = "-".join(["sk", "ant", "api03", "FAKE" * 6 + "0000"])
FAKE_UNSHAPED = "zz-not-a-token-shape-7f3a9c"


def test_known_values_and_token_shapes_are_redacted():
    known = redact.secret_values([FAKE_UNSHAPED, "short", ""])
    data = f"a {FAKE_UNSHAPED} b {FAKE} c ghp_{'x' * 36}".encode()
    clean, n = redact.redact(data, known)
    assert n == 3
    assert FAKE.encode() not in clean and FAKE_UNSHAPED.encode() not in clean
    assert redact.scan(clean, known) == {}  # second scan: zero
    assert redact.scan(data, known) == {"known-value": 1, "anthropic-token": 1, "github-token": 1}


def test_short_values_are_not_treated_as_secrets():
    # redacting "ollama" or "1" would wreck ordinary output
    assert redact.secret_values(["ollama", "1", ""]) == []


def test_scan_dir_reports_rule_and_count_never_the_value(tmp_path: Path):
    (tmp_path / "stdout").write_text(f"token={FAKE}\n")
    findings = redact.scan_dir(tmp_path, [])
    assert findings == [{"file": "stdout", "rule": "anthropic-token", "count": 1}]
    assert FAKE not in repr(findings)


def test_env_file_parsing_matches_docker(tmp_path: Path):
    f = tmp_path / "a.env"
    f.write_text("# comment\n\nANTHROPIC_API_KEY=abc=def\nNOVALUE\nX=\n")
    assert redact.parse_env_file(f) == {"ANTHROPIC_API_KEY": "abc=def", "X": ""}


def test_diff_covers_added_removed_modified_binary_and_skips_git(tmp_path: Path):
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "HEAD").write_text("ref\n")
    (src / "keep.txt").write_text("same\n")
    (src / "mod.txt").write_text("one\n")
    (src / "gone.txt").write_text("bye\n")
    (src / "bin.dat").write_bytes(b"\0\1\2")
    before, after = tmp_path / "before", tmp_path / "after"
    info = workdiff.copy_tree(src, before)
    workdiff.copy_tree(src, after)
    assert info["files"] == 5
    (after / "mod.txt").write_text("two\n")
    (after / "gone.txt").unlink()
    (after / "new.txt").write_text("hi")
    (after / "bin.dat").write_bytes(b"\0\x09")
    (after / ".git" / "HEAD").write_text("changed\n")
    diff, stats = workdiff.diff_trees(before, after)
    text = diff.decode()
    assert stats == {"added": 1, "removed": 1, "modified": 2}
    assert "--- a/mod.txt\n+++ b/mod.txt" in text and "+two" in text
    assert "+++ b/new.txt" in text and "\\ No newline at end of file" in text
    assert "--- a/gone.txt\n+++ /dev/null" in text
    assert "Binary file bin.dat modified:" in text
    assert ".git" not in text
    assert str(tmp_path) not in text  # no host paths in the record


def test_identical_trees_give_an_empty_diff(tmp_path: Path):
    src = tmp_path / "s"
    src.mkdir()
    (src / "f").write_text("x")
    workdiff.copy_tree(src, tmp_path / "a")
    workdiff.copy_tree(src, tmp_path / "b")
    assert workdiff.diff_trees(tmp_path / "a", tmp_path / "b") == (b"", {"added": 0, "removed": 0, "modified": 0})


def test_copy_excludes_the_runs_dir(tmp_path: Path):
    src = tmp_path / "proj"
    (src / "runs" / "old").mkdir(parents=True)
    (src / "runs" / "old" / "x").write_text("1")
    (src / "a").write_text("1")
    info = workdiff.copy_tree(src, tmp_path / "copy", exclude=src / "runs")
    assert info["files"] == 1 and not (tmp_path / "copy" / "runs").exists()
