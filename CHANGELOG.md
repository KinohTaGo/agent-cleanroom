# Changelog

## 0.1.0 — unreleased

First version of agent-cleanroom, a rewrite of the earlier `cc-cleanroom` project with a new
history. Carried over: the pinning practice of the image, the runtime verifier and its tests, the
distrusted-root build guard, and the CI conventions.

### Added
- Two images: `base` (Debian 13, Node 24, git, curl, jq, tini, verifier, gateway — open-source
  only) and `claude-code` (base + an exact, unmodified Claude Code CLI, 2.1.308).
- Verifier record schema 3.0: backend identity (runtime and version, model and digest, seed fixed
  or not, endpoint match, reachability), proxy endpoint, kernel-reported hardening, and undeclared
  project inputs in the working directory now fail the run.
- Closed network by default: an internal Docker network plus a gateway that forwards only the
  declared backend (host port, or an allow-listed HTTPS host through a CONNECT proxy).
- Hardened runs: `--cap-drop ALL`, `no-new-privileges`, read-only root, tmpfs HOME and /tmp,
  memory and process limits, non-root user.
- Backend profiles `ollama` and `anthropic`; custom profiles from a TOML file.
- Python CLI: `verify`, `run`, `bundle verify`; run records with `SHA256SUMS`, JSON schemas, and
  scrubbing of every secret value given to the run plus credential-shaped strings.
- CI: unit tests (bats, pytest, shellcheck, ruff) and an amd64 image test. No publishing.

### Removed (compared with cc-cleanroom)
- `setup-auth.sh`: the tool no longer receives or stores a subscription token; see docs/auth.md.
- The single all-in-one image, and publishing from CI.
