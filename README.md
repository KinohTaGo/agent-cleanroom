# agent-cleanroom

> 日本語: [docs/ja/README.md](docs/ja/README.md)

Reproducible, network-isolated runs of coding agents against local LLMs (Ollama) or APIs,
with a verifiable record of every run.

**Status: 0.1.0, pre-release.** Private while it is being built; the record format may still
change before 1.0. Not affiliated with or endorsed by Anthropic.

## Why

An agent CLI run on a developer machine inherits a large, invisible environment: global
instruction files, plugins, hooks, memory, whatever CLI version last auto-updated, remotely
fetched feature flags — and an open network. Any of those can change the outcome, so two
runs are hard to compare and a run is hard to reproduce later.

agent-cleanroom removes that surface, pins what remains, and writes down what it could not pin:

- **Clean room** — a container with an empty HOME and config directory, an exact CLI version,
  self-update and non-essential traffic off, run as an unprivileged user. A verifier inside the
  container fails the run if anything was reintroduced.
- **Closed network** — the agent's container has no route anywhere. A gateway passes on exactly
  one thing: the declared model backend (a port on the host for Ollama, or an allow-listed HTTPS
  host for an API). Everything else is refused.
- **Hardened container** — `--cap-drop ALL`, `no-new-privileges`, read-only root filesystem
  (writable: tmpfs and the working copy only), memory and process limits.
- **Run record** — a directory per run with the verifier's report, the backend's identity
  (runtime version, model name and digest, whether a seed was fixed), the agent's output, a diff
  of what it changed, and `SHA256SUMS`. Secrets given to the run are scrubbed from every file.

## Quickstart (Ollama on the same machine)

Requirements: Docker, Python 3.11+ with [uv](https://docs.astral.sh/uv/), and an Ollama server
on the host with a model already pulled (agent-cleanroom never pulls models).

```sh
# build the two images (no registry is used in 0.1)
docker build -f images/base/Dockerfile -t agent-cleanroom/base:local .
docker build -f images/claude-code/Dockerfile \
  --build-arg BASE_IMAGE=agent-cleanroom/base:local -t agent-cleanroom/claude-code:local .

uv sync
# check the clean room without running the agent
uv run agent-cleanroom verify --backend ollama --model <model> --workdir ./myproject
# run the agent and write a record under ./runs/<id>/
uv run agent-cleanroom run --backend ollama --model <model> --workdir ./myproject \
  --prompt "Add a unit test for parse()" --skip-permissions
uv run agent-cleanroom bundle verify runs/<id>
```

`--backend-url http://127.0.0.1:<port>` points at a server on another port. A small local model
may not handle the agent's tool use well; that is a property of the model, and the record shows
which model and digest produced the result.

## Commands

| Command | Does | Exit |
|---|---|---|
| `verify` | starts the clean room exactly as a run would and runs only the verifier; prints its JSON | 0 clean, 1 not clean, 2 error |
| `run` | verify → run the agent (default `claude -p <prompt>`, or any command after `--`) → write `runs/<id>/` | 0 ok, 1 not clean (agent not started), 2 error, 3 agent failed/timed out, 4 a secret-shaped string survived |
| `bundle verify <dir>` | checks sums, unlisted/missing files, JSON schemas, and secret shapes | 0 intact, 1 problems, 2 not a bundle |

Backends: `ollama` (host server, Anthropic-compatible `/v1/messages`), `anthropic` (the API with
your own credentials, see [docs/auth.md](docs/auth.md)), `none` (no network at all), or your own
profile file (`--backend-file`).

## The run record

```
runs/<id>/
  manifest.json   status, command, image ids, network plan, hardening, env names, secret scan
  env.json        the verifier's report (schema 3.0)
  backend.json    runtime + version, model + digest, sampling and seed (fixed or not)
  stdout, stderr  the agent's output
  workdir.diff    what the agent changed in its copy of the working directory
  gateway.log     the gateway's allow/deny decisions (targets only)
  SHA256SUMS      `sha256sum -c` compatible
```

The record says what was **not** fixed: agent-cleanroom 0.1 does not fix sampling parameters or a
seed (Ollama's `/v1/messages` does not accept one), model output is not deterministic, and a hosted
API's model can change behind the same name. Schemas: `src/agent_cleanroom/schemas/`.

## Scope

- Isolates the *environment* and records it. It does not make model output deterministic, and
  should not be described as doing so.
- The verifier detects drift; it is not a security boundary against someone who controls the
  `docker run` command line.
- On a Mac the model runs on the host (Metal); Docker Desktop cannot pass the GPU into a container.
- CI tests `linux/amd64`. `linux/arm64` (Apple Silicon) is exercised locally only in 0.1.

## Not yet / later

| Planned | What |
|---|---|
| 0.2 | many trials per scenario with resume, `compare` of two records, `llamacpp` and `litellm` backends, optional raw request/response bodies (off by default), fixing a seed where the runtime allows it, Dependabot and a freshness check |
| 0.3 | decide whether to integrate with Inspect AI / inspect_swe (ADR); run CI on arm64 |
| 0.5 | image signing (cosign), provenance, SBOM, vulnerability gate; publishing images to a registry starts here |
| 1.0 | frozen record schema, reproduction guide, CITATION.cff, public release |

Not planned before 1.0: other agents, NVIDIA GPU profiles, Kubernetes, gVisor, dashboards.

## Terms

- The `claude-code` image contains the Claude Code CLI exactly as Anthropic publishes it on npm
  (`@anthropic-ai/claude-code`, unmodified; © Anthropic PBC, all rights reserved). Its use is
  governed by Anthropic's terms: <https://code.claude.com/docs/en/legal-and-compliance>.
- You sign in with your own credentials. agent-cleanroom provides no model access, does not pay
  for, resell or intermediate anyone's usage, and does not collect, store or forward credentials:
  it hands the file you wrote to the container and scrubs its values from the record.
- "Claude Code" names the CLI the image contains; it is not part of this project's name.
- The MIT license covers this repository's files, not the Claude Code CLI inside the image.

## License

MIT — see [LICENSE](LICENSE).
