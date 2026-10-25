# Security Policy

## Reporting a vulnerability

Please report security issues through
[GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository, rather than opening a public issue.

Include what you can: version or commit, reproduction steps, and the impact you observed. A partial
report is more useful than none.

## Scope

Security-relevant defects include:

- **A way out of the network** — the agent's container reaching anything other than the declared
  backend (through the gateway, DNS, the host, or otherwise).
- **Weakened hardening** — a run starting without `--cap-drop ALL`, `no-new-privileges`, a
  read-only root filesystem, or its limits, without the verifier failing it.
- **Silent under-reporting by the verifier** — reporting a clean room without having examined what
  it claims to have examined. Treated as a security defect, not a bug: a checker that fails open is
  worse than no checker.
- **Credential exposure** — a key or token ending up in an image, a layer, a run record, a log, or
  the docker command line.
- **Outdated or vulnerable components in the images** — base OS packages, Node.js, the CA trust
  store, the pinned agent CLI and its bundled runtime. The images pin these by design, so a fix
  upstream reaches users only through a new pin.
- **Workflow injection** in `.github/workflows/`.

Defects in the Claude Code CLI itself should be reported to Anthropic.

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` | yes (pre-release) |
