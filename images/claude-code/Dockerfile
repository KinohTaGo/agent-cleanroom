# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────────────────
# agent-cleanroom/claude-code — the base image plus the Claude Code CLI
# ─────────────────────────────────────────────────────────────────────────────
#
# Build (from the repository root, after images/base):
#     docker build -f images/claude-code/Dockerfile \
#         --build-arg BASE_IMAGE=agent-cleanroom/base:local \
#         -t agent-cleanroom/claude-code:local .
#
# The CLI is installed exactly as Anthropic publishes it on npm
# (@anthropic-ai/claude-code), unmodified. Its use is governed by Anthropic's
# terms: https://code.claude.com/docs/en/legal-and-compliance . Nothing in this
# image signs in: credentials are the user's own and are passed at run time.
#
# What is pinned
#   - CLI by EXACT version — no semver range, no ^, no ~, no "latest"
#   - CLI self-update disabled (DISABLE_AUTOUPDATER=1, inherited from base):
#     without it the CLI can replace itself in the middle of a run
#   - Non-essential traffic disabled (CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1,
#     inherited): telemetry, error reporting and remote feature-flag fetches off
#
# Re-pinning the CLI
#   1. npm view @anthropic-ai/claude-code dist-tags
#   2. Change CLAUDE_CLI_VERSION below and record why in the history
# ─────────────────────────────────────────────────────────────────────────────

ARG BASE_IMAGE=agent-cleanroom/base:local
FROM ${BASE_IMAGE}

# CLI version — EXACT pin.
#
# History of this value is recorded rather than silently fixed, because "why
# is the pin not the newest version" is exactly the question a reader of a
# reproducibility artifact should be able to answer:
#   0.1.0  2.1.308  (npm `stable` on 2026-10-25; `latest` was 2.1.310). The
#                   predecessor project pinned 2.1.306, whose bundled Bun
#                   runtime still carried the pre-fix Brotli decoder.
ARG CLAUDE_CLI_VERSION=2.1.308

USER root

# Install the CLI at the exact pinned version. If that version is yanked from
# npm the build fails — intentionally. A silent fallback to a different version
# would defeat the purpose of the pin.
# HOME/CLAUDE_CONFIG_DIR point at /root for this step only, so npm's cache does
# not land inside the clean HOME.
RUN HOME=/root CLAUDE_CONFIG_DIR=/root/.claude \
        npm install -g "@anthropic-ai/claude-code@${CLAUDE_CLI_VERSION}" \
 && HOME=/root CLAUDE_CONFIG_DIR=/root/.claude claude --version | tee /etc/cleanroom-claude-version \
 && rm -rf /root/.npm /root/.claude /root/.claude.json

ENV CLAUDE_CLI_VERSION=${CLAUDE_CLI_VERSION} \
    ACR_AGENT=claude-code

USER cleanroom
WORKDIR /cleanroom

LABEL org.opencontainers.image.title="agent-cleanroom-claude-code" \
      org.opencontainers.image.description="agent-cleanroom base plus an exact, unmodified Claude Code CLI release" \
      org.opencontainers.image.licenses="MIT AND LicenseRef-Claude-Code" \
      io.github.agent-cleanroom.agent="claude-code" \
      io.github.agent-cleanroom.agent.version="${CLAUDE_CLI_VERSION}"

ENTRYPOINT []
