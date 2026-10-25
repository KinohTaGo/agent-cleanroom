# syntax=docker/dockerfile:1.7
# ─────────────────────────────────────────────────────────────────────────────
# agent-cleanroom/base — the agent-independent half of the clean room
# ─────────────────────────────────────────────────────────────────────────────
#
# Contents: Debian 13 slim, Node 24, git, curl, jq, tini, the runtime verifier
# and the egress gateway. Open-source software only — no agent CLI. The agent
# layer (images/claude-code) is built FROM this image; the gateway container
# of every run uses this image as it is.
#
# Build (from the repository root):
#     docker build -f images/base/Dockerfile -t agent-cleanroom/base:local .
#
# What is pinned
#   - Base image by manifest-list digest (not by tag) — multi-arch, resolves the
#     same layer set on arm64 and amd64
#   - HOME=/cleanroom and CLAUDE_CONFIG_DIR=/cleanroom/.claude, both empty: no
#     global instructions, no settings, no plugins, no hooks, no history
#   - Toolchain versions recorded into /etc/cleanroom-* at build time so a
#     running container can report what it is
#
# Re-pinning the base image
#   1. docker buildx imagetools inspect node:24-trixie-slim   # new index digest
#   2. Replace the digest on FROM below and record why in the comment
# ─────────────────────────────────────────────────────────────────────────────

# Base image: node:24.22.1-trixie-slim (Node 24 LTS on Debian 13), multi-arch
# manifest-list digest. Carried over from cc-cleanroom 0.2.0 (captured
# 2026-10-22) and re-checked against registry-1.docker.io on 2026-10-25: the
# `24-trixie-slim` and `24.22.1-trixie-slim` tags both still resolve to it.
#   linux/amd64    : sha256:e79437bb05061f860be420634f676f4394619028df216d4b9361966d7fcc7a14
#   linux/arm64/v8 : sha256:401346cb1fc12bb388a82ed58ea72eeed2fe8530804d2964bcddce63a4eda4d8
# Node 24.22.1 carries the 2026-10-21 Node security release (Brotli
# out-of-bounds write, TLS fixes, the eMudhra key blocklist).
FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea

ARG CLEANROOM_UID=10001
# Base image identity, recorded into the image. CI derives both values from the
# FROM line above (so a bump of FROM cannot leave them stale); a local build
# without --build-arg records "unknown" rather than a guess.
ARG CLEANROOM_BASE_NAME=unknown
ARG CLEANROOM_BASE_DIGEST=unknown

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    HOME=/cleanroom \
    CLAUDE_CONFIG_DIR=/cleanroom/.claude \
    XDG_CONFIG_HOME=/cleanroom/.config \
    XDG_DATA_HOME=/cleanroom/.local/share \
    XDG_CACHE_HOME=/cleanroom/.cache \
    DISABLE_AUTOUPDATER=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    ACR_AGENT=none

# Minimal toolchain — deliberately small, since every extra package is another
# thing that can differ between builds.
#   git           — capture the commit under test from inside the container
#   curl, ca-cert — TLS trust store for git/curl; the verifier's backend probe
#   jq            — JSON handling in run scripts
#   tini          — PID 1 for agent runs (signals, zombie reaping); there is no
#                   ENTRYPOINT, the host CLI prefixes commands with it
# ca-certificates comes from trixie-security; 20250419+deb13u1 (2026-10-20)
# blocklists "emSign ECC Root CA - G3" and "Comodo AAA Services root".
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
        jq \
        tini \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg-query -W -f='${Version}\n' ca-certificates > /etc/cleanroom-ca-certificates-version \
 && . /etc/os-release && printf '%s\n' "$PRETTY_NAME" > /etc/cleanroom-os

# Refuse to build if either trust store (the OS bundle used by git/curl, or
# Node's built-in one) still trusts a root whose subordinate keys were
# compromised in October 2026. A stale apt mirror or a base-image regression
# then fails the build instead of shipping quietly.
COPY build/check-distrusted-roots.js /usr/local/lib/agent-cleanroom/check-distrusted-roots.js
RUN node /usr/local/lib/agent-cleanroom/check-distrusted-roots.js /etc/ssl/certs/ca-certificates.crt

# Unprivileged user. The Claude Code CLI refuses --dangerously-skip-permissions
# under root, and a self-update could rewrite /usr/local mid-run.
# Clean HOME: empty except for the XDG directories. CLAUDE_CONFIG_DIR is NOT
# created here; it must not exist (or hold only .credentials.json) at start.
# `agent-cleanroom run` mounts a fresh tmpfs over /cleanroom anyway (the root
# filesystem is read-only during runs).
RUN useradd --uid "${CLEANROOM_UID}" --user-group --home-dir /cleanroom \
        --no-create-home --shell /bin/bash cleanroom \
 && mkdir -p /cleanroom /cleanroom/.config /cleanroom/.local/share /cleanroom/.cache /work /out \
 && chown -R cleanroom:cleanroom /cleanroom /work /out \
 && chmod 1777 /cleanroom /cleanroom/.config /cleanroom/.local /cleanroom/.local/share /cleanroom/.cache

# Runtime verifier and egress gateway.
COPY verifier/verify.sh /usr/local/bin/verify.sh
COPY net/gateway.js /usr/local/lib/agent-cleanroom/gateway.js
RUN chmod 0755 /usr/local/bin/verify.sh \
 && chmod 0644 /usr/local/lib/agent-cleanroom/gateway.js

# Record build-time toolchain versions so a running container can report them.
RUN node --version > /etc/cleanroom-node-version \
 && npm  --version > /etc/cleanroom-npm-version \
 && printf '%s\n' "${CLEANROOM_BASE_DIGEST}" > /etc/cleanroom-base-digest

USER cleanroom
WORKDIR /cleanroom

LABEL org.opencontainers.image.title="agent-cleanroom-base" \
      org.opencontainers.image.description="Agent-independent clean-room base: Debian 13, Node 24, verifier, egress gateway" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="${CLEANROOM_BASE_NAME}" \
      org.opencontainers.image.base.digest="${CLEANROOM_BASE_DIGEST}"

# No ENTRYPOINT: `docker run IMAGE <cmd>` runs <cmd> as given.
ENTRYPOINT []
