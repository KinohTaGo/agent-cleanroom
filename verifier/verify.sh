#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# verify.sh — runtime verifier for agent-cleanroom (record schema 3.0)
#
# Emits one JSON document describing the container a run is about to happen
# in, and fails if that container is not the clean room the image promises.
#
# Usage (inside the image; there is no ENTRYPOINT, so the command is the script):
#     docker run --rm agent-cleanroom/claude-code:<tag> verify.sh
# The `agent-cleanroom verify` and `agent-cleanroom run` commands call it for
# you with the backend, network and hardening settings filled in.
#
# Contract
#   Exit 0 — every assertion held. JSON on stdout.
#   Exit 1 — at least one assertion failed. JSON is still emitted (with
#            "verification_passed": false and the reasons in "failures"), so a
#            harness can archive it before aborting the run:
#                VERIFY_JSON=$(verify.sh) || abort
#   Stderr carries human-readable diagnostics. Stdout is JSON only.
#
# What fails the run (an un-clean room)
#   - HOME is not /cleanroom, or CLAUDE_CONFIG_DIR is not $HOME/.claude
#   - anything in HOME besides .config .local .cache .claude
#   - .config / .local / .cache not empty (e.g. a git config or an old auth
#     volume mounted there)
#   - CLAUDE_CONFIG_DIR holding anything besides .credentials.json
#     (CLAUDE.md, settings, plugins, hooks, agents, history, memory …)
#   - managed settings under /etc/claude-code
#   - project inputs in the working directory (CLAUDE.md, .mcp.json,
#     .claude/settings*.json) unless the run declares them
#     (ACR_ALLOW_PROJECT_INPUTS=1); declared inputs are recorded by sha256
#   - the running CLI version differs from the pinned one (self-update drift)
#   - self-update not disabled
#   - running as root
#   - a required tool missing
#   - a declared backend (ACR_BACKEND) whose endpoint does not match
#     ANTHROPIC_BASE_URL, or that cannot be reached when probing is on
#     (ACR_VERIFY_PROBE=1)
#   - hardening that the run requires (ACR_REQUIRE_HARDENING=1) but that the
#     kernel does not report: empty capability bounding set, no_new_privs,
#     read-only root filesystem
#
# What is only recorded (inputs a run is allowed to have, but must declare)
#   - auth method in use (booleans only; never a value)
#   - model endpoint (scheme://host[:port] of ANTHROPIC_BASE_URL) and the model
#     selection variables — so a run against a different backend is visible
#   - backend identity handed in by the host: runtime name and version, model
#     name and digest, and whether a sampling seed was fixed
#   - proxy endpoint (scheme://host[:port] of HTTPS_PROXY), never credentials
#   - names (never values) of every environment variable that can change
#     agent behaviour
#   - git HEAD + dirty flag of the working directory
#   - image identity: /etc/cleanroom-* written at build time
#
# Test hook: ACR_VERIFY_SYSROOT prefixes /cleanroom, /etc and /proc paths so
# the script can be unit-tested outside the image. Its value is recorded in
# the JSON ("sysroot"); a real run has it empty.
# Compatible with bash 3.2 (macOS) so the unit tests run there too.
# ─────────────────────────────────────────────────────────────────────────────

set -u

SYSROOT="${ACR_VERIFY_SYSROOT:-}"
EXPECTED_HOME="${SYSROOT}/cleanroom"
EXPECTED_CONFIG_DIR="${EXPECTED_HOME}/.claude"
ETC="${SYSROOT}/etc"
PROC="${SYSROOT}/proc"
AGENT="${ACR_AGENT:-claude-code}"

FAILURES=()
log()  { printf '[verify] %s\n' "$*" >&2; }
fail() { printf '[verify] FAIL: %s\n' "$*" >&2; FAILURES+=("$*"); }

# ── JSON helpers (pure bash; no python/node/jq needed) ─────────────────────
json_str() {
    local s
    s=$(printf '%s' "$1" | LC_ALL=C tr -d '\000-\010\013\014\016-\037')
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '"%s"' "$s"
}
json_str_or_null() { if [[ -n "$1" ]]; then json_str "$1"; else printf 'null'; fi; }
json_bool() { if [[ "$1" == "1" ]]; then printf 'true'; else printf 'false'; fi; }
# json_tristate 1|0|"" → true|false|null
json_tristate() { case "$1" in 1) printf 'true' ;; 0) printf 'false' ;; *) printf 'null' ;; esac; }
# json_arr "a" "b" … → ["a", "b"]; no arguments → []
json_arr() {
    local out="[" sep="" e
    for e in "$@"; do out+="${sep}$(json_str "$e")"; sep=", "; done
    printf '%s]' "$out"
}
truthy() { case "${1:-}" in 1|true|TRUE|True|yes|on) return 0 ;; *) return 1 ;; esac; }
first_line() { if [[ -r "$1" ]]; then head -n1 "$1" 2>/dev/null; fi; }
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}
# list_entries <dir> → names of direct children, one per line (empty if none / no dir)
list_entries() {
    [[ -d "$1" ]] || return 0
    find "$1" -mindepth 1 -maxdepth 1 -print 2>/dev/null | while IFS= read -r p; do basename "$p"; done | LC_ALL=C sort
}
# scheme://host[:port] only — userinfo, path, query and fragment are dropped
endpoint_of() {
    local u="$1" scheme rest hostport
    [[ -n "$u" ]] || { printf ''; return; }
    case "$u" in *://*) scheme=${u%%://*}; rest=${u#*://} ;; *) scheme=""; rest=$u ;; esac
    rest=${rest%%/*}; rest=${rest%%\?*}; rest=${rest%%#*}
    hostport=${rest##*@}
    if [[ -n "$scheme" ]]; then printf '%s://%s' "$scheme" "$hostport"; else printf '%s' "$hostport"; fi
}

# ── 1. Identity: HOME, CLAUDE_CONFIG_DIR, user ─────────────────────────────
ACTUAL_HOME="${HOME:-}"
[[ "$ACTUAL_HOME" == "$EXPECTED_HOME" ]] || fail "HOME='$ACTUAL_HOME', expected '$EXPECTED_HOME'"
ACTUAL_CONFIG_DIR="${CLAUDE_CONFIG_DIR:-}"
[[ "$ACTUAL_CONFIG_DIR" == "$EXPECTED_CONFIG_DIR" ]] \
    || fail "CLAUDE_CONFIG_DIR='$ACTUAL_CONFIG_DIR', expected '$EXPECTED_CONFIG_DIR' (another value can point the CLI at a host config)"
UID_NOW=$(id -u 2>/dev/null || echo "")
[[ "$UID_NOW" != "0" ]] || fail "running as root (uid 0); the image runs as 'cleanroom' — the CLI also refuses --dangerously-skip-permissions under root"

# ── 2. HOME contents ───────────────────────────────────────────────────────
ALLOWED_HOME=(".cache" ".claude" ".config" ".local")
UNEXPECTED_HOME=()
while IFS= read -r e; do
    [[ -n "$e" ]] || continue
    ok=0; for a in "${ALLOWED_HOME[@]}"; do [[ "$e" == "$a" ]] && ok=1 && break; done
    [[ $ok -eq 1 ]] || UNEXPECTED_HOME+=("$e")
done < <(list_entries "$EXPECTED_HOME")
if [[ ${#UNEXPECTED_HOME[@]} -gt 0 ]]; then
    fail "unexpected entries in HOME: ${UNEXPECTED_HOME[*]}"
fi

# 2a. Host artefacts by name (kept as separate booleans for older readers)
GLOBAL_CLAUDE_MD=0; PLUGINS_DIR=0; HOOKS_DIR=0; CLAUDE_MEMORY_DIR=0
[[ -e "$EXPECTED_HOME/CLAUDE.md" || -e "$EXPECTED_CONFIG_DIR/CLAUDE.md" ]] && GLOBAL_CLAUDE_MD=1
[[ -d "$EXPECTED_CONFIG_DIR/plugins" ]] && PLUGINS_DIR=1
[[ -d "$EXPECTED_CONFIG_DIR/hooks" ]] && HOOKS_DIR=1
[[ -d "$EXPECTED_HOME/.claude-memory" || -d "$EXPECTED_HOME/.claude-backup" || -d "$EXPECTED_CONFIG_DIR/projects" ]] && CLAUDE_MEMORY_DIR=1

# 2b. XDG directories must hold no files at start (empty sub-directories such
#     as .local/share are part of the image and allowed)
files_under() {
    [[ -d "$1" ]] || return 0
    (cd "$1" && find . -mindepth 1 ! -type d -print 2>/dev/null) | sed 's#^\./##' | LC_ALL=C sort
}
XDG_NONEMPTY=()
for d in .config .local .cache; do
    n=$(files_under "$EXPECTED_HOME/$d" | grep -c . || true)
    if [[ "$n" -gt 0 ]]; then
        XDG_NONEMPTY+=("$d")
        fail "HOME/$d is not empty ($n file(s)): $(files_under "$EXPECTED_HOME/$d" | head -n 5 | tr '\n' ' ')"
    fi
done

# 2c. CLAUDE_CONFIG_DIR may hold only a mounted credentials file
CONFIG_DIR_ENTRIES=()
CREDENTIALS_FILE=0
while IFS= read -r e; do
    [[ -n "$e" ]] || continue
    if [[ "$e" == ".credentials.json" ]]; then CREDENTIALS_FILE=1; continue; fi
    CONFIG_DIR_ENTRIES+=("$e")
done < <(list_entries "$EXPECTED_CONFIG_DIR")
if [[ ${#CONFIG_DIR_ENTRIES[@]} -gt 0 ]]; then
    fail "CLAUDE_CONFIG_DIR holds state from elsewhere: ${CONFIG_DIR_ENTRIES[*]}"
fi

HOME_WAS_EMPTY=1
if [[ ${#UNEXPECTED_HOME[@]} -gt 0 || ${#XDG_NONEMPTY[@]} -gt 0 || ${#CONFIG_DIR_ENTRIES[@]} -gt 0 ]]; then
    HOME_WAS_EMPTY=0
fi

# ── 3. Managed settings (system-wide policy files override everything) ─────
MANAGED=()
while IFS= read -r e; do [[ -n "$e" ]] && MANAGED+=("$e"); done < <(list_entries "$ETC/claude-code")
if [[ ${#MANAGED[@]} -gt 0 ]]; then
    fail "managed settings present in $ETC/claude-code: ${MANAGED[*]}"
fi

# ── 4. Tools and version drift ─────────────────────────────────────────────
tool_present() { command -v "$1" >/dev/null 2>&1 && echo 1 || echo 0; }
tool_version() { if command -v "$1" >/dev/null 2>&1; then "$1" --version 2>&1 | head -n1; fi; }
CLAUDE_PRESENT=$(tool_present claude); GIT_PRESENT=$(tool_present git)
JQ_PRESENT=$(tool_present jq);         CURL_PRESENT=$(tool_present curl)
NODE_PRESENT=$(tool_present node);     NPM_PRESENT=$(tool_present npm)
case "$AGENT" in
    claude-code) [[ "$CLAUDE_PRESENT" -eq 1 ]] || fail "claude CLI not found in PATH" ;;
    none) ;;
    *) fail "unknown ACR_AGENT='$AGENT' (expected claude-code or none)" ;;
esac
[[ "$GIT_PRESENT"    -eq 1 ]] || fail "git not found in PATH"
[[ "$JQ_PRESENT"     -eq 1 ]] || fail "jq not found in PATH"
[[ "$CURL_PRESENT"   -eq 1 ]] || fail "curl not found in PATH"

CLAUDE_VERSION=$(tool_version claude); GIT_VERSION=$(tool_version git)
JQ_VERSION=$(tool_version jq);         CURL_VERSION=$(tool_version curl)
NODE_VERSION=$(tool_version node);     NPM_VERSION=$(tool_version npm)

PINNED="${CLAUDE_CLI_VERSION:-}"
BUILT=$(first_line "$ETC/cleanroom-claude-version")
RUNNING_V=${CLAUDE_VERSION%% *}
BUILT_V=${BUILT%% *}
CLI_VERSION_MATCHES=0
if [[ -n "$PINNED" && "$RUNNING_V" == "$PINNED" && ( -z "$BUILT_V" || "$BUILT_V" == "$PINNED" ) ]]; then
    CLI_VERSION_MATCHES=1
elif [[ "$AGENT" == "claude-code" && "$CLAUDE_PRESENT" -eq 1 ]]; then
    fail "CLI version drift: running '${RUNNING_V}', pinned CLAUDE_CLI_VERSION='${PINNED}', built '${BUILT_V}'"
fi

AUTOUPDATE_DISABLED=0
if truthy "${DISABLE_AUTOUPDATER:-}" || truthy "${DISABLE_UPDATES:-}"; then AUTOUPDATE_DISABLED=1
elif [[ "$AGENT" == "claude-code" ]]; then
    fail "self-update is not disabled (set DISABLE_AUTOUPDATER=1); the CLI could replace itself mid-run"
fi
NONESSENTIAL_OFF=0
truthy "${CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC:-}" && NONESSENTIAL_OFF=1
[[ $NONESSENTIAL_OFF -eq 1 ]] || log "note: CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC is off — remote feature flags may differ between runs"

# ── 5. Recorded inputs: auth, model endpoint, behaviour-changing env names ─
is_set() { [[ -n "${!1-}" ]] && echo 1 || echo 0; }
AUTH_OAUTH=$(is_set CLAUDE_CODE_OAUTH_TOKEN)
AUTH_API_KEY=$(is_set ANTHROPIC_API_KEY)
AUTH_BEARER=$(is_set ANTHROPIC_AUTH_TOKEN)

MODEL_ENDPOINT=$(endpoint_of "${ANTHROPIC_BASE_URL:-}")
PROXY_ENDPOINT=$(endpoint_of "${HTTPS_PROXY:-${https_proxy:-}}")

MODEL_VARS=(ANTHROPIC_MODEL ANTHROPIC_SMALL_FAST_MODEL ANTHROPIC_DEFAULT_OPUS_MODEL
            ANTHROPIC_DEFAULT_SONNET_MODEL ANTHROPIC_DEFAULT_HAIKU_MODEL CLAUDE_CODE_SUBAGENT_MODEL)
MODEL_JSON="{"; sep=""
for v in "${MODEL_VARS[@]}"; do
    MODEL_JSON+="${sep}$(json_str "$v"): $(json_str_or_null "${!v-}")"; sep=", "
done
MODEL_JSON+="}"

ENV_NAMES=()
while IFS= read -r name; do
    [[ -n "$name" ]] && ENV_NAMES+=("$name")
done < <(compgen -e | LC_ALL=C grep -E '^(ACR_|ANTHROPIC_|CLAUDE_|DISABLE_|MCP_|OTEL_|OLLAMA_|GIT_CONFIG|BASH_ENV$|ENV$|NODE_OPTIONS$|NODE_EXTRA_CA_CERTS$|SSL_CERT_(FILE|DIR)$|CURL_CA_BUNDLE$|((HTTPS?|ALL|NO)_PROXY|(https?|all|no)_proxy)$)' | LC_ALL=C sort)

# ── 6. Backend declared by the host (agent-cleanroom run/verify) ───────────
BACKEND="${ACR_BACKEND:-}"
BACKEND_EXPECTED=$(endpoint_of "${ACR_BACKEND_ENDPOINT:-}")
BACKEND_MATCH=""; BACKEND_REACHABLE=""; BACKEND_HTTP=""
SEED_FIXED=""
if [[ -n "$BACKEND" ]]; then
    if [[ -z "$BACKEND_EXPECTED" ]]; then
        fail "backend '$BACKEND' declared without ACR_BACKEND_ENDPOINT"
        BACKEND_MATCH=0
    elif [[ "$MODEL_ENDPOINT" == "$BACKEND_EXPECTED" ]]; then
        BACKEND_MATCH=1
    else
        BACKEND_MATCH=0
        fail "endpoint mismatch: ANTHROPIC_BASE_URL points at '${MODEL_ENDPOINT:-<unset>}', backend '$BACKEND' is '$BACKEND_EXPECTED'"
    fi
    if truthy "${ACR_VERIFY_PROBE:-}" && [[ -n "$BACKEND_EXPECTED" ]]; then
        if [[ "$CURL_PRESENT" -eq 1 ]]; then
            BACKEND_HTTP=$(curl -s -o /dev/null -w '%{http_code}' --max-time "${ACR_VERIFY_PROBE_TIMEOUT:-5}" "$BACKEND_EXPECTED/" 2>/dev/null || true)
            case "$BACKEND_HTTP" in
                [1-5][0-9][0-9]) BACKEND_REACHABLE=1 ;;
                *) BACKEND_REACHABLE=0; fail "backend '$BACKEND' unreachable at '$BACKEND_EXPECTED' (no HTTP answer)" ;;
            esac
        else
            BACKEND_REACHABLE=0; fail "cannot probe backend: curl not found"
        fi
    fi
    case "${ACR_SEED_FIXED:-}" in 1|true) SEED_FIXED=1 ;; 0|false) SEED_FIXED=0 ;; *) SEED_FIXED="" ;; esac
fi

# ── 7. Hardening reported by the kernel (Linux /proc; null elsewhere) ──────
CAPBND_EMPTY=""; NO_NEW_PRIVS=""; ROOT_RO=""
if [[ -r "$PROC/self/status" ]]; then
    capbnd=$(awk '$1=="CapBnd:" {print $2}' "$PROC/self/status" 2>/dev/null)
    nnp=$(awk '$1=="NoNewPrivs:" {print $2}' "$PROC/self/status" 2>/dev/null)
    if [[ -n "$capbnd" ]]; then
        if [[ "$capbnd" =~ ^0+$ ]]; then CAPBND_EMPTY=1; else CAPBND_EMPTY=0; fi
    fi
    case "$nnp" in 1) NO_NEW_PRIVS=1 ;; 0) NO_NEW_PRIVS=0 ;; esac
fi
if [[ -r "$PROC/self/mountinfo" ]]; then
    rootopts=$(awk '$5=="/" {o=$6} END {print o}' "$PROC/self/mountinfo" 2>/dev/null)
    if [[ -n "$rootopts" ]]; then
        case ",$rootopts," in *,ro,*) ROOT_RO=1 ;; *) ROOT_RO=0 ;; esac
    fi
fi
HARDENING_REQUIRED=0
if truthy "${ACR_REQUIRE_HARDENING:-}"; then
    HARDENING_REQUIRED=1
    [[ "$CAPBND_EMPTY" == "1" ]] || fail "capability bounding set is not empty (run with --cap-drop ALL)"
    [[ "$NO_NEW_PRIVS" == "1" ]] || fail "no_new_privs is not set (run with --security-opt no-new-privileges)"
    [[ "$ROOT_RO" == "1" ]]      || fail "root filesystem is not read-only (run with --read-only)"
fi

# ── 8. Project inputs in the working directory ─────────────────────────────
WORKDIR=$(pwd)
PROJECT_ALLOWED=0; truthy "${ACR_ALLOW_PROJECT_INPUTS:-}" && PROJECT_ALLOWED=1
PROJECT_JSON="{"; sep=""; PROJECT_PRESENT=()
for f in CLAUDE.md CLAUDE.local.md .mcp.json .claude/settings.json .claude/settings.local.json; do
    if [[ -f "$WORKDIR/$f" ]]; then h=$(json_str "$(sha256_of "$WORKDIR/$f")"); PROJECT_PRESENT+=("$f"); else h=null; fi
    PROJECT_JSON+="${sep}$(json_str "$f"): ${h}"; sep=", "
done
PROJECT_JSON+="}"
if [[ ${#PROJECT_PRESENT[@]} -gt 0 && $PROJECT_ALLOWED -eq 0 ]]; then
    fail "project inputs in the working directory change agent behaviour and were not declared: ${PROJECT_PRESENT[*]} (declare them with --allow-project-inputs)"
fi
GIT_HEAD=""; GIT_DIRTY=""
if [[ "$GIT_PRESENT" -eq 1 ]] && git -C "$WORKDIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    GIT_HEAD=$(git -C "$WORKDIR" rev-parse HEAD 2>/dev/null || true)
    if [[ -n "$(git -C "$WORKDIR" status --porcelain 2>/dev/null | head -n1)" ]]; then GIT_DIRTY=true; else GIT_DIRTY=false; fi
fi

# ── 9. Emit ────────────────────────────────────────────────────────────────
PASSED=0; [[ ${#FAILURES[@]} -eq 0 ]] && PASSED=1
TS_UTC="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

cat <<EOF
{
  "schema_version": "3.0",
  "verification_timestamp_utc": "${TS_UTC}",
  "sysroot": $(json_str "$SYSROOT"),
  "agent": $(json_str "$AGENT"),
  "home": $(json_str "$EXPECTED_HOME"),
  "home_actual": $(json_str "$ACTUAL_HOME"),
  "claude_config_dir": $(json_str "$EXPECTED_CONFIG_DIR"),
  "claude_config_dir_actual": $(json_str "$ACTUAL_CONFIG_DIR"),
  "uid": $(json_str "$UID_NOW"),
  "home_was_empty_at_start": $(json_bool $HOME_WAS_EMPTY),
  "global_claude_md_present": $(json_bool $GLOBAL_CLAUDE_MD),
  "plugins_dir_present": $(json_bool $PLUGINS_DIR),
  "hooks_dir_present": $(json_bool $HOOKS_DIR),
  "claude_memory_dir_present": $(json_bool $CLAUDE_MEMORY_DIR),
  "allowed_home_entries": $(json_arr "${ALLOWED_HOME[@]}"),
  "unexpected_home_entries": $(json_arr ${UNEXPECTED_HOME[@]+"${UNEXPECTED_HOME[@]}"}),
  "nonempty_xdg_dirs": $(json_arr ${XDG_NONEMPTY[@]+"${XDG_NONEMPTY[@]}"}),
  "unexpected_config_dir_entries": $(json_arr ${CONFIG_DIR_ENTRIES[@]+"${CONFIG_DIR_ENTRIES[@]}"}),
  "managed_settings_entries": $(json_arr ${MANAGED[@]+"${MANAGED[@]}"}),
  "cli_version_pinned": $(json_str "$PINNED"),
  "cli_version_built": $(json_str "$BUILT_V"),
  "cli_version_running": $(json_str "$RUNNING_V"),
  "cli_version_matches_pin": $(json_bool $CLI_VERSION_MATCHES),
  "autoupdate_disabled": $(json_bool $AUTOUPDATE_DISABLED),
  "nonessential_traffic_disabled": $(json_bool $NONESSENTIAL_OFF),
  "auth": {
    "oauth_token_env": $(json_bool "$AUTH_OAUTH"),
    "api_key_env": $(json_bool "$AUTH_API_KEY"),
    "auth_token_env": $(json_bool "$AUTH_BEARER"),
    "credentials_file": $(json_bool $CREDENTIALS_FILE)
  },
  "model_endpoint": $(json_str_or_null "$MODEL_ENDPOINT"),
  "model_selection": ${MODEL_JSON},
  "backend": {
    "name": $(json_str_or_null "$BACKEND"),
    "expected_endpoint": $(json_str_or_null "$BACKEND_EXPECTED"),
    "endpoint_matches": $(json_tristate "$BACKEND_MATCH"),
    "probed": $(json_bool "$( [[ -n "$BACKEND_REACHABLE" ]] && echo 1 || echo 0 )"),
    "reachable": $(json_tristate "$BACKEND_REACHABLE"),
    "probe_http_status": $(json_str_or_null "$BACKEND_HTTP"),
    "runtime": $(json_str_or_null "${ACR_BACKEND_RUNTIME:-}"),
    "runtime_version": $(json_str_or_null "${ACR_BACKEND_RUNTIME_VERSION:-}"),
    "model": $(json_str_or_null "${ACR_MODEL:-}"),
    "model_digest": $(json_str_or_null "${ACR_MODEL_DIGEST:-}"),
    "seed_fixed": $(json_tristate "$SEED_FIXED"),
    "seed": $(json_str_or_null "${ACR_SEED:-}")
  },
  "network": {
    "proxy_endpoint": $(json_str_or_null "$PROXY_ENDPOINT")
  },
  "hardening": {
    "required": $(json_bool $HARDENING_REQUIRED),
    "capability_bounding_set_empty": $(json_tristate "$CAPBND_EMPTY"),
    "no_new_privs": $(json_tristate "$NO_NEW_PRIVS"),
    "root_filesystem_read_only": $(json_tristate "$ROOT_RO")
  },
  "behaviour_env_names": $(json_arr ${ENV_NAMES[@]+"${ENV_NAMES[@]}"}),
  "workdir": $(json_str "$WORKDIR"),
  "project_inputs_allowed": $(json_bool $PROJECT_ALLOWED),
  "project_inputs_sha256": ${PROJECT_JSON},
  "workdir_git_head": $(json_str_or_null "$GIT_HEAD"),
  "workdir_git_dirty": ${GIT_DIRTY:-null},
  "image": {
    "os": $(json_str_or_null "$(first_line "$ETC/cleanroom-os")"),
    "base_digest": $(json_str_or_null "$(first_line "$ETC/cleanroom-base-digest")"),
    "ca_certificates": $(json_str_or_null "$(first_line "$ETC/cleanroom-ca-certificates-version")"),
    "node": $(json_str_or_null "$(first_line "$ETC/cleanroom-node-version")"),
    "npm": $(json_str_or_null "$(first_line "$ETC/cleanroom-npm-version")")
  },
  "tools": {
    "claude": { "present": $(json_bool "$CLAUDE_PRESENT"), "version": $(json_str "$CLAUDE_VERSION") },
    "git":    { "present": $(json_bool "$GIT_PRESENT"),    "version": $(json_str "$GIT_VERSION") },
    "jq":     { "present": $(json_bool "$JQ_PRESENT"),     "version": $(json_str "$JQ_VERSION") },
    "curl":   { "present": $(json_bool "$CURL_PRESENT"),   "version": $(json_str "$CURL_VERSION") },
    "node":   { "present": $(json_bool "$NODE_PRESENT"),   "version": $(json_str "$NODE_VERSION") },
    "npm":    { "present": $(json_bool "$NPM_PRESENT"),    "version": $(json_str "$NPM_VERSION") }
  },
  "env": {
    "HOME": $(json_str "${HOME:-}"),
    "CLAUDE_CONFIG_DIR": $(json_str "${CLAUDE_CONFIG_DIR:-}"),
    "XDG_CONFIG_HOME": $(json_str "${XDG_CONFIG_HOME:-}"),
    "XDG_DATA_HOME": $(json_str "${XDG_DATA_HOME:-}"),
    "XDG_CACHE_HOME": $(json_str "${XDG_CACHE_HOME:-}"),
    "CLAUDE_CLI_VERSION": $(json_str "${CLAUDE_CLI_VERSION:-}")
  },
  "failures": $(json_arr ${FAILURES[@]+"${FAILURES[@]}"}),
  "verification_passed": $(json_bool $PASSED)
}
EOF

[[ $PASSED -eq 1 ]] && exit 0 || exit 1
