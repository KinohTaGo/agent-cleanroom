#!/usr/bin/env bats
# Unit tests for verifier/verify.sh, run outside the image through the
# ACR_VERIFY_SYSROOT test hook. Each test builds a fake root with stub tools,
# so it runs on macOS (bash 3.2) and on the CI runner alike.
# The container-level checks (real image, real CLI) live in tests/integration.

VERIFY="${VERIFY_UNDER_TEST:-${BATS_TEST_DIRNAME}/../../verifier/verify.sh}"
PIN="2.1.308"

setup() {
    ROOT="$BATS_TEST_TMPDIR/root"
    BIN="$BATS_TEST_TMPDIR/bin"
    WORK="$BATS_TEST_TMPDIR/work"
    mkdir -p "$ROOT/cleanroom/.config" "$ROOT/cleanroom/.local/share" "$ROOT/cleanroom/.cache" \
             "$ROOT/etc" "$BIN" "$WORK"
    printf '%s (Claude Code)\n' "$PIN" > "$ROOT/etc/cleanroom-claude-version"
    printf 'Debian GNU/Linux 13 (trixie)\n' > "$ROOT/etc/cleanroom-os"
    printf '20250419+deb13u1\n' > "$ROOT/etc/cleanroom-ca-certificates-version"
    stub claude "$PIN (Claude Code)"
    stub jq "jq-1.7.1"
    stub node "v24.22.1"
    stub npm "11.6.2"
    # curl: prints a version, or an HTTP status when asked for one (-w)
    cat > "$BIN/curl" <<'EOF'
#!/bin/sh
for a in "$@"; do
    if [ "$a" = "-w" ]; then printf '%s' "${STUB_HTTP_CODE:-200}"; exit "${STUB_CURL_RC:-0}"; fi
done
echo "curl 8.14.1"
EOF
    chmod +x "$BIN/curl"
    CLI_VERSION_ENV="$PIN"
    JQ="$(command -v jq)"
}

stub() {  # stub <name> <version line>
    printf '#!/bin/sh\necho "%s"\n' "$2" > "$BIN/$1"
    chmod +x "$BIN/$1"
}

# run_verify [VAR=value ...] — clean environment plus overrides
run_verify() {
    run env -i \
        PATH="$BIN:/usr/bin:/bin" \
        HOME="$ROOT/cleanroom" \
        CLAUDE_CONFIG_DIR="$ROOT/cleanroom/.claude" \
        CLAUDE_CLI_VERSION="$CLI_VERSION_ENV" \
        DISABLE_AUTOUPDATER=1 \
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
        ACR_VERIFY_SYSROOT="$ROOT" \
        "$@" \
        bash -c 'cd "$1" && exec bash "$2" 2>/dev/null' _ "$WORK" "$VERIFY"
}

field() { printf '%s' "$output" | "$JQ" -c "$1"; }

# fake_proc <CapBnd hex> <NoNewPrivs 0|1> <root mount options>
fake_proc() {
    mkdir -p "$ROOT/proc/self"
    printf 'Name:\tbash\nCapEff:\t0000000000000000\nCapBnd:\t%s\nNoNewPrivs:\t%s\n' "$1" "$2" > "$ROOT/proc/self/status"
    printf '100 90 0:50 / / %s master:1 - overlay overlay rw\n101 100 0:51 / /tmp rw,nosuid - tmpfs tmpfs rw\n' "$3" > "$ROOT/proc/self/mountinfo"
}

# ── carried over from cc-cleanroom 0.2.0 (schema 2.0), adapted to 3.0 ──────

@test "clean room passes and emits valid JSON" {
    run_verify
    [ "$status" -eq 0 ]
    [ "$(field .verification_passed)" = "true" ]
    [ "$(field .failures)" = "[]" ]
    [ "$(field .schema_version)" = '"3.0"' ]
    [ "$(field .cli_version_matches_pin)" = "true" ]
    [ "$(field .home_was_empty_at_start)" = "true" ]
}

@test "empty .local/share directory is allowed" {
    [ -d "$ROOT/cleanroom/.local/share" ]
    run_verify
    [ "$status" -eq 0 ]
}

@test "CLAUDE.md in HOME fails" {
    echo "be terse" > "$ROOT/cleanroom/CLAUDE.md"
    run_verify
    [ "$status" -eq 1 ]
    [ "$(field .global_claude_md_present)" = "true" ]
    [ "$(field .unexpected_home_entries)" = '["CLAUDE.md"]' ]
}

@test "settings in CLAUDE_CONFIG_DIR fail" {
    mkdir -p "$ROOT/cleanroom/.claude/plugins"
    echo '{}' > "$ROOT/cleanroom/.claude/settings.json"
    run_verify
    [ "$status" -eq 1 ]
    [ "$(field .unexpected_config_dir_entries)" = '["plugins","settings.json"]' ]
    [ "$(field .plugins_dir_present)" = "true" ]
}

@test "history (projects/) in CLAUDE_CONFIG_DIR fails" {
    mkdir -p "$ROOT/cleanroom/.claude/projects/-work"
    run_verify
    [ "$status" -eq 1 ]
    [ "$(field .claude_memory_dir_present)" = "true" ]
}

@test "a mounted credentials file alone is allowed and recorded" {
    mkdir -p "$ROOT/cleanroom/.claude"
    echo '{}' > "$ROOT/cleanroom/.claude/.credentials.json"
    run_verify
    [ "$status" -eq 0 ]
    [ "$(field .auth.credentials_file)" = "true" ]
}

@test "a git config under XDG_CONFIG_HOME fails" {
    mkdir -p "$ROOT/cleanroom/.config/git"
    echo '[core]' > "$ROOT/cleanroom/.config/git/config"
    run_verify
    [ "$status" -eq 1 ]
    [ "$(field .nonempty_xdg_dirs)" = '[".config"]' ]
}

@test "managed settings fail" {
    mkdir -p "$ROOT/etc/claude-code"
    echo '{}' > "$ROOT/etc/claude-code/managed-settings.json"
    run_verify
    [ "$status" -eq 1 ]
    [ "$(field .managed_settings_entries)" = '["managed-settings.json"]' ]
}

@test "running CLI newer than the pin fails (self-update drift)" {
    stub claude "2.1.310 (Claude Code)"
    run_verify
    [ "$status" -eq 1 ]
    [ "$(field .cli_version_matches_pin)" = "false" ]
    [ "$(field .cli_version_running)" = '"2.1.310"' ]
}

@test "image built with a different CLI than the env pin fails" {
    printf '2.1.306 (Claude Code)\n' > "$ROOT/etc/cleanroom-claude-version"
    run_verify
    [ "$status" -eq 1 ]
}

@test "self-update enabled fails; DISABLE_UPDATES alone is accepted" {
    run_verify DISABLE_AUTOUPDATER=0
    [ "$status" -eq 1 ]
    [ "$(field .autoupdate_disabled)" = "false" ]
    run_verify DISABLE_AUTOUPDATER= DISABLE_UPDATES=1
    [ "$status" -eq 0 ]
}

@test "CLAUDE_CONFIG_DIR pointing elsewhere fails" {
    run_verify CLAUDE_CONFIG_DIR=/home/someone/.claude
    [ "$status" -eq 1 ]
    [ "$(field .claude_config_dir_actual)" = '"/home/someone/.claude"' ]
}

@test "model endpoint is recorded as scheme://host:port only; secrets never appear" {
    run_verify \
        ANTHROPIC_BASE_URL='https://user:pw-SECR''ET@llm.example:8080/v1/x?k=SECRET' \
        ANTHROPIC_MODEL=local-model-7b \
        ANTHROPIC_API_KEY=sk-SECRET-1 \
        CLAUDE_CODE_OAUTH_TOKEN=oat-SECRET-2
    [ "$status" -eq 0 ]
    [ "$(field .model_endpoint)" = '"https://llm.example:8080"' ]
    [ "$(field .model_selection.ANTHROPIC_MODEL)" = '"local-model-7b"' ]
    [ "$(field .auth.api_key_env)" = "true" ]
    [ "$(field .auth.oauth_token_env)" = "true" ]
    [[ "$output" != *SECRET* ]]
    [[ "$(field .behaviour_env_names)" == *'"ANTHROPIC_API_KEY"'* ]]
}

@test "no endpoint override is recorded as null" {
    run_verify
    [ "$(field .model_endpoint)" = "null" ]
    [ "$(field .model_selection.ANTHROPIC_MODEL)" = "null" ]
}

@test "declared project inputs and git HEAD of the workdir are recorded" {
    git -C "$WORK" init -q
    echo "# project rules" > "$WORK/CLAUDE.md"
    git -C "$WORK" add CLAUDE.md
    git -C "$WORK" -c user.email=t@example.invalid -c user.name=t commit -q -m init
    run_verify ACR_ALLOW_PROJECT_INPUTS=1
    [ "$status" -eq 0 ]
    [ "$(field .project_inputs_allowed)" = "true" ]
    [ "$(field '.project_inputs_sha256["CLAUDE.md"] | length')" = "64" ]
    [ "$(field '.project_inputs_sha256[".mcp.json"]')" = "null" ]
    [ "$(field '.workdir_git_head | length')" = "40" ]
    [ "$(field .workdir_git_dirty)" = "false" ]
    echo change >> "$WORK/CLAUDE.md"
    run_verify ACR_ALLOW_PROJECT_INPUTS=1
    [ "$(field .workdir_git_dirty)" = "true" ]
}

@test "odd file names in HOME still produce valid JSON" {
    touch "$ROOT/cleanroom/$(printf 'we"ird\tname')"
    run_verify
    [ "$status" -eq 1 ]
    printf '%s' "$output" | "$JQ" -e . >/dev/null
}

@test "a missing required tool fails but JSON is still emitted" {
    rm "$BIN/jq"
    # a system PATH with every tool except jq (jq may live in /usr/bin)
    SYS="$BATS_TEST_TMPDIR/sys"; mkdir -p "$SYS"
    for f in /bin/* /usr/bin/*; do
        n=${f##*/}; [ "$n" = jq ] && continue
        [ -e "$SYS/$n" ] || ln -s "$f" "$SYS/$n"
    done
    run env -i PATH="$BIN:$SYS" HOME="$ROOT/cleanroom" CLAUDE_CONFIG_DIR="$ROOT/cleanroom/.claude" \
        CLAUDE_CLI_VERSION="$PIN" DISABLE_AUTOUPDATER=1 ACR_VERIFY_SYSROOT="$ROOT" \
        /bin/bash -c 'cd "$1" && exec /bin/bash "$2" 2>/dev/null' _ "$WORK" "$VERIFY"
    [ "$status" -eq 1 ]
    [ "$(field .tools.jq.present)" = "false" ]
    [ "$(field .tools.claude.present)" = "true" ]
}

# ── new in schema 3.0 ───────────────────────────────────────────────────────

@test "undeclared CLAUDE.md in the working directory fails" {
    echo "# project rules" > "$WORK/CLAUDE.md"
    run_verify
    [ "$status" -eq 1 ]
    [ "$(field .project_inputs_allowed)" = "false" ]
    [[ "$(field .failures)" == *"project inputs"* ]]
    rm "$WORK/CLAUDE.md"
    mkdir -p "$WORK/.claude"; echo '{}' > "$WORK/.claude/settings.json"
    run_verify
    [ "$status" -eq 1 ]
}

@test "ACR_AGENT=none does not require the claude CLI; an unknown agent fails" {
    rm "$BIN/claude"
    run_verify ACR_AGENT=none CLAUDE_CLI_VERSION= DISABLE_AUTOUPDATER=
    [ "$status" -eq 0 ]
    [ "$(field .agent)" = '"none"' ]
    [ "$(field .tools.claude.present)" = "false" ]
    run_verify ACR_AGENT=other-agent
    [ "$status" -eq 1 ]
}

@test "a declared backend with a matching endpoint passes and is recorded" {
    run_verify ACR_BACKEND=ollama ACR_BACKEND_ENDPOINT=http://gateway:11434 \
        ANTHROPIC_BASE_URL=http://gateway:11434 \
        ACR_BACKEND_RUNTIME=ollama ACR_BACKEND_RUNTIME_VERSION=0.31.1 \
        ACR_MODEL=tiny:0.5b ACR_MODEL_DIGEST=sha256:abc ACR_SEED_FIXED=0
    [ "$status" -eq 0 ]
    [ "$(field .backend.name)" = '"ollama"' ]
    [ "$(field .backend.endpoint_matches)" = "true" ]
    [ "$(field .backend.runtime_version)" = '"0.31.1"' ]
    [ "$(field .backend.model_digest)" = '"sha256:abc"' ]
    [ "$(field .backend.seed_fixed)" = "false" ]
    [ "$(field .backend.probed)" = "false" ]
    [ "$(field .backend.reachable)" = "null" ]
}

@test "a backend endpoint that does not match ANTHROPIC_BASE_URL fails" {
    run_verify ACR_BACKEND=ollama ACR_BACKEND_ENDPOINT=http://gateway:11434 \
        ANTHROPIC_BASE_URL=http://elsewhere.example:11434
    [ "$status" -eq 1 ]
    [ "$(field .backend.endpoint_matches)" = "false" ]
    run_verify ACR_BACKEND=anthropic ACR_BACKEND_ENDPOINT=https://api.anthropic.com
    [ "$status" -eq 1 ]
    [[ "$(field .failures)" == *"endpoint mismatch"* ]]
}

@test "probing records a reachable backend and fails an unreachable one" {
    run_verify ACR_BACKEND=ollama ACR_BACKEND_ENDPOINT=http://gateway:11434 \
        ANTHROPIC_BASE_URL=http://gateway:11434 ACR_VERIFY_PROBE=1 STUB_HTTP_CODE=200
    [ "$status" -eq 0 ]
    [ "$(field .backend.reachable)" = "true" ]
    [ "$(field .backend.probe_http_status)" = '"200"' ]
    run_verify ACR_BACKEND=ollama ACR_BACKEND_ENDPOINT=http://gateway:11434 \
        ANTHROPIC_BASE_URL=http://gateway:11434 ACR_VERIFY_PROBE=1 STUB_HTTP_CODE=000 STUB_CURL_RC=7
    [ "$status" -eq 1 ]
    [ "$(field .backend.reachable)" = "false" ]
    [[ "$(field .failures)" == *"unreachable"* ]]
}

@test "required hardening passes when the kernel reports all three" {
    fake_proc 0000000000000000 1 ro,relatime
    run_verify ACR_REQUIRE_HARDENING=1
    [ "$status" -eq 0 ]
    [ "$(field .hardening.capability_bounding_set_empty)" = "true" ]
    [ "$(field .hardening.no_new_privs)" = "true" ]
    [ "$(field .hardening.root_filesystem_read_only)" = "true" ]
}

@test "required hardening fails for each missing property" {
    fake_proc 00000000a80425fb 1 ro,relatime
    run_verify ACR_REQUIRE_HARDENING=1
    [ "$status" -eq 1 ]
    [ "$(field .hardening.capability_bounding_set_empty)" = "false" ]
    fake_proc 0000000000000000 0 ro,relatime
    run_verify ACR_REQUIRE_HARDENING=1
    [ "$status" -eq 1 ]
    [ "$(field .hardening.no_new_privs)" = "false" ]
    fake_proc 0000000000000000 1 rw,relatime
    run_verify ACR_REQUIRE_HARDENING=1
    [ "$status" -eq 1 ]
    [ "$(field .hardening.root_filesystem_read_only)" = "false" ]
}

@test "hardening is recorded as null outside Linux and fails only when required" {
    run_verify
    [ "$status" -eq 0 ]
    [ "$(field .hardening.no_new_privs)" = "null" ]
    run_verify ACR_REQUIRE_HARDENING=1
    [ "$status" -eq 1 ]
}

@test "proxy endpoint is recorded without credentials" {
    run_verify HTTPS_PROXY='http://u:pw-SECR''ET@gateway:3128/'
    [ "$status" -eq 0 ]
    [ "$(field .network.proxy_endpoint)" = '"http://gateway:3128"' ]
    [[ "$output" != *SECRET* ]]
}
