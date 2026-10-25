# Credentials for the `anthropic` backend

agent-cleanroom never asks for, collects, stores or forwards credentials. You write a file; the
tool checks its permissions, hands it to `docker run --env-file`, and scrubs its values from the
run record.

## 1. Choose a credential

- **API key** (Anthropic Console or a cloud provider) — the documented choice for tools and
  automation.
- **Your own subscription** — run `claude setup-token` yourself, on your own machine, and copy the
  token it prints. Use it only for your own runs.

See Anthropic's terms for which applies to you:
<https://code.claude.com/docs/en/legal-and-compliance>.

## 2. Write the file without echoing the value

```sh
mkdir -p ~/.config/agent-cleanroom
( umask 077
  printf 'paste the key (input hidden): ' >&2
  IFS= read -r -s KEY; printf '\n' >&2
  printf 'ANTHROPIC_API_KEY=%s\n' "$KEY" > ~/.config/agent-cleanroom/auth.env
  unset KEY )
stat -f %Lp ~/.config/agent-cleanroom/auth.env 2>/dev/null || stat -c %a ~/.config/agent-cleanroom/auth.env
```

The last line must print `600`. For a setup-token token use `CLAUDE_CODE_OAUTH_TOKEN=` instead.
agent-cleanroom refuses a file that group or others can read.

## 3. Use it

```sh
uv run agent-cleanroom run --backend anthropic --auth-env-file ~/.config/agent-cleanroom/auth.env \
  --model <model> --prompt "…"
```

The container reaches only the API host, through the gateway's allow-listed CONNECT proxy. The
record's `env.json` says *that* a key or token was present (booleans), never its value.

## What was dropped from the predecessor

The predecessor's `setup-auth.sh` ran `claude setup-token` and stored the token for you. That
helper is gone on purpose: a tool that receives and stores a subscription token is exactly what
the terms above rule out for third-party products. Its good habits stay here as instructions —
input not echoed, mode 600, and checking the result.
