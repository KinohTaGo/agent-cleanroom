from pathlib import Path

import pytest

from agent_cleanroom.backends import BackendError, builtin_names, load_backend, with_url
from agent_cleanroom.netplan import NetPlanError, plan_for


def test_builtin_profiles_load():
    assert builtin_names() == ["anthropic", "ollama"]
    o = load_backend(name="ollama")
    assert (o.kind, o.auth_mode, o.placeholder, o.seed_supported) == ("ollama", "placeholder", "ollama", False)
    a = load_backend(name="anthropic")
    assert (a.kind, a.auth_mode, a.url) == ("anthropic", "env-file", "https://api.anthropic.com")


def test_unknown_or_malformed_profile_is_refused(tmp_path: Path):
    with pytest.raises(BackendError):
        load_backend(name="nope")
    bad = tmp_path / "bad.toml"
    bad.write_text('schema = "agent-cleanroom/backend-profile/1"\nkind = "vllm"\n')
    with pytest.raises(BackendError, match="kind"):
        load_backend(path=bad)
    bad.write_text('kind = "ollama"\n')
    with pytest.raises(BackendError, match="schema"):
        load_backend(path=bad)


def test_profile_file_source_has_no_host_path(tmp_path: Path):
    p = tmp_path / "mine.toml"
    p.write_text(
        'schema = "agent-cleanroom/backend-profile/1"\nkind = "ollama"\n'
        '[endpoint]\nurl = "http://127.0.0.1:11500"\n[auth]\nmode = "placeholder"\nplaceholder = "x"\n'
    )
    b = load_backend(path=p)
    assert b.source == "file:mine.toml"
    assert str(tmp_path) not in b.source


def test_url_override():
    b = with_url(load_backend(name="ollama"), "http://127.0.0.1:11500/")
    assert b.url == "http://127.0.0.1:11500"
    with pytest.raises(BackendError):
        with_url(b, "127.0.0.1:11500")


def test_local_backend_is_forwarded_through_the_gateway():
    p = plan_for("http://127.0.0.1:11500")
    assert p.mode == "forward"
    assert p.container_base_url == "http://gateway:11500"
    assert p.gateway_env() == {"ACR_FORWARDS": "11500=host.docker.internal:11500"}
    assert p.proxy_url is None


def test_remote_api_goes_through_an_allow_listed_connect_proxy():
    p = plan_for("https://api.anthropic.com")
    assert p.mode == "connect-proxy"
    assert p.container_base_url == "https://api.anthropic.com"
    assert p.connect_allow == ("api.anthropic.com:443",)
    assert p.gateway_env() == {"ACR_CONNECT_PORT": "3128", "ACR_CONNECT_ALLOW": "api.anthropic.com:443"}


def test_no_backend_means_no_gateway():
    p = plan_for(None)
    assert p.mode == "none" and not p.needs_gateway and p.gateway_env() == {}


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com",  # remote plain http
        "https://127.0.0.1:11434",  # local https cannot be TCP-forwarded with the right name
        "http://u:p@127.0.0.1:11434",  # credentials in the URL
        "http://127.0.0.1:11434/v1",  # a path
        "ftp://127.0.0.1",
    ],
)
def test_unsafe_or_ambiguous_urls_are_refused(url):
    with pytest.raises(NetPlanError):
        plan_for(url)
