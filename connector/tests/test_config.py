import pytest

from lambda_connector.config import ConfigError, Settings

GOOD = {
    "PUBLIC_URL": "https://lab.example.run.app/",
    "LAMBDA_API_KEY": "k",
    "SSH_PRIVATE_KEY": "key",
    "OAUTH_SIGNING_KEY": "s" * 40,
    "OWNER_PASSPHRASE": "p" * 20,
}


def set_env(monkeypatch, **env):
    for k in ("PUBLIC_URL", "LAMBDA_API_KEY", "SSH_PRIVATE_KEY", "OAUTH_SIGNING_KEY", "OWNER_PASSPHRASE", "MAX_EXPERIMENT_USD"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def test_defaults_and_overrides(monkeypatch):
    set_env(monkeypatch, **GOOD, MAX_EXPERIMENT_USD="250")
    s = Settings.from_env()
    assert s.public_url == "https://lab.example.run.app"
    assert s.mcp_url == "https://lab.example.run.app/mcp"
    assert s.max_experiment_usd == 250 and s.max_hours_limit == 72 and s.instance_prefix == "claude-lab-"
    # Secrets don't show up in the repr (and so not in tracebacks or logs).
    assert "s" * 40 not in repr(s) and "p" * 20 not in repr(s)


@pytest.mark.parametrize(
    "change, message",
    [
        ({"LAMBDA_API_KEY": ""}, "LAMBDA_API_KEY"),
        ({"PUBLIC_URL": "http://lab.example.com"}, "https"),
        ({"OAUTH_SIGNING_KEY": "short"}, "32"),
        ({"OWNER_PASSPHRASE": "short"}, "16"),
    ],
)
def test_rejects_bad_config(monkeypatch, change, message):
    set_env(monkeypatch, **{**GOOD, **change})
    with pytest.raises(ConfigError, match=message):
        Settings.from_env()
