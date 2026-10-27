"""Settings read from the environment.

Secrets (Lambda API key, SSH private key, token signing key, owner passphrase)
arrive as environment variables that Cloud Run fills from Secret Manager. They
are never logged and never returned by any tool.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class ConfigError(RuntimeError):
    pass


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"Missing required environment variable {name}")
    return value


@dataclass(frozen=True)
class Settings:
    public_url: str
    lambda_api_key: str = field(repr=False)
    ssh_private_key: str = field(repr=False)
    oauth_signing_key: str = field(repr=False)
    owner_passphrase: str = field(repr=False)
    state_bucket: str | None
    lambda_api_base: str = "https://cloud.lambda.ai/api/v1"
    max_experiment_usd: float = 500.0
    max_hours_limit: float = 72.0
    max_concurrent_instances: int = 3
    instance_prefix: str = "claude-lab-"
    ssh_key_name: str = "claude-lab-connector"
    ssh_user: str = "ubuntu"
    reaper_interval_minutes: int = 10
    reaper_service_account: str | None = None
    allow_loopback_redirects: bool = True

    @property
    def mcp_url(self) -> str:
        return self.public_url + "/mcp"

    @property
    def reaper_url(self) -> str:
        return self.public_url + "/tasks/reap"

    @classmethod
    def from_env(cls) -> "Settings":
        public_url = _required("PUBLIC_URL").rstrip("/")
        if not public_url.startswith("https://") and not public_url.startswith("http://localhost"):
            raise ConfigError("PUBLIC_URL must be the https:// address of the service")
        signing_key = _required("OAUTH_SIGNING_KEY")
        if len(signing_key) < 32:
            raise ConfigError("OAUTH_SIGNING_KEY must be at least 32 characters")
        passphrase = _required("OWNER_PASSPHRASE")
        if len(passphrase) < 16:
            raise ConfigError("OWNER_PASSPHRASE must be at least 16 characters")
        return cls(
            public_url=public_url,
            lambda_api_key=_required("LAMBDA_API_KEY"),
            ssh_private_key=_required("SSH_PRIVATE_KEY"),
            oauth_signing_key=signing_key,
            owner_passphrase=passphrase,
            state_bucket=os.environ.get("STATE_BUCKET") or None,
            lambda_api_base=os.environ.get("LAMBDA_API_BASE", cls.lambda_api_base).rstrip("/"),
            max_experiment_usd=float(os.environ.get("MAX_EXPERIMENT_USD", cls.max_experiment_usd)),
            max_hours_limit=float(os.environ.get("MAX_HOURS_LIMIT", cls.max_hours_limit)),
            max_concurrent_instances=int(os.environ.get("MAX_CONCURRENT_INSTANCES", cls.max_concurrent_instances)),
            instance_prefix=os.environ.get("INSTANCE_PREFIX", cls.instance_prefix),
            ssh_key_name=os.environ.get("SSH_KEY_NAME", cls.ssh_key_name),
            ssh_user=os.environ.get("SSH_USER", cls.ssh_user),
            reaper_interval_minutes=int(os.environ.get("REAPER_INTERVAL_MINUTES", cls.reaper_interval_minutes)),
            reaper_service_account=os.environ.get("REAPER_SERVICE_ACCOUNT") or None,
            allow_loopback_redirects=os.environ.get("ALLOW_LOOPBACK_REDIRECTS", "true").lower() == "true",
        )
