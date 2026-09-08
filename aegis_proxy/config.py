"""Proxy configuration loaded from env vars and/or CLI args."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class ProxyConfig:
    """Configuration for the AEGIS proxy server.

    Values are resolved in order: explicit argument > env var > default.
    """

    upstream_url: str = ""
    upstream_key: str = ""
    port: int = 8419
    host: str = "127.0.0.1"
    aegis_mode: str = "enforce"
    aegis_config: str = ""
    client_keys: tuple[str, ...] = field(default_factory=tuple)
    max_body_bytes: int = 1_048_576
    max_concurrent_requests: int = 32
    request_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls, **overrides: str | int) -> ProxyConfig:
        """Build config from environment variables with optional overrides."""
        cfg = cls(
            upstream_url=str(overrides.get("upstream_url", ""))
            or os.environ.get("AEGIS_PROXY_UPSTREAM_URL", ""),
            upstream_key=str(overrides.get("upstream_key", ""))
            or os.environ.get("AEGIS_PROXY_UPSTREAM_KEY", ""),
            port=int(overrides.get("port", 0)) or int(os.environ.get("AEGIS_PROXY_PORT", "8419")),
            host=str(overrides.get("host", "")) or os.environ.get("AEGIS_PROXY_HOST", "127.0.0.1"),
            aegis_mode=str(overrides.get("mode", "")) or os.environ.get("AEGIS_MODE", "enforce"),
            aegis_config=str(overrides.get("aegis_config", ""))
            or os.environ.get("AEGIS_CONFIG", ""),
            client_keys=tuple(
                key.strip()
                for key in os.environ.get("AEGIS_PROXY_CLIENT_KEYS", "").split(",")
                if key.strip()
            ),
            max_body_bytes=int(os.environ.get("AEGIS_PROXY_MAX_BODY_BYTES", "1048576")),
            max_concurrent_requests=int(
                os.environ.get("AEGIS_PROXY_MAX_CONCURRENT_REQUESTS", "32")
            ),
            request_timeout_seconds=float(
                os.environ.get("AEGIS_PROXY_REQUEST_TIMEOUT_SECONDS", "30")
            ),
        )
        return cfg
