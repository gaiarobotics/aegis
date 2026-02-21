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
    host: str = "0.0.0.0"
    aegis_mode: str = "enforce"
    aegis_config: str = ""

    @classmethod
    def from_env(cls, **overrides: str | int) -> ProxyConfig:
        """Build config from environment variables with optional overrides."""
        cfg = cls(
            upstream_url=str(overrides.get("upstream_url", ""))
            or os.environ.get("AEGIS_PROXY_UPSTREAM_URL", ""),
            upstream_key=str(overrides.get("upstream_key", ""))
            or os.environ.get("AEGIS_PROXY_UPSTREAM_KEY", ""),
            port=int(overrides.get("port", 0))
            or int(os.environ.get("AEGIS_PROXY_PORT", "8419")),
            host=str(overrides.get("host", ""))
            or os.environ.get("AEGIS_PROXY_HOST", "0.0.0.0"),
            aegis_mode=str(overrides.get("mode", ""))
            or os.environ.get("AEGIS_MODE", "enforce"),
            aegis_config=str(overrides.get("aegis_config", ""))
            or os.environ.get("AEGIS_CONFIG", ""),
        )
        return cfg
