"""Configuration for the AEGIS monitor service."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class MonitorConfig:
    """Monitor service configuration."""

    host: str = "0.0.0.0"
    port: int = 8080
    database_path: str = "monitor.db"
    database_url: str = ""  # postgresql:// URL — takes priority over database_path
    api_keys: list[str] = field(default_factory=list)
    agent_public_keys: dict[str, bytes] = field(default_factory=dict)
    clustering_enabled: bool = False
    r0_window_hours: int = 24
    compromise_rate_limit: int = 5
    compromise_rate_window: int = 3600
    compromise_min_trust_tier: int = 1
    compromise_quorum: int = 2
    compromise_hash_max_distance: int = 96

    @property
    def effective_database_url(self) -> str:
        """Return ``database_url`` if set, otherwise ``database_path``."""
        return self.database_url or self.database_path

    @classmethod
    def load(cls, path: str | Path | None = None) -> "MonitorConfig":
        """Load configuration from YAML file and/or environment variables.

        Discovery order:
        1. Explicit path
        2. ``monitor.yaml`` in cwd
        3. Environment variables (``MONITOR_*``)
        4. Defaults
        """
        raw: dict[str, Any] = {}
        if path is not None:
            p = Path(path)
            if p.is_file():
                raw = yaml.safe_load(p.read_text()) or {}
        else:
            candidate = Path("monitor.yaml")
            if candidate.is_file():
                raw = yaml.safe_load(candidate.read_text()) or {}

        cfg = cls(
            host=raw.get("host", "0.0.0.0"),
            port=int(raw.get("port", 8080)),
            database_path=raw.get("database_path", "monitor.db"),
            database_url=raw.get("database_url", ""),
            api_keys=raw.get("api_keys", []),
            clustering_enabled=bool(raw.get("clustering_enabled", False)),
            r0_window_hours=int(raw.get("r0_window_hours", 24)),
            compromise_rate_limit=int(raw.get("compromise_rate_limit", 5)),
            compromise_rate_window=int(raw.get("compromise_rate_window", 3600)),
            compromise_min_trust_tier=int(raw.get("compromise_min_trust_tier", 1)),
            compromise_quorum=int(raw.get("compromise_quorum", 2)),
            compromise_hash_max_distance=int(raw.get("compromise_hash_max_distance", 96)),
        )

        # Environment overrides
        if v := os.environ.get("MONITOR_HOST"):
            cfg.host = v
        if v := os.environ.get("MONITOR_PORT"):
            cfg.port = int(v)
        if v := os.environ.get("MONITOR_DATABASE_PATH"):
            cfg.database_path = v
        if v := os.environ.get("MONITOR_DATABASE_URL"):
            cfg.database_url = v
        if v := os.environ.get("MONITOR_API_KEYS"):
            cfg.api_keys = [k.strip() for k in v.split(",") if k.strip()]
        if v := os.environ.get("MONITOR_CLUSTERING_ENABLED"):
            cfg.clustering_enabled = v.lower() in ("1", "true", "yes")
        if v := os.environ.get("MONITOR_R0_WINDOW_HOURS"):
            cfg.r0_window_hours = int(v)
        if v := os.environ.get("MONITOR_COMPROMISE_RATE_LIMIT"):
            cfg.compromise_rate_limit = int(v)
        if v := os.environ.get("MONITOR_COMPROMISE_RATE_WINDOW"):
            cfg.compromise_rate_window = int(v)
        if v := os.environ.get("MONITOR_COMPROMISE_MIN_TRUST_TIER"):
            cfg.compromise_min_trust_tier = int(v)
        if v := os.environ.get("MONITOR_COMPROMISE_QUORUM"):
            cfg.compromise_quorum = int(v)
        if v := os.environ.get("MONITOR_COMPROMISE_HASH_MAX_DISTANCE"):
            cfg.compromise_hash_max_distance = int(v)

        return cfg
