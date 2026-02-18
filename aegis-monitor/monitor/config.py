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
    api_keys: list[str] = field(default_factory=list)
    agent_public_keys: dict[str, bytes] = field(default_factory=dict)
    clustering_enabled: bool = False
    r0_window_hours: int = 24

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
            api_keys=raw.get("api_keys", []),
            clustering_enabled=bool(raw.get("clustering_enabled", False)),
            r0_window_hours=int(raw.get("r0_window_hours", 24)),
        )

        # Environment overrides
        if v := os.environ.get("MONITOR_HOST"):
            cfg.host = v
        if v := os.environ.get("MONITOR_PORT"):
            cfg.port = int(v)
        if v := os.environ.get("MONITOR_DATABASE_PATH"):
            cfg.database_path = v
        if v := os.environ.get("MONITOR_API_KEYS"):
            cfg.api_keys = [k.strip() for k in v.split(",") if k.strip()]
        if v := os.environ.get("MONITOR_CLUSTERING_ENABLED"):
            cfg.clustering_enabled = v.lower() in ("1", "true", "yes")
        if v := os.environ.get("MONITOR_R0_WINDOW_HOURS"):
            cfg.r0_window_hours = int(v)

        return cfg
