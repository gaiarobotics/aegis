"""Configuration for the AEGIS monitor service."""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class AgentKey:
    """Public key for agent report signature verification."""
    key_type: str   # "hmac-sha256" or "ed25519"
    key_bytes: bytes


_KEY_TYPE_MAP = {"hmac": "hmac-sha256", "ed25519": "ed25519"}


@dataclass
class ClusteringConfig:
    """Clio-inspired clustering and summarization configuration."""

    cluster_summarizer: str = "template"  # "template", "keybert", or "llm"
    llm_endpoint: str = ""  # Ollama/vLLM endpoint for LLM summarizer
    llm_model: str = ""  # Model name for LLM summarizer
    min_events_per_cluster: int = 3  # Privacy: min events to surface a cluster
    min_agents_per_cluster: int = 2  # Privacy: min unique agents per cluster
    redact_agent_ids_below: int = 5  # Privacy: redact IDs in small clusters
    coordination_enabled: bool = True
    coordination_min_agents: int = 3
    coordination_drift_window_seconds: float = 300.0
    coordination_drift_threshold: float = 0.5
    distribution_enabled: bool = True
    distribution_window_minutes: int = 60
    distribution_shift_threshold: float = 0.3


@dataclass
class MonitorConfig:
    """Monitor service configuration."""

    host: str = "0.0.0.0"
    port: int = 8080
    database_path: str = "monitor.db"
    database_url: str = ""  # postgresql:// URL — takes priority over database_path
    api_keys: dict[str, str] = field(default_factory=dict)
    session_secret: str = ""
    session_ttl_seconds: int = 28800
    agent_public_keys: dict[str, AgentKey] = field(default_factory=dict)
    clustering_enabled: bool = False
    clio: ClusteringConfig = field(default_factory=ClusteringConfig)
    r0_window_hours: int = 24
    compromise_rate_limit: int = 5
    compromise_rate_window: int = 3600
    compromise_min_trust_tier: int = 1
    compromise_quorum: int = 2

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

        raw_pubkeys = raw.get("agent_public_keys", {})
        parsed_pubkeys: dict[str, AgentKey] = {}
        if isinstance(raw_pubkeys, dict):
            for agent_id, key_str in raw_pubkeys.items():
                parsed_pubkeys[agent_id] = cls._parse_agent_key(key_str)

        # Parse Clio clustering config
        raw_clio = raw.get("clio", {})
        if not isinstance(raw_clio, dict):
            raw_clio = {}
        clio_cfg = ClusteringConfig(
            cluster_summarizer=str(raw_clio.get("cluster_summarizer", "template")),
            llm_endpoint=str(raw_clio.get("llm_endpoint", "")),
            llm_model=str(raw_clio.get("llm_model", "")),
            min_events_per_cluster=int(raw_clio.get("min_events_per_cluster", 3)),
            min_agents_per_cluster=int(raw_clio.get("min_agents_per_cluster", 2)),
            redact_agent_ids_below=int(raw_clio.get("redact_agent_ids_below", 5)),
            coordination_enabled=bool(raw_clio.get("coordination_enabled", True)),
            coordination_min_agents=int(raw_clio.get("coordination_min_agents", 3)),
            coordination_drift_window_seconds=float(raw_clio.get("coordination_drift_window_seconds", 300.0)),
            coordination_drift_threshold=float(raw_clio.get("coordination_drift_threshold", 0.5)),
            distribution_enabled=bool(raw_clio.get("distribution_enabled", True)),
            distribution_window_minutes=int(raw_clio.get("distribution_window_minutes", 60)),
            distribution_shift_threshold=float(raw_clio.get("distribution_shift_threshold", 0.3)),
        )

        cfg = cls(
            host=raw.get("host", "0.0.0.0"),
            port=int(raw.get("port", 8080)),
            database_path=raw.get("database_path", "monitor.db"),
            database_url=raw.get("database_url", ""),
            api_keys=cls._parse_api_keys(raw.get("api_keys")),
            session_secret=raw.get("session_secret", ""),
            session_ttl_seconds=int(raw.get("session_ttl_seconds", 28800)),
            agent_public_keys=parsed_pubkeys,
            clustering_enabled=bool(raw.get("clustering_enabled", False)),
            clio=clio_cfg,
            r0_window_hours=int(raw.get("r0_window_hours", 24)),
            compromise_rate_limit=int(raw.get("compromise_rate_limit", 5)),
            compromise_rate_window=int(raw.get("compromise_rate_window", 3600)),
            compromise_min_trust_tier=int(raw.get("compromise_min_trust_tier", 1)),
            compromise_quorum=int(raw.get("compromise_quorum", 2)),
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
            cfg.api_keys = cls._parse_env_api_keys(v)
        if v := os.environ.get("MONITOR_SESSION_SECRET"):
            cfg.session_secret = v
        if v := os.environ.get("MONITOR_SESSION_TTL_SECONDS"):
            cfg.session_ttl_seconds = int(v)
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
        if v := os.environ.get("MONITOR_AGENT_PUBLIC_KEYS"):
            parsed: dict[str, AgentKey] = {}
            for entry in v.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split(":")
                if len(parts) != 3:
                    raise ValueError(
                        f"MONITOR_AGENT_PUBLIC_KEYS entry '{entry}' has invalid format. "
                        "Expected exactly: agent_id:type:hexbytes (3 colon-separated parts). "
                        "Agent IDs must not contain colons."
                    )
                agent_id, type_prefix, hex_bytes = parts
                key = cls._parse_agent_key(f"{type_prefix}:{hex_bytes}")
                parsed[agent_id] = key
            cfg.agent_public_keys = parsed

        return cfg

    @staticmethod
    def _parse_agent_key(value: str) -> "AgentKey":
        """Parse a prefixed key string like ``hmac:aabb...`` into an AgentKey."""
        if ":" not in value:
            raise ValueError(f"Agent key must have type prefix (hmac: or ed25519:), got: {value!r}")
        prefix, hex_bytes = value.split(":", 1)
        key_type = _KEY_TYPE_MAP.get(prefix)
        if key_type is None:
            raise ValueError(f"Unsupported key type prefix: {prefix!r}. Use 'hmac' or 'ed25519'.")
        return AgentKey(key_type=key_type, key_bytes=bytes.fromhex(hex_bytes))

    @staticmethod
    def _parse_api_keys(raw_value: Any) -> dict[str, str]:
        """Parse api_keys from YAML value into a dict mapping key -> role."""
        if raw_value is None:
            return {}
        if isinstance(raw_value, dict):
            return {str(k): str(v) for k, v in raw_value.items()}
        if isinstance(raw_value, list):
            warnings.warn(
                "api_keys as a list is deprecated; use a dict mapping key -> role",
                DeprecationWarning,
                stacklevel=3,
            )
            return {str(k): "operator" for k in raw_value}
        return {}

    @staticmethod
    def _parse_env_api_keys(value: str) -> dict[str, str]:
        """Parse MONITOR_API_KEYS env var into a dict mapping key -> role.

        Supports ``key:role,key:role`` format.  Bare keys (no colon) are
        treated as ``operator`` with a deprecation warning.
        """
        result: dict[str, str] = {}
        has_bare = False
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if ":" in entry:
                key, role = entry.split(":", 1)
                result[key.strip()] = role.strip()
            else:
                result[entry] = "operator"
                has_bare = True
        if has_bare:
            warnings.warn(
                "MONITOR_API_KEYS entries without roles are deprecated; use key:role format",
                DeprecationWarning,
                stacklevel=2,
            )
        return result
