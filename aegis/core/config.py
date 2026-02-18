"""AEGIS configuration — auto-discovery with YAML/JSON/env support."""

from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_MODULES = {
    "scanner": True,
    "broker": True,
    "identity": True,
    "memory": True,
    "behavior": True,
    "skills": True,
    "recovery": True,
}

_DEFAULT_SCANNER = {
    "pattern_matching": True,
    "semantic_analysis": True,
    "prompt_envelope": True,
    "outbound_sanitizer": True,
    "sensitivity": 0.5,
    "block_on_threat": False,
    "confidence_threshold": 0.7,
    "signatures": {
        "use_bundled": True,
        "additional_files": [],
        "remote_feed_enabled": False,
    },
    "llm_guard": {
        "enabled": False,
        "prompt_injection": {
            "enabled": True,
            "threshold": 0.5,
            "model": None,
        },
        "toxicity": {
            "enabled": False,
            "threshold": 0.7,
            "model": None,
        },
        "ban_topics": {
            "enabled": False,
            "topics": [],
            "threshold": 0.5,
            "model": None,
        },
    },
}

_DEFAULT_BROKER = {
    "default_posture": "deny_write",
    "budgets": {
        "max_write_tool_calls": 20,
        "max_posts_messages": 5,
        "max_external_http_writes": 10,
        "max_new_domains": 3,
    },
    "quarantine_triggers": {
        "repeated_denied_writes": 5,
        "new_domain_burst": 3,
        "tool_rate_spike_sigma": 3.0,
        "drift_score_threshold": 3.0,
    },
}

_DEFAULT_IDENTITY = {
    "attestation": {
        "enabled": True,
        "key_type": "hmac-sha256",
        "ttl_seconds": 86400,
        "auto_generate_keys": True,
    },
    "trust": {
        "establish_threshold": 50,
        "establish_age_days": 3,
        "vouch_threshold": 3,
        "trust_halflife_days": 14,
        "anomaly_penalty": 0.3,
        "persistence_path": ".aegis/trust.json",
    },
    "nkcell": {
        "enabled": True,
        "thresholds": {
            "elevated": 0.3,
            "suspicious": 0.6,
            "hostile": 0.85,
        },
    },
}

_DEFAULT_MEMORY = {
    "allowed_categories": ["fact", "state", "observation", "history_summary"],
    "blocked_categories": ["instruction", "policy", "directive", "tool_config"],
    "default_ttl_hours": 168,
    "taint_tracking": True,
    "diff_anomaly_detection": True,
}

_DEFAULT_BEHAVIOR = {
    "window_size": 100,
    "drift_threshold": 2.5,
    "min_events_for_profile": 10,
}

_DEFAULT_SKILLS = {
    "require_manifest": True,
    "require_signature": False,
    "static_analysis": True,
    "auto_approve_clean": False,
    "incubation_mode": True,
    "max_code_size": 100000,
}

_DEFAULT_RECOVERY = {
    "auto_quarantine": True,
    "quarantine_on_hostile_nk": True,
    "purge_window_hours": 24,
}

_DEFAULT_MONITORING = {
    "enabled": False,
    "service_url": "https://aegis.gaiarobotics.com/api/v1",
    "api_key": "",
    "heartbeat_interval_seconds": 60,
    "retry_max_attempts": 3,
    "retry_backoff_seconds": 5,
    "timeout_seconds": 10,
    "queue_max_size": 1000,
}

_DEFAULT_TELEMETRY = {
    "local_log": True,
    "local_log_path": ".aegis/telemetry.jsonl",
    "remote_enabled": False,
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base, returning a new dict."""
    result = deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


@dataclass
class AegisConfig:
    """AEGIS unified configuration."""

    mode: str = "observe"
    killswitch: bool = False
    agent_id: str = ""
    agent_name: str = ""
    agent_purpose: str = ""
    operator_id: str = ""
    modules: dict[str, bool] = field(default_factory=lambda: deepcopy(_DEFAULT_MODULES))
    scanner: dict[str, Any] = field(default_factory=lambda: deepcopy(_DEFAULT_SCANNER))
    broker: dict[str, Any] = field(default_factory=lambda: deepcopy(_DEFAULT_BROKER))
    identity: dict[str, Any] = field(default_factory=lambda: deepcopy(_DEFAULT_IDENTITY))
    memory: dict[str, Any] = field(default_factory=lambda: deepcopy(_DEFAULT_MEMORY))
    behavior: dict[str, Any] = field(default_factory=lambda: deepcopy(_DEFAULT_BEHAVIOR))
    skills: dict[str, Any] = field(default_factory=lambda: deepcopy(_DEFAULT_SKILLS))
    recovery: dict[str, Any] = field(default_factory=lambda: deepcopy(_DEFAULT_RECOVERY))
    monitoring: dict[str, Any] = field(default_factory=lambda: deepcopy(_DEFAULT_MONITORING))
    telemetry: dict[str, Any] = field(default_factory=lambda: deepcopy(_DEFAULT_TELEMETRY))

    def is_module_enabled(self, name: str) -> bool:
        return self.modules.get(name, False)


_KNOWN_SECTIONS = {
    "mode", "killswitch", "agent_id", "agent_name", "agent_purpose", "operator_id",
    "modules", "scanner", "broker", "identity", "memory", "behavior",
    "skills", "recovery", "monitoring", "telemetry",
}

_SECTION_DEFAULTS = {
    "scanner": _DEFAULT_SCANNER,
    "broker": _DEFAULT_BROKER,
    "identity": _DEFAULT_IDENTITY,
    "memory": _DEFAULT_MEMORY,
    "behavior": _DEFAULT_BEHAVIOR,
    "skills": _DEFAULT_SKILLS,
    "recovery": _DEFAULT_RECOVERY,
    "monitoring": _DEFAULT_MONITORING,
    "telemetry": _DEFAULT_TELEMETRY,
    "modules": _DEFAULT_MODULES,
}

# Env var overrides: AEGIS_<KEY> for top-level, AEGIS_<SECTION>_<KEY> for nested
_ENV_OVERRIDES: list[tuple[str, str, str | None, type]] = [
    ("AEGIS_MODE", "mode", None, str),
    ("AEGIS_KILLSWITCH", "killswitch", None, lambda v: v.lower() in ("1", "true", "yes")),
    ("AEGIS_SCANNER_SENSITIVITY", "scanner", "sensitivity", float),
    ("AEGIS_SCANNER_CONFIDENCE_THRESHOLD", "scanner", "confidence_threshold", float),
    ("AEGIS_BROKER_DEFAULT_POSTURE", "broker", "default_posture", str),
    ("AEGIS_BEHAVIOR_DRIFT_THRESHOLD", "behavior", "drift_threshold", float),
    ("AEGIS_BEHAVIOR_WINDOW_SIZE", "behavior", "window_size", int),
    ("AEGIS_MONITORING_ENABLED", "monitoring", "enabled", lambda v: v.lower() in ("1", "true", "yes")),
    ("AEGIS_MONITORING_SERVICE_URL", "monitoring", "service_url", str),
    ("AEGIS_MONITORING_API_KEY", "monitoring", "api_key", str),
]


def _discover_config_file(start: Path | None = None) -> Path | None:
    """Search for aegis.yaml or aegis.json from start directory up to root."""
    if start is None:
        start = Path.cwd()
    current = start.resolve()
    while True:
        for name in ("aegis.yaml", "aegis.yml", "aegis.json"):
            candidate = current / name
            if candidate.is_file():
                return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _load_file(path: Path) -> dict:
    """Load config from YAML or JSON file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(text) or {}
    elif path.suffix == ".json":
        return json.loads(text) if text.strip() else {}
    raise ValueError(f"Unsupported config format: {path.suffix}")


def _apply_env_overrides(data: dict) -> dict:
    """Apply AEGIS_* environment variable overrides."""
    for env_var, section, key, converter in _ENV_OVERRIDES:
        value = os.environ.get(env_var)
        if value is None:
            continue
        converted = converter(value)
        if key is None:
            data[section] = converted
        else:
            if section not in data:
                data[section] = {}
            data[section][key] = converted
    return data


def load_config(path: str | Path | None = None) -> AegisConfig:
    """Load AEGIS configuration.

    Discovery order:
    1. Explicit path (if provided)
    2. Auto-discover aegis.yaml / aegis.json from cwd upward
    3. Fall back to defaults

    Environment variables (AEGIS_*) override file values.
    """
    raw: dict = {}

    if path is not None:
        p = Path(path)
        if p.is_file():
            raw = _load_file(p)
    else:
        discovered = _discover_config_file()
        if discovered is not None:
            raw = _load_file(discovered)

    raw = _apply_env_overrides(raw)

    # Build config with defaults
    cfg = AegisConfig()

    # Apply top-level scalars
    if "mode" in raw:
        cfg.mode = raw["mode"]
    if "killswitch" in raw:
        cfg.killswitch = bool(raw["killswitch"])
    for scalar in ("agent_id", "agent_name", "agent_purpose", "operator_id"):
        if scalar in raw:
            setattr(cfg, scalar, raw[scalar])

    # Apply section dicts with deep merge
    for section, defaults in _SECTION_DEFAULTS.items():
        if section in raw and isinstance(raw[section], dict):
            merged = _deep_merge(defaults, raw[section])
            setattr(cfg, section, merged)

    return cfg
