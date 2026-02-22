"""AEGIS configuration — auto-discovery with YAML/JSON/env support."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Scanner sub-models
# ---------------------------------------------------------------------------

class ScannerSignaturesConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    use_bundled: bool = True
    additional_files: list[str] = Field(default_factory=list)
    remote_feed_enabled: bool = False


class LLMGuardScannerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    threshold: float = 0.5
    model: str | None = None


class BanTopicsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = False
    topics: list[str] = Field(default_factory=list)
    threshold: float = 0.5
    model: str | None = None


class LLMGuardConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = False
    prompt_injection: LLMGuardScannerConfig = Field(default_factory=LLMGuardScannerConfig)
    toxicity: LLMGuardScannerConfig = Field(
        default_factory=lambda: LLMGuardScannerConfig(enabled=False, threshold=0.7),
    )
    ban_topics: BanTopicsConfig = Field(default_factory=BanTopicsConfig)


class PiiConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = False
    entities: list[str] = Field(default_factory=lambda: [
        "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD",
        "US_SSN", "IP_ADDRESS", "IBAN_CODE",
    ])
    score_threshold: float = 0.5
    action: str = "redact"
    redact_char: str = "*"


class YaraConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    additional_rules: list[str] = Field(default_factory=list)


class ScannerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    pattern_matching: bool = True
    semantic_analysis: bool = True
    prompt_envelope: bool = True
    outbound_sanitizer: bool = True
    sensitivity: float = 0.5
    block_on_threat: bool = False
    confidence_threshold: float = 0.8
    signatures: ScannerSignaturesConfig = Field(default_factory=ScannerSignaturesConfig)
    llm_guard: LLMGuardConfig = Field(default_factory=LLMGuardConfig)
    pii: PiiConfig = Field(default_factory=PiiConfig)
    yara: YaraConfig = Field(default_factory=YaraConfig)


# ---------------------------------------------------------------------------
# Broker sub-models
# ---------------------------------------------------------------------------

class BudgetLimitsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    max_write_tool_calls: int = 20
    max_posts_messages: int = 5
    max_external_http_writes: int = 10
    max_new_domains: int = 10


class QuarantineTriggersConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    repeated_denied_writes: int = 50
    new_domain_burst: int = 10
    tool_rate_spike_sigma: float = 3.0
    drift_score_threshold: float = 3.0


class BrokerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    default_posture: str = "deny_write"
    auto_register_unknown: bool = True
    budgets: BudgetLimitsConfig = Field(default_factory=BudgetLimitsConfig)
    quarantine_triggers: QuarantineTriggersConfig = Field(
        default_factory=QuarantineTriggersConfig,
    )


# ---------------------------------------------------------------------------
# Identity sub-models
# ---------------------------------------------------------------------------

class AttestationConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    key_type: str = "hmac-sha256"
    ttl_seconds: int = 86400
    auto_generate_keys: bool = True


class TrustConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    establish_threshold: int = 50
    establish_age_days: int = 3
    vouch_threshold: int = 3
    trust_halflife_days: int = 14
    anomaly_penalty: float = 0.3
    persistence_path: str = ".aegis/trust.json"
    interaction_min_interval: float = 0.1


class NKCellThresholdsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    elevated: float = 0.3
    suspicious: float = 0.6
    hostile: float = 0.85


class NKCellConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    thresholds: NKCellThresholdsConfig = Field(default_factory=NKCellThresholdsConfig)


class ResolverConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    aliases: dict[str, str] | None = None
    auto_learn: bool = True


class IdentityConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    attestation: AttestationConfig = Field(default_factory=AttestationConfig)
    trust: TrustConfig = Field(default_factory=TrustConfig)
    nkcell: NKCellConfig = Field(default_factory=NKCellConfig)
    resolver: ResolverConfig = Field(default_factory=ResolverConfig)


# ---------------------------------------------------------------------------
# Memory sub-models
# ---------------------------------------------------------------------------

class MemoryConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    allowed_categories: list[str] = Field(
        default_factory=lambda: ["fact", "state", "observation", "history_summary"],
    )
    blocked_categories: list[str] = Field(
        default_factory=lambda: ["instruction", "policy", "directive", "tool_config"],
    )
    default_ttl_hours: int = 168
    taint_tracking: bool = True
    diff_anomaly_detection: bool = True


# ---------------------------------------------------------------------------
# Behavior sub-models
# ---------------------------------------------------------------------------

class MessageDriftConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    window_size: int = 20
    baseline_size: int = 10
    threshold: float = 2.5


class PromptMonitorConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    watch_files: list[str] = Field(default_factory=list)


class IsolationForestConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = False
    n_estimators: int = 100
    contamination: float | str = "auto"
    min_samples: int = 20


class BehaviorConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    window_size: int = 100
    drift_threshold: float = 2.5
    min_events_for_profile: int = 10
    max_tracked_agents: int = 10000
    anchor_window: int = 20
    message_drift: MessageDriftConfig = Field(default_factory=MessageDriftConfig)
    prompt_monitor: PromptMonitorConfig = Field(default_factory=PromptMonitorConfig)
    isolation_forest: IsolationForestConfig = Field(default_factory=IsolationForestConfig)


# ---------------------------------------------------------------------------
# Skills sub-models
# ---------------------------------------------------------------------------

class SkillsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    require_manifest: bool = True
    require_signature: bool = False
    static_analysis: bool = True
    auto_approve_clean: bool = False
    incubation_mode: bool = True
    max_code_size: int = 100000
    skills_base_dir: str | None = None


# ---------------------------------------------------------------------------
# Recovery sub-models
# ---------------------------------------------------------------------------

class RecoveryConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    auto_quarantine: bool = True
    quarantine_on_hostile_nk: bool = True
    purge_window_hours: int = 24
    drift_sigma_threshold: float = 3.0


# ---------------------------------------------------------------------------
# Monitoring sub-models
# ---------------------------------------------------------------------------

class MonitoringConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = False
    service_url: str = "https://aegis.gaiarobotics.com/api/v1"
    api_key: str = ""
    heartbeat_interval_seconds: float = 60
    retry_max_attempts: int = 3
    retry_backoff_seconds: float = 5
    timeout_seconds: float = 10
    queue_max_size: int = 1000


# ---------------------------------------------------------------------------
# Telemetry sub-models
# ---------------------------------------------------------------------------

class TelemetryConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    local_log: bool = True
    local_log_path: str = ".aegis/telemetry.jsonl"
    remote_enabled: bool = False


# ---------------------------------------------------------------------------
# Integrity sub-models
# ---------------------------------------------------------------------------

class IntegrityConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hash_on_load: str = "async"              # "sync" | "async" | "off"
    rehash_interval_seconds: int = 3600      # periodic full re-hash (0 = disabled)
    inotify_enabled: bool = True             # attempt inotify on Linux
    ollama_models_path: str = ""             # override; empty = auto-detect
    hf_cache_path: str = ""                  # override; empty = auto-detect
    model_file_extensions: list[str] = Field(default_factory=lambda: [
        ".safetensors", ".bin", ".pt", ".pth", ".gguf", ".ggml", ".model",
    ])


# ---------------------------------------------------------------------------
# Killswitch sub-models
# ---------------------------------------------------------------------------

class KillswitchConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    monitors: list[str] = Field(default_factory=list)   # URLs or "aegis-central"
    ttl_seconds: int = 60


# ---------------------------------------------------------------------------
# Self-Integrity sub-models
# ---------------------------------------------------------------------------

class SelfIntegrityConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    enabled: bool = True
    check_interval_seconds: float = 5
    on_tamper: str = "block"       # "exit" | "block" | "log"
    watch_package: bool = False    # Watch aegis/ source files
    watch_config: bool = True      # Watch the config file used at startup


# ---------------------------------------------------------------------------
# Modules toggle
# ---------------------------------------------------------------------------

_DEFAULT_MODULES: dict[str, bool] = {
    "scanner": True,
    "broker": True,
    "identity": True,
    "memory": True,
    "behavior": True,
    "skills": True,
    "recovery": True,
    "integrity": True,
}


# ---------------------------------------------------------------------------
# Top-level AegisConfig
# ---------------------------------------------------------------------------

class AegisConfig(BaseModel):
    """AEGIS unified configuration."""

    model_config = ConfigDict(extra="ignore")

    mode: str = "enforce"
    agent_id: str = ""
    agent_name: str = ""
    agent_purpose: str = ""
    operator_id: str = ""
    config_path: str = ""
    modules: dict[str, bool] = Field(default_factory=lambda: dict(_DEFAULT_MODULES))
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    broker: BrokerConfig = Field(default_factory=BrokerConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    behavior: BehaviorConfig = Field(default_factory=BehaviorConfig)
    skills: SkillsConfig = Field(default_factory=SkillsConfig)
    recovery: RecoveryConfig = Field(default_factory=RecoveryConfig)
    integrity: IntegrityConfig = Field(default_factory=IntegrityConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    killswitch: KillswitchConfig = Field(default_factory=KillswitchConfig)
    self_integrity: SelfIntegrityConfig = Field(default_factory=SelfIntegrityConfig)

    def is_module_enabled(self, name: str) -> bool:
        return self.modules.get(name, False)


# ---------------------------------------------------------------------------
# File discovery and loading
# ---------------------------------------------------------------------------

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


# Env var overrides: AEGIS_<KEY> for top-level, AEGIS_<SECTION>_<KEY> for nested
_ENV_OVERRIDES: list[tuple[str, str, str | None, type]] = [
    ("AEGIS_MODE", "mode", None, str),
    ("AEGIS_SCANNER_SENSITIVITY", "scanner", "sensitivity", float),
    ("AEGIS_SCANNER_CONFIDENCE_THRESHOLD", "scanner", "confidence_threshold", float),
    ("AEGIS_BROKER_DEFAULT_POSTURE", "broker", "default_posture", str),
    ("AEGIS_BEHAVIOR_DRIFT_THRESHOLD", "behavior", "drift_threshold", float),
    ("AEGIS_BEHAVIOR_WINDOW_SIZE", "behavior", "window_size", int),
    ("AEGIS_MONITORING_ENABLED", "monitoring", "enabled", lambda v: v.lower() in ("1", "true", "yes")),
    ("AEGIS_MONITORING_SERVICE_URL", "monitoring", "service_url", str),
    ("AEGIS_MONITORING_API_KEY", "monitoring", "api_key", str),
    ("AEGIS_INTEGRITY_HASH_ON_LOAD", "integrity", "hash_on_load", str),
    ("AEGIS_INTEGRITY_REHASH_INTERVAL", "integrity", "rehash_interval_seconds", int),
]


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
    resolved_path: str = ""

    if path is not None:
        p = Path(path)
        if p.is_file():
            raw = _load_file(p)
            resolved_path = str(p.resolve())
    else:
        discovered = _discover_config_file()
        if discovered is not None:
            raw = _load_file(discovered)
            resolved_path = str(discovered.resolve())

    raw = _apply_env_overrides(raw)

    config = AegisConfig.model_validate(raw)
    if resolved_path:
        config.config_path = resolved_path
    return config
