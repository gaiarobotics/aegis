"""AEGIS Shield — unified orchestrator composing all modules into a pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from aegis.core import killswitch
from aegis.core.config import AegisConfig, load_config
from aegis.core.telemetry import TelemetryLogger


@dataclass
class ScanResult:
    """Result from shield.scan_input()."""

    threat_score: float = 0.0
    is_threat: bool = False
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionResult:
    """Result from shield.evaluate_action()."""

    allowed: bool = True
    decision: str = "allow"
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SanitizeResult:
    """Result from shield.sanitize_output()."""

    cleaned_text: str = ""
    modifications: list[str] = field(default_factory=list)


class ThreatBlockedError(Exception):
    """Raised when enforce mode blocks a detected threat.

    Attributes:
        scan_result: The ScanResult that triggered the block.
    """

    def __init__(self, scan_result: ScanResult, message: str = ""):
        self.scan_result = scan_result
        super().__init__(message or f"Threat blocked (score={scan_result.threat_score})")


class Shield:
    """Unified AEGIS orchestrator.

    Composes modules into a detection-and-response pipeline:
    1. Scanner — detect threats in input
    2. Identity — assess trust and NK cell verdict
    3. Broker — enforce action policies
    4. Behavior — track and detect drift
    5. Recovery — quarantine/rollback on anomalies

    Args:
        policy: Path to config file, or None for auto-discovery.
        modules: List of module names to enable, or None for config defaults.
        mode: "observe" (log only) or "enforce" (block threats).
        config: Pre-built AegisConfig (overrides policy if provided).
    """

    def __init__(
        self,
        policy: str | None = None,
        modules: list[str] | None = None,
        mode: str | None = None,
        config: AegisConfig | None = None,
    ) -> None:
        if config is not None:
            self._config = config
        elif policy is not None:
            self._config = load_config(policy)
        else:
            self._config = load_config()

        if mode is not None:
            self._config.mode = mode

        if modules is not None:
            for mod in list(self._config.modules.keys()):
                self._config.modules[mod] = mod in modules

        self._mode = self._config.mode
        self._telemetry = TelemetryLogger(
            log_path=self._config.telemetry.get("local_log_path", ".aegis/telemetry.jsonl"),
        )

        # Instantiate modules based on config
        self._scanner = None
        self._broker = None
        self._trust_manager = None
        self._nk_cell = None
        self._behavior_tracker = None
        self._drift_detector = None
        self._memory_guard = None
        self._recovery_quarantine = None
        self._context_rollback = None
        self._monitoring_client = None
        self._identity_resolver = None

        self._init_modules()
        self._init_monitoring()

    def _init_modules(self) -> None:
        """Instantiate enabled modules with graceful degradation."""
        if self._config.is_module_enabled("scanner"):
            try:
                from aegis.scanner import Scanner
                self._scanner = Scanner(config=self._config)
            except Exception:
                pass

        if self._config.is_module_enabled("broker"):
            try:
                from aegis.broker import Broker
                self._broker = Broker(config=self._config)
            except Exception:
                pass

        if self._config.is_module_enabled("identity"):
            try:
                from aegis.identity import NKCell, TrustManager
                from aegis.identity.resolver import IdentityResolver
                self._trust_manager = TrustManager(config=self._config.identity.get("trust"))
                self._nk_cell = NKCell(config=self._config.identity.get("nkcell"))
                resolver_cfg = self._config.identity.get("resolver", {})
                self._identity_resolver = IdentityResolver(
                    aliases=resolver_cfg.get("aliases"),
                    auto_learn=resolver_cfg.get("auto_learn", True),
                )
            except Exception:
                pass

        if self._config.is_module_enabled("behavior"):
            try:
                from aegis.behavior import BehaviorTracker, DriftDetector
                self._behavior_tracker = BehaviorTracker(config=self._config.behavior)
                self._drift_detector = DriftDetector(config=self._config.behavior)
            except Exception:
                pass

        if self._config.is_module_enabled("memory"):
            try:
                from aegis.memory import MemoryGuard
                self._memory_guard = MemoryGuard(config=self._config.memory, scanner=self._scanner)
            except Exception:
                pass

        if self._config.is_module_enabled("recovery"):
            try:
                from aegis.recovery import ContextRollback, RecoveryQuarantine
                self._recovery_quarantine = RecoveryQuarantine(config=self._config.recovery)
                self._context_rollback = ContextRollback()
            except Exception:
                pass

    def _init_monitoring(self) -> None:
        """Initialize monitoring client if enabled."""
        mon_cfg = self._config.monitoring
        if not mon_cfg.get("enabled", False):
            return
        try:
            from aegis.monitoring.client import MonitoringClient
            from aegis.identity.attestation import generate_keypair

            key_type = self._config.identity.get("attestation", {}).get(
                "key_type", "hmac-sha256"
            )
            keypair = generate_keypair(key_type)

            self._monitoring_client = MonitoringClient(
                config=mon_cfg,
                agent_id=self._config.agent_id,
                operator_id=self._config.operator_id,
                keypair=keypair,
            )

            # Wire compromise callback
            if self._trust_manager is not None:
                self._trust_manager.set_compromise_callback(
                    self._on_compromise_reported
                )

            self._monitoring_client.start()
        except Exception:
            self._monitoring_client = None

    def _on_compromise_reported(self, agent_id: str) -> None:
        """Callback from TrustManager.report_compromise()."""
        if self._monitoring_client is None:
            return
        try:
            nk_info = {}
            if self._nk_cell is not None:
                nk_info = {"nk_score": 1.0, "nk_verdict": "hostile"}
            self._monitoring_client.send_compromise_report(
                compromised_agent_id=agent_id,
                source="trust_manager",
                nk_score=nk_info.get("nk_score", 0.0),
                nk_verdict=nk_info.get("nk_verdict", ""),
            )
        except Exception:
            pass

    @property
    def config(self) -> AegisConfig:
        """Access the active configuration."""
        return self._config

    @property
    def mode(self) -> str:
        """Current mode: 'observe' or 'enforce'."""
        return self._mode

    @property
    def scanner(self):
        """Access the scanner module (may be None)."""
        return self._scanner

    @property
    def broker(self):
        """Access the broker module (may be None)."""
        return self._broker

    def scan_input(self, text: str) -> ScanResult:
        """Scan input text through the pipeline.

        Pipeline:
        1. Scanner detects threats
        2. Identity (NK cell) assesses context if available
        3. Behavior tracker records event
        4. Recovery auto-quarantine if thresholds exceeded

        Returns clean result when killswitch is active.
        """
        if killswitch.is_active():
            return ScanResult()

        result = ScanResult()

        # Step 1: Scanner
        if self._scanner is not None:
            scan_result = self._scanner.scan_input(text)
            result.threat_score = scan_result.threat_score
            result.is_threat = scan_result.is_threat
            result.details["scanner"] = {
                "matches": len(scan_result.matches),
                "threat_score": scan_result.threat_score,
                "is_threat": scan_result.is_threat,
            }

        # Step 2: Identity / NK cell assessment
        if self._nk_cell is not None:
            try:
                from aegis.identity import AgentContext
                context = AgentContext(
                    agent_id="self",
                    has_attestation=False,
                    attestation_valid=False,
                    attestation_expired=False,
                    capabilities_within_scope=True,
                    drift_sigma=0.0,
                    clean_interaction_ratio=1.0,
                    scanner_threat_score=result.threat_score,
                    communication_count=0,
                    purpose_hash_changed=False,
                )
                verdict = self._nk_cell.assess(context)
                result.details["nk_cell"] = {
                    "score": verdict.score,
                    "verdict": verdict.verdict,
                }
                # If NK cell flags as hostile, escalate threat
                if verdict.verdict == "hostile":
                    result.is_threat = True
            except Exception:
                pass

        # Step 3: Recovery auto-quarantine check
        if self._recovery_quarantine is not None and result.is_threat:
            nk_verdict = result.details.get("nk_cell")
            if nk_verdict:
                try:
                    from aegis.identity import NKVerdict
                    verdict_obj = NKVerdict(
                        score=nk_verdict["score"],
                        verdict=nk_verdict["verdict"],
                        recommended_action="quarantine" if nk_verdict["verdict"] == "hostile" else "none",
                    )
                    self._recovery_quarantine.auto_quarantine(nk_verdict=verdict_obj)
                except Exception:
                    pass

        # Monitoring reporting
        if self._monitoring_client is not None:
            try:
                if result.is_threat:
                    scanner_info = result.details.get("scanner", {})
                    nk_info = result.details.get("nk_cell", {})
                    self._monitoring_client.send_threat_event(
                        threat_score=result.threat_score,
                        is_threat=True,
                        scanner_match_count=scanner_info.get("matches", 0),
                        nk_score=nk_info.get("score", 0.0),
                        nk_verdict=nk_info.get("verdict", ""),
                    )
                    # If NK cell flagged hostile, also send compromise report
                    nk_verdict = result.details.get("nk_cell", {}).get("verdict", "")
                    if nk_verdict == "hostile":
                        self._monitoring_client.send_compromise_report(
                            compromised_agent_id=self._config.agent_id,
                            source="nk_cell",
                            nk_score=nk_info.get("score", 0.0),
                            nk_verdict=nk_verdict,
                        )
            except Exception:
                pass

        # Log telemetry
        self._telemetry.log_event(
            "scan_input",
            threat_score=result.threat_score,
            is_threat=result.is_threat,
            mode=self._mode,
        )

        return result

    def evaluate_action(self, action_request) -> ActionResult:
        """Evaluate an action request through the broker.

        Returns allow-all result when killswitch is active or broker absent.
        In observe mode, threats are logged but not blocked.
        """
        if killswitch.is_active():
            return ActionResult(allowed=True, decision="allow", reason="killswitch active")

        if self._broker is None:
            return ActionResult(allowed=True, decision="allow", reason="no broker configured")

        # Get trust tier if identity module available
        trust_tier = None
        if self._trust_manager is not None:
            try:
                trust_tier = self._trust_manager.get_tier(
                    getattr(action_request, "source_provenance", None) or "unknown"
                )
            except Exception:
                pass

        response = self._broker.evaluate(action_request, trust_tier=trust_tier)

        allowed = response.decision.value == "allow"
        decision = response.decision.value
        reason = response.reason

        # In observe mode, log but don't block
        if self._mode == "observe" and not allowed:
            self._telemetry.log_event(
                "action_would_block",
                decision=decision,
                reason=reason,
                target=getattr(action_request, "target", "unknown"),
            )
            return ActionResult(
                allowed=True,
                decision="observe_deny",
                reason=f"[observe mode] {reason}",
                details={"original_decision": decision},
            )

        # In enforce mode, respect the decision
        self._telemetry.log_event(
            "action_decision",
            decision=decision,
            reason=reason,
            target=getattr(action_request, "target", "unknown"),
        )

        return ActionResult(
            allowed=allowed,
            decision=decision,
            reason=reason,
        )

    def sanitize_output(self, text: str) -> SanitizeResult:
        """Sanitize model output through the scanner.

        Returns text unchanged when killswitch is active or scanner absent.
        """
        if killswitch.is_active():
            return SanitizeResult(cleaned_text=text)

        if self._scanner is None:
            return SanitizeResult(cleaned_text=text)

        result = self._scanner.sanitize_output(text)
        return SanitizeResult(
            cleaned_text=result.cleaned_text,
            modifications=result.modifications,
        )

    def resolve_agent_id(self, raw_id: str) -> str:
        """Resolve a raw agent identifier to its canonical form.

        Returns the raw ID unchanged if no resolver is configured.
        """
        if self._identity_resolver is None:
            return raw_id
        return self._identity_resolver.resolve(raw_id)

    def record_trust_interaction(
        self,
        agent_id: str,
        clean: bool = True,
        anomaly: bool = False,
    ) -> None:
        """Record a trust interaction for an agent.

        Resolves the agent_id to a canonical form before recording.
        No-op when identity module is disabled or killswitch is active.
        """
        if killswitch.is_active():
            return
        if self._trust_manager is None:
            return
        canonical = self.resolve_agent_id(agent_id)
        self._trust_manager.record_interaction(canonical, clean=clean, anomaly=anomaly)

    def wrap_messages(
        self,
        messages: list[dict[str, Any]],
        provenance_map: dict | None = None,
    ) -> list[dict[str, Any]]:
        """Wrap messages with provenance tags via the scanner envelope.

        Returns messages unchanged when killswitch is active or scanner absent.
        """
        if killswitch.is_active():
            return messages

        if self._scanner is None:
            return messages

        return self._scanner.wrap_messages(messages, provenance_map=provenance_map)

    def wrap(self, client: Any, tools: list | None = None) -> Any:
        """Wrap an LLM client with AEGIS protection.

        Returns a wrapped client that intercepts API calls for scanning,
        action brokering, and output sanitization.
        """
        from aegis.providers.base import BaseWrapper
        wrapper = BaseWrapper(shield=self)
        return wrapper.wrap(client, tools=tools)
