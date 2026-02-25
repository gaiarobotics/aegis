"""AEGIS Shield — unified orchestrator composing all modules into a pipeline."""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from aegis.core.config import AegisConfig, load_config
from aegis.core.telemetry import TelemetryLogger

logger = logging.getLogger(__name__)


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


class InferenceBlockedError(Exception):
    """Raised when a remote killswitch blocks inference.

    Attributes:
        reason: Human-readable reason from the blocking monitor.
    """

    def __init__(self, reason: str = ""):
        self.reason = reason
        super().__init__(reason or "Inference blocked by remote killswitch")


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
            log_path=self._config.telemetry.local_log_path,
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
        self._message_drift_detector = None
        self._prompt_monitor = None
        self._isolation_forest = None
        self._content_hash_tracker = None
        self._integrity_monitor = None
        self._killswitch = None
        self._self_integrity = None
        self._self_integrity_blocked = False

        self._init_modules()
        self._init_monitoring()
        self._init_killswitch()
        self._init_self_integrity()

    def _init_modules(self) -> None:
        """Instantiate enabled modules with graceful degradation."""
        if self._config.is_module_enabled("scanner"):
            try:
                from aegis.scanner import Scanner
                self._scanner = Scanner(config=self._config)
            except Exception:
                logger.debug("Scanner module init failed", exc_info=True)

        if self._config.is_module_enabled("broker"):
            try:
                from aegis.broker import Broker
                self._broker = Broker(config=self._config)
            except Exception:
                logger.debug("Broker module init failed", exc_info=True)

        if self._config.is_module_enabled("identity"):
            try:
                from aegis.identity import NKCell, TrustManager
                from aegis.identity.resolver import IdentityResolver
                self._trust_manager = TrustManager(config=self._config.identity.trust)
                self._nk_cell = NKCell(config=self._config.identity.nkcell)
                self._identity_resolver = IdentityResolver(
                    aliases=self._config.identity.resolver.aliases,
                    auto_learn=self._config.identity.resolver.auto_learn,
                )
            except Exception:
                logger.debug("Identity module init failed", exc_info=True)

        if self._config.is_module_enabled("behavior"):
            try:
                from aegis.behavior import BehaviorTracker, DriftDetector
                self._behavior_tracker = BehaviorTracker(config=self._config.behavior)
                self._drift_detector = DriftDetector(config=self._config.behavior)
                try:
                    from aegis.behavior.message_drift import MessageDriftDetector
                    msg_drift_cfg = self._config.behavior.message_drift
                    self._message_drift_detector = MessageDriftDetector(config=msg_drift_cfg)
                except Exception:
                    logger.debug("Message drift detector init failed", exc_info=True)
                try:
                    from aegis.behavior.prompt_monitor import PromptMonitor
                    prompt_mon_cfg = self._config.behavior.prompt_monitor
                    self._prompt_monitor = PromptMonitor(config=prompt_mon_cfg)
                except Exception:
                    logger.debug("Prompt monitor init failed", exc_info=True)
                # IsolationForest anomaly detection (optional sklearn-based)
                try:
                    iso_cfg = self._config.behavior.isolation_forest
                    if iso_cfg.enabled:
                        from aegis.behavior.isolation_forest import (
                            IsolationForestDetector,
                        )
                        self._isolation_forest = IsolationForestDetector(
                            config=iso_cfg,
                        )
                except Exception:
                    logger.debug("IsolationForest init failed", exc_info=True)
                # Content hash tracker (LSH fingerprinting)
                try:
                    from aegis.behavior.content_hash import ContentHashTracker
                    ch_cfg = self._config.behavior.content_hash
                    if ch_cfg.enabled:
                        self._content_hash_tracker = ContentHashTracker(
                            window_size=ch_cfg.window_size,
                            semantic_enabled=ch_cfg.semantic_enabled,
                        )
                except Exception:
                    logger.debug("Content hash tracker init failed", exc_info=True)
            except Exception:
                logger.debug("Behavior module init failed", exc_info=True)

        if self._config.is_module_enabled("memory"):
            try:
                from aegis.memory import MemoryGuard
                self._memory_guard = MemoryGuard(config=self._config.memory, scanner=self._scanner)
            except Exception:
                logger.debug("Memory module init failed", exc_info=True)

        if self._config.is_module_enabled("recovery"):
            try:
                from aegis.recovery import ContextRollback, RecoveryQuarantine
                self._recovery_quarantine = RecoveryQuarantine(config=self._config.recovery)
                self._context_rollback = ContextRollback()
            except Exception:
                logger.debug("Recovery module init failed", exc_info=True)

        if self._config.is_module_enabled("integrity"):
            try:
                from aegis.integrity.monitor import IntegrityMonitor
                self._integrity_monitor = IntegrityMonitor(
                    config=self._config.integrity,
                )
            except Exception:
                logger.debug("Integrity module init failed", exc_info=True)

    @property
    def integrity_monitor(self):
        """Access the integrity monitor module (may be None)."""
        return self._integrity_monitor

    def check_model_integrity(
        self,
        model_name: str,
        provider: str,
        *,
        model_path: str | None = None,
    ) -> None:
        """Check model file integrity, registering the model on first call.

        In enforce mode, raises ModelTamperedError if tampering detected.
        In observe mode, logs the tampering but allows inference to proceed.

        No-op when integrity module is disabled.
        """
        if self._integrity_monitor is None:
            return

        # Auto-register on first call for this model
        if not self._integrity_monitor.is_registered(model_name):
            self._integrity_monitor.register_model(
                model_name, provider, model_path=model_path,
            )

        # Fast stat check
        issues = self._integrity_monitor.check_integrity(model_name)
        if not issues:
            return

        # Tampering detected
        from aegis.integrity.monitor import ModelTamperedError

        detail = "; ".join(issues)
        first_file = issues[0].split(": ", 1)[-1] if issues else "unknown"

        self._telemetry.log_event(
            "model_integrity",
            model_name=model_name,
            provider=provider,
            tampering_detected=True,
            issues=issues,
            mode=self._mode,
        )

        if self._mode == "enforce":
            raise ModelTamperedError(
                model_name=model_name,
                file_path=first_file,
                detail=detail,
            )
        else:
            logger.warning(
                "Model tampering detected (observe mode): %s -- %s",
                model_name, detail,
            )

    def _init_monitoring(self) -> None:
        """Initialize monitoring client if enabled."""
        mon_cfg = self._config.monitoring
        if not mon_cfg.enabled:
            return
        try:
            from aegis.monitoring.client import MonitoringClient
            from aegis.identity.attestation import generate_keypair

            key_type = self._config.identity.attestation.key_type
            keypair = generate_keypair(key_type)

            self._monitoring_client = MonitoringClient(
                config=mon_cfg,
                agent_id=self._config.agent_id,
                operator_id=self._config.operator_id,
                keypair=keypair,
                content_hash_provider=self._get_content_hashes,
            )

            # Wire compromise callback
            if self._trust_manager is not None:
                self._trust_manager.set_compromise_callback(
                    self._on_compromise_reported
                )

            self._monitoring_client.start()
        except Exception:
            logger.debug("Monitoring client init failed", exc_info=True)
            self._monitoring_client = None

    def _init_killswitch(self) -> None:
        """Initialize remote killswitch if monitors are configured."""
        ks_cfg = self._config.killswitch
        if not ks_cfg.monitors:
            return
        try:
            from aegis.core.remote_killswitch import RemoteKillswitch
            self._killswitch = RemoteKillswitch(
                config=ks_cfg,
                agent_id=self._config.agent_id,
                operator_id=self._config.operator_id,
            )
            self._killswitch.start()
        except Exception:
            logger.debug("Remote killswitch init failed", exc_info=True)

    def _init_self_integrity(self) -> None:
        """Initialize self-integrity watcher if enabled."""
        si_cfg = self._config.self_integrity
        if not si_cfg.enabled:
            return
        try:
            from aegis.core.self_integrity import SelfIntegrityWatcher
            import aegis
            package_dir = Path(aegis.__file__).parent
            self._self_integrity = SelfIntegrityWatcher(
                config=si_cfg,
                package_dir=package_dir,
                config_path=self._config.config_path,
                on_tamper=self._on_self_tamper,
            )
            self._self_integrity.start()
        except Exception:
            logger.debug("Self-integrity watcher init failed", exc_info=True)

    def _on_self_tamper(self, path: str) -> None:
        """Callback when AEGIS file tampering is detected."""
        action = self._config.self_integrity.on_tamper
        msg = f"AEGIS self-integrity violation: {path}"
        if action == "exit":
            print(msg, file=sys.stderr, flush=True)
            os._exit(78)  # EX_CONFIG — cannot be caught
        elif action == "block":
            self._self_integrity_blocked = True
        else:  # "log"
            logger.critical(msg)

    @property
    def is_blocked(self) -> bool:
        """True if the remote killswitch or self-integrity is blocking inference."""
        if self._self_integrity_blocked:
            return True
        if self._killswitch is None:
            return False
        return self._killswitch.is_blocked()

    def check_killswitch(self) -> None:
        """Raise InferenceBlockedError if remote killswitch or self-integrity block is active."""
        if self._self_integrity_blocked:
            raise InferenceBlockedError("AEGIS files tampered — inference blocked")
        if self._killswitch is not None and self._killswitch.is_blocked():
            raise InferenceBlockedError(self._killswitch.block_reason)

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
            logger.debug("Compromise report sending failed", exc_info=True)

    def _get_content_hashes(self) -> dict[str, str]:
        """Return current content hashes for heartbeat inclusion."""
        if self._content_hash_tracker is None:
            return {}
        try:
            return self._content_hash_tracker.get_hashes()
        except Exception:
            return {}

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
        """
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
                logger.debug("NK cell assessment failed", exc_info=True)

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
                    logger.debug("Recovery auto-quarantine failed", exc_info=True)

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
                logger.debug("Monitoring threat event reporting failed", exc_info=True)

        # Content hash update
        if self._content_hash_tracker is not None:
            try:
                profile = None
                if self._message_drift_detector is not None:
                    from aegis.behavior.message_drift import MessageDriftDetector
                    profile = MessageDriftDetector.compute_profile(text)
                self._content_hash_tracker.update(text, profile=profile)
            except Exception:
                logger.debug("Content hash update failed", exc_info=True)

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

        Returns allow-all result when broker is absent.
        In observe mode, threats are logged but not blocked.
        """
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
                logger.debug("Trust tier lookup failed", exc_info=True)

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

        Returns text unchanged when scanner is absent.
        """
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
        No-op when identity module is disabled.
        """
        if self._trust_manager is None:
            return
        canonical = self.resolve_agent_id(agent_id)
        self._trust_manager.record_interaction(canonical, clean=clean, anomaly=anomaly)

    def record_response_behavior(
        self,
        response: Any,
        provider: str,
        agent_id: str = "self",
        kwargs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record behavioral data from an LLM response and check for drift.

        Extracts tool calls, output length, and content type from the
        response.  Feeds data into the behavior tracker, drift detector,
        message drift detector, and prompt monitor.  Results are forwarded
        to the NK cell when anomalies are detected.

        Returns a dict with drift metrics or an empty dict on early exit.
        """
        if self._behavior_tracker is None:
            return {}

        try:
            import time
            from aegis.providers.base import (
                _classify_content_type,
                _extract_response_text,
                _extract_response_text_length,
                _extract_tool_calls,
            )
            from aegis.behavior.tracker import BehaviorEvent

            output_length = _extract_response_text_length(response, provider)
            tool_calls = _extract_tool_calls(response, provider)
            content_type = _classify_content_type(response, provider)
            response_text = _extract_response_text(response, provider)

            # Record primary event
            event = BehaviorEvent(
                agent_id=agent_id,
                timestamp=time.time(),
                event_type="llm_response",
                output_length=output_length,
                tool_used=tool_calls[0] if tool_calls else None,
                content_type=content_type,
                target=None,
            )
            self._behavior_tracker.record_event(event)

            # Record additional tool call events
            for tool_name in tool_calls[1:]:
                extra = BehaviorEvent(
                    agent_id=agent_id,
                    timestamp=time.time(),
                    event_type="tool_call",
                    output_length=0,
                    tool_used=tool_name,
                    content_type="tool_use",
                    target=None,
                )
                self._behavior_tracker.record_event(extra)

            # Check drift against anchor
            drift_result = None
            drift_sigma = 0.0
            anchor = self._behavior_tracker.get_anchor(agent_id)
            if anchor is not None and self._drift_detector is not None:
                current_fp = self._behavior_tracker.get_fingerprint(agent_id)
                drift_result = self._drift_detector.check_drift(
                    current_fp, event, baseline=anchor,
                )
                drift_sigma = drift_result.max_sigma

            # Message-level semantic drift
            message_drift_sigma = 0.0
            if self._message_drift_detector is not None and response_text:
                message_drift_sigma = self._message_drift_detector.record_and_check(
                    agent_id, response_text,
                )
                drift_sigma = max(drift_sigma, message_drift_sigma)

            # IsolationForest anomaly detection
            iso_result = None
            if self._isolation_forest is not None:
                current_fp = self._behavior_tracker.get_fingerprint(agent_id)
                if current_fp is not None:
                    iso_result = self._isolation_forest.record_and_check(current_fp)
                    if iso_result.is_anomaly:
                        # Scale anomaly score to sigma-comparable value
                        drift_sigma = max(drift_sigma, iso_result.anomaly_score * 5.0)

            # System prompt integrity
            purpose_hash_changed = False
            if self._prompt_monitor is not None and kwargs is not None:
                purpose_hash_changed = self._prompt_monitor.check(kwargs)

            # Feed into NK cell if anomalies detected
            nk_verdict = None
            if self._nk_cell is not None and (drift_sigma > 0.0 or purpose_hash_changed):
                try:
                    from aegis.identity import AgentContext
                    context = AgentContext(
                        agent_id=agent_id,
                        has_attestation=False,
                        attestation_valid=False,
                        attestation_expired=False,
                        capabilities_within_scope=True,
                        drift_sigma=drift_sigma,
                        clean_interaction_ratio=1.0,
                        scanner_threat_score=0.0,
                        communication_count=0,
                        purpose_hash_changed=purpose_hash_changed,
                    )
                    nk_verdict = self._nk_cell.assess(context)
                except Exception:
                    logger.debug("NK cell assessment in behavior failed", exc_info=True)

            # Log telemetry
            self._telemetry.log_event(
                "behavior_recorded",
                agent_id=agent_id,
                output_length=output_length,
                tool_calls=tool_calls,
                content_type=content_type,
                drift_sigma=drift_sigma,
                is_drifting=drift_result.is_drifting if drift_result else False,
                message_drift_sigma=message_drift_sigma,
                purpose_hash_changed=purpose_hash_changed,
                nk_verdict=nk_verdict.verdict if nk_verdict else None,
                iso_anomaly=iso_result.is_anomaly if iso_result else False,
            )

            return {
                "drift_sigma": drift_sigma,
                "is_drifting": drift_result.is_drifting if drift_result else False,
                "drift_details": drift_result.per_dimension_scores if drift_result else {},
                "new_tools": drift_result.new_tools if drift_result else [],
                "message_drift_sigma": message_drift_sigma,
                "purpose_hash_changed": purpose_hash_changed,
                "nk_verdict": nk_verdict.verdict if nk_verdict else None,
                "iso_anomaly": iso_result.is_anomaly if iso_result else False,
            }
        except Exception:
            logger.debug("Behavior recording failed", exc_info=True)
            return {}

    def wrap_messages(
        self,
        messages: list[dict[str, Any]],
        provenance_map: dict | None = None,
    ) -> list[dict[str, Any]]:
        """Wrap messages with provenance tags via the scanner envelope.

        Returns messages unchanged when scanner is absent.
        """
        if self._scanner is None:
            return messages

        return self._scanner.wrap_messages(messages, provenance_map=provenance_map)

    def wrap(self, client: Any, tools: list | None = None) -> Any:
        """Wrap an LLM client with AEGIS protection.

        Returns a wrapped client that intercepts API calls for scanning,
        action brokering, and output sanitization.  Automatically selects
        the appropriate provider wrapper based on the client's module.
        """
        client_module = type(client).__module__ or ""
        if "anthropic" in client_module:
            from aegis.providers.anthropic import AnthropicWrapper
            wrapper = AnthropicWrapper(shield=self)
        elif "ollama" in client_module:
            from aegis.providers.ollama import OllamaWrapper
            wrapper = OllamaWrapper(shield=self)
        elif "vllm" in client_module:
            from aegis.providers.vllm import VLLMWrapper
            wrapper = VLLMWrapper(shield=self)
        elif "openai" in client_module:
            from aegis.providers.openai import OpenAIWrapper
            wrapper = OpenAIWrapper(shield=self)
        else:
            from aegis.providers.generic import GenericWrapper
            wrapper = GenericWrapper(shield=self)
        return wrapper.wrap(client, tools=tools)
