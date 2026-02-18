"""NK Cell analysis module for agent immune response.

Inspired by Natural Killer cells in the immune system, this module assesses
agent behavior through activating and inhibitory signals to determine if an
agent is behaving normally or exhibiting signs of compromise.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class AgentContext:
    """Context information about an agent for NK cell assessment."""

    agent_id: str
    has_attestation: bool
    attestation_valid: bool
    attestation_expired: bool
    capabilities_within_scope: bool
    drift_sigma: float
    clean_interaction_ratio: float
    scanner_threat_score: float
    communication_count: int
    purpose_hash_changed: bool


@dataclass
class NKVerdict:
    """Result of an NK cell assessment."""

    score: float  # 0.0 to 1.0
    verdict: str  # normal, elevated, suspicious, hostile
    recommended_action: str  # none, increase_scanning, flag, quarantine
    activating_signals: dict[str, float] = field(default_factory=dict)
    inhibitory_signals: dict[str, float] = field(default_factory=dict)


# Verdict thresholds
THRESHOLD_ELEVATED = 0.3
THRESHOLD_SUSPICIOUS = 0.6
THRESHOLD_HOSTILE = 0.85

# Communication explosion threshold
COMM_EXPLOSION_THRESHOLD = 100


class NKCell:
    """Natural Killer cell analogue for agent assessment.

    Evaluates agent behavior through activating signals (threats) and
    inhibitory signals (evidence of legitimacy). The net score determines
    the verdict and recommended action.

    Args:
        config: Optional configuration dict for overriding defaults.
    """

    def __init__(self, config: dict | None = None):
        self._config = config or {}

    def _compute_activating_signals(self, context: AgentContext) -> dict[str, float]:
        """Compute activating (threat) signals, each in [0.0, 1.0]."""
        signals: dict[str, float] = {}

        # Missing attestation
        if not context.has_attestation:
            signals["missing_attestation"] = 1.0

        # Expired attestation
        if context.attestation_expired:
            signals["expired_attestation"] = 0.8

        # Capability violation
        if not context.capabilities_within_scope:
            signals["capability_violation"] = 0.9

        # Severe drift (sigma > 3)
        if context.drift_sigma > 3.0:
            # Scale from 0 at sigma=3 to 1.0 at sigma>=6
            drift_score = min(1.0, (context.drift_sigma - 3.0) / 3.0)
            signals["severe_drift"] = drift_score

        # Content threats from scanner
        if context.scanner_threat_score > 0.0:
            signals["content_threats"] = min(1.0, context.scanner_threat_score)

        # Communication explosion
        if context.communication_count > COMM_EXPLOSION_THRESHOLD:
            # Scale logarithmically
            explosion_score = min(
                1.0,
                (context.communication_count - COMM_EXPLOSION_THRESHOLD)
                / (COMM_EXPLOSION_THRESHOLD * 9),
            )
            signals["communication_explosion"] = max(0.1, explosion_score)

        # Purpose hash changed
        if context.purpose_hash_changed:
            signals["purpose_hash_change"] = 0.9

        return signals

    def _compute_inhibitory_signals(self, context: AgentContext) -> dict[str, float]:
        """Compute inhibitory (safety) signals, each in [0.0, 1.0]."""
        signals: dict[str, float] = {}

        # Valid attestation
        if context.attestation_valid:
            signals["valid_attestation"] = 0.8

        # Within scope
        if context.capabilities_within_scope:
            signals["within_scope"] = 0.5

        # Stable profile (sigma < 1)
        if context.drift_sigma < 1.0:
            signals["stable_profile"] = 0.6 * (1.0 - context.drift_sigma)

        # Clean history (> 98%)
        if context.clean_interaction_ratio > 0.98:
            signals["clean_history"] = 0.7

        return signals

    def assess(self, context: AgentContext) -> NKVerdict:
        """Assess an agent and produce a verdict.

        Args:
            context: The agent context to evaluate.

        Returns:
            An NKVerdict with score, verdict, action, and signal details.
        """
        # Guard against NaN/inf values in context fields
        if math.isnan(context.drift_sigma) or math.isinf(context.drift_sigma):
            context.drift_sigma = 0.0
        if math.isnan(context.clean_interaction_ratio) or math.isinf(context.clean_interaction_ratio):
            context.clean_interaction_ratio = 0.0
        if math.isnan(context.scanner_threat_score) or math.isinf(context.scanner_threat_score):
            context.scanner_threat_score = 0.0

        activating = self._compute_activating_signals(context)
        inhibitory = self._compute_inhibitory_signals(context)

        # Score = sum(activating) - sum(inhibitory), clamped to [0, 1]
        raw_score = sum(activating.values()) - sum(inhibitory.values())
        score = max(0.0, min(1.0, raw_score))

        # Determine verdict and action
        if score >= THRESHOLD_HOSTILE:
            verdict = "hostile"
            action = "quarantine"
        elif score >= THRESHOLD_SUSPICIOUS:
            verdict = "suspicious"
            action = "flag"
        elif score >= THRESHOLD_ELEVATED:
            verdict = "elevated"
            action = "increase_scanning"
        else:
            verdict = "normal"
            action = "none"

        return NKVerdict(
            score=score,
            verdict=verdict,
            recommended_action=action,
            activating_signals=activating,
            inhibitory_signals=inhibitory,
        )
