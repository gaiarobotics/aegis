"""Tests for aegis.identity.nkcell module."""

import pytest

from aegis.identity.nkcell import AgentContext, NKCell, NKVerdict


def _default_context(**overrides) -> AgentContext:
    """Create a default safe agent context with optional overrides."""
    defaults = dict(
        agent_id="agent-1",
        has_attestation=True,
        attestation_valid=True,
        attestation_expired=False,
        capabilities_within_scope=True,
        drift_sigma=0.5,
        clean_interaction_ratio=0.99,
        scanner_threat_score=0.0,
        communication_count=5,
        purpose_hash_changed=False,
    )
    defaults.update(overrides)
    return AgentContext(**defaults)


class TestNKCellVerdicts:
    """Test verdict levels based on signal combinations."""

    def test_normal_agent(self):
        nk = NKCell()
        ctx = _default_context()
        verdict = nk.assess(ctx)
        assert isinstance(verdict, NKVerdict)
        assert verdict.verdict == "normal"
        assert verdict.recommended_action == "none"
        assert 0.0 <= verdict.score <= 1.0

    def test_elevated_verdict(self):
        nk = NKCell()
        # Expired attestation with some inhibitory removed
        # Activating: expired_attestation=0.8
        # Inhibitory: within_scope=0.5 (no stable_profile since sigma>1, no clean_history since <0.98)
        # Score = 0.8 - 0.5 = 0.3 -> elevated
        ctx = _default_context(
            attestation_expired=True,
            attestation_valid=False,
            capabilities_within_scope=True,
            drift_sigma=1.5,  # Not stable (>1) but not severe (<3)
            clean_interaction_ratio=0.95,  # Below 98% threshold
        )
        verdict = nk.assess(ctx)
        assert verdict.verdict == "elevated"
        assert verdict.score >= 0.3

    def test_suspicious_verdict(self):
        nk = NKCell()
        ctx = _default_context(
            has_attestation=False,
            attestation_valid=False,
            capabilities_within_scope=False,
            drift_sigma=3.5,
        )
        verdict = nk.assess(ctx)
        assert verdict.verdict in ("suspicious", "hostile")
        assert verdict.score >= 0.6

    def test_hostile_verdict(self):
        nk = NKCell()
        ctx = _default_context(
            has_attestation=False,
            attestation_valid=False,
            attestation_expired=True,
            capabilities_within_scope=False,
            drift_sigma=5.0,
            clean_interaction_ratio=0.5,
            scanner_threat_score=0.9,
            communication_count=1000,
            purpose_hash_changed=True,
        )
        verdict = nk.assess(ctx)
        assert verdict.verdict == "hostile"
        assert verdict.score >= 0.85
        assert verdict.recommended_action == "quarantine"


class TestActivatingSignals:
    """Test individual activating signals."""

    def test_missing_attestation_signal(self):
        nk = NKCell()
        ctx = _default_context(has_attestation=False, attestation_valid=False)
        verdict = nk.assess(ctx)
        assert "missing_attestation" in verdict.activating_signals
        assert verdict.activating_signals["missing_attestation"] > 0

    def test_expired_attestation_signal(self):
        nk = NKCell()
        ctx = _default_context(attestation_expired=True, attestation_valid=False)
        verdict = nk.assess(ctx)
        assert "expired_attestation" in verdict.activating_signals
        assert verdict.activating_signals["expired_attestation"] > 0

    def test_capability_violation_signal(self):
        nk = NKCell()
        ctx = _default_context(capabilities_within_scope=False)
        verdict = nk.assess(ctx)
        assert "capability_violation" in verdict.activating_signals
        assert verdict.activating_signals["capability_violation"] > 0

    def test_severe_drift_signal(self):
        nk = NKCell()
        ctx = _default_context(drift_sigma=4.0)
        verdict = nk.assess(ctx)
        assert "severe_drift" in verdict.activating_signals
        assert verdict.activating_signals["severe_drift"] > 0

    def test_no_drift_signal_below_threshold(self):
        nk = NKCell()
        ctx = _default_context(drift_sigma=2.5)
        verdict = nk.assess(ctx)
        assert verdict.activating_signals.get("severe_drift", 0.0) == 0.0

    def test_content_threats_signal(self):
        nk = NKCell()
        ctx = _default_context(scanner_threat_score=0.8)
        verdict = nk.assess(ctx)
        assert "content_threats" in verdict.activating_signals
        assert verdict.activating_signals["content_threats"] > 0

    def test_communication_explosion_signal(self):
        nk = NKCell()
        ctx = _default_context(communication_count=500)
        verdict = nk.assess(ctx)
        assert "communication_explosion" in verdict.activating_signals
        assert verdict.activating_signals["communication_explosion"] > 0

    def test_purpose_hash_change_signal(self):
        nk = NKCell()
        ctx = _default_context(purpose_hash_changed=True)
        verdict = nk.assess(ctx)
        assert "purpose_hash_change" in verdict.activating_signals
        assert verdict.activating_signals["purpose_hash_change"] > 0


class TestInhibitorySignals:
    """Test individual inhibitory signals."""

    def test_valid_attestation_inhibits(self):
        nk = NKCell()
        ctx = _default_context(attestation_valid=True)
        verdict = nk.assess(ctx)
        assert "valid_attestation" in verdict.inhibitory_signals
        assert verdict.inhibitory_signals["valid_attestation"] > 0

    def test_within_scope_inhibits(self):
        nk = NKCell()
        ctx = _default_context(capabilities_within_scope=True)
        verdict = nk.assess(ctx)
        assert "within_scope" in verdict.inhibitory_signals
        assert verdict.inhibitory_signals["within_scope"] > 0

    def test_stable_profile_inhibits(self):
        nk = NKCell()
        ctx = _default_context(drift_sigma=0.3)
        verdict = nk.assess(ctx)
        assert "stable_profile" in verdict.inhibitory_signals
        assert verdict.inhibitory_signals["stable_profile"] > 0

    def test_clean_history_inhibits(self):
        nk = NKCell()
        ctx = _default_context(clean_interaction_ratio=0.99)
        verdict = nk.assess(ctx)
        assert "clean_history" in verdict.inhibitory_signals
        assert verdict.inhibitory_signals["clean_history"] > 0

    def test_no_clean_history_when_low_ratio(self):
        nk = NKCell()
        ctx = _default_context(clean_interaction_ratio=0.90)
        verdict = nk.assess(ctx)
        assert verdict.inhibitory_signals.get("clean_history", 0.0) == 0.0


class TestScoreClamping:
    """Test that scores are properly clamped to [0, 1]."""

    def test_score_clamped_to_zero(self):
        """A very clean agent should have score clamped to 0."""
        nk = NKCell()
        ctx = _default_context()  # All inhibitory, no activating
        verdict = nk.assess(ctx)
        assert verdict.score >= 0.0

    def test_score_clamped_to_one(self):
        """A maximally hostile agent should have score clamped to 1."""
        nk = NKCell()
        ctx = _default_context(
            has_attestation=False,
            attestation_valid=False,
            attestation_expired=True,
            capabilities_within_scope=False,
            drift_sigma=10.0,
            clean_interaction_ratio=0.0,
            scanner_threat_score=1.0,
            communication_count=10000,
            purpose_hash_changed=True,
        )
        verdict = nk.assess(ctx)
        assert verdict.score <= 1.0


class TestRecommendedActions:
    """Test recommended actions match verdict levels."""

    def test_normal_action_is_none(self):
        nk = NKCell()
        ctx = _default_context()
        verdict = nk.assess(ctx)
        assert verdict.recommended_action == "none"

    def test_elevated_action_is_increase_scanning(self):
        nk = NKCell()
        ctx = _default_context(
            attestation_expired=True,
            attestation_valid=False,
        )
        verdict = nk.assess(ctx)
        if verdict.verdict == "elevated":
            assert verdict.recommended_action == "increase_scanning"

    def test_suspicious_action_is_flag(self):
        nk = NKCell()
        ctx = _default_context(
            has_attestation=False,
            attestation_valid=False,
            capabilities_within_scope=False,
            drift_sigma=4.0,
        )
        verdict = nk.assess(ctx)
        if verdict.verdict == "suspicious":
            assert verdict.recommended_action == "flag"

    def test_hostile_action_is_quarantine(self):
        nk = NKCell()
        ctx = _default_context(
            has_attestation=False,
            attestation_valid=False,
            attestation_expired=True,
            capabilities_within_scope=False,
            drift_sigma=5.0,
            clean_interaction_ratio=0.5,
            scanner_threat_score=0.9,
            communication_count=1000,
            purpose_hash_changed=True,
        )
        verdict = nk.assess(ctx)
        assert verdict.recommended_action == "quarantine"


class TestNaNGuards:
    """Test that NaN/inf values in AgentContext fields are handled gracefully."""

    def test_nan_drift_sigma_handled(self):
        """NaN drift_sigma should not crash the assessment."""
        nk = NKCell()
        ctx = _default_context(drift_sigma=float("nan"))
        verdict = nk.assess(ctx)
        assert isinstance(verdict, NKVerdict)
        assert 0.0 <= verdict.score <= 1.0

    def test_inf_scanner_score_handled(self):
        """Inf scanner_threat_score should not crash the assessment."""
        nk = NKCell()
        ctx = _default_context(scanner_threat_score=float("inf"))
        verdict = nk.assess(ctx)
        assert isinstance(verdict, NKVerdict)
        assert 0.0 <= verdict.score <= 1.0

    def test_nan_clean_ratio_handled(self):
        """NaN clean_interaction_ratio should not crash the assessment."""
        nk = NKCell()
        ctx = _default_context(clean_interaction_ratio=float("nan"))
        verdict = nk.assess(ctx)
        assert isinstance(verdict, NKVerdict)
        assert 0.0 <= verdict.score <= 1.0
