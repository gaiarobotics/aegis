"""Tests for aegis.identity.trust module."""

import json
import math
import os
import tempfile
import time

import pytest

from aegis.identity.trust import TrustManager, TrustRecord


class TestTrustManagerBasics:
    """Basic trust manager operations."""

    def test_unknown_agent_tier_zero(self):
        tm = TrustManager()
        assert tm.get_tier("unknown-agent") == 0
        assert tm.get_score("unknown-agent") == 0.0

    def test_record_clean_interaction_increases_score(self):
        tm = TrustManager()
        tm.record_interaction("agent-1", clean=True)
        assert tm.get_score("agent-1") > 0.0

    def test_score_grows_logarithmically(self):
        tm = TrustManager()
        scores = []
        for i in range(20):
            tm.record_interaction("agent-1", clean=True)
            scores.append(tm.get_score("agent-1"))
        # Increments should decrease (logarithmic growth)
        increments = [scores[i + 1] - scores[i] for i in range(len(scores) - 1)]
        # Later increments should generally be smaller than earlier ones
        assert increments[-1] < increments[0]


class TestTierTransitions:
    """Test tier progression."""

    def test_tier_1_at_score_15(self):
        tm = TrustManager()
        # Build score above 15
        for _ in range(50):
            tm.record_interaction("agent-1", clean=True)
        score = tm.get_score("agent-1")
        assert score >= 15.0
        assert tm.get_tier("agent-1") >= 1

    def test_tier_2_requires_score_50_and_age(self):
        tm = TrustManager()
        # Build some base score from interactions
        for _ in range(50):
            tm.record_interaction("agent-2", clean=True)
        # Use operator delegation to push score above 50
        tm.set_operator_delegation("agent-2", bonus=35.0)
        score = tm.get_score("agent-2")
        assert score >= 50.0
        # Without 3 days age, should not be Tier 2
        tier = tm.get_tier("agent-2")
        assert tier < 2  # Not old enough

        # Simulate age by adjusting created timestamp
        record = tm._records["agent-2"]
        record.created = time.time() - (3 * 86400 + 1)
        assert tm.get_tier("agent-2") == 2

    def test_tier_3_requires_vouchers(self):
        tm = TrustManager()
        # Helper to make an agent reach Tier 2
        def make_tier2(agent_id):
            for _ in range(20):
                tm.record_interaction(agent_id, clean=True)
            tm.set_operator_delegation(agent_id, bonus=40.0)
            tm._records[agent_id].created = time.time() - (4 * 86400)
            assert tm.get_tier(agent_id) == 2

        # Create target at Tier 2
        make_tier2("target")

        # Create 3 Tier 2 vouchers
        for voucher_name in ["v1", "v2", "v3"]:
            make_tier2(voucher_name)

        # Vouch
        tm.vouch("v1", "target")
        tm.vouch("v2", "target")
        tm.vouch("v3", "target")

        assert tm.get_tier("target") == 3


class TestAnomalyAndCompromise:
    """Tests for anomaly penalties and compromise reporting."""

    def test_anomaly_penalty(self):
        tm = TrustManager()
        for _ in range(50):
            tm.record_interaction("agent-1", clean=True)
        score_before = tm.get_score("agent-1")
        tm.record_interaction("agent-1", clean=False, anomaly=True)
        score_after = tm.get_score("agent-1")
        assert score_after < score_before

    def test_report_compromise(self):
        tm = TrustManager()
        for _ in range(50):
            tm.record_interaction("agent-1", clean=True)
        assert tm.get_score("agent-1") > 0
        tm.report_compromise("agent-1")
        assert tm.get_score("agent-1") == 0.0
        assert tm.get_tier("agent-1") == 0


class TestVouching:
    """Tests for the vouch mechanism."""

    def test_vouch_increases_score(self):
        tm = TrustManager()
        # Create qualified voucher (Tier 2+)
        for _ in range(20):
            tm.record_interaction("voucher", clean=True)
        tm.set_operator_delegation("voucher", bonus=40.0)
        tm._records["voucher"].created = time.time() - (4 * 86400)
        assert tm.get_tier("voucher") >= 2

        tm.record_interaction("target", clean=True)
        score_before = tm.get_score("target")
        tm.vouch("voucher", "target")
        score_after = tm.get_score("target")
        assert score_after - score_before == pytest.approx(8.0)

    def test_vouch_from_low_tier_ignored(self):
        tm = TrustManager()
        tm.record_interaction("low-voucher", clean=True)
        tm.record_interaction("target", clean=True)
        score_before = tm.get_score("target")
        tm.vouch("low-voucher", "target")
        score_after = tm.get_score("target")
        # Voucher not qualified, score should not change
        assert score_after == score_before

    def test_duplicate_vouch_ignored(self):
        tm = TrustManager()
        for _ in range(20):
            tm.record_interaction("voucher", clean=True)
        tm.set_operator_delegation("voucher", bonus=40.0)
        tm._records["voucher"].created = time.time() - (4 * 86400)

        tm.record_interaction("target", clean=True)
        tm.vouch("voucher", "target")
        score_first = tm.get_score("target")
        tm.vouch("voucher", "target")
        score_second = tm.get_score("target")
        assert score_first == score_second


class TestDecay:
    """Tests for score decay."""

    def test_decay_reduces_score(self):
        tm = TrustManager()
        for _ in range(50):
            tm.record_interaction("agent-1", clean=True)
        score_before = tm.get_score("agent-1")
        tm.apply_decay()
        score_after = tm.get_score("agent-1")
        assert score_after < score_before

    def test_decay_14_day_half_life(self):
        tm = TrustManager()
        for _ in range(100):
            tm.record_interaction("agent-1", clean=True)
        score_before = tm.get_score("agent-1")
        # Apply decay 14 times (simulating 14 days of daily decay)
        for _ in range(14):
            tm.apply_decay()
        score_after = tm.get_score("agent-1")
        # After 14 applications (one per day), score should be roughly half
        ratio = score_after / score_before
        assert 0.4 < ratio < 0.6


class TestOperatorDelegation:
    """Tests for operator delegation bonus."""

    def test_set_operator_delegation(self):
        tm = TrustManager()
        tm.record_interaction("agent-1", clean=True)
        score_before = tm.get_score("agent-1")
        tm.set_operator_delegation("agent-1", bonus=10.0)
        score_after = tm.get_score("agent-1")
        assert score_after == score_before + 10.0


class TestPersistence:
    """Tests for save/load."""

    def test_save_and_load(self):
        tm = TrustManager()
        for _ in range(20):
            tm.record_interaction("agent-1", clean=True)
        tm.record_interaction("agent-1", clean=False, anomaly=True)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tm.save(path)
            tm2 = TrustManager()
            tm2.load(path)
            assert tm2.get_score("agent-1") == pytest.approx(tm.get_score("agent-1"))
            assert tm2.get_tier("agent-1") == tm.get_tier("agent-1")
            record = tm2._records["agent-1"]
            assert record.anomaly_count == 1
        finally:
            os.unlink(path)

    def test_load_nonexistent_file(self):
        tm = TrustManager()
        with pytest.raises(FileNotFoundError):
            tm.load("/tmp/nonexistent_trust_data.json")
