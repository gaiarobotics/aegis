"""Tests for aegis.identity.trust module."""

import json
import math
import os
import tempfile
import time

import pytest

from aegis.identity.trust import (
    MAX_DELEGATION_BONUS,
    MAX_VOUCHES_PER_VOUCHER,
    TrustManager,
    TrustRecord,
)


def _tm(**kwargs):
    """Create a TrustManager with rate-limiting disabled for tests."""
    config = {"interaction_min_interval": 0}
    config.update(kwargs)
    return TrustManager(config=config)


class TestTrustManagerBasics:
    """Basic trust manager operations."""

    def test_unknown_agent_tier_zero(self):
        tm = _tm()
        assert tm.get_tier("unknown-agent") == 0
        assert tm.get_score("unknown-agent") == 0.0

    def test_record_clean_interaction_increases_score(self):
        tm = _tm()
        tm.record_interaction("agent-1", clean=True)
        assert tm.get_score("agent-1") > 0.0

    def test_score_grows_logarithmically(self):
        tm = _tm()
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
        tm = _tm()
        # Build score above 15
        for _ in range(50):
            tm.record_interaction("agent-1", clean=True)
        score = tm.get_score("agent-1")
        assert score >= 15.0
        assert tm.get_tier("agent-1") >= 1

    def test_tier_2_requires_score_50_and_age(self):
        tm = _tm()
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
        tm = _tm()
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
        tm = _tm()
        for _ in range(50):
            tm.record_interaction("agent-1", clean=True)
        score_before = tm.get_score("agent-1")
        tm.record_interaction("agent-1", clean=False, anomaly=True)
        score_after = tm.get_score("agent-1")
        assert score_after < score_before

    def test_report_compromise(self):
        tm = _tm()
        for _ in range(50):
            tm.record_interaction("agent-1", clean=True)
        assert tm.get_score("agent-1") > 0
        tm.report_compromise("agent-1")
        assert tm.get_score("agent-1") == 0.0
        assert tm.get_tier("agent-1") == 0


class TestVouching:
    """Tests for the vouch mechanism."""

    def test_vouch_increases_score(self):
        tm = _tm()
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
        tm = _tm()
        tm.record_interaction("low-voucher", clean=True)
        tm.record_interaction("target", clean=True)
        score_before = tm.get_score("target")
        tm.vouch("low-voucher", "target")
        score_after = tm.get_score("target")
        # Voucher not qualified, score should not change
        assert score_after == score_before

    def test_duplicate_vouch_ignored(self):
        tm = _tm()
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
        tm = _tm()
        for _ in range(50):
            tm.record_interaction("agent-1", clean=True)
        score_before = tm.get_score("agent-1")
        tm.apply_decay()
        score_after = tm.get_score("agent-1")
        assert score_after < score_before

    def test_decay_14_day_half_life(self):
        tm = _tm()
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
        tm = _tm()
        tm.record_interaction("agent-1", clean=True)
        score_before = tm.get_score("agent-1")
        tm.set_operator_delegation("agent-1", bonus=10.0)
        score_after = tm.get_score("agent-1")
        assert score_after == score_before + 10.0


class TestPersistence:
    """Tests for save/load."""

    def test_save_and_load(self):
        tm = _tm()
        for _ in range(20):
            tm.record_interaction("agent-1", clean=True)
        tm.record_interaction("agent-1", clean=False, anomaly=True)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tm.save(path)
            tm2 = _tm()
            tm2.load(path)
            assert tm2.get_score("agent-1") == pytest.approx(tm.get_score("agent-1"))
            assert tm2.get_tier("agent-1") == tm.get_tier("agent-1")
            record = tm2._records["agent-1"]
            assert record.anomaly_count == 1
        finally:
            os.unlink(path)

    def test_load_nonexistent_file(self):
        tm = _tm()
        with pytest.raises(FileNotFoundError):
            tm.load("/tmp/nonexistent_trust_data.json")

    def test_compromised_set_persists(self):
        """Compromised agents should survive save/load round-trip."""
        tm = _tm()
        for _ in range(10):
            tm.record_interaction("agent-good", clean=True)
            tm.record_interaction("agent-bad", clean=True)
        tm.report_compromise("agent-bad")

        assert tm.get_score("agent-bad") == 0.0
        assert tm.get_tier("agent-bad") == 0

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tm.save(path)
            tm2 = _tm()
            tm2.load(path)
            # Compromised status should persist
            assert tm2.get_tier("agent-bad") == 0
            assert "agent-bad" in tm2._compromised
            # Good agent should be unaffected
            assert tm2.get_score("agent-good") > 0
        finally:
            os.unlink(path)

    def test_save_and_load_with_vouchers(self):
        """Vouchers should survive save/load round-trip."""
        tm = _tm()
        # Create established agents (Tier 2+)
        for agent in ["v1", "v2", "v3"]:
            rec = tm._ensure_record(agent)
            rec.earned_score = 60.0
            rec.score = 60.0
            rec.created = time.time() - 86400 * 10  # 10 days old

        # Vouch for target
        for _ in range(20):
            tm.record_interaction("target", clean=True)
        tm.vouch("v1", "target")
        tm.vouch("v2", "target")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            tm.save(path)
            tm2 = _tm()
            tm2.load(path)
            assert "v1" in tm2._records["target"].vouchers
            assert "v2" in tm2._records["target"].vouchers
        finally:
            os.unlink(path)


class TestScoreAggregation:
    """Test earned_score + bonus_score = score."""

    def test_anomaly_penalizes_both_earned_and_bonus(self):
        tm = _tm()
        for _ in range(20):
            tm.record_interaction("agent-1", clean=True)
        tm.set_operator_delegation("agent-1", bonus=20.0)
        earned_before = tm._records["agent-1"].earned_score
        bonus_before = tm._records["agent-1"].bonus_score
        tm.record_interaction("agent-1", clean=False, anomaly=True)
        rec = tm._records["agent-1"]
        assert rec.earned_score < earned_before
        assert rec.bonus_score < bonus_before
        assert rec.score == pytest.approx(rec.earned_score + rec.bonus_score)


class TestDelegationCap:
    """Delegation bonus must be capped."""

    def test_delegation_capped(self):
        tm = _tm()
        tm.set_operator_delegation("agent-1", bonus=MAX_DELEGATION_BONUS + 100)
        assert tm._records["agent-1"].bonus_score <= MAX_DELEGATION_BONUS

    def test_delegation_accumulates_up_to_cap(self):
        tm = _tm()
        tm.set_operator_delegation("agent-1", bonus=30.0)
        tm.set_operator_delegation("agent-1", bonus=30.0)
        assert tm._records["agent-1"].bonus_score <= MAX_DELEGATION_BONUS


class TestVouchLimits:
    """Each voucher is limited in total sponsorships."""

    def _make_tier2(self, tm, agent_id):
        for _ in range(20):
            tm.record_interaction(agent_id, clean=True)
        tm.set_operator_delegation(agent_id, bonus=40.0)
        tm._records[agent_id].created = time.time() - (4 * 86400)

    def test_vouch_limit_per_voucher(self):
        tm = _tm()
        self._make_tier2(tm, "voucher")
        # Vouch for MAX_VOUCHES_PER_VOUCHER targets
        for i in range(MAX_VOUCHES_PER_VOUCHER):
            tm.record_interaction(f"target-{i}", clean=True)
            tm.vouch("voucher", f"target-{i}")
        # Next vouch should be rejected
        tm.record_interaction("target-extra", clean=True)
        score_before = tm.get_score("target-extra")
        tm.vouch("voucher", "target-extra")
        assert tm.get_score("target-extra") == score_before


class TestRateLimiting:
    """Interactions within INTERACTION_MIN_INTERVAL should be silently dropped."""

    def test_rapid_interactions_rate_limited(self):
        tm = TrustManager()  # Default has rate-limiting enabled
        tm.record_interaction("agent-1", clean=True)
        # Second call immediately after should be rate-limited
        tm.record_interaction("agent-1", clean=True)
        assert tm._records["agent-1"].total_interactions == 1

    def test_interactions_after_interval_accepted(self):
        tm = TrustManager()  # Default has rate-limiting enabled
        tm.record_interaction("agent-1", clean=True)
        # Simulate time passing
        tm._records["agent-1"].last_interaction -= 1.0
        tm.record_interaction("agent-1", clean=True)
        assert tm._records["agent-1"].total_interactions == 2


class TestLoadValidation:
    """load() must reject malformed data."""

    def test_load_invalid_compromised(self):
        data = {"compromised": "not-a-list", "records": {}}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(data, f)
            path = f.name
        try:
            tm = _tm()
            with pytest.raises(ValueError, match="compromised"):
                tm.load(path)
        finally:
            os.unlink(path)

    def test_load_invalid_score_type(self):
        data = {"compromised": [], "records": {
            "a": {"agent_id": "a", "score": "not-a-number", "clean_interactions": 0,
                   "total_interactions": 0, "last_interaction": 0, "created": 0}
        }}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            json.dump(data, f)
            path = f.name
        try:
            tm = _tm()
            with pytest.raises(ValueError, match="Invalid score"):
                tm.load(path)
        finally:
            os.unlink(path)


class TestAtomicSave:
    """save() must use atomic file replacement."""

    def test_save_creates_file(self):
        tm = _tm()
        tm.record_interaction("agent-1", clean=True)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            tm.save(path)
            assert os.path.exists(path)
            with open(path) as f:
                data = json.load(f)
            assert "records" in data
            assert "agent-1" in data["records"]
            assert "earned_score" in data["records"]["agent-1"]
        finally:
            os.unlink(path)


class TestIdNormalization:
    """Agent IDs should be normalized (lowered, stripped) in all public methods."""

    def test_case_insensitive_get_score(self):
        """get_score('Alice') same as get_score('alice')."""
        tm = _tm()
        tm.record_interaction("alice", clean=True)
        score_lower = tm.get_score("alice")
        score_upper = tm.get_score("Alice")
        assert score_lower == score_upper
        assert score_lower > 0.0

    def test_whitespace_stripped(self):
        """get_score(' alice ') same as get_score('alice')."""
        tm = _tm()
        tm.record_interaction("alice", clean=True)
        assert tm.get_score(" alice ") == tm.get_score("alice")

    def test_normalize_in_vouch(self):
        """Vouching with mixed case works."""
        tm = _tm()
        # Create qualified voucher (Tier 2+)
        for _ in range(20):
            tm.record_interaction("voucher", clean=True)
        tm.set_operator_delegation("voucher", bonus=40.0)
        tm._records["voucher"].created = time.time() - (4 * 86400)
        assert tm.get_tier("VOUCHER") >= 2

        tm.record_interaction("target", clean=True)
        score_before = tm.get_score("target")
        tm.vouch("VOUCHER", "TARGET")
        score_after = tm.get_score("target")
        assert score_after > score_before

    def test_normalize_in_report_compromise(self):
        """Compromising 'ALICE' affects 'alice'."""
        tm = _tm()
        for _ in range(10):
            tm.record_interaction("alice", clean=True)
        assert tm.get_score("alice") > 0
        tm.report_compromise("ALICE")
        assert tm.get_score("alice") == 0.0
        assert tm.get_tier("alice") == 0
