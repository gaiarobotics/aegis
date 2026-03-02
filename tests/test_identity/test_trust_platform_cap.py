"""Tests for trust tier capping by platform."""

import time
import pytest

from aegis.core.config import TrustConfig
from aegis.identity.trust import TrustManager


def _tm(**kwargs):
    """Create a TrustManager with rate-limiting disabled for tests."""
    kwargs.setdefault("interaction_min_interval", 0)
    return TrustManager(config=TrustConfig(**kwargs))


class TestMaxTierByPlatform:

    def test_no_cap_without_config(self):
        tm = _tm()
        for _ in range(20):
            tm.record_interaction("moltbook:alice", clean=True)
        tm.set_operator_delegation("moltbook:alice", bonus=10.0)
        tier = tm.get_tier("moltbook:alice")
        assert tier >= 1

    def test_moltbook_capped_at_tier_1(self):
        tm = _tm(max_tier_by_platform={"moltbook": 1})
        for _ in range(60):
            tm.record_interaction("moltbook:alice", clean=True)
        tm.set_operator_delegation("moltbook:alice", bonus=40.0)
        record = tm._records["moltbook:alice"]
        record.created = time.time() - (4 * 86400)
        natural_score = tm.get_score("moltbook:alice")
        assert natural_score >= 50.0
        assert tm.get_tier("moltbook:alice") == 1

    def test_non_moltbook_agent_not_capped(self):
        tm = _tm(max_tier_by_platform={"moltbook": 1})
        for _ in range(60):
            tm.record_interaction("slack:bob", clean=True)
        tm.set_operator_delegation("slack:bob", bonus=40.0)
        record = tm._records["slack:bob"]
        record.created = time.time() - (4 * 86400)
        assert tm.get_tier("slack:bob") == 2

    def test_cap_at_tier_0(self):
        tm = _tm(max_tier_by_platform={"moltbook": 0})
        for _ in range(20):
            tm.record_interaction("moltbook:charlie", clean=True)
        tm.set_operator_delegation("moltbook:charlie", bonus=10.0)
        assert tm.get_tier("moltbook:charlie") == 0

    def test_multiple_platform_caps(self):
        tm = _tm(max_tier_by_platform={"moltbook": 1, "discord": 0})
        for _ in range(20):
            tm.record_interaction("moltbook:alice", clean=True)
        tm.set_operator_delegation("moltbook:alice", bonus=10.0)
        for _ in range(20):
            tm.record_interaction("discord:bob", clean=True)
        tm.set_operator_delegation("discord:bob", bonus=10.0)
        assert tm.get_tier("moltbook:alice") == 1
        assert tm.get_tier("discord:bob") == 0

    def test_compromised_agent_still_tier_0(self):
        tm = _tm(max_tier_by_platform={"moltbook": 1})
        for _ in range(20):
            tm.record_interaction("moltbook:evil", clean=True)
        tm.set_operator_delegation("moltbook:evil", bonus=10.0)
        tm.report_compromise("moltbook:evil")
        assert tm.get_tier("moltbook:evil") == 0
