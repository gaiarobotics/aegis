"""Tests for the R0 estimator."""

import time

from monitor.epidemiology import R0Estimator
from monitor.models import CompromiseRecord


def _make_record(reporter: str, compromised: str, ts: float = 0) -> CompromiseRecord:
    return CompromiseRecord(
        record_id=f"{reporter}->{compromised}",
        reporter_agent_id=reporter,
        compromised_agent_id=compromised,
        timestamp=ts or time.time(),
    )


class TestR0Estimator:
    def test_no_records(self):
        est = R0Estimator()
        assert est.estimate_r0() == 0.0

    def test_single_infection(self):
        est = R0Estimator()
        est.add_record(_make_record("a1", "a2"))
        r0 = est.estimate_r0(window_hours=1)
        assert r0 == 1.0  # 1 primary → 1 secondary

    def test_multiple_secondaries(self):
        est = R0Estimator()
        now = time.time()
        est.add_record(_make_record("a1", "a2", now))
        est.add_record(_make_record("a1", "a3", now))
        est.add_record(_make_record("a1", "a4", now))
        r0 = est.estimate_r0(window_hours=1)
        assert r0 == 3.0  # 1 primary → 3 secondaries

    def test_multiple_primaries(self):
        est = R0Estimator()
        now = time.time()
        est.add_record(_make_record("a1", "a2", now))
        est.add_record(_make_record("a1", "a3", now))
        est.add_record(_make_record("b1", "b2", now))
        r0 = est.estimate_r0(window_hours=1)
        # a1 → 2 secondaries, b1 → 1 secondary. Mean = 1.5
        assert r0 == 1.5

    def test_window_excludes_old(self):
        est = R0Estimator()
        old = time.time() - 7200  # 2 hours ago
        est.add_record(_make_record("a1", "a2", old))
        r0 = est.estimate_r0(window_hours=1)
        assert r0 == 0.0

    def test_self_reports_excluded(self):
        est = R0Estimator()
        est.add_record(_make_record("a1", "a1"))
        assert est.estimate_r0(window_hours=1) == 0.0


class TestPropagationChains:
    def test_simple_chain(self):
        est = R0Estimator()
        now = time.time()
        est.add_record(_make_record("a1", "a2", now))
        est.add_record(_make_record("a2", "a3", now + 1))
        chains = est.get_propagation_chains()
        assert len(chains) >= 1
        # Should contain a chain a1 → a2 → a3
        found = any(c == ["a1", "a2", "a3"] for c in chains)
        assert found, f"Expected chain [a1, a2, a3], got {chains}"

    def test_branching(self):
        est = R0Estimator()
        now = time.time()
        est.add_record(_make_record("a1", "a2", now))
        est.add_record(_make_record("a1", "a3", now))
        chains = est.get_propagation_chains()
        assert len(chains) == 2


class TestR0Trend:
    def test_trend_format(self):
        est = R0Estimator()
        now = time.time()
        est.add_record(_make_record("a1", "a2", now))
        trend = est.get_r0_trend(window_hours=1, buckets=4)
        assert len(trend) == 4
        assert "timestamp" in trend[0]
        assert "r0" in trend[0]

    def test_empty_trend(self):
        est = R0Estimator()
        trend = est.get_r0_trend(window_hours=1, buckets=4)
        assert len(trend) == 4
        assert all(t["r0"] == 0.0 for t in trend)
