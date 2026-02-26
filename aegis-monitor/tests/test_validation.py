"""Unit tests for ReportValidator anti-poisoning defenses."""

import time

import pytest

from monitor.config import MonitorConfig
from monitor.validation import ReportValidator


def _cfg(**overrides) -> MonitorConfig:
    defaults = dict(
        compromise_rate_limit=3,
        compromise_rate_window=60,
        compromise_min_trust_tier=1,
        compromise_quorum=2,
        compromise_hash_max_distance=96,
    )
    defaults.update(overrides)
    return MonitorConfig(**defaults)


HASH_A = "a" * 32
HASH_B = "b" * 32


class TestRateLimiting:
    def test_accept_up_to_rate_limit(self):
        v = ReportValidator(_cfg(compromise_rate_limit=3))
        for i in range(3):
            r = v.validate("reporter", "victim", HASH_A, 2, False, [])
            assert r.accepted is True

    def test_reject_after_rate_limit(self):
        v = ReportValidator(_cfg(compromise_rate_limit=3))
        for _ in range(3):
            v.validate("reporter", "victim", HASH_A, 2, False, [])
        r = v.validate("reporter", "victim", HASH_A, 2, False, [])
        assert r.accepted is False
        assert r.rejection_reason == "rate_limited"

    def test_accept_after_window_expires(self, monkeypatch):
        v = ReportValidator(_cfg(compromise_rate_limit=2, compromise_rate_window=10))
        base = time.time()
        monkeypatch.setattr(time, "time", lambda: base)
        v.validate("reporter", "victim", HASH_A, 2, False, [])
        v.validate("reporter", "victim", HASH_A, 2, False, [])

        # Should be rejected now
        r = v.validate("reporter", "victim", HASH_A, 2, False, [])
        assert r.accepted is False

        # Advance past the window
        monkeypatch.setattr(time, "time", lambda: base + 11)
        r = v.validate("reporter", "victim", HASH_A, 2, False, [])
        assert r.accepted is True

    def test_different_reporters_have_separate_counters(self):
        v = ReportValidator(_cfg(compromise_rate_limit=1))
        r1 = v.validate("reporter-1", "victim", HASH_A, 2, False, [])
        assert r1.accepted is True
        r2 = v.validate("reporter-2", "victim", HASH_A, 2, False, [])
        assert r2.accepted is True


class TestTrustTier:
    def test_low_trust_not_confirmed(self):
        v = ReportValidator(_cfg(compromise_min_trust_tier=1, compromise_quorum=1))
        r = v.validate("reporter", "victim", HASH_A, 0, False, [])
        assert r.accepted is True
        assert r.hash_confirmed is False
        assert r.rejection_reason == "low_trust"

    def test_sufficient_trust_proceeds(self):
        v = ReportValidator(_cfg(compromise_min_trust_tier=1, compromise_quorum=1))
        r = v.validate("reporter", "victim", HASH_A, 1, False, [])
        assert r.accepted is True
        assert r.hash_confirmed is True


class TestQuarantinedReporter:
    def test_quarantined_not_confirmed(self):
        v = ReportValidator(_cfg(compromise_quorum=1))
        r = v.validate("reporter", "victim", HASH_A, 2, True, [])
        assert r.accepted is True
        assert r.hash_confirmed is False
        assert r.rejection_reason == "reporter_quarantined"


class TestHashConsistency:
    def test_hash_within_distance_accepted(self):
        """Hash close to victim's known hash passes consistency."""
        v = ReportValidator(_cfg(compromise_hash_max_distance=96, compromise_quorum=1))
        # Same hash => distance 0
        r = v.validate("reporter", "victim", HASH_A, 2, False, [HASH_A])
        assert r.accepted is True
        assert r.hash_confirmed is True

    def test_hash_beyond_distance_rejected(self):
        """Hash far from victim's known hashes is inconsistent."""
        v = ReportValidator(_cfg(compromise_hash_max_distance=4, compromise_quorum=1))
        # 'a' (0x61) vs 'b' (0x62) differ in 2 bits per byte, 32 bytes = 64 bits differ
        r = v.validate("reporter", "victim", HASH_B, 2, False, [HASH_A])
        assert r.accepted is True
        assert r.hash_confirmed is False
        assert r.rejection_reason == "hash_inconsistent"

    def test_no_known_hashes_skips_check(self):
        """With no known victim hashes, consistency check is skipped."""
        v = ReportValidator(_cfg(compromise_hash_max_distance=4, compromise_quorum=1))
        r = v.validate("reporter", "victim", HASH_B, 2, False, [])
        assert r.accepted is True
        assert r.hash_confirmed is True


class TestQuorum:
    def test_single_reporter_pending(self):
        v = ReportValidator(_cfg(compromise_quorum=2))
        r = v.validate("reporter-1", "victim", HASH_A, 2, False, [])
        assert r.accepted is True
        assert r.hash_confirmed is False
        assert r.rejection_reason == "pending_quorum"

    def test_second_reporter_confirms(self):
        v = ReportValidator(_cfg(compromise_quorum=2))
        v.validate("reporter-1", "victim", HASH_A, 2, False, [])
        r = v.validate("reporter-2", "victim", HASH_A, 2, False, [])
        assert r.accepted is True
        assert r.hash_confirmed is True

    def test_same_reporter_twice_no_confirm(self):
        """Same reporter doesn't count twice toward quorum."""
        v = ReportValidator(_cfg(compromise_quorum=2))
        v.validate("reporter-1", "victim", HASH_A, 2, False, [])
        r = v.validate("reporter-1", "victim", HASH_A, 2, False, [])
        assert r.hash_confirmed is False

    def test_similarity_grouping(self):
        """Two hashes within Hamming distance 16 merge into same group."""
        v = ReportValidator(_cfg(compromise_quorum=2))
        # 'a' * 32 = 0x61 repeated -> certain bit pattern
        # Create a hash that differs by only 1 bit from HASH_A
        h_int = int(HASH_A, 16) ^ 1  # flip 1 bit
        similar_hash = f"{h_int:032x}"
        v.validate("reporter-1", "victim", HASH_A, 2, False, [])
        r = v.validate("reporter-2", "victim", similar_hash, 2, False, [])
        assert r.hash_confirmed is True

    def test_quorum_one_immediate(self):
        """With quorum=1, single report confirms immediately."""
        v = ReportValidator(_cfg(compromise_quorum=1))
        r = v.validate("reporter-1", "victim", HASH_A, 2, False, [])
        assert r.accepted is True
        assert r.hash_confirmed is True


class TestEmptyHash:
    def test_empty_hash_skips_all_checks(self):
        v = ReportValidator(_cfg(compromise_quorum=2))
        r = v.validate("reporter", "victim", "", 0, True, [HASH_A])
        assert r.accepted is True
        assert r.hash_confirmed is False
        assert r.rejection_reason == ""


class TestPendingPruning:
    def test_old_pending_entries_pruned(self, monkeypatch):
        v = ReportValidator(_cfg(compromise_quorum=2, compromise_rate_window=10))
        base = time.time()
        monkeypatch.setattr(time, "time", lambda: base)
        v.validate("reporter-1", "victim", HASH_A, 2, False, [])

        # Advance past 2 * rate_window
        monkeypatch.setattr(time, "time", lambda: base + 21)
        # Second reporter after expiry — old entry should be pruned, new pending
        r = v.validate("reporter-2", "victim", HASH_A, 2, False, [])
        assert r.hash_confirmed is False
        assert r.rejection_reason == "pending_quorum"
