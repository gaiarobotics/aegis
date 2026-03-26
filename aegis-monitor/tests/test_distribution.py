"""Tests for Clio-inspired attack distribution tracking and shift detection."""

import time

import pytest

from monitor.distribution import (
    AttackDistributionTracker,
    DistributionConfig,
)


class TestAttackDistributionTracker:
    def test_record_event(self):
        tracker = AttackDistributionTracker()
        tracker.record_event("prompt_injection")
        tracker.record_event("prompt_injection")
        tracker.record_event("data_exfiltration")
        assert tracker._current_window["prompt_injection"] == 2
        assert tracker._current_window["data_exfiltration"] == 1

    def test_no_shift_without_history(self):
        tracker = AttackDistributionTracker()
        tracker.record_event("prompt_injection")
        assert tracker.check_shift() is None

    @staticmethod
    def _force_rotate(tracker):
        """Force a window rotation by directly appending current to history."""
        if tracker._current_window:
            tracker._windows.append(dict(tracker._current_window))
        tracker._current_window = {}
        tracker._window_start = time.time()

    def test_shift_detection(self):
        tracker = AttackDistributionTracker(
            config=DistributionConfig(
                window_minutes=60,
                shift_threshold=0.1,
            ),
        )
        # Build baseline: mostly prompt_injection
        for _ in range(10):
            tracker.record_event("prompt_injection")
        self._force_rotate(tracker)

        for _ in range(10):
            tracker.record_event("prompt_injection")
        self._force_rotate(tracker)

        # Current window: completely different distribution
        for _ in range(10):
            tracker.record_event("data_exfiltration")

        shift = tracker.check_shift()
        assert shift is not None
        assert shift.divergence > 0.1
        assert "data_exfiltration" in shift.new_categories or "data_exfiltration" in shift.spiking_categories

    def test_no_shift_same_distribution(self):
        tracker = AttackDistributionTracker(
            config=DistributionConfig(
                window_minutes=60,
                shift_threshold=0.3,
            ),
        )
        # Build baseline
        for _ in range(10):
            tracker.record_event("prompt_injection")
        self._force_rotate(tracker)

        for _ in range(10):
            tracker.record_event("prompt_injection")
        self._force_rotate(tracker)

        # Current: same distribution
        for _ in range(10):
            tracker.record_event("prompt_injection")

        shift = tracker.check_shift()
        assert shift is None

    def test_distribution_history(self):
        tracker = AttackDistributionTracker(
            config=DistributionConfig(window_minutes=60),
        )
        tracker.record_event("a")
        tracker.record_event("b")
        self._force_rotate(tracker)

        tracker.record_event("c")

        history = tracker.get_distribution_history()
        assert len(history) == 2  # 1 historical + 1 current
        assert history[-1].get("is_current") is True

    def test_get_recent_alerts(self):
        tracker = AttackDistributionTracker(
            config=DistributionConfig(
                window_minutes=60,
                shift_threshold=0.01,
            ),
        )
        # Build baseline
        for _ in range(5):
            tracker.record_event("a")
        self._force_rotate(tracker)

        for _ in range(5):
            tracker.record_event("a")
        self._force_rotate(tracker)

        # Trigger shift
        for _ in range(5):
            tracker.record_event("b")
        tracker.check_shift()

        alerts = tracker.get_recent_alerts()
        assert len(alerts) >= 1
        assert "divergence" in alerts[0]

    def test_alert_to_dict(self):
        tracker = AttackDistributionTracker(
            config=DistributionConfig(
                window_minutes=60,
                shift_threshold=0.01,
            ),
        )
        for _ in range(5):
            tracker.record_event("x")
        self._force_rotate(tracker)
        for _ in range(5):
            tracker.record_event("x")
        self._force_rotate(tracker)
        for _ in range(5):
            tracker.record_event("y")

        shift = tracker.check_shift()
        if shift is not None:
            d = shift.to_dict()
            assert isinstance(d["divergence"], float)
            assert isinstance(d["new_categories"], list)
            assert isinstance(d["timestamp"], float)

    def test_jensen_shannon_identical(self):
        tracker = AttackDistributionTracker()
        p = {"a": 0.5, "b": 0.5}
        assert tracker._jensen_shannon(p, p) == pytest.approx(0.0, abs=1e-10)

    def test_jensen_shannon_disjoint(self):
        tracker = AttackDistributionTracker()
        p = {"a": 1.0}
        q = {"b": 1.0}
        js = tracker._jensen_shannon(p, q)
        assert js == pytest.approx(1.0, abs=0.01)

    def test_jensen_shannon_bounded(self):
        tracker = AttackDistributionTracker()
        p = {"a": 0.7, "b": 0.3}
        q = {"a": 0.3, "b": 0.7}
        js = tracker._jensen_shannon(p, q)
        assert 0.0 <= js <= 1.0

    def test_empty_window(self):
        tracker = AttackDistributionTracker()
        assert tracker.check_shift() is None

    def test_spike_detection(self):
        tracker = AttackDistributionTracker(
            config=DistributionConfig(spike_ratio=1.5),
        )
        baseline = {"a": 0.5, "b": 0.5}
        current = {"a": 0.95, "b": 0.05}
        spikes = tracker._find_spikes(baseline, current)
        assert "a" in spikes  # 0.95/0.5 = 1.9 > 1.5 spike_ratio

    def test_decline_detection(self):
        tracker = AttackDistributionTracker()
        baseline = {"a": 0.5, "b": 0.5}
        current = {"a": 0.95, "b": 0.05}
        declines = tracker._find_declines(baseline, current)
        assert "b" in declines
