"""Attack distribution tracking and shift detection.

Inspired by Clio's temporal topic distribution monitoring: tracks the
distribution of attack categories over time windows and alerts when the
distribution shifts significantly (new attack types emerging, sudden spikes).

Uses Jensen-Shannon divergence for distribution comparison — symmetric,
bounded [0, 1], and works well for sparse categorical distributions.

No ML dependencies required — pure Python implementation.
"""

from __future__ import annotations

import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DistributionShiftAlert:
    """Alert for a detected shift in the attack-type distribution."""

    divergence: float  # JS divergence value
    new_categories: list[str]  # categories not seen in baseline
    spiking_categories: list[str]  # categories with significantly increased frequency
    declining_categories: list[str]  # categories with significantly decreased frequency
    current_distribution: dict[str, float]
    baseline_distribution: dict[str, float]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "divergence": round(self.divergence, 4),
            "new_categories": self.new_categories,
            "spiking_categories": self.spiking_categories,
            "declining_categories": self.declining_categories,
            "current_distribution": {
                k: round(v, 4) for k, v in self.current_distribution.items()
            },
            "baseline_distribution": {
                k: round(v, 4) for k, v in self.baseline_distribution.items()
            },
            "timestamp": self.timestamp,
        }


@dataclass
class DistributionConfig:
    """Configuration for distribution tracking."""

    window_minutes: int = 60  # width of each time window
    max_windows: int = 24  # number of historical windows to retain
    shift_threshold: float = 0.3  # JS divergence threshold for alerting
    spike_ratio: float = 2.0  # ratio above baseline to count as a spike


class AttackDistributionTracker:
    """Tracks attack-type distributions over time windows and alerts on shifts.

    Inspired by how Clio tracks topic distributions over time to detect
    emerging patterns and coordinated campaigns.
    """

    def __init__(self, config: DistributionConfig | None = None) -> None:
        cfg = config or DistributionConfig()
        self._window_minutes = cfg.window_minutes
        self._shift_threshold = cfg.shift_threshold
        self._spike_ratio = cfg.spike_ratio

        self._windows: deque[dict[str, int]] = deque(maxlen=cfg.max_windows)
        self._current_window: dict[str, int] = {}
        self._window_start: float = time.time()
        self._alerts: deque[DistributionShiftAlert] = deque(maxlen=100)

    def record_event(self, attack_category: str) -> None:
        """Record an event's attack category in the current window."""
        self._maybe_rotate_window()
        self._current_window[attack_category] = (
            self._current_window.get(attack_category, 0) + 1
        )

    def check_shift(self) -> DistributionShiftAlert | None:
        """Compare current window to historical baseline.

        Returns a ``DistributionShiftAlert`` if the Jensen-Shannon divergence
        exceeds the configured threshold, otherwise ``None``.
        """
        self._maybe_rotate_window()

        if len(self._windows) < 2:
            return None

        if not self._current_window:
            return None

        baseline = self._compute_baseline()
        current = self._normalize(self._current_window)

        if not baseline:
            return None

        divergence = self._jensen_shannon(baseline, current)

        if divergence <= self._shift_threshold:
            return None

        new_cats = sorted(set(current) - set(baseline))
        spiking = self._find_spikes(baseline, current)
        declining = self._find_declines(baseline, current)

        alert = DistributionShiftAlert(
            divergence=divergence,
            new_categories=new_cats,
            spiking_categories=spiking,
            declining_categories=declining,
            current_distribution=current,
            baseline_distribution=baseline,
        )
        self._alerts.append(alert)
        return alert

    def get_distribution_history(self) -> list[dict[str, Any]]:
        """Return the distribution of each historical window for charting."""
        history: list[dict[str, Any]] = []
        for i, window in enumerate(self._windows):
            total = sum(window.values())
            if total == 0:
                continue
            history.append({
                "window_index": i,
                "total_events": total,
                "distribution": {k: v / total for k, v in window.items()},
            })
        # Include current window
        total = sum(self._current_window.values())
        if total > 0:
            history.append({
                "window_index": len(self._windows),
                "total_events": total,
                "distribution": {
                    k: v / total for k, v in self._current_window.items()
                },
                "is_current": True,
            })
        return history

    def get_recent_alerts(self, max_age_seconds: float = 3600.0) -> list[dict]:
        """Return recent distribution shift alerts."""
        cutoff = time.time() - max_age_seconds
        return [a.to_dict() for a in self._alerts if a.timestamp >= cutoff]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _maybe_rotate_window(self) -> None:
        """Rotate the current window into history if the time window has elapsed."""
        now = time.time()
        elapsed = (now - self._window_start) / 60.0
        if elapsed >= self._window_minutes:
            if self._current_window:
                self._windows.append(dict(self._current_window))
            self._current_window = {}
            self._window_start = now

    def _compute_baseline(self) -> dict[str, float]:
        """Compute average distribution across historical windows."""
        totals: dict[str, float] = {}
        count = len(self._windows)
        if count == 0:
            return {}
        for window in self._windows:
            window_total = sum(window.values())
            if window_total == 0:
                continue
            for cat, cnt in window.items():
                totals[cat] = totals.get(cat, 0.0) + cnt / window_total
        # Average
        return {cat: val / count for cat, val in totals.items()}

    @staticmethod
    def _normalize(window: dict[str, int]) -> dict[str, float]:
        """Normalize counts to a probability distribution."""
        total = sum(window.values())
        if total == 0:
            return {}
        return {cat: cnt / total for cat, cnt in window.items()}

    @staticmethod
    def _jensen_shannon(p: dict[str, float], q: dict[str, float]) -> float:
        """Compute Jensen-Shannon divergence between two distributions.

        Returns a value in [0, 1].  Uses base-2 logarithm so the result
        is bounded by 1.
        """
        all_keys = set(p) | set(q)
        if not all_keys:
            return 0.0

        # Build aligned probability vectors with smoothing
        epsilon = 1e-12
        m: dict[str, float] = {}
        for k in all_keys:
            m[k] = 0.5 * (p.get(k, 0.0) + q.get(k, 0.0))

        kl_pm = 0.0
        kl_qm = 0.0
        for k in all_keys:
            pk = p.get(k, 0.0)
            qk = q.get(k, 0.0)
            mk = m[k]
            if pk > epsilon and mk > epsilon:
                kl_pm += pk * math.log2(pk / mk)
            if qk > epsilon and mk > epsilon:
                kl_qm += qk * math.log2(qk / mk)

        return 0.5 * kl_pm + 0.5 * kl_qm

    def _find_spikes(
        self, baseline: dict[str, float], current: dict[str, float]
    ) -> list[str]:
        """Find categories whose frequency spiked above the threshold ratio."""
        spikes = []
        for cat, cur_val in current.items():
            base_val = baseline.get(cat, 0.0)
            if base_val > 0:
                if cur_val / base_val >= self._spike_ratio:
                    spikes.append(cat)
            elif cur_val > 0:
                spikes.append(cat)  # new category = spike
        return sorted(spikes)

    def _find_declines(
        self, baseline: dict[str, float], current: dict[str, float]
    ) -> list[str]:
        """Find categories whose frequency dropped significantly."""
        declines = []
        for cat, base_val in baseline.items():
            cur_val = current.get(cat, 0.0)
            if base_val > 0.05 and cur_val < base_val / self._spike_ratio:
                declines.append(cat)
        return sorted(declines)
