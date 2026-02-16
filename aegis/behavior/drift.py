"""Drift detection for agent behavioral anomalies."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.behavior.tracker import BehaviorEvent, BehaviorFingerprint


@dataclass
class DriftResult:
    """Result of a drift check against an established behavioral fingerprint."""

    max_sigma: float
    per_dimension_scores: dict[str, float]
    anomalous_dimensions: list[str]
    is_drifting: bool
    new_tools: list[str]


class DriftDetector:
    """Detects behavioral drift by comparing events against an established fingerprint."""

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self._threshold: float = config.get("drift_threshold", 2.5)

    def check_drift(
        self, fingerprint: BehaviorFingerprint, event: BehaviorEvent
    ) -> DriftResult:
        """Check if a new event drifts from the established fingerprint.

        Computes per-dimension z-scores and flags anomalies beyond the threshold.
        """
        per_dimension_scores: dict[str, float] = {}
        anomalous_dimensions: list[str] = []
        new_tools: list[str] = []

        dims = fingerprint.dimensions

        # --- output_length z-score ---
        ol = dims.get("output_length", {"mean": 0.0, "std": 0.0})
        ol_mean = ol["mean"]
        ol_std = ol["std"]
        ol_value = float(event.output_length)
        ol_sigma = self._compute_zscore(ol_value, ol_mean, ol_std)
        per_dimension_scores["output_length"] = ol_sigma
        if ol_sigma > self._threshold:
            anomalous_dimensions.append("output_length")

        # --- content_type ratio z-score ---
        # Check if the event's content_type ratio deviates from established ratios
        cr = dims.get("content_ratios", {})
        event_ct = event.content_type
        # Expected ratio for this content type (0 if never seen)
        expected_ratio = cr.get(event_ct, 0.0)
        # For a single event, the "value" is 1.0 (this event is 100% that type)
        # The deviation is |1.0 - expected_ratio|; we normalize roughly
        # We use a simple approach: if the content_type is new (ratio 0), flag it
        if expected_ratio == 0.0 and len(cr) > 0:
            ct_sigma = self._threshold + 1.0  # force flag
        else:
            # Not anomalous for content type alone
            ct_sigma = 0.0
        per_dimension_scores["content_ratios"] = ct_sigma
        if ct_sigma > self._threshold:
            anomalous_dimensions.append("content_ratios")

        # --- new tool detection ---
        td = dims.get("tool_distribution", {})
        if event.tool_used is not None:
            if event.tool_used not in td:
                new_tools.append(event.tool_used)

        # --- is_drifting ---
        max_sigma = max(per_dimension_scores.values()) if per_dimension_scores else 0.0
        is_drifting = max_sigma > self._threshold or len(new_tools) > 0

        return DriftResult(
            max_sigma=max_sigma,
            per_dimension_scores=per_dimension_scores,
            anomalous_dimensions=anomalous_dimensions,
            is_drifting=is_drifting,
            new_tools=new_tools,
        )

    @staticmethod
    def _compute_zscore(value: float, mean: float, std: float) -> float:
        """Compute z-score with zero-variance handling.

        If std is 0 and the value differs from the mean, use ratio-based detection
        to flag the anomaly. Returns a large sigma in that case.
        """
        if std == 0.0:
            if value == mean:
                return 0.0
            # Ratio-based fallback: flag as highly anomalous
            # Use the ratio of difference to mean (or absolute diff if mean is 0)
            if mean != 0.0:
                return abs(value - mean) / abs(mean) * 10.0
            else:
                return float("inf")
        return abs(value - mean) / std
