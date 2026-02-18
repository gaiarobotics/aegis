"""Drift detection for agent behavioral anomalies."""

from __future__ import annotations

import math
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
        self,
        fingerprint: BehaviorFingerprint,
        event: BehaviorEvent,
        baseline: BehaviorFingerprint | None = None,
    ) -> DriftResult:
        """Check if a new event drifts from the established fingerprint.

        Computes per-dimension z-scores and flags anomalies beyond the threshold.

        If *baseline* is provided (e.g. an anchor fingerprint), it is used as
        the reference instead of *fingerprint* for drift comparison.
        """
        ref = baseline if baseline is not None else fingerprint

        per_dimension_scores: dict[str, float] = {}
        anomalous_dimensions: list[str] = []
        new_tools: list[str] = []

        dims = ref.dimensions

        # --- output_length z-score ---
        ol = dims.get("output_length", {"mean": 0.0, "std": 0.0})
        ol_mean = ol["mean"]
        ol_std = ol["std"]
        ol_value = float(event.output_length)
        ol_sigma = self._compute_zscore(ol_value, ol_mean, ol_std)
        per_dimension_scores["output_length"] = ol_sigma
        if ol_sigma > self._threshold:
            anomalous_dimensions.append("output_length")

        # --- content_type ratio z-score (Bernoulli) ---
        cr = dims.get("content_ratios", {})
        current_cr = fingerprint.dimensions.get("content_ratios", {})
        ct_sigma = 0.0
        if cr:
            # Compare text_ratio between current fingerprint and baseline
            baseline_text_ratio = cr.get("text", 0.0)
            current_text_ratio = current_cr.get("text", 0.0)
            p = baseline_text_ratio
            std = math.sqrt(p * (1 - p)) if 0 < p < 1 else 0.01
            ct_sigma = abs(current_text_ratio - p) / std if std > 0 else 0.0
        per_dimension_scores["content_ratios"] = ct_sigma
        if ct_sigma > self._threshold:
            anomalous_dimensions.append("content_ratios")

        # --- new tool detection ---
        td = dims.get("tool_distribution", {})
        if event.tool_used is not None:
            if event.tool_used not in td:
                new_tools.append(event.tool_used)

        # --- tool distribution ratio z-score ---
        current_td = fingerprint.dimensions.get("tool_distribution", {})
        sample_count = fingerprint.event_count
        td_sigma = 0.0
        for tool, current_ratio in current_td.items():
            if tool in td:
                baseline_ratio = td[tool]
                p = baseline_ratio
                n = max(sample_count, 1)
                std = math.sqrt(p * (1 - p) / n) if 0 < p < 1 else 0.01
                sigma = abs(current_ratio - p) / std if std > 0 else 0.0
                if sigma > td_sigma:
                    td_sigma = sigma
        per_dimension_scores["tool_distribution"] = td_sigma
        if td_sigma > self._threshold:
            anomalous_dimensions.append("tool_distribution")

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
