"""scikit-learn IsolationForest anomaly detection — optional multivariate behavioral anomaly detection.

Augments the existing z-score DriftDetector with multivariate anomaly detection
using sklearn's IsolationForest. Automatically trains on a configurable number
of initial behavioral fingerprints, then flags anomalies.

Requires: pip install aegis-shield[ml-behavior]
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from aegis.core.config import IsolationForestConfig

logger = logging.getLogger(__name__)

_SKLEARN_AVAILABLE: bool | None = None


def is_sklearn_available() -> bool:
    """Check whether scikit-learn is importable."""
    global _SKLEARN_AVAILABLE
    if _SKLEARN_AVAILABLE is None:
        try:
            import sklearn  # noqa: F401

            _SKLEARN_AVAILABLE = True
        except ImportError:
            _SKLEARN_AVAILABLE = False
    return _SKLEARN_AVAILABLE


@dataclass
class IsolationForestResult:
    """Result from IsolationForest anomaly check."""

    is_anomaly: bool = False
    anomaly_score: float = 0.0  # 0.0 = normal, 1.0 = highly anomalous
    feature_vector: list[float] = field(default_factory=list)


class IsolationForestDetector:
    """Multivariate anomaly detection using sklearn's IsolationForest.

    Collects behavioral fingerprints into a training buffer. Once
    min_samples are collected, fits the IsolationForest model and
    begins flagging anomalies.

    Args:
        config: IsolationForestConfig with model hyperparameters.
    """

    def __init__(self, config: IsolationForestConfig | None = None) -> None:
        self._config = config or IsolationForestConfig()
        self._model = None
        self._is_fitted = False
        self._training_buffer: list[list[float]] = []
        self._min_samples = self._config.min_samples
        self._lock = threading.Lock()

    @property
    def is_fitted(self) -> bool:
        """Whether the model has been trained."""
        return self._is_fitted

    @property
    def training_buffer_size(self) -> int:
        """Number of samples in the training buffer."""
        return len(self._training_buffer)

    def fingerprint_to_features(self, fingerprint: Any) -> list[float]:
        """Extract a fixed-length feature vector from a BehaviorFingerprint.

        Feature layout (16 dimensions):
        - [0] output_length mean
        - [1] output_length std
        - [2-5] content ratios (text, code, url, structured)
        - [6-15] top-10 tool usage ratios (sorted by tool name, padded)

        Args:
            fingerprint: A BehaviorFingerprint with a .dimensions dict.

        Returns:
            Fixed-length list of floats.
        """
        dims = fingerprint.dimensions

        # Output length stats
        ol = dims.get("output_length", {})
        features = [
            ol.get("mean", 0.0),
            ol.get("std", 0.0),
        ]

        # Content ratios (fixed order)
        cr = dims.get("content_ratios", {})
        for ct in ("text", "code", "url", "structured"):
            features.append(cr.get(ct, 0.0))

        # Tool distribution (sorted keys for determinism, pad to 10)
        td = dims.get("tool_distribution", {})
        tool_vals = [v for _, v in sorted(td.items())]
        features.extend(tool_vals[:10])
        features.extend([0.0] * max(0, 10 - len(tool_vals)))

        return features

    def record_and_check(self, fingerprint: Any) -> IsolationForestResult:
        """Record a fingerprint and check for anomalies.

        During the training phase (before min_samples collected), adds
        the fingerprint to the training buffer and returns a non-anomaly
        result. Once trained, returns anomaly scores.

        Args:
            fingerprint: A BehaviorFingerprint object.

        Returns:
            IsolationForestResult with anomaly status and score.
        """
        if not is_sklearn_available() or not self._config.enabled:
            return IsolationForestResult()

        features = self.fingerprint_to_features(fingerprint)

        with self._lock:
            if not self._is_fitted:
                self._training_buffer.append(features)
                if len(self._training_buffer) >= self._min_samples:
                    self._fit()
                return IsolationForestResult(feature_vector=features)

        # Predict (model is thread-safe for predict after fit)
        try:
            import numpy as np

            X = np.array([features])
            score = self._model.score_samples(X)[0]
            prediction = self._model.predict(X)[0]

            # Normalize: sklearn scores are negative (more negative = more anomalous)
            # Map to 0-1 range where higher = more anomalous
            normalized_score = max(0.0, min(1.0, -score))

            return IsolationForestResult(
                is_anomaly=bool(prediction == -1),
                anomaly_score=float(round(normalized_score, 4)),
                feature_vector=features,
            )
        except Exception:
            logger.debug("IsolationForest prediction failed", exc_info=True)
            return IsolationForestResult(feature_vector=features)

    def _fit(self) -> None:
        """Train the IsolationForest on the collected training buffer.

        Called internally once min_samples are collected. Must be called
        while holding self._lock.
        """
        try:
            from sklearn.ensemble import IsolationForest
            import numpy as np

            X = np.array(self._training_buffer)
            self._model = IsolationForest(
                n_estimators=self._config.n_estimators,
                contamination=self._config.contamination,
                random_state=42,
            )
            self._model.fit(X)
            self._is_fitted = True
            logger.info(
                "IsolationForest trained on %d samples (%d features)",
                len(self._training_buffer),
                X.shape[1],
            )
        except Exception:
            logger.warning("IsolationForest training failed", exc_info=True)
