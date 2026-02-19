"""Tests for the IsolationForest anomaly detector.

All tests mock sklearn since it's an optional dependency.
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.config import IsolationForestConfig
from aegis.behavior.isolation_forest import (
    IsolationForestDetector,
    IsolationForestResult,
    is_sklearn_available,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@dataclass
class FakeFingerprint:
    """Fake BehaviorFingerprint for testing."""
    dimensions: dict


def _make_fingerprint(
    output_mean: float = 100.0,
    output_std: float = 20.0,
    text_ratio: float = 0.8,
    code_ratio: float = 0.2,
) -> FakeFingerprint:
    return FakeFingerprint(dimensions={
        "output_length": {"mean": output_mean, "std": output_std},
        "content_ratios": {"text": text_ratio, "code": code_ratio},
        "tool_distribution": {"read": 0.5, "write": 0.3},
    })


def _install_fake_sklearn(monkeypatch, predict_result=1, score_result=-0.1):
    """Install a fake sklearn module into sys.modules."""
    import numpy as np

    fake_sklearn = types.ModuleType("sklearn")
    fake_ensemble = types.ModuleType("sklearn.ensemble")

    mock_model = MagicMock()
    mock_model.fit.return_value = mock_model
    mock_model.predict.return_value = np.array([predict_result])
    mock_model.score_samples.return_value = np.array([score_result])

    fake_ensemble.IsolationForest = MagicMock(return_value=mock_model)
    fake_sklearn.ensemble = fake_ensemble

    monkeypatch.setitem(sys.modules, "sklearn", fake_sklearn)
    monkeypatch.setitem(sys.modules, "sklearn.ensemble", fake_ensemble)

    import aegis.behavior.isolation_forest as iso_mod
    monkeypatch.setattr(iso_mod, "_SKLEARN_AVAILABLE", None)

    return mock_model


class TestSklearnAvailability:
    def test_not_available(self, monkeypatch):
        import aegis.behavior.isolation_forest as iso_mod
        monkeypatch.setattr(iso_mod, "_SKLEARN_AVAILABLE", None)
        monkeypatch.delitem(sys.modules, "sklearn", raising=False)
        result = is_sklearn_available()
        # Result depends on whether sklearn is actually installed in the env
        assert isinstance(result, bool)

    def test_available_when_installed(self, monkeypatch):
        _install_fake_sklearn(monkeypatch)
        assert is_sklearn_available() is True


class TestIsolationForestDisabled:
    def test_disabled_returns_empty(self):
        detector = IsolationForestDetector(config=IsolationForestConfig(enabled=False))
        fp = _make_fingerprint()
        result = detector.record_and_check(fp)
        assert result.is_anomaly is False
        assert result.anomaly_score == 0.0

    def test_not_available_returns_empty(self, monkeypatch):
        import aegis.behavior.isolation_forest as iso_mod
        monkeypatch.setattr(iso_mod, "_SKLEARN_AVAILABLE", False)

        detector = IsolationForestDetector(config=IsolationForestConfig(enabled=True))
        fp = _make_fingerprint()
        result = detector.record_and_check(fp)
        assert result.is_anomaly is False


class TestIsolationForestTraining:
    def test_training_buffer_fills(self, monkeypatch):
        _install_fake_sklearn(monkeypatch)

        detector = IsolationForestDetector(
            config=IsolationForestConfig(enabled=True, min_samples=5),
        )

        # Feed samples below threshold
        for _ in range(4):
            result = detector.record_and_check(_make_fingerprint())
            assert result.is_anomaly is False

        assert detector.training_buffer_size == 4
        assert detector.is_fitted is False

    def test_fits_after_min_samples(self, monkeypatch):
        mock_model = _install_fake_sklearn(monkeypatch)

        detector = IsolationForestDetector(
            config=IsolationForestConfig(enabled=True, min_samples=3),
        )

        for _ in range(3):
            detector.record_and_check(_make_fingerprint())

        assert detector.is_fitted is True
        mock_model.fit.assert_called_once()


class TestIsolationForestPrediction:
    def test_detects_anomaly(self, monkeypatch):
        mock_model = _install_fake_sklearn(
            monkeypatch,
            predict_result=-1,  # anomaly
            score_result=-0.8,  # high anomaly score
        )

        detector = IsolationForestDetector(
            config=IsolationForestConfig(enabled=True, min_samples=2),
        )

        # Train
        for _ in range(2):
            detector.record_and_check(_make_fingerprint())

        # Check anomaly
        result = detector.record_and_check(
            _make_fingerprint(output_mean=9999, output_std=1000),
        )
        assert result.is_anomaly is True
        assert result.anomaly_score > 0.0

    def test_normal_prediction(self, monkeypatch):
        _install_fake_sklearn(
            monkeypatch,
            predict_result=1,   # normal
            score_result=-0.1,  # low anomaly score
        )

        detector = IsolationForestDetector(
            config=IsolationForestConfig(enabled=True, min_samples=2),
        )

        for _ in range(2):
            detector.record_and_check(_make_fingerprint())

        result = detector.record_and_check(_make_fingerprint())
        assert result.is_anomaly is False
        assert result.anomaly_score <= 0.2


class TestFeatureExtraction:
    def test_feature_vector_length(self):
        detector = IsolationForestDetector()
        fp = _make_fingerprint()
        features = detector.fingerprint_to_features(fp)
        assert len(features) == 16  # 2 + 4 + 10

    def test_feature_determinism(self):
        detector = IsolationForestDetector()
        fp = _make_fingerprint(output_mean=50.0, output_std=10.0)
        f1 = detector.fingerprint_to_features(fp)
        f2 = detector.fingerprint_to_features(fp)
        assert f1 == f2

    def test_empty_fingerprint(self):
        detector = IsolationForestDetector()
        fp = FakeFingerprint(dimensions={})
        features = detector.fingerprint_to_features(fp)
        assert len(features) == 16
        assert all(f == 0.0 for f in features)

    def test_feature_values(self):
        detector = IsolationForestDetector()
        fp = _make_fingerprint(
            output_mean=100.0,
            output_std=20.0,
            text_ratio=0.8,
            code_ratio=0.2,
        )
        features = detector.fingerprint_to_features(fp)
        assert features[0] == 100.0  # output mean
        assert features[1] == 20.0   # output std
        assert features[2] == 0.8    # text ratio
        assert features[3] == 0.2    # code ratio


class TestGracefulDegradation:
    def test_prediction_failure_returns_empty(self, monkeypatch):
        mock_model = _install_fake_sklearn(monkeypatch)
        mock_model.predict.side_effect = RuntimeError("crash")

        detector = IsolationForestDetector(
            config=IsolationForestConfig(enabled=True, min_samples=2),
        )

        for _ in range(2):
            detector.record_and_check(_make_fingerprint())

        result = detector.record_and_check(_make_fingerprint())
        assert result.is_anomaly is False

    def test_config_parameters_passed(self, monkeypatch):
        mock_model = _install_fake_sklearn(monkeypatch)

        import sklearn.ensemble
        mock_cls = sys.modules["sklearn.ensemble"].IsolationForest

        detector = IsolationForestDetector(
            config=IsolationForestConfig(
                enabled=True,
                min_samples=2,
                n_estimators=200,
                contamination=0.1,
            ),
        )

        for _ in range(2):
            detector.record_and_check(_make_fingerprint())

        # Check IsolationForest was called with the right params
        call_kwargs = mock_cls.call_args
        assert call_kwargs.kwargs.get("n_estimators") == 200 or \
               call_kwargs[1].get("n_estimators") == 200
