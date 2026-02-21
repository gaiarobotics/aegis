"""Tests for the Presidio PII detection adapter.

All tests mock the presidio packages since they're optional heavy dependencies.
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.config import PiiConfig
from aegis.scanner.pii import (
    PiiDetector,
    PiiEntity,
    PiiResult,
    is_presidio_available,
)


# ---------------------------------------------------------------------------
# Helpers: fake presidio modules
# ---------------------------------------------------------------------------


@dataclass
class FakeAnalyzerResult:
    entity_type: str
    start: int
    end: int
    score: float


@dataclass
class FakeAnonymizedResult:
    text: str


def _install_fake_presidio(monkeypatch, analyzer_results=None):
    """Install fake presidio modules into sys.modules."""
    fake_analyzer_mod = types.ModuleType("presidio_analyzer")
    fake_anonymizer_mod = types.ModuleType("presidio_anonymizer")
    fake_anon_entities = types.ModuleType("presidio_anonymizer.entities")

    # AnalyzerEngine mock
    mock_engine = MagicMock()
    mock_engine.analyze.return_value = analyzer_results or []
    fake_analyzer_mod.AnalyzerEngine = MagicMock(return_value=mock_engine)

    # AnonymizerEngine mock
    mock_anon_engine = MagicMock()
    mock_anon_engine.anonymize.return_value = FakeAnonymizedResult(text="[REDACTED]")
    fake_anonymizer_mod.AnonymizerEngine = MagicMock(return_value=mock_anon_engine)

    # OperatorConfig mock
    fake_anon_entities.OperatorConfig = MagicMock()

    monkeypatch.setitem(sys.modules, "presidio_analyzer", fake_analyzer_mod)
    monkeypatch.setitem(sys.modules, "presidio_anonymizer", fake_anonymizer_mod)
    monkeypatch.setitem(sys.modules, "presidio_anonymizer.entities", fake_anon_entities)

    # Reset availability cache
    import aegis.scanner.pii as pii_mod

    monkeypatch.setattr(pii_mod, "_PRESIDIO_AVAILABLE", None)

    return mock_engine, mock_anon_engine


class TestPresidioAvailability:
    def test_not_available_when_not_installed(self, monkeypatch):
        import aegis.scanner.pii as pii_mod

        monkeypatch.setattr(pii_mod, "_PRESIDIO_AVAILABLE", None)
        # Ensure presidio is NOT in sys.modules
        monkeypatch.delitem(sys.modules, "presidio_analyzer", raising=False)
        assert is_presidio_available() is False

    def test_available_when_installed(self, monkeypatch):
        _install_fake_presidio(monkeypatch)
        assert is_presidio_available() is True


class TestPiiDetectorDisabled:
    def test_disabled_returns_original_text(self):
        detector = PiiDetector(config=PiiConfig(enabled=False))
        result = detector.detect("my email is test@example.com")
        assert result.had_pii is False
        assert result.redacted_text == "my email is test@example.com"
        assert result.entities == []

    def test_disabled_redact_returns_original_text(self):
        detector = PiiDetector(config=PiiConfig(enabled=False))
        result = detector.redact("my email is test@example.com")
        assert result.had_pii is False
        assert result.redacted_text == "my email is test@example.com"


class TestPiiDetectorEnabled:
    def test_detect_finds_entities(self, monkeypatch):
        analyzer_results = [
            FakeAnalyzerResult(
                entity_type="EMAIL_ADDRESS",
                start=12,
                end=28,
                score=0.85,
            )
        ]
        mock_engine, _ = _install_fake_presidio(monkeypatch, analyzer_results)

        detector = PiiDetector(config=PiiConfig(enabled=True))
        text = "my email is test@example.com"
        result = detector.detect(text)

        assert result.had_pii is True
        assert len(result.entities) == 1
        assert result.entities[0].entity_type == "EMAIL_ADDRESS"
        assert result.entities[0].text == "test@example.com"
        assert result.entities[0].score == 0.85

    def test_detect_no_pii(self, monkeypatch):
        _install_fake_presidio(monkeypatch, analyzer_results=[])

        detector = PiiDetector(config=PiiConfig(enabled=True))
        result = detector.detect("hello world")

        assert result.had_pii is False
        assert result.entities == []

    def test_redact_replaces_pii(self, monkeypatch):
        analyzer_results = [
            FakeAnalyzerResult(
                entity_type="EMAIL_ADDRESS",
                start=12,
                end=28,
                score=0.85,
            )
        ]
        _, mock_anon = _install_fake_presidio(monkeypatch, analyzer_results)
        mock_anon.anonymize.return_value = FakeAnonymizedResult(
            text="my email is ****************"
        )

        detector = PiiDetector(config=PiiConfig(enabled=True))
        result = detector.redact("my email is test@example.com")

        assert result.had_pii is True
        assert "test@example.com" not in result.redacted_text

    def test_custom_entities(self, monkeypatch):
        mock_engine, _ = _install_fake_presidio(monkeypatch, [])

        detector = PiiDetector(
            config=PiiConfig(
                enabled=True,
                entities=["PHONE_NUMBER"],
            )
        )
        detector.detect("call me at 555-0100")

        # Verify analyzer was called with only the configured entities
        call_kwargs = mock_engine.analyze.call_args
        assert call_kwargs.kwargs.get("entities") == [
            "PHONE_NUMBER"
        ] or call_kwargs[1].get("entities") == ["PHONE_NUMBER"]

    def test_custom_score_threshold(self, monkeypatch):
        mock_engine, _ = _install_fake_presidio(monkeypatch, [])

        detector = PiiDetector(
            config=PiiConfig(
                enabled=True,
                score_threshold=0.9,
            )
        )
        detector.detect("some text")

        call_kwargs = mock_engine.analyze.call_args
        threshold = call_kwargs.kwargs.get(
            "score_threshold"
        ) or call_kwargs[1].get("score_threshold")
        assert threshold == 0.9


class TestPiiDetectorGracefulDegradation:
    def test_no_presidio_returns_empty(self, monkeypatch):
        import aegis.scanner.pii as pii_mod

        monkeypatch.setattr(pii_mod, "_PRESIDIO_AVAILABLE", False)

        detector = PiiDetector(config=PiiConfig(enabled=True))
        result = detector.detect("my email is test@example.com")

        assert result.had_pii is False
        assert result.redacted_text == "my email is test@example.com"

    def test_analyzer_exception_returns_empty(self, monkeypatch):
        mock_engine, _ = _install_fake_presidio(monkeypatch)
        mock_engine.analyze.side_effect = RuntimeError("crash")

        detector = PiiDetector(config=PiiConfig(enabled=True))
        result = detector.detect("test text")

        assert result.had_pii is False
        assert result.redacted_text == "test text"


class TestManualRedaction:
    def test_manual_redact_replaces_text(self):
        detector = PiiDetector(config=PiiConfig(enabled=True, redact_char="*"))
        entities = [
            PiiEntity(
                entity_type="EMAIL",
                text="test@test.com",
                start=5,
                end=18,
                score=0.9,
            ),
        ]
        result = detector._manual_redact("addr test@test.com end", entities)
        assert "test@test.com" not in result
        assert "*" in result

    def test_manual_redact_multiple_entities(self):
        detector = PiiDetector(config=PiiConfig(enabled=True, redact_char="#"))
        entities = [
            PiiEntity(
                entity_type="EMAIL", text="a@b.c", start=0, end=5, score=0.9
            ),
            PiiEntity(
                entity_type="PHONE", text="555", start=10, end=13, score=0.8
            ),
        ]
        result = detector._manual_redact("a@b.c and 555 done", entities)
        assert "a@b.c" not in result
        assert "555" not in result
