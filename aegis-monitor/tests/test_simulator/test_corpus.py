"""Tests for the pluggable payload corpus system."""

from __future__ import annotations

import json
import random
import tempfile
from pathlib import Path

import pytest

from monitor.simulator.models import CorpusConfig, Payload, TechniqueType


# ---------------------------------------------------------------------------
# TestBuiltinCorpus
# ---------------------------------------------------------------------------


class TestBuiltinCorpus:
    """Verify the built-in corpus source ships adequate payloads."""

    def test_loads_payloads(self):
        from monitor.simulator.corpus import BuiltinCorpusSource

        payloads = BuiltinCorpusSource().load()
        assert len(payloads) >= 18
        for p in payloads:
            assert isinstance(p, Payload)
            assert p.text
            assert p.source == "builtin"

    def test_has_all_technique_types(self):
        from monitor.simulator.corpus import BuiltinCorpusSource

        payloads = BuiltinCorpusSource().load()
        covered = set()
        for p in payloads:
            for t in p.techniques:
                covered.add(t)
        assert covered == set(TechniqueType), (
            f"Missing techniques: {set(TechniqueType) - covered}"
        )

    def test_has_composite_payloads(self):
        """At least one payload should exercise 2+ techniques."""
        from monitor.simulator.corpus import BuiltinCorpusSource

        payloads = BuiltinCorpusSource().load()
        composites = [p for p in payloads if len(p.techniques) >= 2]
        assert len(composites) >= 1

    def test_severity_values_valid(self):
        from monitor.simulator.corpus import BuiltinCorpusSource

        payloads = BuiltinCorpusSource().load()
        valid_severities = {"low", "medium", "high", "critical"}
        for p in payloads:
            assert p.severity in valid_severities, f"Invalid severity: {p.severity}"


# ---------------------------------------------------------------------------
# TestMoltbookSignatureSource
# ---------------------------------------------------------------------------


class TestMoltbookSignatureSource:
    """Verify Moltbook signature loading and category mapping."""

    def test_loads_from_signatures_file(self):
        from monitor.simulator.corpus import MoltbookSignatureSource

        payloads = MoltbookSignatureSource().load()
        assert len(payloads) >= 12, f"Expected >= 12 payloads, got {len(payloads)}"
        for p in payloads:
            assert isinstance(p, Payload)
            assert p.source == "moltbook"

    def test_maps_categories_to_techniques(self):
        from monitor.simulator.corpus import MoltbookSignatureSource

        payloads = MoltbookSignatureSource().load()
        technique_set = set()
        for p in payloads:
            for t in p.techniques:
                technique_set.add(t)
        assert len(technique_set) >= 3, (
            f"Expected >= 3 different techniques, got {technique_set}"
        )

    def test_severity_mapping(self):
        """Severity floats are correctly mapped to string labels."""
        from monitor.simulator.corpus import MoltbookSignatureSource

        payloads = MoltbookSignatureSource().load()
        valid_severities = {"low", "medium", "high", "critical"}
        for p in payloads:
            assert p.severity in valid_severities, f"Invalid severity: {p.severity}"

    def test_payload_texts_contain_signature_ids(self):
        """Each payload text should reference the signature ID."""
        from monitor.simulator.corpus import MoltbookSignatureSource

        payloads = MoltbookSignatureSource().load()
        for p in payloads:
            # Text should be non-empty at minimum
            assert len(p.text) > 0


# ---------------------------------------------------------------------------
# TestFileCorpusSource
# ---------------------------------------------------------------------------


class TestFileCorpusSource:
    """Verify JSONL file loading and technique string mapping."""

    def test_loads_jsonl(self):
        from monitor.simulator.corpus import FileCorpusSource

        records = [
            {
                "text": "Payload one",
                "techniques": ["worm_propagation"],
                "severity": "high",
            },
            {
                "text": "Payload two",
                "techniques": ["memory_poisoning", "shell_injection"],
                "severity": "critical",
            },
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")
            tmp_path = f.name

        try:
            source = FileCorpusSource(path=tmp_path)
            payloads = source.load()
            assert len(payloads) == 2

            assert payloads[0].text == "Payload one"
            assert payloads[0].techniques == [TechniqueType.WORM_PROPAGATION]
            assert payloads[0].severity == "high"
            assert payloads[0].source == "file"

            assert payloads[1].text == "Payload two"
            assert set(payloads[1].techniques) == {
                TechniqueType.MEMORY_POISONING,
                TechniqueType.SHELL_INJECTION,
            }
            assert payloads[1].severity == "critical"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_empty_file(self):
        from monitor.simulator.corpus import FileCorpusSource

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            tmp_path = f.name

        try:
            source = FileCorpusSource(path=tmp_path)
            payloads = source.load()
            assert payloads == []
        finally:
            Path(tmp_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# TestPayloadCorpus
# ---------------------------------------------------------------------------


class TestPayloadCorpus:
    """Verify the main PayloadCorpus class."""

    def test_generate_payload_from_config(self):
        """With worm_propagation=1.0 and others=0.0, payload has WORM_PROPAGATION."""
        from monitor.simulator.corpus import PayloadCorpus

        config = CorpusConfig(
            sources=[{"type": "builtin"}],
            technique_probabilities={
                "worm_propagation": 1.0,
                "memory_poisoning": 0.0,
                "role_hijacking": 0.0,
                "credential_extraction": 0.0,
                "shell_injection": 0.0,
            },
        )
        corpus = PayloadCorpus(config)
        rng = random.Random(42)
        payload = corpus.generate(rng)
        assert TechniqueType.WORM_PROPAGATION in payload.techniques
        assert payload.is_benign is False

    def test_generate_benign(self):
        """With all probabilities=0.0, generates benign payload."""
        from monitor.simulator.corpus import PayloadCorpus

        config = CorpusConfig(
            sources=[{"type": "builtin"}],
            technique_probabilities={
                "worm_propagation": 0.0,
                "memory_poisoning": 0.0,
                "role_hijacking": 0.0,
                "credential_extraction": 0.0,
                "shell_injection": 0.0,
            },
        )
        corpus = PayloadCorpus(config)
        rng = random.Random(42)
        payload = corpus.generate(rng)
        assert payload.is_benign is True
        assert payload.severity == "none"

    def test_generate_background_message(self):
        """generate_background returns benign payload with source='background'."""
        from monitor.simulator.corpus import PayloadCorpus

        config = CorpusConfig(
            sources=[{"type": "builtin"}],
        )
        corpus = PayloadCorpus(config)
        rng = random.Random(42)
        payload = corpus.generate_background(rng)
        assert payload.is_benign is True
        assert payload.source == "background"
        assert payload.severity == "none"
        assert len(payload.text) > 0

    def test_generate_composite_payload(self):
        """With multiple techniques at 1.0, composite payload has all of them."""
        from monitor.simulator.corpus import PayloadCorpus

        config = CorpusConfig(
            sources=[{"type": "builtin"}],
            technique_probabilities={
                "worm_propagation": 1.0,
                "memory_poisoning": 1.0,
                "role_hijacking": 0.0,
                "credential_extraction": 0.0,
                "shell_injection": 0.0,
            },
        )
        corpus = PayloadCorpus(config)
        rng = random.Random(42)
        payload = corpus.generate(rng)
        assert TechniqueType.WORM_PROPAGATION in payload.techniques
        assert TechniqueType.MEMORY_POISONING in payload.techniques

    def test_indexes_payloads_by_technique(self):
        """Internal index maps each technique to matching payloads."""
        from monitor.simulator.corpus import PayloadCorpus

        config = CorpusConfig(
            sources=[{"type": "builtin"}],
        )
        corpus = PayloadCorpus(config)
        # Every technique should have at least one indexed payload
        for technique in TechniqueType:
            assert len(corpus._index[technique]) >= 1

    def test_multiple_sources(self):
        """Corpus can load from multiple sources at once."""
        from monitor.simulator.corpus import PayloadCorpus

        config = CorpusConfig(
            sources=[
                {"type": "builtin"},
                {"type": "moltbook_signatures"},
            ],
        )
        corpus = PayloadCorpus(config)
        # Should have at least builtin (18) + moltbook (12) payloads
        assert len(corpus._payloads) >= 30

    def test_background_messages_varied(self):
        """Background messages should include variety."""
        from monitor.simulator.corpus import PayloadCorpus

        config = CorpusConfig(sources=[{"type": "builtin"}])
        corpus = PayloadCorpus(config)
        rng = random.Random(42)
        messages = {corpus.generate_background(rng).text for _ in range(50)}
        assert len(messages) >= 5, "Expected at least 5 distinct background messages"
