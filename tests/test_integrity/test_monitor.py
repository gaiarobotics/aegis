"""Tests for aegis.integrity.monitor."""

from __future__ import annotations

import os
import tempfile
import threading
import time

import pytest

from aegis.integrity.monitor import (
    IntegrityMonitor,
    ModelFileRecord,
    ModelTamperedError,
    ProvenanceStatus,
    RegisteredModel,
    StatSnapshot,
    _compute_sha256,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeConfig:
    """Minimal config for IntegrityMonitor tests."""

    def __init__(
        self,
        hash_on_load: str = "off",
        rehash_interval_seconds: int = 0,
        inotify_enabled: bool = False,
        ollama_models_path: str = "",
        hf_cache_path: str = "",
        model_file_extensions: list[str] | None = None,
    ):
        self.hash_on_load = hash_on_load
        self.rehash_interval_seconds = rehash_interval_seconds
        self.inotify_enabled = inotify_enabled
        self.ollama_models_path = ollama_models_path
        self.hf_cache_path = hf_cache_path
        self.model_file_extensions = model_file_extensions or [
            ".safetensors", ".bin", ".pt", ".pth", ".gguf", ".ggml", ".model",
        ]


# ---------------------------------------------------------------------------
# StatSnapshot tests
# ---------------------------------------------------------------------------


class TestStatSnapshot:
    def test_from_path_captures_metadata(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(b"hello world")
        snap = StatSnapshot.from_path(str(p))
        assert snap.size == 11
        assert snap.mtime_ns > 0
        assert snap.inode > 0

    def test_changes_after_write(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(b"data1")
        snap1 = StatSnapshot.from_path(str(p))

        time.sleep(0.01)  # ensure mtime changes
        p.write_bytes(b"data1+more")
        snap2 = StatSnapshot.from_path(str(p))

        assert snap2.size != snap1.size
        assert snap2.mtime_ns != snap1.mtime_ns

    def test_from_path_nonexistent(self):
        with pytest.raises(FileNotFoundError):
            StatSnapshot.from_path("/nonexistent/path/model.bin")


# ---------------------------------------------------------------------------
# ModelTamperedError tests
# ---------------------------------------------------------------------------


class TestModelTamperedError:
    def test_attributes(self):
        err = ModelTamperedError(
            model_name="llama3",
            file_path="/models/llama.bin",
            detail="mtime changed",
        )
        assert err.model_name == "llama3"
        assert err.file_path == "/models/llama.bin"
        assert err.detail == "mtime changed"
        assert "llama3" in str(err)

    def test_default_values(self):
        err = ModelTamperedError()
        assert err.model_name == ""
        assert err.file_path == ""
        assert err.detail == ""


# ---------------------------------------------------------------------------
# IntegrityMonitor registration tests
# ---------------------------------------------------------------------------


class TestIntegrityMonitorRegistration:
    def test_register_unknown_provider_empty_files(self):
        """Unknown provider yields empty registration."""
        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        try:
            monitor.register_model("test-model", "unknown_provider")
            assert monitor.is_registered("test-model")
            status = monitor.get_status("test-model")
            assert status is not None
            assert status.files == []
        finally:
            monitor.stop()

    def test_is_registered_false_for_unknown(self):
        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        try:
            assert not monitor.is_registered("nonexistent")
        finally:
            monitor.stop()

    def test_register_idempotent(self):
        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        try:
            monitor.register_model("test-model", "unknown_provider")
            status1 = monitor.get_status("test-model")
            monitor.register_model("test-model", "unknown_provider")
            status2 = monitor.get_status("test-model")
            assert status1 is status2
        finally:
            monitor.stop()

    def test_get_status_none_for_unknown(self):
        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        try:
            assert monitor.get_status("nope") is None
        finally:
            monitor.stop()


# ---------------------------------------------------------------------------
# Integrity check tests
# ---------------------------------------------------------------------------


class TestIntegrityCheck:
    def test_clean_returns_empty(self, tmp_path):
        """No issues when files haven't changed."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"model data")

        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
            )
            monitor._models["test"] = RegisteredModel(
                model_name="test", provider="test", files=[record],
            )
            issues = monitor.check_integrity("test")
            assert issues == []
        finally:
            monitor.stop()

    def test_mtime_change_detected(self, tmp_path):
        """Detects mtime changes."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"original")

        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
            )
            monitor._models["test"] = RegisteredModel(
                model_name="test", provider="test", files=[record],
            )

            # Modify the file
            time.sleep(0.01)
            model_file.write_bytes(b"tampered!")
            issues = monitor.check_integrity("test")
            assert any("mtime changed" in i for i in issues)
        finally:
            monitor.stop()

    def test_size_change_detected(self, tmp_path):
        """Detects size changes."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"short")

        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
            )
            monitor._models["test"] = RegisteredModel(
                model_name="test", provider="test", files=[record],
            )

            time.sleep(0.01)
            model_file.write_bytes(b"much longer content here")
            issues = monitor.check_integrity("test")
            assert any("size changed" in i for i in issues)
        finally:
            monitor.stop()

    def test_file_missing_detected(self, tmp_path):
        """Detects deleted files."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"data")

        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
            )
            monitor._models["test"] = RegisteredModel(
                model_name="test", provider="test", files=[record],
            )

            model_file.unlink()
            issues = monitor.check_integrity("test")
            assert any("file missing" in i for i in issues)
        finally:
            monitor.stop()

    def test_unregistered_model_returns_empty(self):
        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        try:
            issues = monitor.check_integrity("nonexistent")
            assert issues == []
        finally:
            monitor.stop()


# ---------------------------------------------------------------------------
# Hashing tests
# ---------------------------------------------------------------------------


class TestHashing:
    def test_compute_sha256(self, tmp_path):
        p = tmp_path / "data.bin"
        p.write_bytes(b"hello")
        import hashlib
        expected = hashlib.sha256(b"hello").hexdigest()
        assert _compute_sha256(str(p)) == expected

    def test_sync_hash_sets_sha256(self, tmp_path):
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"model content")

        config = FakeConfig(hash_on_load="sync")
        monitor = IntegrityMonitor(config)
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
            )
            monitor._hash_file(record)
            assert record.sha256 != ""
            assert len(record.sha256) == 64  # SHA256 hex
        finally:
            monitor.stop()

    def test_sync_hash_provenance_verified(self, tmp_path):
        """When manifest digest matches, provenance is VERIFIED_MANIFEST."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"model content")

        import hashlib
        expected = hashlib.sha256(b"model content").hexdigest()

        config = FakeConfig(hash_on_load="sync")
        monitor = IntegrityMonitor(config)
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
                manifest_digest=expected,
            )
            monitor._hash_file(record)
            assert record.provenance == ProvenanceStatus.VERIFIED_MANIFEST
        finally:
            monitor.stop()

    def test_sync_hash_provenance_unverified_mismatch(self, tmp_path):
        """When manifest digest doesn't match, provenance is UNVERIFIED."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"model content")

        config = FakeConfig(hash_on_load="sync")
        monitor = IntegrityMonitor(config)
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
                manifest_digest="deadbeef" * 8,
            )
            monitor._hash_file(record)
            assert record.provenance == ProvenanceStatus.UNVERIFIED
        finally:
            monitor.stop()

    def test_sync_hash_provenance_unverified_no_manifest(self, tmp_path):
        """Without manifest digest, provenance is UNVERIFIED."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"model content")

        config = FakeConfig(hash_on_load="sync")
        monitor = IntegrityMonitor(config)
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
            )
            monitor._hash_file(record)
            assert record.provenance == ProvenanceStatus.UNVERIFIED
        finally:
            monitor.stop()

    def test_async_hash_completes_eventually(self, tmp_path):
        """Async hashing eventually processes queued files."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"async content")

        config = FakeConfig(hash_on_load="async")
        monitor = IntegrityMonitor(config)
        try:
            record = ModelFileRecord(
                path=str(model_file),
                stat=StatSnapshot.from_path(str(model_file)),
            )
            assert record.sha256 == ""
            assert record.provenance == ProvenanceStatus.PENDING

            with monitor._hash_queue_lock:
                monitor._hash_queue.append(("test-model", record))

            # Wait for async processing
            deadline = time.time() + 5.0
            while record.sha256 == "" and time.time() < deadline:
                time.sleep(0.05)

            assert record.sha256 != ""
            assert len(record.sha256) == 64
        finally:
            monitor.stop()


# ---------------------------------------------------------------------------
# Stop / shutdown tests
# ---------------------------------------------------------------------------


class TestMonitorStop:
    def test_stop_terminates_threads(self):
        config = FakeConfig(hash_on_load="async", rehash_interval_seconds=3600)
        monitor = IntegrityMonitor(config)

        assert monitor._hash_thread is not None
        assert monitor._hash_thread.is_alive()
        assert monitor._rehash_thread is not None
        assert monitor._rehash_thread.is_alive()

        monitor.stop()

        assert not monitor._hash_thread.is_alive()
        assert not monitor._rehash_thread.is_alive()

    def test_stop_idempotent(self):
        config = FakeConfig()
        monitor = IntegrityMonitor(config)
        monitor.stop()
        monitor.stop()  # should not raise


# ---------------------------------------------------------------------------
# ProvenanceStatus tests
# ---------------------------------------------------------------------------


class TestProvenanceStatus:
    def test_enum_values(self):
        assert ProvenanceStatus.PENDING.value == "pending"
        assert ProvenanceStatus.VERIFIED_MANIFEST.value == "verified_manifest"
        assert ProvenanceStatus.UNVERIFIED.value == "unverified"
