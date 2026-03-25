"""Tests for the HMAC-chained append-only state log."""

import json
import os
import time

import pytest

from aegis.core.state_log import (
    _GENESIS_CHAIN,
    StateEvent,
    StateLog,
    TamperDetectedError,
    _hmac_sign,
    _hmac_verify,
    _sha256_hex,
    resolve_state_key,
)

# ── Helpers ──────────────────────────────────────────────────────────

def _make_log(tmp_path, key=None, apply_fs_protection=False):
    key = key or os.urandom(32)
    return StateLog(
        tmp_path / "events.jsonl", key=key,
        apply_fs_protection=apply_fs_protection,
    ), key


# ── StateEvent ───────────────────────────────────────────────────────

class TestStateEvent:
    def test_canonical_bytes_deterministic(self):
        e = StateEvent(
            event_type="test",
            data={"b": 2, "a": 1},
            timestamp=1000.0,
            sequence=0,
            chain_hash="abc",
        )
        assert e.canonical_bytes() == e.canonical_bytes()

    def test_canonical_bytes_sorted_keys(self):
        e = StateEvent(
            event_type="test",
            data={"z": 1, "a": 2},
            timestamp=1.0,
            sequence=0,
            chain_hash="x",
        )
        canonical = e.canonical_bytes().decode()
        # JSON keys must be sorted
        assert '"a":2' in canonical
        assert canonical.index('"a"') < canonical.index('"z"')

    def test_different_data_different_canonical(self):
        e1 = StateEvent(event_type="test", data={"x": 1})
        e2 = StateEvent(event_type="test", data={"x": 2})
        assert e1.canonical_bytes() != e2.canonical_bytes()


# ── HMAC helpers ─────────────────────────────────────────────────────

class TestHMAC:
    def test_sign_and_verify(self):
        key = os.urandom(32)
        data = b"hello world"
        sig = _hmac_sign(data, key)
        assert _hmac_verify(data, sig, key)

    def test_wrong_key_fails(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        data = b"test"
        sig = _hmac_sign(data, key1)
        assert not _hmac_verify(data, sig, key2)

    def test_tampered_data_fails(self):
        key = os.urandom(32)
        sig = _hmac_sign(b"original", key)
        assert not _hmac_verify(b"tampered", sig, key)


# ── resolve_state_key ────────────────────────────────────────────────

class TestResolveStateKey:
    def test_hex_env_key(self, monkeypatch):
        hex_key = os.urandom(32).hex()
        monkeypatch.setenv("AEGIS_STATE_KEY", hex_key)
        key = resolve_state_key()
        assert len(key) == 32
        assert key == bytes.fromhex(hex_key)

    def test_raw_env_key(self, monkeypatch):
        monkeypatch.setenv("AEGIS_STATE_KEY", "my-secret-passphrase")
        key = resolve_state_key()
        assert len(key) == 32

    def test_ephemeral_key_when_no_env(self, monkeypatch):
        monkeypatch.delenv("AEGIS_STATE_KEY", raising=False)
        key = resolve_state_key()
        assert len(key) == 32


# ── StateLog: basic operations ───────────────────────────────────────

class TestStateLogBasic:
    def test_append_creates_file(self, tmp_path):
        log, _ = _make_log(tmp_path)
        log.append("test_event", msg="hello")
        assert log.path.exists()

    def test_append_returns_signed_event(self, tmp_path):
        log, _ = _make_log(tmp_path)
        event = log.append("test", value=42)
        assert event.event_type == "test"
        assert event.data == {"value": 42}
        assert event.sequence == 0
        assert event.signature != ""
        assert event.chain_hash == _sha256_hex(_GENESIS_CHAIN)

    def test_sequence_increments(self, tmp_path):
        log, _ = _make_log(tmp_path)
        e0 = log.append("a")
        e1 = log.append("b")
        e2 = log.append("c")
        assert e0.sequence == 0
        assert e1.sequence == 1
        assert e2.sequence == 2
        assert log.sequence == 3

    def test_chain_links(self, tmp_path):
        log, _ = _make_log(tmp_path)
        e0 = log.append("first")
        e1 = log.append("second")
        assert e1.chain_hash == _sha256_hex(e0.signature)

    def test_multiple_events_written_as_jsonl(self, tmp_path):
        log, _ = _make_log(tmp_path)
        log.append("a", x=1)
        log.append("b", x=2)
        log.append("c", x=3)
        lines = log.path.read_text().strip().split("\n")
        assert len(lines) == 3
        for line in lines:
            parsed = json.loads(line)
            assert "event_type" in parsed
            assert "signature" in parsed
            assert "chain_hash" in parsed


# ── StateLog: load and verify ────────────────────────────────────────

class TestStateLogVerify:
    def test_load_empty_file(self, tmp_path):
        log, _ = _make_log(tmp_path)
        log._ensure_file()
        events = log.load_and_verify()
        assert events == []

    def test_load_nonexistent_file(self, tmp_path):
        log, _ = _make_log(tmp_path)
        events = log.load_and_verify()
        assert events == []

    def test_round_trip(self, tmp_path):
        key = os.urandom(32)
        log1 = StateLog(tmp_path / "events.jsonl", key=key)
        log1.append("trust_interaction", agent_id="a1", clean=True)
        log1.append("budget_action", action_type="tool_call", read_write="write")
        log1.append("quarantine_enter", reason="hostile NK")

        log2 = StateLog(tmp_path / "events.jsonl", key=key)
        events = log2.load_and_verify()
        assert len(events) == 3
        assert events[0].event_type == "trust_interaction"
        assert events[1].event_type == "budget_action"
        assert events[2].event_type == "quarantine_enter"
        assert events[2].data["reason"] == "hostile NK"

    def test_verify_updates_internal_state(self, tmp_path):
        key = os.urandom(32)
        log1 = StateLog(tmp_path / "events.jsonl", key=key)
        log1.append("a")
        log1.append("b")

        log2 = StateLog(tmp_path / "events.jsonl", key=key)
        log2.load_and_verify()
        # Should be able to continue appending
        e = log2.append("c")
        assert e.sequence == 2

        # Reload and verify all 3
        log3 = StateLog(tmp_path / "events.jsonl", key=key)
        events = log3.load_and_verify()
        assert len(events) == 3


# ── StateLog: tamper detection ───────────────────────────────────────

class TestStateLogTamperDetection:
    """Tests that modify the log file on disk to simulate tampering.

    All logs created here disable filesystem append protection so the
    test can actually write to the file.
    """

    def test_detect_modified_data(self, tmp_path):
        key = os.urandom(32)
        log = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        log.append("trust_interaction", agent_id="a1", clean=True)

        # Tamper: change agent_id
        content = log.path.read_text()
        tampered = content.replace('"a1"', '"hacker"')
        log.path.write_text(tampered)

        log2 = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        with pytest.raises(TamperDetectedError, match="invalid signature"):
            log2.load_and_verify()

    def test_detect_deleted_entry(self, tmp_path):
        key = os.urandom(32)
        log = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        log.append("a")
        log.append("b")
        log.append("c")

        # Delete middle entry
        lines = log.path.read_text().strip().split("\n")
        log.path.write_text(lines[0] + "\n" + lines[2] + "\n")

        log2 = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        with pytest.raises(TamperDetectedError):
            log2.load_and_verify()

    def test_detect_inserted_entry(self, tmp_path):
        key = os.urandom(32)
        log = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        log.append("a")
        log.append("c")

        # Insert a forged entry between a and c
        lines = log.path.read_text().strip().split("\n")
        forged = json.dumps({
            "event_type": "forged",
            "data": {},
            "timestamp": time.time(),
            "sequence": 1,
            "chain_hash": "0" * 64,
            "signature": "f" * 64,
        })
        log.path.write_text(lines[0] + "\n" + forged + "\n" + lines[1] + "\n")

        log2 = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        with pytest.raises(TamperDetectedError):
            log2.load_and_verify()

    def test_detect_wrong_key(self, tmp_path):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        log1 = StateLog(tmp_path / "events.jsonl", key=key1, apply_fs_protection=False)
        log1.append("test")

        log2 = StateLog(tmp_path / "events.jsonl", key=key2, apply_fs_protection=False)
        with pytest.raises(TamperDetectedError, match="invalid signature"):
            log2.load_and_verify()

    def test_detect_reordered_entries(self, tmp_path):
        key = os.urandom(32)
        log = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        log.append("first")
        log.append("second")

        # Swap order
        lines = log.path.read_text().strip().split("\n")
        log.path.write_text(lines[1] + "\n" + lines[0] + "\n")

        log2 = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        with pytest.raises(TamperDetectedError):
            log2.load_and_verify()

    def test_detect_corrupted_json(self, tmp_path):
        key = os.urandom(32)
        log = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        log.append("test")

        log.path.write_text("not valid json\n")

        log2 = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        with pytest.raises(TamperDetectedError, match="invalid JSON"):
            log2.load_and_verify()

    def test_detect_sequence_gap(self, tmp_path):
        key = os.urandom(32)
        log = StateLog(tmp_path / "events.jsonl", key=key, apply_fs_protection=False)
        e0 = log.append("a")

        # Manually forge an entry with sequence=5 instead of 1
        forged_event = StateEvent(
            event_type="forged",
            data={},
            timestamp=time.time(),
            sequence=5,
            chain_hash=_sha256_hex(e0.signature),
        )
        forged_event.signature = _hmac_sign(forged_event.canonical_bytes(), key)
        line = json.dumps({
            "event_type": forged_event.event_type,
            "data": forged_event.data,
            "timestamp": forged_event.timestamp,
            "sequence": forged_event.sequence,
            "chain_hash": forged_event.chain_hash,
            "signature": forged_event.signature,
        }, sort_keys=True, separators=(",", ":"))

        with open(log.path, "a") as f:
            f.write(line + "\n")

        log2 = StateLog(tmp_path / "events.jsonl", key=key)
        with pytest.raises(TamperDetectedError, match="sequence gap"):
            log2.load_and_verify()


# ── StateLog: checkpoints ────────────────────────────────────────────

class TestStateLogCheckpoint:
    def test_checkpoint_round_trip(self, tmp_path):
        key = os.urandom(32)
        log = StateLog(tmp_path / "events.jsonl", key=key)
        log.append("a")
        log.append("b")

        state = {"trust": {"agent1": {"score": 42.0}}}
        cp_path = tmp_path / "checkpoint.json"
        log.write_checkpoint(state, cp_path)
        assert cp_path.exists()

        log2 = StateLog(tmp_path / "events.jsonl", key=key)
        result = log2.load_checkpoint(cp_path)
        assert result is not None
        assert result["state"]["trust"]["agent1"]["score"] == 42.0
        assert result["sequence"] == 2

    def test_checkpoint_tamper_detected(self, tmp_path):
        key = os.urandom(32)
        log = StateLog(tmp_path / "events.jsonl", key=key)
        log.append("a")

        cp_path = tmp_path / "checkpoint.json"
        log.write_checkpoint({"trust": {}}, cp_path)

        # Tamper with checkpoint
        content = cp_path.read_text()
        tampered = content.replace('"trust"', '"hacked"')
        cp_path.write_text(tampered)

        log2 = StateLog(tmp_path / "events.jsonl", key=key)
        result = log2.load_checkpoint(cp_path)
        assert result is None  # rejected, not raised

    def test_checkpoint_wrong_key_rejected(self, tmp_path):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        log1 = StateLog(tmp_path / "events.jsonl", key=key1)
        log1.append("a")

        cp_path = tmp_path / "checkpoint.json"
        log1.write_checkpoint({"data": "secret"}, cp_path)

        log2 = StateLog(tmp_path / "events.jsonl", key=key2)
        result = log2.load_checkpoint(cp_path)
        assert result is None

    def test_checkpoint_restores_sequence(self, tmp_path):
        key = os.urandom(32)
        log = StateLog(tmp_path / "events.jsonl", key=key)
        log.append("a")
        log.append("b")
        log.append("c")

        cp_path = tmp_path / "checkpoint.json"
        log.write_checkpoint({}, cp_path)

        log2 = StateLog(tmp_path / "events.jsonl", key=key)
        result = log2.load_checkpoint(cp_path)
        assert log2.sequence == 3

    def test_nonexistent_checkpoint_returns_none(self, tmp_path):
        log, _ = _make_log(tmp_path)
        result = log.load_checkpoint(tmp_path / "nope.json")
        assert result is None
