"""Tests for the tamper-proof state store."""

import json
import math
import os
import time
from pathlib import Path

import pytest

from aegis.core.state_log import TamperDetectedError
from aegis.core.state_store import (
    BehaviorBaseline,
    BudgetState,
    QuarantineState,
    StateStore,
    TrustState,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _make_store(tmp_path, key=None, apply_fs_protection=False, **kwargs):
    key = key or os.urandom(32)
    return StateStore(
        log_dir=tmp_path / "state", key=key,
        apply_fs_protection=apply_fs_protection, **kwargs,
    ), key


# ── Trust ────────────────────────────────────────────────────────────

class TestTrustState:
    def test_record_clean_interaction(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.record_trust_interaction("agent-1", clean=True)
        ts = store.get_trust("agent-1")
        assert ts is not None
        assert ts.clean_interactions == 1
        assert ts.total_interactions == 1
        assert ts.earned_score > 0

    def test_score_grows_logarithmically(self, tmp_path):
        store, _ = _make_store(tmp_path)
        for _ in range(100):
            store.record_trust_interaction("agent-1", clean=True)
        ts = store.get_trust("agent-1")
        # 5 * ln(101) ≈ 23.1
        assert 23.0 < ts.earned_score < 24.0

    def test_anomaly_penalises(self, tmp_path):
        store, _ = _make_store(tmp_path)
        for _ in range(50):
            store.record_trust_interaction("agent-1", clean=True)
        score_before = store.get_trust("agent-1").score
        store.record_trust_interaction("agent-1", anomaly=True)
        score_after = store.get_trust("agent-1").score
        assert score_after < score_before * 0.75  # 30% penalty

    def test_compromise_zeros_score(self, tmp_path):
        store, _ = _make_store(tmp_path)
        for _ in range(20):
            store.record_trust_interaction("agent-1", clean=True)
        store.report_compromise("agent-1")
        ts = store.get_trust("agent-1")
        assert ts.score == 0.0
        assert ts.compromised is True
        assert store.get_trust_tier("agent-1") == 0

    def test_tier_1_at_15_score(self, tmp_path):
        store, _ = _make_store(tmp_path)
        # Need ~20 clean interactions to reach score 15
        for _ in range(20):
            store.record_trust_interaction("agent-x", clean=True)
        assert store.get_trust_tier("agent-x") >= 1

    def test_vouch_adds_bonus(self, tmp_path):
        store, _ = _make_store(tmp_path)
        # Build voucher to tier 2: needs score >= 50 and age >= 3 days
        # 5 * ln(n+1) >= 50 ⟹ n >= e^10 - 1 ≈ 22025
        # Use direct state manipulation to avoid 22k events in a test
        store.record_trust_interaction("voucher-1", clean=True)
        store._trust["voucher-1"].earned_score = 55.0
        store._trust["voucher-1"].created = time.time() - 4 * 86400

        store.record_trust_interaction("target-1", clean=True)
        score_before = store.get_trust("target-1").score
        store.record_vouch("voucher-1", "target-1")
        score_after = store.get_trust("target-1").score
        assert score_after == score_before + 8.0

    def test_decay_reduces_scores(self, tmp_path):
        store, _ = _make_store(tmp_path)
        for _ in range(50):
            store.record_trust_interaction("agent-1", clean=True)
        score_before = store.get_trust("agent-1").score
        store.apply_trust_decay()
        score_after = store.get_trust("agent-1").score
        assert score_after < score_before

    def test_unknown_agent_returns_none(self, tmp_path):
        store, _ = _make_store(tmp_path)
        assert store.get_trust("nobody") is None
        assert store.get_trust_tier("nobody") == 0

    def test_agent_id_normalised(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.record_trust_interaction("  Agent-1  ", clean=True)
        assert store.get_trust("agent-1") is not None
        assert store.get_trust("AGENT-1") is not None


# ── Budgets ──────────────────────────────────────────────────────────

class TestBudgetState:
    def test_record_write_action(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.record_budget_action("tool_call", "write", target="bash")
        limits = {"max_write_tool_calls": 50}
        remaining = store.get_budget_remaining(limits)
        assert remaining["write_tool_calls"] == 49

    def test_read_actions_not_counted(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.record_budget_action("tool_call", "read")
        limits = {"max_write_tool_calls": 50}
        remaining = store.get_budget_remaining(limits)
        assert remaining["write_tool_calls"] == 50

    def test_domain_tracking(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.record_budget_action("http_write", "write", target="example.com")
        store.record_budget_action("http_write", "write", target="example.com")
        store.record_budget_action("http_write", "write", target="other.com")
        limits = {"max_new_domains": 5}
        remaining = store.get_budget_remaining(limits)
        assert remaining["new_domains"] == 3  # 5 - 2 unique domains

    def test_post_message_tracking(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.record_budget_action("post_message", "write")
        store.record_budget_action("post_message", "write")
        limits = {"max_posts_messages": 20}
        remaining = store.get_budget_remaining(limits)
        assert remaining["posts_messages"] == 18


# ── Quarantine ───────────────────────────────────────────────────────

class TestQuarantineState:
    def test_enter_quarantine(self, tmp_path):
        store, _ = _make_store(tmp_path)
        assert not store.is_quarantined()
        store.enter_quarantine("hostile NK verdict", severity="high")
        assert store.is_quarantined()
        q = store.get_quarantine()
        assert q.reason == "hostile NK verdict"
        assert q.severity == "high"

    def test_exit_quarantine(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.enter_quarantine("test")
        store.exit_quarantine(exit_token="any")
        assert not store.is_quarantined()

    def test_escalation(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.enter_quarantine("initial threat")
        store.escalate_quarantine("repeated threats while quarantined")
        q = store.get_quarantine()
        assert q.escalated is True
        assert "repeated" in q.escalation_reason


# ── Behavior baselines ───────────────────────────────────────────────

class TestBehaviorBaseline:
    def test_record_events(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.record_behavior_event("agent-1", 500, "bash", "code")
        store.record_behavior_event("agent-1", 300, "read", "text")
        bl = store.get_baseline("agent-1")
        assert bl is not None
        assert bl.event_count == 2
        assert bl.avg_output_length == 400.0
        assert bl.tool_counts == {"bash": 1, "read": 1}

    def test_baseline_freezes_after_anchor_window(self, tmp_path):
        store, _ = _make_store(tmp_path, anchor_window=3)
        for i in range(5):
            store.record_behavior_event("agent-1", 100 * (i + 1), "bash", "text")
        bl = store.get_baseline("agent-1")
        assert bl.frozen is True
        # Only first 3 events recorded (frozen after anchor_window)
        assert bl.event_count == 3

    def test_no_baseline_for_unknown_agent(self, tmp_path):
        store, _ = _make_store(tmp_path)
        assert store.get_baseline("ghost") is None


# ── Persistence across restarts ──────────────────────────────────────

class TestPersistence:
    def test_state_survives_restart(self, tmp_path):
        key = os.urandom(32)
        store_dir = tmp_path / "state"

        # Session 1: build up state
        s1 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        for _ in range(10):
            s1.record_trust_interaction("agent-1", clean=True)
        s1.record_budget_action("tool_call", "write")
        s1.enter_quarantine("test reason")
        s1.record_behavior_event("agent-1", 500, "bash", "code")

        score_1 = s1.get_trust("agent-1").score

        # Session 2: reload from log
        s2 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        ts = s2.get_trust("agent-1")
        assert ts is not None
        assert ts.clean_interactions == 10
        # Score should be approximately the same (time-dependent created
        # stamp may differ slightly between apply runs)
        assert abs(ts.score - score_1) < 1.0

        assert s2.is_quarantined()
        remaining = s2.get_budget_remaining({"max_write_tool_calls": 50})
        assert remaining["write_tool_calls"] == 49

        bl = s2.get_baseline("agent-1")
        assert bl is not None
        assert bl.event_count == 1

    def test_checkpoint_accelerates_reload(self, tmp_path):
        key = os.urandom(32)
        store_dir = tmp_path / "state"

        # Session 1: write many events and force checkpoint
        s1 = StateStore(log_dir=store_dir, key=key, checkpoint_interval=5, apply_fs_protection=False)
        for i in range(20):
            s1.record_trust_interaction(f"agent-{i % 3}", clean=True)
        s1.force_checkpoint()

        # Session 2: should load from checkpoint
        s2 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        # All 3 agents should have trust records
        for i in range(3):
            assert s2.get_trust(f"agent-{i}") is not None

    def test_tampered_log_detected_on_reload(self, tmp_path):
        key = os.urandom(32)
        store_dir = tmp_path / "state"

        s1 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        s1.record_trust_interaction("agent-1", clean=True)

        # Tamper with the log file
        log_file = store_dir / "events.jsonl"
        content = log_file.read_text()
        tampered = content.replace('"agent-1"', '"hacker"')
        log_file.write_text(tampered)

        with pytest.raises(TamperDetectedError):
            StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)

    def test_wrong_key_on_reload_detected(self, tmp_path):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        store_dir = tmp_path / "state"

        s1 = StateStore(log_dir=store_dir, key=key1, apply_fs_protection=False)
        s1.record_trust_interaction("agent-1", clean=True)

        with pytest.raises(TamperDetectedError):
            StateStore(log_dir=store_dir, key=key2, apply_fs_protection=False)

    def test_continue_appending_after_reload(self, tmp_path):
        key = os.urandom(32)
        store_dir = tmp_path / "state"

        s1 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        s1.record_trust_interaction("agent-1", clean=True)

        s2 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        s2.record_trust_interaction("agent-1", clean=True)
        assert s2.get_trust("agent-1").clean_interactions == 2

        # Session 3 should see both
        s3 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        assert s3.get_trust("agent-1").clean_interactions == 2


# ── Snapshot ─────────────────────────────────────────────────────────

class TestSnapshot:
    def test_snapshot_returns_full_state(self, tmp_path):
        store, _ = _make_store(tmp_path)
        store.record_trust_interaction("agent-1", clean=True)
        store.record_budget_action("tool_call", "write")
        store.enter_quarantine("test")

        snap = store.snapshot()
        assert "trust" in snap
        assert "budgets" in snap
        assert "quarantine" in snap
        assert "baselines" in snap
        assert "agent-1" in snap["trust"]
        assert snap["quarantine"]["active"] is True


# ── Agent cannot forge state ─────────────────────────────────────────

class TestAgentCannotForge:
    """Tests that simulate a compromised agent attempting to tamper with state files."""

    def test_cannot_inflate_trust_via_file_edit(self, tmp_path):
        """An agent that edits the log file to inflate trust is caught."""
        key = os.urandom(32)
        store_dir = tmp_path / "state"

        s1 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        s1.record_trust_interaction("agent-evil", clean=True)

        # Agent tries to add a forged high-trust entry
        log_file = store_dir / "events.jsonl"
        forged_line = json.dumps({
            "event_type": "trust_interaction",
            "data": {"agent_id": "agent-evil", "clean": True, "anomaly": False},
            "timestamp": time.time(),
            "sequence": 1,
            "chain_hash": "0" * 64,
            "signature": "f" * 64,
        })
        with open(log_file, "a") as f:
            f.write(forged_line + "\n")

        with pytest.raises(TamperDetectedError):
            StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)

    def test_cannot_remove_quarantine_via_file_edit(self, tmp_path):
        """An agent that deletes the quarantine event is caught."""
        key = os.urandom(32)
        store_dir = tmp_path / "state"

        s1 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        s1.enter_quarantine("hostile NK")

        # Force a checkpoint so state is preserved
        s1.force_checkpoint()

        # Agent wipes the log
        log_file = store_dir / "events.jsonl"
        log_file.write_text("")

        # Checkpoint still shows quarantine
        s2 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        assert s2.is_quarantined()

    def test_cannot_tamper_checkpoint(self, tmp_path):
        """An agent that edits the checkpoint file is caught."""
        key = os.urandom(32)
        store_dir = tmp_path / "state"

        s1 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        s1.enter_quarantine("hostile")
        s1.force_checkpoint()

        # Tamper: change quarantine to inactive
        cp_path = store_dir / "checkpoint.json"
        content = json.loads(cp_path.read_text())
        content["payload"]["state"]["quarantine"]["active"] = False
        cp_path.write_text(json.dumps(content))

        # Should reject checkpoint (bad sig) and fall back to log replay
        s2 = StateStore(log_dir=store_dir, key=key, apply_fs_protection=False)
        assert s2.is_quarantined()  # log replay restores quarantine
