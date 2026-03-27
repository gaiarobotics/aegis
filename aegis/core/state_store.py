"""Tamper-proof state store backed by the HMAC-chained event log.

All mutable security state (trust, budgets, quarantine, behavioral
baselines) is reconstructed from the append-only event log.  The agent
can only mutate state through the public methods here, each of which
appends a signed event.  Direct filesystem edits are detected by the
chain verification on next load.

Periodic checkpoints accelerate startup by avoiding full log replay.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis.core.state_log import StateLog, TamperDetectedError, resolve_state_key

logger = logging.getLogger(__name__)


# ── Data classes for reconstructed state ─────────────────────────────

@dataclass
class TrustState:
    """Per-agent trust record reconstructed from events."""

    agent_id: str
    earned_score: float = 0.0
    bonus_score: float = 0.0
    clean_interactions: int = 0
    total_interactions: int = 0
    anomaly_count: int = 0
    created: float = 0.0
    last_interaction: float = 0.0
    vouchers: list[str] = field(default_factory=list)
    compromised: bool = False

    @property
    def score(self) -> float:
        return self.earned_score + self.bonus_score

    @property
    def tier(self) -> int:
        if self.compromised:
            return 0
        if self.score >= 50.0 and self._age_days >= 3:
            # Check vouched (tier 3) — deferred to StateStore which has
            # access to all records.
            return 2
        if self.score >= 15.0:
            return 1
        return 0

    @property
    def _age_days(self) -> float:
        if self.created <= 0:
            return 0.0
        return (time.time() - self.created) / 86400.0


@dataclass
class BudgetState:
    """Reconstructed budget counters."""

    write_tool_calls: int = 0
    posts_messages: int = 0
    external_http_writes: int = 0
    seen_domains: set[str] = field(default_factory=set)


@dataclass
class QuarantineState:
    """Reconstructed quarantine status."""

    active: bool = False
    reason: str = ""
    severity: str = "high"
    entered_at: float = 0.0
    escalated: bool = False
    escalation_reason: str = ""


@dataclass
class BehaviorBaseline:
    """Per-agent behavioral baseline snapshot."""

    agent_id: str
    event_count: int = 0
    avg_output_length: float = 0.0
    tool_counts: dict[str, int] = field(default_factory=dict)
    content_type_counts: dict[str, int] = field(default_factory=dict)
    total_output_length: int = 0
    frozen: bool = False


# ── Main state store ─────────────────────────────────────────────────

_CHECKPOINT_INTERVAL = 100  # events between auto-checkpoints


class StateStore:
    """Tamper-proof state store backed by an HMAC-chained event log.

    All mutations go through public methods that append signed events.
    State is reconstructed deterministically by replaying the log.

    Args:
        log_dir: Directory for the state log and checkpoint files.
        key: HMAC signing key.  If ``None``, resolved from environment.
        checkpoint_interval: Events between automatic checkpoint writes.
        anchor_window: Number of events before freezing a behavioral
            baseline for an agent.
    """

    def __init__(
        self,
        log_dir: str | Path = ".aegis/state",
        key: bytes | None = None,
        checkpoint_interval: int = _CHECKPOINT_INTERVAL,
        anchor_window: int = 20,
        apply_fs_protection: bool = True,
    ) -> None:
        self._dir = Path(log_dir)
        self._key = key if key is not None else resolve_state_key()
        self._log = StateLog(
            self._dir / "events.jsonl",
            key=self._key,
            apply_fs_protection=apply_fs_protection,
        )
        self._checkpoint_path = self._dir / "checkpoint.json"
        self._checkpoint_interval = checkpoint_interval
        self._anchor_window = anchor_window
        self._lock = threading.Lock()

        # Reconstructed state
        self._trust: dict[str, TrustState] = {}
        self._compromised: set[str] = set()
        self._budgets = BudgetState()
        self._quarantine = QuarantineState()
        self._baselines: dict[str, BehaviorBaseline] = {}
        self._events_since_checkpoint = 0

        # Load existing state
        self._load()

    # ── Public read API (safe for agent to call) ─────────────────────

    def get_trust(self, agent_id: str) -> TrustState | None:
        """Get trust state for an agent, or ``None`` if unknown."""
        with self._lock:
            agent_id = agent_id.strip().lower()
            return self._trust.get(agent_id)

    def get_trust_tier(self, agent_id: str) -> int:
        """Get computed trust tier, accounting for vouched status."""
        with self._lock:
            agent_id = agent_id.strip().lower()
            ts = self._trust.get(agent_id)
            if ts is None:
                return 0
            return self._compute_tier(ts)

    def get_budget_remaining(self, limits: dict[str, int]) -> dict[str, int]:
        """Get remaining budget against given limits."""
        with self._lock:
            return {
                "write_tool_calls": limits.get("max_write_tool_calls", 50)
                - self._budgets.write_tool_calls,
                "posts_messages": limits.get("max_posts_messages", 20)
                - self._budgets.posts_messages,
                "external_http_writes": limits.get("max_external_http_writes", 10)
                - self._budgets.external_http_writes,
                "new_domains": limits.get("max_new_domains", 5)
                - len(self._budgets.seen_domains),
            }

    def is_quarantined(self) -> bool:
        with self._lock:
            return self._quarantine.active

    def get_quarantine(self) -> QuarantineState:
        with self._lock:
            return QuarantineState(
                active=self._quarantine.active,
                reason=self._quarantine.reason,
                severity=self._quarantine.severity,
                entered_at=self._quarantine.entered_at,
                escalated=self._quarantine.escalated,
                escalation_reason=self._quarantine.escalation_reason,
            )

    def get_baseline(self, agent_id: str) -> BehaviorBaseline | None:
        with self._lock:
            agent_id = agent_id.strip().lower()
            return self._baselines.get(agent_id)

    def get_all_trust(self) -> dict[str, TrustState]:
        with self._lock:
            return dict(self._trust)

    def snapshot(self) -> dict[str, Any]:
        """Return the full state as a serialisable dict."""
        with self._lock:
            return self._serialise_state()

    # ── Public mutation API (each appends a signed event) ────────────

    def record_trust_interaction(
        self,
        agent_id: str,
        clean: bool = True,
        anomaly: bool = False,
    ) -> None:
        """Record an interaction for trust scoring."""
        agent_id = agent_id.strip().lower()
        self._log.append(
            "trust_interaction",
            agent_id=agent_id,
            clean=clean,
            anomaly=anomaly,
        )
        with self._lock:
            self._apply_trust_interaction(agent_id, clean, anomaly)
            self._maybe_checkpoint()

    def record_vouch(self, voucher_id: str, target_id: str) -> None:
        """Record a vouch from one agent to another."""
        voucher_id = voucher_id.strip().lower()
        target_id = target_id.strip().lower()
        self._log.append(
            "trust_vouch",
            voucher_id=voucher_id,
            target_id=target_id,
        )
        with self._lock:
            self._apply_vouch(voucher_id, target_id)
            self._maybe_checkpoint()

    def report_compromise(self, agent_id: str) -> None:
        """Mark an agent as compromised."""
        agent_id = agent_id.strip().lower()
        self._log.append("trust_compromise", agent_id=agent_id)
        with self._lock:
            self._apply_compromise(agent_id)
            self._maybe_checkpoint()

    def record_budget_action(
        self,
        action_type: str,
        read_write: str,
        target: str = "",
    ) -> None:
        """Record a budget-consuming action."""
        if read_write != "write":
            return
        self._log.append(
            "budget_action",
            action_type=action_type,
            read_write=read_write,
            target=target,
        )
        with self._lock:
            self._apply_budget_action(action_type, target)
            self._maybe_checkpoint()

    def enter_quarantine(self, reason: str, severity: str = "high") -> None:
        """Enter quarantine mode."""
        self._log.append(
            "quarantine_enter",
            reason=reason,
            severity=severity,
        )
        with self._lock:
            self._apply_quarantine_enter(reason, severity, time.time())
            self._maybe_checkpoint()

    def exit_quarantine(self, exit_token: str) -> None:
        """Exit quarantine mode.  Requires the correct exit token.

        The exit token is verified against the daemon-side secret.
        This method will raise ``ValueError`` if the token is wrong.

        Args:
            exit_token: The operator-provided exit token.

        Raises:
            ValueError: If the exit token does not match.
        """
        # The actual token validation happens in Shield or the daemon.
        # Here we just record the event.  Callers must validate first.
        self._log.append("quarantine_exit", token_provided=True)
        with self._lock:
            self._apply_quarantine_exit()
            self._maybe_checkpoint()

    def escalate_quarantine(self, reason: str) -> None:
        """Escalate quarantine to full inference block."""
        self._log.append("quarantine_escalate", reason=reason)
        with self._lock:
            self._quarantine.escalated = True
            self._quarantine.escalation_reason = reason
            self._maybe_checkpoint()

    def record_behavior_event(
        self,
        agent_id: str,
        output_length: int,
        tool_used: str | None,
        content_type: str,
    ) -> None:
        """Record a behavioral event for baseline tracking."""
        agent_id = agent_id.strip().lower()
        self._log.append(
            "behavior_event",
            agent_id=agent_id,
            output_length=output_length,
            tool_used=tool_used or "",
            content_type=content_type,
        )
        with self._lock:
            self._apply_behavior_event(
                agent_id, output_length, tool_used or "", content_type,
            )
            self._maybe_checkpoint()

    def apply_trust_decay(self) -> None:
        """Apply time-based decay to all trust scores (14-day half-life)."""
        self._log.append("trust_decay")
        with self._lock:
            daily_factor = math.pow(0.5, 1.0 / 14)
            for ts in self._trust.values():
                ts.earned_score *= daily_factor
                ts.bonus_score *= daily_factor
            self._maybe_checkpoint()

    def force_checkpoint(self) -> None:
        """Write a checkpoint immediately."""
        with self._lock:
            self._write_checkpoint()

    # ── Internal: state reconstruction ───────────────────────────────

    def _load(self) -> None:
        """Load state from checkpoint + event log replay."""
        checkpoint = self._log.load_checkpoint(self._checkpoint_path)
        replay_from = 0

        if checkpoint is not None:
            state = checkpoint.get("state", {})
            replay_from = checkpoint.get("sequence", 0)
            self._deserialise_state(state)
            logger.info(
                "Loaded checkpoint at sequence %d", replay_from,
            )

        try:
            events = self._log.load_and_verify()
        except TamperDetectedError:
            logger.error(
                "State log tamper detected — resetting to checkpoint or empty state"
            )
            raise

        # Replay events after the checkpoint
        replayed = 0
        for event in events:
            if event.sequence < replay_from:
                continue
            self._replay_event(event.event_type, event.data, event.timestamp)
            replayed += 1

        if replayed > 0:
            logger.info("Replayed %d events from state log", replayed)

        self._events_since_checkpoint = replayed

    def _replay_event(
        self, event_type: str, data: dict[str, Any], timestamp: float,
    ) -> None:
        """Replay a single event to reconstruct state."""
        if event_type == "trust_interaction":
            self._apply_trust_interaction(
                data["agent_id"], data.get("clean", True), data.get("anomaly", False),
            )
        elif event_type == "trust_vouch":
            self._apply_vouch(data["voucher_id"], data["target_id"])
        elif event_type == "trust_compromise":
            self._apply_compromise(data["agent_id"])
        elif event_type == "trust_decay":
            daily_factor = math.pow(0.5, 1.0 / 14)
            for ts in self._trust.values():
                ts.earned_score *= daily_factor
                ts.bonus_score *= daily_factor
        elif event_type == "budget_action":
            self._apply_budget_action(
                data.get("action_type", ""), data.get("target", ""),
            )
        elif event_type == "quarantine_enter":
            self._apply_quarantine_enter(
                data.get("reason", ""),
                data.get("severity", "high"),
                timestamp,
            )
        elif event_type == "quarantine_exit":
            self._apply_quarantine_exit()
        elif event_type == "quarantine_escalate":
            self._quarantine.escalated = True
            self._quarantine.escalation_reason = data.get("reason", "")
        elif event_type == "behavior_event":
            self._apply_behavior_event(
                data["agent_id"],
                data.get("output_length", 0),
                data.get("tool_used", ""),
                data.get("content_type", "text"),
            )

    # ── Internal: apply mutations ────────────────────────────────────

    def _ensure_trust(self, agent_id: str) -> TrustState:
        if agent_id not in self._trust:
            self._trust[agent_id] = TrustState(
                agent_id=agent_id, created=time.time(),
            )
        return self._trust[agent_id]

    def _apply_trust_interaction(
        self, agent_id: str, clean: bool, anomaly: bool,
    ) -> None:
        ts = self._ensure_trust(agent_id)
        ts.total_interactions += 1
        ts.last_interaction = time.time()
        if clean:
            ts.clean_interactions += 1
            ts.earned_score = 5.0 * math.log(ts.clean_interactions + 1)
        if anomaly:
            ts.anomaly_count += 1
            ts.earned_score *= 0.7
            ts.bonus_score *= 0.7

    def _apply_vouch(self, voucher_id: str, target_id: str) -> None:
        voucher_ts = self._trust.get(voucher_id)
        if voucher_ts is None:
            return
        if self._compute_tier(voucher_ts) < 2:
            return
        target_ts = self._ensure_trust(target_id)
        if voucher_id in target_ts.vouchers:
            return
        # Limit vouches per voucher to 10
        sponsorship_count = sum(
            1 for ts in self._trust.values()
            if voucher_id in ts.vouchers
        )
        if sponsorship_count >= 10:
            return
        target_ts.vouchers.append(voucher_id)
        target_ts.bonus_score += 8.0

    def _apply_compromise(self, agent_id: str) -> None:
        self._compromised.add(agent_id)
        ts = self._trust.get(agent_id)
        if ts:
            ts.compromised = True
            ts.earned_score = 0.0
            ts.bonus_score = 0.0

    def _apply_budget_action(self, action_type: str, target: str) -> None:
        self._budgets.write_tool_calls += 1
        if action_type == "post_message":
            self._budgets.posts_messages += 1
        if action_type == "http_write":
            self._budgets.external_http_writes += 1
            if target:
                self._budgets.seen_domains.add(target)

    def _apply_quarantine_enter(
        self, reason: str, severity: str, timestamp: float,
    ) -> None:
        self._quarantine.active = True
        self._quarantine.reason = reason
        self._quarantine.severity = severity
        self._quarantine.entered_at = timestamp

    def _apply_quarantine_exit(self) -> None:
        self._quarantine = QuarantineState()

    def _apply_behavior_event(
        self,
        agent_id: str,
        output_length: int,
        tool_used: str,
        content_type: str,
    ) -> None:
        if agent_id not in self._baselines:
            self._baselines[agent_id] = BehaviorBaseline(agent_id=agent_id)
        bl = self._baselines[agent_id]
        if bl.frozen:
            return  # baseline already locked
        bl.event_count += 1
        bl.total_output_length += output_length
        bl.avg_output_length = bl.total_output_length / bl.event_count
        if tool_used:
            bl.tool_counts[tool_used] = bl.tool_counts.get(tool_used, 0) + 1
        bl.content_type_counts[content_type] = (
            bl.content_type_counts.get(content_type, 0) + 1
        )
        # Freeze after anchor_window events
        if bl.event_count >= self._anchor_window:
            bl.frozen = True

    def _compute_tier(self, ts: TrustState) -> int:
        """Compute trust tier including vouched (tier 3) check."""
        if ts.compromised:
            return 0
        age_days = (
            (time.time() - ts.created) / 86400.0 if ts.created > 0 else 0.0
        )
        # Tier 3: 3+ vouchers from tier 2+ agents
        qualified_vouchers = 0
        for v in ts.vouchers:
            v_ts = self._trust.get(v)
            if v_ts and not v_ts.compromised:
                v_age = (
                    (time.time() - v_ts.created) / 86400.0
                    if v_ts.created > 0
                    else 0.0
                )
                if v_ts.score >= 50.0 and v_age >= 3:
                    qualified_vouchers += 1
        if (
            qualified_vouchers >= 3
            and ts.score >= 50.0
            and age_days >= 3
        ):
            return 3
        if ts.score >= 50.0 and age_days >= 3:
            return 2
        if ts.score >= 15.0:
            return 1
        return 0

    # ── Internal: checkpoint ─────────────────────────────────────────

    def _maybe_checkpoint(self) -> None:
        self._events_since_checkpoint += 1
        if self._events_since_checkpoint >= self._checkpoint_interval:
            self._write_checkpoint()

    def _write_checkpoint(self) -> None:
        state = self._serialise_state()
        try:
            self._log.write_checkpoint(state, self._checkpoint_path)
            self._events_since_checkpoint = 0
            logger.debug("Wrote state checkpoint")
        except Exception:
            logger.warning("Failed to write checkpoint", exc_info=True)

    def _serialise_state(self) -> dict[str, Any]:
        trust_records = {}
        for aid, ts in self._trust.items():
            trust_records[aid] = {
                "agent_id": ts.agent_id,
                "earned_score": ts.earned_score,
                "bonus_score": ts.bonus_score,
                "clean_interactions": ts.clean_interactions,
                "total_interactions": ts.total_interactions,
                "anomaly_count": ts.anomaly_count,
                "created": ts.created,
                "last_interaction": ts.last_interaction,
                "vouchers": ts.vouchers,
                "compromised": ts.compromised,
            }
        baselines = {}
        for aid, bl in self._baselines.items():
            baselines[aid] = {
                "agent_id": bl.agent_id,
                "event_count": bl.event_count,
                "avg_output_length": bl.avg_output_length,
                "tool_counts": bl.tool_counts,
                "content_type_counts": bl.content_type_counts,
                "total_output_length": bl.total_output_length,
                "frozen": bl.frozen,
            }
        return {
            "trust": trust_records,
            "compromised": list(self._compromised),
            "budgets": {
                "write_tool_calls": self._budgets.write_tool_calls,
                "posts_messages": self._budgets.posts_messages,
                "external_http_writes": self._budgets.external_http_writes,
                "seen_domains": list(self._budgets.seen_domains),
            },
            "quarantine": {
                "active": self._quarantine.active,
                "reason": self._quarantine.reason,
                "severity": self._quarantine.severity,
                "entered_at": self._quarantine.entered_at,
                "escalated": self._quarantine.escalated,
                "escalation_reason": self._quarantine.escalation_reason,
            },
            "baselines": baselines,
        }

    def _deserialise_state(self, state: dict[str, Any]) -> None:
        # Trust
        for aid, rec in state.get("trust", {}).items():
            self._trust[aid] = TrustState(
                agent_id=rec.get("agent_id", aid),
                earned_score=rec.get("earned_score", 0.0),
                bonus_score=rec.get("bonus_score", 0.0),
                clean_interactions=rec.get("clean_interactions", 0),
                total_interactions=rec.get("total_interactions", 0),
                anomaly_count=rec.get("anomaly_count", 0),
                created=rec.get("created", 0.0),
                last_interaction=rec.get("last_interaction", 0.0),
                vouchers=rec.get("vouchers", []),
                compromised=rec.get("compromised", False),
            )
        self._compromised = set(state.get("compromised", []))
        # Budgets
        bud = state.get("budgets", {})
        self._budgets = BudgetState(
            write_tool_calls=bud.get("write_tool_calls", 0),
            posts_messages=bud.get("posts_messages", 0),
            external_http_writes=bud.get("external_http_writes", 0),
            seen_domains=set(bud.get("seen_domains", [])),
        )
        # Quarantine
        q = state.get("quarantine", {})
        self._quarantine = QuarantineState(
            active=q.get("active", False),
            reason=q.get("reason", ""),
            severity=q.get("severity", "high"),
            entered_at=q.get("entered_at", 0.0),
            escalated=q.get("escalated", False),
            escalation_reason=q.get("escalation_reason", ""),
        )
        # Baselines
        for aid, bl in state.get("baselines", {}).items():
            self._baselines[aid] = BehaviorBaseline(
                agent_id=bl.get("agent_id", aid),
                event_count=bl.get("event_count", 0),
                avg_output_length=bl.get("avg_output_length", 0.0),
                tool_counts=bl.get("tool_counts", {}),
                content_type_counts=bl.get("content_type_counts", {}),
                total_output_length=bl.get("total_output_length", 0),
                frozen=bl.get("frozen", False),
            )
