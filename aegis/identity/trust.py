"""Trust tier management for agent identity.

Implements a progressive trust model where agents earn trust through
clean interactions, age, and vouching from established peers.

Tiers:
    0 - Unknown: No trust established
    1 - Attested: Score >= 15 (has valid attestation)
    2 - Established: Score >= 50 and account age >= 3 days
    3 - Vouched: 3+ vouchers from Tier 2+ agents
"""

from __future__ import annotations

import json
import math
import os
import tempfile
import time
from dataclasses import dataclass, field


# Tier constants
TIER_UNKNOWN = 0
TIER_ATTESTED = 1
TIER_ESTABLISHED = 2
TIER_VOUCHED = 3

# Thresholds
TIER_1_SCORE = 15.0
TIER_2_SCORE = 50.0
TIER_2_AGE_DAYS = 3
TIER_3_VOUCHERS = 3
TIER_3_VOUCHER_MIN_TIER = 2

# Scoring
VOUCH_BONUS = 8.0
DECAY_HALF_LIFE_DAYS = 14
MAX_DELEGATION_BONUS = 50.0
MAX_VOUCHES_PER_VOUCHER = 10
INTERACTION_MIN_INTERVAL = 0.1


@dataclass
class TrustRecord:
    """Trust record for a single agent."""

    agent_id: str
    score: float = 0.0
    earned_score: float = 0.0
    bonus_score: float = 0.0
    tier: int = TIER_UNKNOWN
    clean_interactions: int = 0
    total_interactions: int = 0
    last_interaction: float = 0.0
    created: float = field(default_factory=time.time)
    vouchers: list[str] = field(default_factory=list)
    anomaly_count: int = 0


class TrustManager:
    """Manages trust scores and tiers for agents.

    Args:
        config: Optional configuration dict for overriding defaults.
    """

    def __init__(self, config: dict | None = None):
        self._records: dict[str, TrustRecord] = {}
        self._config = config or {}
        self._compromised: set[str] = set()
        self._compromise_callback = None
        self._interaction_min_interval: float = float(
            self._config.get("interaction_min_interval", INTERACTION_MIN_INTERVAL)
        )

    @staticmethod
    def _normalize_id(agent_id: str) -> str:
        """Normalize an agent ID to a canonical form."""
        return agent_id.strip().lower()

    def set_compromise_callback(self, callback) -> None:
        """Register a callback invoked on ``report_compromise()``.

        The callback receives ``(agent_id: str)`` and is wrapped in
        try/except so that failures never disrupt trust management.
        """
        self._compromise_callback = callback

    def _ensure_record(self, agent_id: str) -> TrustRecord:
        """Get or create a trust record for an agent."""
        agent_id = self._normalize_id(agent_id)
        if agent_id not in self._records:
            self._records[agent_id] = TrustRecord(agent_id=agent_id)
        return self._records[agent_id]

    def get_tier(self, agent_id: str) -> int:
        """Get the current trust tier for an agent.

        Args:
            agent_id: The agent identifier.

        Returns:
            The trust tier (0-3).
        """
        agent_id = self._normalize_id(agent_id)
        if agent_id in self._compromised:
            return TIER_UNKNOWN

        if agent_id not in self._records:
            return TIER_UNKNOWN

        record = self._records[agent_id]
        return self._compute_tier(record)

    def _compute_tier(self, record: TrustRecord) -> int:
        """Compute the tier for a trust record."""
        if record.agent_id in self._compromised:
            return TIER_UNKNOWN

        # Check Tier 3: 3+ vouchers from Tier 2+ agents
        qualified_vouchers = sum(
            1 for v in record.vouchers
            if v in self._records and self._compute_tier_without_vouch(self._records[v]) >= TIER_3_VOUCHER_MIN_TIER
        )
        if (
            qualified_vouchers >= TIER_3_VOUCHERS
            and record.score >= TIER_2_SCORE
            and self._age_days(record) >= TIER_2_AGE_DAYS
        ):
            return TIER_VOUCHED

        # Check Tier 2: score >= 50 and age >= 3 days
        if record.score >= TIER_2_SCORE and self._age_days(record) >= TIER_2_AGE_DAYS:
            return TIER_ESTABLISHED

        # Check Tier 1: score >= 15
        if record.score >= TIER_1_SCORE:
            return TIER_ATTESTED

        return TIER_UNKNOWN

    def _compute_tier_without_vouch(self, record: TrustRecord) -> int:
        """Compute tier without considering vouched status (to avoid recursion)."""
        if record.agent_id in self._compromised:
            return TIER_UNKNOWN
        if record.score >= TIER_2_SCORE and self._age_days(record) >= TIER_2_AGE_DAYS:
            return TIER_ESTABLISHED
        if record.score >= TIER_1_SCORE:
            return TIER_ATTESTED
        return TIER_UNKNOWN

    def _age_days(self, record: TrustRecord) -> float:
        """Get the age of a record in days."""
        return (time.time() - record.created) / 86400.0

    def get_score(self, agent_id: str) -> float:
        """Get the current trust score for an agent.

        Args:
            agent_id: The agent identifier.

        Returns:
            The trust score (>= 0.0).
        """
        agent_id = self._normalize_id(agent_id)
        if agent_id not in self._records:
            return 0.0
        return self._records[agent_id].score

    def record_interaction(
        self, agent_id: str, clean: bool = True, anomaly: bool = False
    ) -> None:
        """Record an interaction for an agent.

        Clean interactions increase score logarithmically.
        Anomalies apply exponential penalty to both earned and bonus scores.

        Args:
            agent_id: The agent identifier.
            clean: Whether the interaction was clean.
            anomaly: Whether an anomaly was detected.
        """
        agent_id = self._normalize_id(agent_id)
        record = self._ensure_record(agent_id)

        # Rate-limit: silently drop calls within the minimum interval
        now = time.time()
        if record.last_interaction > 0 and (now - record.last_interaction) < self._interaction_min_interval:
            return

        record.total_interactions += 1
        record.last_interaction = now

        if clean:
            record.clean_interactions += 1
            # Logarithmic growth: earned_score increases by log(n+1)
            n = record.clean_interactions
            record.earned_score = 5.0 * math.log(n + 1)

        if anomaly:
            record.anomaly_count += 1
            # Exponential penalty: apply to both earned and bonus scores
            penalty_factor = 0.7  # 30% reduction per anomaly
            record.earned_score *= penalty_factor
            record.bonus_score *= penalty_factor

        record.score = record.earned_score + record.bonus_score

    def vouch(self, voucher_id: str, target_id: str) -> None:
        """Register a vouch from one agent to another.

        Only vouchers at Tier 2+ can vouch. Each voucher can only vouch
        for a target once. Each vouch adds VOUCH_BONUS to the target's bonus_score.
        Each voucher is limited to MAX_VOUCHES_PER_VOUCHER total sponsorships.

        Args:
            voucher_id: The vouching agent's identifier.
            target_id: The target agent's identifier.
        """
        voucher_id = self._normalize_id(voucher_id)
        target_id = self._normalize_id(target_id)
        # Check voucher qualification
        if self.get_tier(voucher_id) < TIER_3_VOUCHER_MIN_TIER:
            return

        target = self._ensure_record(target_id)

        # Prevent duplicate vouches
        if voucher_id in target.vouchers:
            return

        # Limit vouches per voucher
        sponsorship_count = sum(
            1 for rec in self._records.values()
            if voucher_id in rec.vouchers
        )
        if sponsorship_count >= MAX_VOUCHES_PER_VOUCHER:
            return

        target.vouchers.append(voucher_id)
        target.bonus_score += VOUCH_BONUS
        target.score = target.earned_score + target.bonus_score

    def report_compromise(self, agent_id: str) -> None:
        """Report an agent as compromised. Immediately drops to Tier 0 with score 0.

        Args:
            agent_id: The compromised agent's identifier.
        """
        agent_id = self._normalize_id(agent_id)
        self._compromised.add(agent_id)
        if agent_id in self._records:
            self._records[agent_id].score = 0.0
            self._records[agent_id].tier = TIER_UNKNOWN

        if self._compromise_callback is not None:
            try:
                self._compromise_callback(agent_id)
            except Exception:
                pass

    def set_operator_delegation(self, agent_id: str, bonus: float) -> None:
        """Apply an operator-delegated trust bonus.

        The bonus is added to bonus_score, which is capped at MAX_DELEGATION_BONUS.

        Args:
            agent_id: The agent identifier.
            bonus: The bonus to add to the score.
        """
        agent_id = self._normalize_id(agent_id)
        record = self._ensure_record(agent_id)
        record.bonus_score = min(record.bonus_score + bonus, MAX_DELEGATION_BONUS)
        record.score = record.earned_score + record.bonus_score

    def apply_decay(self) -> None:
        """Apply time-based decay to all trust scores.

        Uses a 14-day half-life, applied daily.
        The daily decay factor is 2^(-1/14).
        """
        daily_factor = math.pow(0.5, 1.0 / DECAY_HALF_LIFE_DAYS)
        for record in self._records.values():
            record.earned_score *= daily_factor
            record.bonus_score *= daily_factor
            record.score = record.earned_score + record.bonus_score

    def save(self, path: str) -> None:
        """Save trust data to a JSON file (atomic write via temp + rename).

        Args:
            path: File path to save to.
        """
        data = {}
        for agent_id, record in self._records.items():
            data[agent_id] = {
                "agent_id": record.agent_id,
                "score": record.score,
                "earned_score": record.earned_score,
                "bonus_score": record.bonus_score,
                "tier": record.tier,
                "clean_interactions": record.clean_interactions,
                "total_interactions": record.total_interactions,
                "last_interaction": record.last_interaction,
                "created": record.created,
                "vouchers": record.vouchers,
                "anomaly_count": record.anomaly_count,
            }
        dir_name = os.path.dirname(os.path.abspath(path))
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(
                    {"records": data, "compromised": list(self._compromised)},
                    f,
                    indent=2,
                )
            os.replace(tmp_path, path)
        except BaseException:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def load(self, path: str) -> None:
        """Load trust data from a JSON file.

        Args:
            path: File path to load from.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the data is malformed.
        """
        with open(path) as f:
            raw = json.load(f)

        compromised_raw = raw.get("compromised", [])
        if not isinstance(compromised_raw, list):
            raise ValueError("'compromised' must be a list")
        for item in compromised_raw:
            if not isinstance(item, str):
                raise ValueError("Each compromised entry must be a string")

        records_raw = raw.get("records", {})
        if not isinstance(records_raw, dict):
            raise ValueError("'records' must be a dict")

        new_records: dict[str, TrustRecord] = {}
        for agent_id, rec_data in records_raw.items():
            if not isinstance(rec_data, dict):
                raise ValueError(f"Record for '{agent_id}' must be a dict")
            # Validate types
            score = rec_data.get("score", 0.0)
            if not isinstance(score, (int, float)):
                raise ValueError(f"Invalid score type for '{agent_id}'")
            vouchers = rec_data.get("vouchers", [])
            if not isinstance(vouchers, list) or not all(isinstance(v, str) for v in vouchers):
                raise ValueError(f"Invalid vouchers for '{agent_id}'")

            new_records[agent_id] = TrustRecord(
                agent_id=rec_data.get("agent_id", agent_id),
                score=float(score),
                earned_score=float(rec_data.get("earned_score", score)),
                bonus_score=float(rec_data.get("bonus_score", 0.0)),
                tier=rec_data.get("tier", TIER_UNKNOWN),
                clean_interactions=int(rec_data.get("clean_interactions", 0)),
                total_interactions=int(rec_data.get("total_interactions", 0)),
                last_interaction=float(rec_data.get("last_interaction", 0.0)),
                created=float(rec_data.get("created", 0.0)),
                vouchers=vouchers,
                anomaly_count=int(rec_data.get("anomaly_count", 0)),
            )

        self._compromised = set(compromised_raw)
        self._records = new_records
