"""Anti-poisoning validation for compromise report hashes.

Implements three defenses against malicious hash-cloud poisoning:

1. **Rate limiting** — caps reports per agent per time window.
2. **Reporter reputation** — requires minimum trust tier; quarantined
   reporters cannot confirm hashes.
3. **Cross-validation (quorum)** — multiple independent reporters must
   agree before a hash is promoted to the contagion cloud.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from monitor.config import MonitorConfig
from monitor.contagion import hamming_distance, hex_to_int


@dataclass
class ValidationResult:
    accepted: bool = True
    hash_confirmed: bool = False
    rejection_reason: str = ""


class ReportValidator:
    """Central validation gate for compromise report hashes."""

    def __init__(self, config: MonitorConfig) -> None:
        self._rate_limit = config.compromise_rate_limit
        self._rate_window = config.compromise_rate_window
        self._min_trust_tier = config.compromise_min_trust_tier
        self._quorum = config.compromise_quorum

        self._rate_counters: dict[str, list[float]] = {}
        # hash_int -> (set of reporter_ids, oldest_timestamp)
        self._pending_hashes: dict[int, tuple[set[str], float]] = {}

    def validate(
        self,
        reporter_id: str,
        compromised_id: str,
        hash_hex: str,
        reporter_trust_tier: int,
        reporter_is_quarantined: bool,
    ) -> ValidationResult:
        # Empty hash — skip all hash validation
        if not hash_hex:
            return ValidationResult(accepted=True, hash_confirmed=False)

        now = time.time()

        # Defense 1: Rate limiting
        timestamps = self._rate_counters.get(reporter_id, [])
        cutoff = now - self._rate_window
        timestamps = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= self._rate_limit:
            self._rate_counters[reporter_id] = timestamps
            return ValidationResult(
                accepted=False,
                hash_confirmed=False,
                rejection_reason="rate_limited",
            )
        timestamps.append(now)
        self._rate_counters[reporter_id] = timestamps

        # Defense 2: Reporter reputation
        if reporter_trust_tier < self._min_trust_tier:
            return ValidationResult(
                accepted=True,
                hash_confirmed=False,
                rejection_reason="low_trust",
            )
        if reporter_is_quarantined:
            return ValidationResult(
                accepted=True,
                hash_confirmed=False,
                rejection_reason="reporter_quarantined",
            )

        # Defense 3: Cross-validation (quorum)
        self._prune_pending(now)

        reported_int = hex_to_int(hash_hex)

        # Immediate confirmation when quorum is 1
        if self._quorum <= 1:
            return ValidationResult(accepted=True, hash_confirmed=True)

        # Find existing pending group within Hamming distance 16
        matched_key: int | None = None
        for pending_hash in list(self._pending_hashes.keys()):
            if hamming_distance(reported_int, pending_hash) <= 16:
                matched_key = pending_hash
                break

        if matched_key is not None:
            reporters, oldest = self._pending_hashes[matched_key]
            reporters.add(reporter_id)
            if len(reporters) >= self._quorum:
                del self._pending_hashes[matched_key]
                return ValidationResult(accepted=True, hash_confirmed=True)
            self._pending_hashes[matched_key] = (reporters, oldest)
            return ValidationResult(
                accepted=True,
                hash_confirmed=False,
                rejection_reason="pending_quorum",
            )

        # New pending entry
        self._pending_hashes[reported_int] = ({reporter_id}, now)
        return ValidationResult(
            accepted=True,
            hash_confirmed=False,
            rejection_reason="pending_quorum",
        )

    def _prune_pending(self, now: float) -> None:
        """Remove pending hashes older than 2 * rate_window."""
        max_age = 2 * self._rate_window
        expired = [
            h for h, (_, ts) in self._pending_hashes.items()
            if now - ts > max_age
        ]
        for h in expired:
            del self._pending_hashes[h]
