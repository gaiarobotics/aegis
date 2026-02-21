"""Identity resolution — maps variant agent identifiers to canonical IDs.

Without resolution, the same Moltbook user appearing as ``"alice"``,
``"Alice"``, ``"alice@moltbook.social"``, and ``"@alice"`` would accumulate
trust under four independent records.  The resolver collapses these to a
single canonical ID.

Resolution strategy (applied in order):

1. **Normalize** — lowercase, strip whitespace, strip leading ``@``.
2. **Platform prefix extraction** — ``user@platform`` becomes
   ``platform:user`` so cross-platform identities stay distinct.
3. **Alias registry** — explicit mappings (``display_name → canonical``)
   configured by the operator or learned from metadata.
4. **Fuzzy dedup** — optional Levenshtein check catches typos within
   edit-distance 1 of a known canonical ID.
"""

from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Optional rapidfuzz integration
# ---------------------------------------------------------------------------

_RAPIDFUZZ_AVAILABLE: bool | None = None


def is_rapidfuzz_available() -> bool:
    """Check whether the rapidfuzz package is importable."""
    global _RAPIDFUZZ_AVAILABLE
    if _RAPIDFUZZ_AVAILABLE is None:
        try:
            import rapidfuzz  # noqa: F401
            _RAPIDFUZZ_AVAILABLE = True
        except ImportError:
            _RAPIDFUZZ_AVAILABLE = False
    return _RAPIDFUZZ_AVAILABLE


# Known platform suffixes → canonical platform prefix
_PLATFORM_SUFFIXES: dict[str, str] = {
    "moltbook.social": "moltbook",
    "moltbook.com": "moltbook",
    "openclaw.io": "openclaw",
    "openclaw.com": "openclaw",
    "slack.com": "slack",
    "discord.gg": "discord",
}

# Characters stripped from the beginning of raw IDs
_STRIP_PREFIXES = ("@", "#", "!")


class IdentityResolver:
    """Resolves raw agent identifiers to canonical IDs.

    Args:
        aliases: Optional initial alias mapping ``{raw: canonical}``.
        auto_learn: If True, the first normalized form seen for a new
            canonical root becomes the canonical, and subsequent variants
            are auto-aliased.  Defaults to False.
    """

    def __init__(
        self,
        aliases: dict[str, str] | None = None,
        auto_learn: bool = False,
    ) -> None:
        # canonical → canonical (identity), raw_variant → canonical
        self._aliases: dict[str, str] = {}
        self._auto_learn = auto_learn
        # Track all known canonical IDs for fuzzy matching
        self._canonicals: set[str] = set()

        if aliases:
            for raw, canonical in aliases.items():
                self.add_alias(raw, canonical)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def resolve(self, raw_id: str) -> str:
        """Resolve a raw identifier to its canonical form.

        Steps:
        1. Normalize (lowercase, strip prefixes/whitespace)
        2. Check alias registry
        3. Extract platform prefix from ``user@domain``
        4. Fuzzy-match against known canonicals
        5. If auto_learn, register as new canonical
        """
        normalized = self._normalize(raw_id)
        if not normalized:
            return raw_id.strip()

        # Check alias registry first (exact match on normalized form)
        if normalized in self._aliases:
            return self._aliases[normalized]

        # Platform prefix extraction: alice@moltbook.social → moltbook:alice
        platformed = self._extract_platform(normalized)
        if platformed != normalized:
            # Check alias for the platformed form too
            if platformed in self._aliases:
                return self._aliases[platformed]
            normalized = platformed

        # Check alias again after platform extraction
        if normalized in self._aliases:
            return self._aliases[normalized]

        # Fuzzy match against known canonicals (edit distance 1)
        fuzzy = self._fuzzy_match(normalized)
        if fuzzy is not None:
            self._aliases[normalized] = fuzzy
            return fuzzy

        # No match — this is a new canonical identity
        if self._auto_learn:
            self._canonicals.add(normalized)
            self._aliases[normalized] = normalized

        return normalized

    def add_alias(self, raw: str, canonical: str) -> None:
        """Explicitly map a raw identifier to a canonical ID."""
        norm_raw = self._normalize(raw)
        norm_canonical = self._normalize(canonical)
        if not norm_raw or not norm_canonical:
            return
        self._aliases[norm_raw] = norm_canonical
        self._canonicals.add(norm_canonical)

    @property
    def known_canonicals(self) -> set[str]:
        """All known canonical IDs."""
        return set(self._canonicals)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize(raw: str) -> str:
        """Lowercase, strip whitespace and common prefixes."""
        s = raw.strip().lower()
        for prefix in _STRIP_PREFIXES:
            if s.startswith(prefix):
                s = s[len(prefix):]
        return s.strip()

    @staticmethod
    def _extract_platform(normalized: str) -> str:
        """Convert ``user@domain`` to ``platform:user`` if domain is known."""
        if "@" not in normalized:
            return normalized
        parts = normalized.rsplit("@", 1)
        if len(parts) != 2:
            return normalized
        user, domain = parts
        platform = _PLATFORM_SUFFIXES.get(domain)
        if platform:
            return f"{platform}:{user}"
        return normalized

    def _fuzzy_match(self, normalized: str) -> str | None:
        """Find a canonical ID within edit distance 1 of normalized.

        Only matches if exactly one canonical is within distance 1,
        to avoid ambiguous merges.
        """
        if len(normalized) < 5:
            # Too short for reliable fuzzy matching
            return None

        candidates = []
        for canonical in self._canonicals:
            if _edit_distance_at_most(normalized, canonical, 1):
                candidates.append(canonical)

        if len(candidates) == 1:
            return candidates[0]
        return None


def _edit_distance_at_most(a: str, b: str, max_dist: int) -> bool:
    """Check if edit distance between a and b is <= max_dist.

    Uses rapidfuzz when available for faster computation,
    falling back to pure-Python implementation.
    """
    if abs(len(a) - len(b)) > max_dist:
        return False
    if a == b:
        return True

    # Fast path: use rapidfuzz when available
    if is_rapidfuzz_available():
        from rapidfuzz.distance import Levenshtein
        return Levenshtein.distance(a, b) <= max_dist

    # Pure-Python fallback
    if max_dist == 1:
        return _edit_distance_one(a, b)

    # General bounded Levenshtein
    m, n = len(a), len(b)
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        curr = [i] + [0] * n
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1]
            else:
                curr[j] = 1 + min(prev[j], curr[j - 1], prev[j - 1])
        prev = curr
    return prev[n] <= max_dist


def _edit_distance_one(a: str, b: str) -> bool:
    """Optimized check for edit distance exactly 0 or 1."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False

    diffs = 0
    i = j = 0
    while i < la and j < lb:
        if a[i] != b[j]:
            diffs += 1
            if diffs > 1:
                return False
            if la > lb:
                i += 1
                continue
            elif lb > la:
                j += 1
                continue
        i += 1
        j += 1

    return True
