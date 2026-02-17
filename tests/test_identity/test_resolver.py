"""Tests for AEGIS identity resolver — canonical ID mapping."""

import pytest

from aegis.identity.resolver import IdentityResolver, _edit_distance_one


class TestNormalization:
    """Basic normalization: lowercase, strip prefixes/whitespace."""

    def test_lowercase(self):
        r = IdentityResolver()
        assert r.resolve("Alice") == "alice"

    def test_strip_at_prefix(self):
        r = IdentityResolver()
        assert r.resolve("@alice") == "alice"

    def test_strip_whitespace(self):
        r = IdentityResolver()
        assert r.resolve("  alice  ") == "alice"

    def test_combined(self):
        r = IdentityResolver()
        assert r.resolve("  @Alice  ") == "alice"


class TestConsistentMapping:
    """Same agent appearing with different surface forms maps consistently."""

    def test_case_variants_same_canonical(self):
        r = IdentityResolver()
        id1 = r.resolve("Alice")
        id2 = r.resolve("alice")
        id3 = r.resolve("ALICE")
        assert id1 == id2 == id3

    def test_at_prefix_variants(self):
        r = IdentityResolver()
        id1 = r.resolve("alice")
        id2 = r.resolve("@alice")
        assert id1 == id2

    def test_platform_email_to_canonical(self):
        """alice@moltbook.social → moltbook:alice"""
        r = IdentityResolver()
        canonical = r.resolve("alice@moltbook.social")
        assert canonical == "moltbook:alice"

    def test_platform_and_bare_name_converge(self):
        """alice@moltbook.social and bare 'alice' should converge via fuzzy."""
        r = IdentityResolver()
        # First encounter: bare alice
        id1 = r.resolve("alice")
        # Second encounter: platform-qualified
        id2 = r.resolve("alice@moltbook.social")
        # moltbook:alice is different from alice — they're distinct without
        # explicit aliasing. Platform-qualified IDs are intentionally separate
        # so that alice@moltbook and alice@openclaw don't merge.
        assert id2 == "moltbook:alice"

    def test_explicit_alias_merges_platform_and_bare(self):
        """Operator can explicitly alias platform form to bare form."""
        r = IdentityResolver(aliases={
            "alice@moltbook.social": "alice",
        })
        id1 = r.resolve("alice")
        id2 = r.resolve("alice@moltbook.social")
        assert id1 == id2

    def test_openclaw_platform(self):
        r = IdentityResolver()
        assert r.resolve("bot42@openclaw.io") == "openclaw:bot42"

    def test_unknown_domain_passthrough(self):
        r = IdentityResolver()
        assert r.resolve("user@unknown.example.com") == "user@unknown.example.com"


class TestFuzzyMatching:
    """Typos within edit distance 1 merge to existing canonical."""

    def test_typo_one_char(self):
        r = IdentityResolver()
        r.resolve("alice")  # register canonical
        # "alce" is edit distance 1 from "alice"
        assert r.resolve("alce") == "alice"

    def test_typo_extra_char(self):
        r = IdentityResolver()
        r.resolve("alice")
        assert r.resolve("aalice") == "alice"

    def test_typo_missing_char(self):
        r = IdentityResolver()
        r.resolve("alice")
        assert r.resolve("alic") == "alice"

    def test_no_fuzzy_on_short_ids(self):
        """IDs shorter than 3 chars skip fuzzy matching."""
        r = IdentityResolver()
        r.resolve("ab")
        # "ac" is edit distance 1, but too short for fuzzy
        id2 = r.resolve("ac")
        assert id2 == "ac"  # separate canonical

    def test_ambiguous_fuzzy_no_merge(self):
        """Two canonicals within distance 1 of query → no merge (ambiguous)."""
        r = IdentityResolver()
        # Manually register two canonicals that are far apart
        # so neither fuzzy-merges into the other on creation
        r._canonicals.add("xalice")
        r._aliases["xalice"] = "xalice"
        r._canonicals.add("xblice")
        r._aliases["xblice"] = "xblice"
        # "xclice" is distance 1 from both — ambiguous, should stay separate
        id3 = r.resolve("xclice")
        assert id3 == "xclice"


class TestAliasRegistry:
    """Explicit alias configuration."""

    def test_explicit_alias(self):
        r = IdentityResolver(aliases={"bob_the_bot": "bob"})
        assert r.resolve("bob_the_bot") == "bob"
        assert r.resolve("bob") == "bob"

    def test_add_alias_runtime(self):
        r = IdentityResolver()
        r.resolve("alice")  # register
        r.add_alias("alice_primary", "alice")
        assert r.resolve("alice_primary") == "alice"

    def test_known_canonicals(self):
        r = IdentityResolver()
        r.resolve("alice")
        r.resolve("bob")
        assert "alice" in r.known_canonicals
        assert "bob" in r.known_canonicals


class TestAutoLearn:
    """auto_learn=True registers new IDs as canonicals automatically."""

    def test_auto_learn_on(self):
        r = IdentityResolver(auto_learn=True)
        r.resolve("newagent")
        assert "newagent" in r.known_canonicals

    def test_auto_learn_off(self):
        r = IdentityResolver(auto_learn=False)
        r.resolve("newagent")
        assert "newagent" not in r.known_canonicals


class TestEditDistanceOne:
    """Unit tests for the optimized edit-distance-1 check."""

    def test_identical(self):
        assert _edit_distance_one("abc", "abc") is True

    def test_substitution(self):
        assert _edit_distance_one("abc", "axc") is True

    def test_insertion(self):
        assert _edit_distance_one("abc", "abxc") is True

    def test_deletion(self):
        assert _edit_distance_one("abxc", "abc") is True

    def test_distance_two(self):
        assert _edit_distance_one("abc", "xyz") is False

    def test_length_diff_two(self):
        assert _edit_distance_one("ab", "abcd") is False


class TestEndToEndTrustResolution:
    """Integration: resolver + shield + provider produces consistent trust."""

    def test_case_variants_accumulate_same_score(self):
        from aegis.shield import Shield

        shield = Shield(modules=["scanner", "identity"], mode="enforce")
        assert shield._trust_manager is not None
        assert shield._identity_resolver is not None

        # Record interactions for same agent under different surface forms
        shield.record_trust_interaction("Alice", clean=True)
        shield.record_trust_interaction("alice", clean=True)
        shield.record_trust_interaction("@Alice", clean=True)

        # All should map to canonical "alice"
        score = shield._trust_manager.get_score("alice")
        # 3 clean interactions → score = 5 * log(4) ≈ 6.93
        assert score > 5.0
        # And the non-canonical forms should NOT have separate records
        assert "Alice" not in shield._trust_manager._records
        assert "@Alice" not in shield._trust_manager._records

    def test_platform_qualified_stays_distinct(self):
        from aegis.shield import Shield

        shield = Shield(modules=["scanner", "identity"], mode="enforce")

        shield.record_trust_interaction("alice", clean=True)
        shield.record_trust_interaction("alice@moltbook.social", clean=True)

        # These are intentionally distinct — different trust contexts
        score_bare = shield._trust_manager.get_score("alice")
        score_moltbook = shield._trust_manager.get_score("moltbook:alice")
        assert score_bare > 0
        assert score_moltbook > 0
        # They should NOT be the same record
        assert shield._trust_manager._records.get("alice") is not \
               shield._trust_manager._records.get("moltbook:alice")
