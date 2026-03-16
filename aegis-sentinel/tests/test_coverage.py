"""Tests for sentinel coverage manager."""

from __future__ import annotations

from sentinel.config import CoverageMode, SentinelConfig
from sentinel.coverage import CoverageManager


class TestCoverageManager:
    def test_broad_mode_starts_empty_discovers(self):
        cfg = SentinelConfig(coverage_mode=CoverageMode.BROAD)
        mgr = CoverageManager(cfg)
        assert mgr.mode == CoverageMode.BROAD
        assert mgr.subscribed_submolts == set()
        assert mgr.followed_agents == set()

    def test_watchlist_mode_seeds_from_config(self):
        cfg = SentinelConfig(
            coverage_mode=CoverageMode.WATCHLIST,
            watchlist=["submolt:security", "moltbook:alice"],
        )
        mgr = CoverageManager(cfg)
        assert "submolt:security" in mgr.subscribed_submolts
        assert "moltbook:alice" in mgr.followed_agents

    def test_add_submolt(self):
        cfg = SentinelConfig(coverage_mode=CoverageMode.BROAD)
        mgr = CoverageManager(cfg)
        mgr.add_submolt("submolt:general")
        assert "submolt:general" in mgr.subscribed_submolts

    def test_add_agent(self):
        cfg = SentinelConfig(coverage_mode=CoverageMode.BROAD)
        mgr = CoverageManager(cfg)
        mgr.add_agent("moltbook:bob")
        assert "moltbook:bob" in mgr.followed_agents

    def test_discover_from_posts(self):
        cfg = SentinelConfig(coverage_mode=CoverageMode.BROAD)
        mgr = CoverageManager(cfg)
        posts = [
            {"submolt": "submolt:tech", "author": "moltbook:carol"},
            {"submolt": "submolt:tech", "author": "moltbook:dave"},
            {"submolt": "submolt:art", "author": "moltbook:carol"},
        ]
        mgr.discover_from_posts(posts)
        assert "submolt:tech" in mgr.subscribed_submolts
        assert "submolt:art" in mgr.subscribed_submolts
        assert "moltbook:carol" in mgr.followed_agents
        assert "moltbook:dave" in mgr.followed_agents

    def test_watchlist_mode_ignores_discovery(self):
        cfg = SentinelConfig(
            coverage_mode=CoverageMode.WATCHLIST,
            watchlist=["submolt:security"],
        )
        mgr = CoverageManager(cfg)
        mgr.discover_from_posts([{"submolt": "submolt:tech", "author": "moltbook:x"}])
        assert "submolt:tech" not in mgr.subscribed_submolts

    def test_get_targets(self):
        cfg = SentinelConfig(
            coverage_mode=CoverageMode.WATCHLIST,
            watchlist=["submolt:security", "moltbook:alice"],
        )
        mgr = CoverageManager(cfg)
        targets = mgr.get_targets()
        assert targets["submolts"] == {"submolt:security"}
        assert targets["agents"] == {"moltbook:alice"}
