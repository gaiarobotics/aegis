"""Tests for sentinel configuration."""

from __future__ import annotations

import pytest

from sentinel.config import CoverageMode, SentinelConfig


class TestSentinelConfig:
    def test_defaults(self):
        cfg = SentinelConfig()
        assert cfg.agent_id == "sentinel"
        assert cfg.operator_id == ""
        assert cfg.coverage_mode == CoverageMode.BROAD
        assert cfg.watchlist == []
        assert cfg.poll_interval_seconds == 30.0
        assert cfg.like_rate_limit == 100
        assert cfg.monitor_url == ""

    def test_watchlist_mode(self):
        cfg = SentinelConfig(
            coverage_mode=CoverageMode.WATCHLIST,
            watchlist=["moltbook:alice", "submolt:security"],
        )
        assert cfg.coverage_mode == CoverageMode.WATCHLIST
        assert len(cfg.watchlist) == 2

    def test_from_dict(self):
        data = {
            "agent_id": "sentinel-01",
            "operator_id": "gaia",
            "coverage_mode": "watchlist",
            "watchlist": ["moltbook:bob"],
            "poll_interval_seconds": 15.0,
        }
        cfg = SentinelConfig.model_validate(data)
        assert cfg.agent_id == "sentinel-01"
        assert cfg.coverage_mode == CoverageMode.WATCHLIST

    def test_like_rate_limit_positive(self):
        with pytest.raises(ValueError):
            SentinelConfig(like_rate_limit=-1)
