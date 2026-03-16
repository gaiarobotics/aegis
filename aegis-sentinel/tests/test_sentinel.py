"""Tests for sentinel orchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from sentinel.config import CoverageMode, SentinelConfig
from sentinel.sentinel import Sentinel


class TestSentinel:
    def _make_config(self, **overrides) -> SentinelConfig:
        defaults = {
            "agent_id": "sentinel-test",
            "operator_id": "test-org",
        }
        defaults.update(overrides)
        return SentinelConfig(**defaults)

    @patch("sentinel.sentinel.Shield")
    def test_init_creates_shield_with_sentinel_profile(self, MockShield):
        cfg = self._make_config()
        sentinel = Sentinel(config=cfg)
        assert sentinel._shield is not None
        assert sentinel._observer is not None
        assert sentinel._coverage is not None
        assert sentinel._reporter is not None

    @patch("sentinel.sentinel.Shield")
    def test_declared_capabilities_are_read_only(self, MockShield):
        cfg = self._make_config()
        sentinel = Sentinel(config=cfg)
        assert sentinel.declared_capabilities == ["like", "subscribe", "read"]

    @patch("sentinel.sentinel.Shield")
    def test_process_posts_delegates_to_observer(self, MockShield):
        cfg = self._make_config()
        sentinel = Sentinel(config=cfg)
        sentinel._observer = MagicMock()
        sentinel._observer.observe_post.return_value = MagicMock(is_threat=False)
        sentinel._coverage = MagicMock()

        posts = [
            {"id": "p1", "author": "moltbook:a", "content": "hi", "submolt": "submolt:x"},
        ]
        results = sentinel.process_posts(posts)
        assert len(results) == 1
        sentinel._observer.observe_post.assert_called_once()

    @patch("sentinel.sentinel.Shield")
    def test_process_posts_feeds_discovery_in_broad_mode(self, MockShield):
        cfg = self._make_config(coverage_mode=CoverageMode.BROAD)
        sentinel = Sentinel(config=cfg)
        sentinel._observer = MagicMock()
        sentinel._observer.observe_post.return_value = MagicMock(is_threat=False)

        posts = [
            {"id": "p1", "author": "moltbook:a", "content": "hi", "submolt": "submolt:new"},
        ]
        sentinel.process_posts(posts)
        assert "submolt:new" in sentinel._coverage.subscribed_submolts

    @patch("sentinel.sentinel.Shield")
    def test_broker_blocks_post_action(self, MockShield):
        cfg = self._make_config()
        mock_shield_instance = MockShield.return_value
        mock_shield_instance.evaluate_action.return_value = MagicMock(
            allowed=False,
            decision="deny",
            reason="budget exceeded: max_posts_messages=0",
        )
        sentinel = Sentinel(config=cfg)
        result = sentinel.attempt_write_action("post_message", "submolt:x")
        assert result.allowed is False

    @patch("sentinel.sentinel.Shield")
    def test_broker_blocks_dm_action(self, MockShield):
        cfg = self._make_config()
        mock_shield_instance = MockShield.return_value
        mock_shield_instance.evaluate_action.return_value = MagicMock(
            allowed=False,
            decision="deny",
            reason="budget exceeded: max_posts_messages=0",
        )
        sentinel = Sentinel(config=cfg)
        result = sentinel.attempt_write_action("post_message", "moltbook:alice")
        assert result.allowed is False
