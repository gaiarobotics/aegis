"""Tests for platform auto-detection."""

import threading
import pytest

from aegis.core.platform_detection import PlatformDetector


class TestPlatformDetector:

    def test_no_platforms_initially(self):
        pd = PlatformDetector()
        assert pd.active_platforms == set()

    def test_agent_id_triggers_detection(self):
        pd = PlatformDetector()
        pd.check_agent_id("moltbook:alice")
        assert "moltbook" in pd.active_platforms

    def test_agent_id_non_platform_ignored(self):
        pd = PlatformDetector()
        pd.check_agent_id("agent-123")
        assert pd.active_platforms == set()

    def test_tool_call_heartbeat_triggers(self):
        pd = PlatformDetector()
        pd.check_tool_call("read_file", target="heartbeat.md")
        assert "moltbook" in pd.active_platforms

    def test_tool_call_moltbook_api_triggers(self):
        pd = PlatformDetector()
        pd.check_tool_call("http_get", target="https://api.moltbook.com/feed")
        assert "moltbook" in pd.active_platforms

    def test_tool_call_openclaw_path_triggers(self):
        pd = PlatformDetector()
        pd.check_tool_call("read_file", target="/home/user/.openclaw/config.yaml")
        assert "moltbook" in pd.active_platforms

    def test_tool_call_moltbot_path_triggers(self):
        pd = PlatformDetector()
        pd.check_tool_call("read_file", target="/home/user/.moltbot/SOUL.md")
        assert "moltbook" in pd.active_platforms

    def test_unrelated_tool_call_ignored(self):
        pd = PlatformDetector()
        pd.check_tool_call("read_file", target="/etc/hosts")
        assert pd.active_platforms == set()

    def test_one_way_latch(self):
        pd = PlatformDetector()
        pd.check_agent_id("moltbook:alice")
        assert pd.is_active("moltbook")

    def test_callback_fires_on_activation(self):
        activated = []
        pd = PlatformDetector(on_activate=lambda p: activated.append(p))
        pd.check_agent_id("moltbook:alice")
        assert activated == ["moltbook"]

    def test_callback_fires_only_once(self):
        activated = []
        pd = PlatformDetector(on_activate=lambda p: activated.append(p))
        pd.check_agent_id("moltbook:alice")
        pd.check_agent_id("moltbook:bob")
        assert activated == ["moltbook"]

    def test_explicit_profiles_suppress_autodetect(self):
        activated = []
        pd = PlatformDetector(
            on_activate=lambda p: activated.append(p),
            explicit_profiles={"moltbook"},
        )
        pd.check_agent_id("moltbook:alice")
        assert activated == []

    def test_thread_safety(self):
        activated = []
        pd = PlatformDetector(on_activate=lambda p: activated.append(p))

        def trigger():
            pd.check_agent_id("moltbook:alice")

        threads = [threading.Thread(target=trigger) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert activated.count("moltbook") == 1
