"""Tests for sentinel reporter."""

from __future__ import annotations

from unittest.mock import MagicMock

from sentinel.reporter import SentinelReporter


class TestSentinelReporter:
    def _make_reporter(self) -> tuple[SentinelReporter, MagicMock]:
        mock_client = MagicMock()
        reporter = SentinelReporter(monitoring_client=mock_client)
        return reporter, mock_client

    def test_report_compromised_agent(self):
        reporter, mock_client = self._make_reporter()
        reporter.report_compromised_agent(
            compromised_agent_id="moltbook:eve",
            nk_score=0.8,
            nk_verdict="hostile",
            content_hash_hex="abc123",
        )
        mock_client.send_compromise_report.assert_called_once_with(
            compromised_agent_id="moltbook:eve",
            source="sentinel",
            nk_score=0.8,
            nk_verdict="hostile",
            recommended_action="quarantine",
            content_hash_hex="abc123",
        )

    def test_report_threat_event(self):
        reporter, mock_client = self._make_reporter()
        reporter.report_threat_event(
            threat_score=0.9,
            is_threat=True,
            scanner_match_count=3,
        )
        mock_client.send_threat_event.assert_called_once_with(
            threat_score=0.9,
            is_threat=True,
            scanner_match_count=3,
            nk_score=0.0,
            nk_verdict="",
        )

    def test_report_heartbeat(self):
        reporter, mock_client = self._make_reporter()
        reporter.send_heartbeat()
        mock_client.send_heartbeat.assert_called_once()

    def test_source_tag_is_sentinel(self):
        reporter, mock_client = self._make_reporter()
        reporter.report_compromised_agent(
            compromised_agent_id="moltbook:x",
        )
        call_kwargs = mock_client.send_compromise_report.call_args.kwargs
        assert call_kwargs["source"] == "sentinel"

    def test_none_client_is_noop(self):
        reporter = SentinelReporter(monitoring_client=None)
        reporter.report_compromised_agent(compromised_agent_id="moltbook:x")
        reporter.report_threat_event(threat_score=0.9)
        reporter.send_heartbeat()

    def test_client_exception_is_swallowed(self):
        mock_client = MagicMock()
        mock_client.send_compromise_report.side_effect = RuntimeError("boom")
        reporter = SentinelReporter(monitoring_client=mock_client)
        reporter.report_compromised_agent(compromised_agent_id="moltbook:x")
