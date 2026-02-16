"""Tests for coordination report data structures."""

from aegis.coordination.reports import (
    AgentHeartbeat,
    CompromiseReport,
    ReportBase,
    ThreatEventReport,
    TrustReport,
)
from aegis.identity.attestation import generate_keypair


class TestReportBase:
    def test_defaults(self):
        r = ReportBase()
        assert r.report_id
        assert r.timestamp > 0
        assert r.signature == b""

    def test_to_dict_roundtrip(self):
        r = ReportBase(agent_id="a1", operator_id="op1", report_type="test")
        d = r.to_dict()
        assert isinstance(d["signature"], str)  # base64
        r2 = ReportBase.from_dict(d)
        assert r2.agent_id == "a1"
        assert r2.operator_id == "op1"

    def test_sign_and_verify_hmac(self):
        kp = generate_keypair("hmac-sha256")
        r = ReportBase(agent_id="a1", operator_id="op1")
        r.sign(kp)
        assert r.signature != b""
        assert r.verify(kp.public_key)

    def test_verify_fails_with_wrong_key(self):
        kp1 = generate_keypair("hmac-sha256")
        kp2 = generate_keypair("hmac-sha256")
        r = ReportBase(agent_id="a1")
        r.sign(kp1)
        assert not r.verify(kp2.public_key)

    def test_sign_preserves_after_serialization(self):
        kp = generate_keypair("hmac-sha256")
        r = CompromiseReport(agent_id="a1", compromised_agent_id="a2")
        r.sign(kp)
        d = r.to_dict()
        r2 = CompromiseReport.from_dict(d)
        assert r2.verify(kp.public_key)


class TestCompromiseReport:
    def test_fields(self):
        r = CompromiseReport(
            agent_id="a1",
            compromised_agent_id="a2",
            source="nk_cell",
            nk_score=0.9,
            nk_verdict="hostile",
        )
        assert r.report_type == "compromise"
        assert r.compromised_agent_id == "a2"

    def test_no_content_field(self):
        r = CompromiseReport()
        d = r.to_dict()
        assert "content" not in d
        assert "text" not in d


class TestTrustReport:
    def test_fields(self):
        r = TrustReport(
            target_agent_id="a2",
            trust_score=42.0,
            trust_tier=2,
            clean_interactions=10,
            total_interactions=12,
        )
        assert r.report_type == "trust"
        assert r.trust_score == 42.0

    def test_no_content_field(self):
        d = TrustReport().to_dict()
        assert "content" not in d
        assert "text" not in d


class TestThreatEventReport:
    def test_fields(self):
        r = ThreatEventReport(
            threat_score=0.85, is_threat=True, scanner_match_count=3
        )
        assert r.report_type == "threat_event"
        assert r.is_threat is True

    def test_no_content_field(self):
        d = ThreatEventReport().to_dict()
        assert "content" not in d
        assert "text" not in d
        assert "input" not in d


class TestAgentHeartbeat:
    def test_fields(self):
        r = AgentHeartbeat(
            agent_id="a1",
            trust_tier=2,
            trust_score=55.0,
            edges=[{"target_agent_id": "a2", "direction": "outbound",
                    "last_seen": 1.0, "message_count": 5}],
        )
        assert r.report_type == "heartbeat"
        assert len(r.edges) == 1

    def test_sign_with_edges(self):
        kp = generate_keypair("hmac-sha256")
        r = AgentHeartbeat(
            agent_id="a1",
            edges=[{"target_agent_id": "a2", "direction": "outbound",
                    "last_seen": 1.0, "message_count": 5}],
        )
        r.sign(kp)
        assert r.verify(kp.public_key)

    def test_no_content_field(self):
        d = AgentHeartbeat().to_dict()
        assert "content" not in d
        assert "text" not in d


class TestNoContentGuarantee:
    """Structural guarantee: no report type carries raw user content."""

    def test_all_report_types(self):
        for cls in (ReportBase, CompromiseReport, TrustReport,
                    ThreatEventReport, AgentHeartbeat):
            r = cls()
            d = r.to_dict()
            for forbidden in ("content", "text", "input", "prompt",
                              "message", "user_input"):
                assert forbidden not in d, (
                    f"{cls.__name__} contains forbidden field '{forbidden}'"
                )
