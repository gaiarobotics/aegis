"""Tests for broker action types."""

import time
import uuid

from aegis.broker.actions import ActionDecision, ActionRequest, ActionResponse


class TestActionRequest:
    def test_construction(self):
        req = ActionRequest(
            id="test-uuid",
            timestamp=1000.0,
            source_provenance="trusted.system",
            action_type="http_write",
            read_write="write",
            target="https://example.com",
            args={"method": "POST"},
            risk_hints={},
        )
        assert req.id == "test-uuid"
        assert req.timestamp == 1000.0
        assert req.source_provenance == "trusted.system"
        assert req.action_type == "http_write"
        assert req.read_write == "write"
        assert req.target == "https://example.com"
        assert req.args == {"method": "POST"}
        assert req.risk_hints == {}

    def test_construction_with_risk_hints(self):
        req = ActionRequest(
            id="uuid-2",
            timestamp=2000.0,
            source_provenance="social.content",
            action_type="fs_write",
            read_write="write",
            target="/tmp/file.txt",
            args={"content": "hello"},
            risk_hints={"scanner_score": 0.8, "pattern": "data_exfil"},
        )
        assert req.risk_hints["scanner_score"] == 0.8
        assert req.risk_hints["pattern"] == "data_exfil"

    def test_read_action(self):
        req = ActionRequest(
            id="uuid-3",
            timestamp=3000.0,
            source_provenance="trusted.system",
            action_type="fs_write",
            read_write="read",
            target="/etc/passwd",
            args={},
            risk_hints={},
        )
        assert req.read_write == "read"

    def test_action_types(self):
        for action_type in ("http_write", "fs_write", "tool_call", "post_message"):
            req = ActionRequest(
                id=str(uuid.uuid4()),
                timestamp=time.time(),
                source_provenance="trusted.system",
                action_type=action_type,
                read_write="write",
                target="target",
                args={},
                risk_hints={},
            )
            assert req.action_type == action_type


class TestActionDecision:
    def test_enum_values(self):
        assert ActionDecision.ALLOW == "allow"
        assert ActionDecision.DENY == "deny"
        assert ActionDecision.QUARANTINE == "quarantine"
        assert ActionDecision.REQUIRE_APPROVAL == "require_approval"

    def test_enum_count(self):
        assert len(ActionDecision) == 4

    def test_string_comparison(self):
        assert ActionDecision.ALLOW == "allow"
        assert ActionDecision.DENY == "deny"

    def test_is_string(self):
        assert isinstance(ActionDecision.ALLOW, str)


class TestActionResponse:
    def test_construction(self):
        resp = ActionResponse(
            request_id="req-1",
            decision=ActionDecision.ALLOW,
            reason="Within budget",
        )
        assert resp.request_id == "req-1"
        assert resp.decision == ActionDecision.ALLOW
        assert resp.reason == "Within budget"
        assert resp.policy_rule is None

    def test_construction_with_policy_rule(self):
        resp = ActionResponse(
            request_id="req-2",
            decision=ActionDecision.DENY,
            reason="Budget exceeded",
            policy_rule="budget.max_write_tool_calls",
        )
        assert resp.policy_rule == "budget.max_write_tool_calls"

    def test_deny_response(self):
        resp = ActionResponse(
            request_id="req-3",
            decision=ActionDecision.DENY,
            reason="Not in manifest",
        )
        assert resp.decision == ActionDecision.DENY

    def test_quarantine_response(self):
        resp = ActionResponse(
            request_id="req-4",
            decision=ActionDecision.QUARANTINE,
            reason="Quarantine active",
        )
        assert resp.decision == ActionDecision.QUARANTINE

    def test_require_approval_response(self):
        resp = ActionResponse(
            request_id="req-5",
            decision=ActionDecision.REQUIRE_APPROVAL,
            reason="High risk action",
        )
        assert resp.decision == ActionDecision.REQUIRE_APPROVAL
