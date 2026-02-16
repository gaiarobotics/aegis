"""Integration tests for the Broker policy engine."""

import time

from aegis.broker.actions import ActionDecision, ActionRequest, ActionResponse
from aegis.broker.broker import Broker
from aegis.broker.manifests import ToolManifest
from aegis.core.config import AegisConfig


def _make_request(
    action_type: str = "tool_call",
    read_write: str = "write",
    target: str = "some_tool",
    req_id: str = "1",
) -> ActionRequest:
    return ActionRequest(
        id=req_id,
        timestamp=time.time(),
        source_provenance="trusted.system",
        action_type=action_type,
        read_write=read_write,
        target=target,
        args={},
        risk_hints={},
    )


def _make_manifest(
    name: str = "some_tool",
    allowed_actions: list[str] | None = None,
    allowed_domains: list[str] | None = None,
    allowed_paths: list[str] | None = None,
    read_write: str = "both",
) -> ToolManifest:
    return ToolManifest(
        name=name,
        allowed_actions=allowed_actions or ["tool_call"],
        allowed_domains=allowed_domains or [],
        allowed_paths=allowed_paths or [],
        read_write=read_write,
    )


class TestBrokerInit:
    def test_default_construction(self):
        broker = Broker()
        assert broker is not None

    def test_construction_with_config(self):
        cfg = AegisConfig()
        broker = Broker(config=cfg)
        assert broker is not None


class TestBrokerRegisterTool:
    def test_register_and_evaluate(self):
        broker = Broker()
        manifest = _make_manifest(name="some_tool")
        broker.register_tool(manifest)
        req = _make_request()
        resp = broker.evaluate(req)
        assert resp.decision == ActionDecision.ALLOW

    def test_unregistered_tool_denied(self):
        broker = Broker()
        req = _make_request(target="unknown_tool")
        resp = broker.evaluate(req)
        assert resp.decision == ActionDecision.DENY


class TestBrokerQuarantineWrite:
    def test_quarantined_write_denied(self):
        broker = Broker()
        broker.register_tool(_make_manifest())
        broker._quarantine.enter_quarantine("test")
        req = _make_request(read_write="write")
        resp = broker.evaluate(req)
        assert resp.decision == ActionDecision.DENY
        assert "quarantine" in resp.reason.lower()

    def test_quarantined_read_allowed(self):
        broker = Broker()
        broker.register_tool(_make_manifest(read_write="read"))
        broker._quarantine.enter_quarantine("test")
        req = _make_request(read_write="read")
        resp = broker.evaluate(req)
        assert resp.decision == ActionDecision.ALLOW


class TestBrokerManifestCheck:
    def test_action_type_not_in_manifest_denied(self):
        broker = Broker()
        manifest = _make_manifest(name="some_tool", allowed_actions=["http_write"])
        broker.register_tool(manifest)
        req = _make_request(action_type="tool_call")
        resp = broker.evaluate(req)
        assert resp.decision == ActionDecision.DENY

    def test_write_denied_when_manifest_is_read_only(self):
        broker = Broker()
        manifest = _make_manifest(name="some_tool", read_write="read")
        broker.register_tool(manifest)
        req = _make_request(read_write="write")
        resp = broker.evaluate(req)
        assert resp.decision == ActionDecision.DENY


class TestBrokerBudget:
    def test_budget_exceeded_denied(self):
        cfg = AegisConfig()
        cfg.broker["budgets"]["max_write_tool_calls"] = 2
        broker = Broker(config=cfg)
        manifest = _make_manifest()
        broker.register_tool(manifest)

        req1 = _make_request(req_id="1")
        req2 = _make_request(req_id="2")
        req3 = _make_request(req_id="3")

        resp1 = broker.evaluate(req1)
        assert resp1.decision == ActionDecision.ALLOW
        resp2 = broker.evaluate(req2)
        assert resp2.decision == ActionDecision.ALLOW
        resp3 = broker.evaluate(req3)
        assert resp3.decision == ActionDecision.DENY


class TestBrokerQuarantineTriggers:
    def test_auto_quarantine_after_denied_writes(self):
        """After enough denied writes, quarantine should auto-trigger."""
        cfg = AegisConfig()
        cfg.broker["quarantine_triggers"]["repeated_denied_writes"] = 3
        broker = Broker(config=cfg)
        # No manifest registered; all writes will be denied

        for i in range(3):
            req = _make_request(req_id=str(i))
            broker.evaluate(req)

        assert broker._quarantine.is_quarantined() is True


class TestBrokerDefaultPosture:
    def test_deny_write_posture_allows_reads(self):
        cfg = AegisConfig()
        cfg.broker["default_posture"] = "deny_write"
        broker = Broker(config=cfg)
        broker.register_tool(_make_manifest(read_write="read"))
        req = _make_request(read_write="read")
        resp = broker.evaluate(req)
        assert resp.decision == ActionDecision.ALLOW

    def test_deny_all_posture_denies_reads(self):
        cfg = AegisConfig()
        cfg.broker["default_posture"] = "deny_all"
        broker = Broker(config=cfg)
        broker.register_tool(_make_manifest(read_write="read"))
        req = _make_request(read_write="read")
        resp = broker.evaluate(req)
        assert resp.decision == ActionDecision.DENY

    def test_allow_all_posture_allows_unregistered_writes(self):
        cfg = AegisConfig()
        cfg.broker["default_posture"] = "allow_all"
        broker = Broker(config=cfg)
        req = _make_request(read_write="write")
        resp = broker.evaluate(req)
        assert resp.decision == ActionDecision.ALLOW


class TestBrokerEvaluateResponse:
    def test_response_has_request_id(self):
        broker = Broker()
        broker.register_tool(_make_manifest())
        req = _make_request(req_id="abc-123")
        resp = broker.evaluate(req)
        assert resp.request_id == "abc-123"

    def test_response_is_action_response(self):
        broker = Broker()
        broker.register_tool(_make_manifest())
        req = _make_request()
        resp = broker.evaluate(req)
        assert isinstance(resp, ActionResponse)

    def test_allow_response_has_reason(self):
        broker = Broker()
        broker.register_tool(_make_manifest())
        req = _make_request()
        resp = broker.evaluate(req)
        assert resp.reason != ""
