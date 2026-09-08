"""Regression tests for security-boundary hardening."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.core.config import AegisConfig, KillswitchConfig
from aegis.core.http import HttpResponse
from aegis.core.remote_killswitch import RemoteKillswitch
from aegis.core.remote_quarantine import RemoteQuarantine
from aegis.core.remote_threat_intel import RemoteThreatIntel
from aegis.core.state_store import StateStore
from aegis.shield import Shield


class ErrorJsonPool:
    def get(self, *_args, **_kwargs):
        return HttpResponse(
            status_code=403,
            body=json.dumps({"detail": "forbidden"}).encode(),
            headers={"content-type": "application/json"},
        )


def test_killswitch_http_error_preserves_block():
    url = "https://monitor.example/status"
    client = RemoteKillswitch(KillswitchConfig(monitors=[url]), http_pool=ErrorJsonPool())
    client._monitor_states[url].blocked = True
    client._monitor_states[url].reason = "existing block"
    client._poll_one(url)
    assert client.is_blocked() is True
    assert client.block_reason == "existing block"


def test_quarantine_http_error_preserves_block():
    client = RemoteQuarantine(
        service_url="https://monitor.example/api/v1",
        api_key="key",
        agent_id="agent-1",
        operator_id="",
        http_pool=ErrorJsonPool(),
    )
    client._quarantined = True
    client._reason = "existing quarantine"
    client._poll()
    assert client.is_quarantined() is True
    assert client.reason == "existing quarantine"


def test_threat_intel_http_error_preserves_cache():
    client = RemoteThreatIntel(
        service_url="https://monitor.example/api/v1",
        api_key="key",
        http_pool=ErrorJsonPool(),
    )
    client._compromised_agents = {"bad-agent"}
    client._poll()
    assert client.is_agent_compromised("bad-agent") is True


def test_enforce_persistence_requires_durable_key(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_STATE_KEY", raising=False)
    config = AegisConfig(
        mode="enforce",
        state_store={"enabled": True, "log_dir": str(tmp_path)},
        self_integrity={"enabled": False},
    )
    with pytest.raises(RuntimeError, match="AEGIS_STATE_KEY"):
        Shield(config=config, modules=[])


def test_persisted_escalation_restored(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_STATE_KEY", "11" * 32)
    store = StateStore(log_dir=tmp_path)
    store.enter_quarantine("operator quarantine", "high")
    store.escalate_quarantine("manual escalation")

    config = AegisConfig(
        mode="enforce",
        state_store={"enabled": True, "log_dir": str(tmp_path)},
        self_integrity={"enabled": False},
    )
    shield = Shield(config=config, modules=["recovery"])
    assert shield.is_blocked is True


def test_openclaw_uses_typed_pre_tool_gate():
    root = Path(__file__).parents[1] / "aegis-openclaw"
    manifest = json.loads((root / "openclaw.plugin.json").read_text())
    package = json.loads((root / "package.json").read_text())
    source = (root / "index.js").read_text()
    assert manifest["id"] == "aegis-security"
    assert package["openclaw"]["extensions"] == ["./index.js"]
    assert '"before_tool_call"' in source
    assert "block: true" in source
    assert not (root / "hooks" / "aegis-tool-audit" / "HOOK.md").exists()


def test_dashboard_does_not_interpolate_agent_id_into_html():
    graph_js = (
        Path(__file__).parents[1] / "aegis-monitor" / "monitor" / "static" / "graph.js"
    ).read_text()
    assert 'onclick="ksBlockAgent' not in graph_js
    assert "blockBtn.textContent" in graph_js
