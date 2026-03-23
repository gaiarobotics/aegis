"""Tests for AEGIS monitor authentication and authorization."""

import os
import pytest
from monitor.config import MonitorConfig, AgentKey


class TestAgentKeyConfig:
    def test_parse_hmac_key_from_yaml(self, tmp_path):
        cfg_file = tmp_path / "monitor.yaml"
        cfg_file.write_text(
            'agent_public_keys:\n'
            '  "agent-1": "hmac:' + 'aa' * 32 + '"\n'
        )
        cfg = MonitorConfig.load(cfg_file)
        assert "agent-1" in cfg.agent_public_keys
        key = cfg.agent_public_keys["agent-1"]
        assert key.key_type == "hmac-sha256"
        assert key.key_bytes == bytes.fromhex('aa' * 32)

    def test_parse_ed25519_key_from_yaml(self, tmp_path):
        cfg_file = tmp_path / "monitor.yaml"
        cfg_file.write_text(
            'agent_public_keys:\n'
            '  "agent-2": "ed25519:' + 'bb' * 32 + '"\n'
        )
        cfg = MonitorConfig.load(cfg_file)
        key = cfg.agent_public_keys["agent-2"]
        assert key.key_type == "ed25519"
        assert key.key_bytes == bytes.fromhex('bb' * 32)

    def test_parse_keys_from_env_var(self, monkeypatch):
        monkeypatch.setenv(
            "MONITOR_AGENT_PUBLIC_KEYS",
            "agent-1:hmac:" + "aa" * 32 + ",agent-2:ed25519:" + "bb" * 32,
        )
        cfg = MonitorConfig.load()
        assert len(cfg.agent_public_keys) == 2
        assert cfg.agent_public_keys["agent-1"].key_type == "hmac-sha256"
        assert cfg.agent_public_keys["agent-2"].key_type == "ed25519"

    def test_env_var_agent_id_with_colon_rejected(self, monkeypatch):
        monkeypatch.setenv(
            "MONITOR_AGENT_PUBLIC_KEYS",
            "bad:id:hmac:" + "aa" * 32,
        )
        with pytest.raises(ValueError):
            MonitorConfig.load()

    def test_empty_agent_public_keys_default(self):
        cfg = MonitorConfig.load()
        assert cfg.agent_public_keys == {}

    def test_invalid_key_type_rejected(self, tmp_path):
        cfg_file = tmp_path / "monitor.yaml"
        cfg_file.write_text(
            'agent_public_keys:\n'
            '  "agent-1": "rsa:' + 'aa' * 32 + '"\n'
        )
        with pytest.raises(ValueError, match="Unsupported key type"):
            MonitorConfig.load(cfg_file)


class TestConfigMigration:
    def test_dict_api_keys(self, tmp_path):
        """New format: dict mapping keys to roles."""
        cfg_file = tmp_path / "monitor.yaml"
        cfg_file.write_text(
            'api_keys:\n  "sk-agent-1": agent\n  "sk-view-1": viewer\n  "sk-ops-1": operator\n'
        )
        cfg = MonitorConfig.load(cfg_file)
        assert cfg.api_keys == {"sk-agent-1": "agent", "sk-view-1": "viewer", "sk-ops-1": "operator"}

    def test_list_api_keys_migration(self, tmp_path):
        """Old format: list of strings treated as operator with warning."""
        cfg_file = tmp_path / "monitor.yaml"
        cfg_file.write_text('api_keys:\n  - "old-key-1"\n  - "old-key-2"\n')
        cfg = MonitorConfig.load(cfg_file)
        assert cfg.api_keys == {"old-key-1": "operator", "old-key-2": "operator"}

    def test_env_var_with_roles(self, monkeypatch):
        """Env var format: key:role,key:role."""
        monkeypatch.setenv("MONITOR_API_KEYS", "sk-a:agent,sk-v:viewer")
        cfg = MonitorConfig.load()
        assert cfg.api_keys == {"sk-a": "agent", "sk-v": "viewer"}

    def test_env_var_without_roles_migration(self, monkeypatch):
        """Env var old format: key,key treated as operator."""
        monkeypatch.setenv("MONITOR_API_KEYS", "old-key-1,old-key-2")
        cfg = MonitorConfig.load()
        assert cfg.api_keys == {"old-key-1": "operator", "old-key-2": "operator"}

    def test_session_secret_from_config(self, tmp_path):
        cfg_file = tmp_path / "monitor.yaml"
        cfg_file.write_text('session_secret: "my-secret-key"\nsession_ttl_seconds: 3600\n')
        cfg = MonitorConfig.load(cfg_file)
        assert cfg.session_secret == "my-secret-key"
        assert cfg.session_ttl_seconds == 3600

    def test_session_secret_default_empty(self):
        cfg = MonitorConfig.load()
        assert cfg.session_secret == ""

    def test_session_ttl_default(self):
        cfg = MonitorConfig.load()
        assert cfg.session_ttl_seconds == 28800


from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from monitor.auth import verify_api_key, require_role, get_config


def _make_app(api_keys: dict[str, str]) -> tuple[FastAPI, TestClient]:
    """Create a minimal FastAPI app with the given api_keys config."""
    test_app = FastAPI()
    cfg = MonitorConfig(api_keys=api_keys)
    test_app.state.config = cfg

    @test_app.get("/agent-only")
    async def agent_only(_role: str = Depends(require_role("agent", "operator"))):
        return {"role": _role}

    @test_app.get("/viewer-only")
    async def viewer_only(_role: str = Depends(require_role("viewer", "operator"))):
        return {"role": _role}

    @test_app.get("/operator-only")
    async def operator_only(_role: str = Depends(require_role("operator"))):
        return {"role": _role}

    return test_app, TestClient(test_app)


class TestRoleResolution:
    def test_open_mode_returns_open(self):
        _, client = _make_app({})
        resp = client.get("/agent-only")
        assert resp.status_code == 200
        assert resp.json()["role"] == "open"

    def test_agent_key_allowed_on_agent_endpoint(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/agent-only", headers={"Authorization": "Bearer sk-a"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "agent"

    def test_agent_key_rejected_on_viewer_endpoint(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/viewer-only", headers={"Authorization": "Bearer sk-a"})
        assert resp.status_code == 403

    def test_agent_key_rejected_on_operator_endpoint(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/operator-only", headers={"Authorization": "Bearer sk-a"})
        assert resp.status_code == 403

    def test_viewer_key_allowed_on_viewer_endpoint(self):
        _, client = _make_app({"sk-v": "viewer"})
        resp = client.get("/viewer-only", headers={"Authorization": "Bearer sk-v"})
        assert resp.status_code == 200

    def test_viewer_key_rejected_on_operator_endpoint(self):
        _, client = _make_app({"sk-v": "viewer"})
        resp = client.get("/operator-only", headers={"Authorization": "Bearer sk-v"})
        assert resp.status_code == 403

    def test_operator_key_allowed_everywhere(self):
        _, client = _make_app({"sk-o": "operator"})
        for path in ["/agent-only", "/viewer-only", "/operator-only"]:
            resp = client.get(path, headers={"Authorization": "Bearer sk-o"})
            assert resp.status_code == 200, f"Failed on {path}"

    def test_invalid_key_rejected(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/agent-only", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 403

    def test_missing_header_rejected(self):
        _, client = _make_app({"sk-a": "agent"})
        resp = client.get("/agent-only")
        assert resp.status_code == 401

    def test_timing_safe_comparison(self):
        """Verify we use hmac.compare_digest (not `in` or `==`)."""
        import inspect
        from monitor import auth
        source = inspect.getsource(auth.verify_api_key)
        assert "compare_digest" in source


import hashlib
import time

from monitor.auth import create_session_token, verify_session_token


class TestSessionTokens:
    SECRET = "test-secret-key"

    def test_roundtrip(self):
        token = create_session_token("viewer", "sk-view-1", self.SECRET)
        payload = verify_session_token(token, self.SECRET, ttl=3600)
        assert payload["role"] == "viewer"
        assert payload["key_hash"] == hashlib.sha256(b"sk-view-1").hexdigest()

    def test_expired_token_rejected(self):
        token = create_session_token("viewer", "sk-view-1", self.SECRET, issued_at=1000)
        payload = verify_session_token(token, self.SECRET, ttl=3600, now=5000)
        assert payload is None

    def test_tampered_token_rejected(self):
        token = create_session_token("viewer", "sk-view-1", self.SECRET)
        parts = token.split(".")
        parts[-1] = "a" + parts[-1][1:]
        tampered = ".".join(parts)
        payload = verify_session_token(tampered, self.SECRET, ttl=3600)
        assert payload is None

    def test_wrong_secret_rejected(self):
        token = create_session_token("viewer", "sk-view-1", self.SECRET)
        payload = verify_session_token(token, "wrong-secret", ttl=3600)
        assert payload is None

    def test_token_contains_key_hash(self):
        token = create_session_token("operator", "sk-ops-1", self.SECRET)
        payload = verify_session_token(token, self.SECRET, ttl=3600)
        expected_hash = hashlib.sha256(b"sk-ops-1").hexdigest()
        assert payload["key_hash"] == expected_hash


from monitor.auth import generate_csrf_token, verify_csrf_token


class TestCSRF:
    SECRET = "test-secret-key"

    def test_roundtrip(self):
        token = generate_csrf_token(self.SECRET)
        assert verify_csrf_token(token, self.SECRET, ttl=3600)

    def test_expired_rejected(self):
        token = generate_csrf_token(self.SECRET, issued_at=1000)
        assert not verify_csrf_token(token, self.SECRET, ttl=3600, now=5000)

    def test_tampered_rejected(self):
        token = generate_csrf_token(self.SECRET)
        assert not verify_csrf_token(token + "x", self.SECRET, ttl=3600)

    def test_wrong_secret_rejected(self):
        token = generate_csrf_token(self.SECRET)
        assert not verify_csrf_token(token, "wrong", ttl=3600)


from monitor.auth import LoginRateLimiter


class TestLoginRateLimiter:
    def test_allows_under_limit(self):
        limiter = LoginRateLimiter(per_minute=5, per_hour=20)
        for _ in range(5):
            assert limiter.check("1.2.3.4")

    def test_blocks_over_per_minute(self):
        limiter = LoginRateLimiter(per_minute=3, per_hour=100)
        now = time.time()
        for _ in range(3):
            assert limiter.check("1.2.3.4", now=now)
        assert not limiter.check("1.2.3.4", now=now)

    def test_resets_after_minute(self):
        limiter = LoginRateLimiter(per_minute=2, per_hour=100)
        now = time.time()
        for _ in range(2):
            limiter.check("1.2.3.4", now=now)
        assert not limiter.check("1.2.3.4", now=now)
        assert limiter.check("1.2.3.4", now=now + 61)

    def test_per_hour_limit(self):
        limiter = LoginRateLimiter(per_minute=100, per_hour=5)
        now = time.time()
        for i in range(5):
            assert limiter.check("1.2.3.4", now=now + i * 61)
        assert not limiter.check("1.2.3.4", now=now + 5 * 61)

    def test_different_ips_independent(self):
        limiter = LoginRateLimiter(per_minute=1, per_hour=100)
        now = time.time()
        assert limiter.check("1.1.1.1", now=now)
        assert not limiter.check("1.1.1.1", now=now)
        assert limiter.check("2.2.2.2", now=now)


from monitor.app import app as monitor_app


@pytest.fixture
def auth_client(tmp_path):
    """Test client with API keys and session secret configured."""
    from fastapi.testclient import TestClient

    db_path = str(tmp_path / "test.db")
    os.environ["MONITOR_DATABASE_PATH"] = db_path
    os.environ.pop("MONITOR_API_KEYS", None)

    with TestClient(monitor_app) as c:
        monitor_app.state.config.api_keys = {
            "sk-agent-1": "agent",
            "sk-view-1": "viewer",
            "sk-ops-1": "operator",
        }
        monitor_app.state.config.session_secret = "test-session-secret"
        monitor_app.state.config.session_ttl_seconds = 3600
        monitor_app.state.config.compromise_quorum = 1
        monitor_app.state.config.compromise_min_trust_tier = 0
        from monitor.validation import ReportValidator
        monitor_app.state.report_validator = ReportValidator(monitor_app.state.config)
        from monitor.cache import InMemoryCache
        monitor_app.state.cache = InMemoryCache()
        yield c

    os.environ.pop("MONITOR_DATABASE_PATH", None)


class TestAuthRoutes:
    def test_login_valid_key(self, auth_client):
        resp = auth_client.post("/auth/login", json={"api_key": "sk-view-1"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "viewer"
        assert "aegis_session" in resp.cookies

    def test_login_invalid_key(self, auth_client):
        resp = auth_client.post("/auth/login", json={"api_key": "wrong"})
        assert resp.status_code == 403

    def test_me_with_session(self, auth_client):
        auth_client.post("/auth/login", json={"api_key": "sk-view-1"})
        resp = auth_client.get("/auth/me")
        assert resp.status_code == 200
        body = resp.json()
        assert body["role"] == "viewer"
        assert "csrf_token" in body

    def test_me_without_session(self, auth_client):
        resp = auth_client.get("/auth/me")
        assert resp.status_code == 401

    def test_logout_clears_session(self, auth_client):
        auth_client.post("/auth/login", json={"api_key": "sk-view-1"})
        resp = auth_client.post("/auth/logout")
        assert resp.status_code == 200
        resp = auth_client.get("/auth/me")
        assert resp.status_code == 401

    def test_logout_without_session_rejected(self, auth_client):
        resp = auth_client.post("/auth/logout")
        assert resp.status_code == 401

    def test_login_open_mode(self, auth_client):
        auth_client.app.state.config.api_keys = {}
        resp = auth_client.post("/auth/login", json={"api_key": "anything"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "open"

    def test_login_rate_limited(self, auth_client):
        """Excessive login attempts should return 429."""
        from monitor.app import _login_limiter
        _login_limiter._attempts.clear()
        for _ in range(10):
            auth_client.post("/auth/login", json={"api_key": "sk-ops-1"})
        resp = auth_client.post("/auth/login", json={"api_key": "sk-ops-1"})
        assert resp.status_code == 429


class TestEndpointPermissions:
    """Verify each endpoint enforces the correct role."""

    AGENT_ENDPOINTS = [
        ("POST", "/api/v1/reports/compromise", {"agent_id": "a", "evidence": {}}),
        ("POST", "/api/v1/reports/trust", {"agent_id": "a", "trust_score": 50}),
        ("POST", "/api/v1/reports/threat", {"agent_id": "a", "threat_score": 0.5}),
        ("POST", "/api/v1/heartbeat", {"agent_id": "a", "operator_id": "o", "trust_tier": 1, "trust_score": 50, "edges": []}),
    ]

    VIEWER_ENDPOINTS = [
        ("GET", "/api/v1/graph", None),
        ("GET", "/api/v1/metrics", None),
        ("GET", "/api/v1/threat-intel", None),
        ("GET", "/api/v1/topic-clusters", None),
        ("GET", "/api/v1/embeddings", None),
        ("GET", "/api/v1/dendrogram", None),
        ("GET", "/api/v1/trust/agent-1", None),
        ("GET", "/api/v1/killswitch/status", None),
        ("GET", "/api/v1/killswitch/rules", None),
        ("GET", "/api/v1/quarantine/status", None),
        ("GET", "/api/v1/quarantine/rules", None),
    ]

    OPERATOR_ENDPOINTS = [
        ("POST", "/api/v1/killswitch/rules", {"scope": "agent", "target": "a-1"}),
        ("DELETE", "/api/v1/killswitch/rules/test-rule-id", None),
        ("POST", "/api/v1/quarantine/rules", {"scope": "agent", "target": "a-1"}),
        ("DELETE", "/api/v1/quarantine/rules/test-rule-id", None),
    ]

    def _request(self, client, method, path, json_body, key):
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        if method == "GET":
            return client.get(path, headers=headers)
        elif method == "DELETE":
            return client.delete(path, headers=headers)
        return client.post(path, json=json_body, headers=headers)

    def test_agent_key_can_submit_reports(self, auth_client):
        for method, path, body in self.AGENT_ENDPOINTS:
            resp = self._request(auth_client, method, path, body, "sk-agent-1")
            assert resp.status_code != 403, f"agent rejected from {path}"

    def test_agent_key_rejected_from_viewer_endpoints(self, auth_client):
        for method, path, body in self.VIEWER_ENDPOINTS:
            resp = self._request(auth_client, method, path, body, "sk-agent-1")
            assert resp.status_code == 403, f"agent allowed on {path}"

    def test_agent_key_rejected_from_operator_endpoints(self, auth_client):
        for method, path, body in self.OPERATOR_ENDPOINTS:
            resp = self._request(auth_client, method, path, body, "sk-agent-1")
            assert resp.status_code == 403, f"agent allowed on {path}"

    def test_viewer_key_can_read(self, auth_client):
        for method, path, body in self.VIEWER_ENDPOINTS:
            resp = self._request(auth_client, method, path, body, "sk-view-1")
            assert resp.status_code != 403, f"viewer rejected from {path}"

    def test_viewer_key_rejected_from_agent_endpoints(self, auth_client):
        for method, path, body in self.AGENT_ENDPOINTS:
            resp = self._request(auth_client, method, path, body, "sk-view-1")
            assert resp.status_code == 403, f"viewer allowed on {path}"

    def test_viewer_key_rejected_from_operator_endpoints(self, auth_client):
        for method, path, body in self.OPERATOR_ENDPOINTS:
            resp = self._request(auth_client, method, path, body, "sk-view-1")
            assert resp.status_code == 403, f"viewer allowed on {path}"

    def test_operator_key_allowed_everywhere(self, auth_client):
        all_endpoints = self.AGENT_ENDPOINTS + self.VIEWER_ENDPOINTS + self.OPERATOR_ENDPOINTS
        for method, path, body in all_endpoints:
            resp = self._request(auth_client, method, path, body, "sk-ops-1")
            assert resp.status_code != 403, f"operator rejected from {path}"


class TestSimulatorPermissions:
    SIMULATOR_ENDPOINTS = [
        ("GET", "/api/v1/simulator/presets"),
        ("GET", "/api/v1/simulator/status"),
        ("POST", "/api/v1/simulator/start"),
        ("POST", "/api/v1/simulator/reset"),
    ]

    def test_agent_rejected(self, auth_client):
        for method, path in self.SIMULATOR_ENDPOINTS:
            headers = {"Authorization": "Bearer sk-agent-1"}
            resp = auth_client.request(method, path, headers=headers)
            assert resp.status_code == 403, f"agent allowed on {path}"

    def test_viewer_rejected(self, auth_client):
        for method, path in self.SIMULATOR_ENDPOINTS:
            headers = {"Authorization": "Bearer sk-view-1"}
            resp = auth_client.request(method, path, headers=headers)
            assert resp.status_code == 403, f"viewer allowed on {path}"

    def test_operator_allowed(self, auth_client):
        for method, path in self.SIMULATOR_ENDPOINTS:
            headers = {"Authorization": "Bearer sk-ops-1"}
            resp = auth_client.request(method, path, headers=headers)
            assert resp.status_code != 403, f"operator rejected from {path}"


class TestWebSocketAuth:
    def test_dashboard_ws_accepted_with_viewer_session(self, auth_client):
        """Viewer session cookie should allow WebSocket upgrade."""
        auth_client.post("/auth/login", json={"api_key": "sk-view-1"})
        with auth_client.websocket_connect("/ws/dashboard") as ws:
            pass

    def test_dashboard_ws_first_message_auth_valid(self, auth_client):
        """Non-browser clients authenticate via first JSON message."""
        with auth_client.websocket_connect("/ws/dashboard") as ws:
            ws.send_json({"auth": {"api_key": "sk-view-1"}})
            resp = ws.receive_json()
            assert resp.get("authenticated") is True

    def test_dashboard_ws_first_message_auth_invalid(self, auth_client):
        """Invalid key in first message should close with 4003."""
        with auth_client.websocket_connect("/ws/dashboard") as ws:
            ws.send_json({"auth": {"api_key": "wrong-key"}})
            resp = ws.receive_json()
            assert resp.get("authenticated") is False

    def test_dashboard_ws_first_message_auth_agent_rejected(self, auth_client):
        """Agent role should be rejected from dashboard WS."""
        with auth_client.websocket_connect("/ws/dashboard") as ws:
            ws.send_json({"auth": {"api_key": "sk-agent-1"}})
            resp = ws.receive_json()
            assert resp.get("authenticated") is False


class TestCSRFEnforcement:
    @pytest.fixture(autouse=True)
    def _clear_rate_limiter(self):
        from monitor.app import _login_limiter
        _login_limiter._attempts.clear()

    def test_operator_mutation_via_cookie_requires_csrf(self, auth_client):
        """Cookie-authenticated mutation without CSRF token should be rejected."""
        auth_client.post("/auth/login", json={"api_key": "sk-ops-1"})
        resp = auth_client.post(
            "/api/v1/killswitch/rules",
            json={"scope": "agent", "target": "a-1"},
        )
        assert resp.status_code == 403
        assert "CSRF" in resp.json().get("detail", "")

    def test_operator_mutation_via_cookie_with_csrf_succeeds(self, auth_client):
        auth_client.post("/auth/login", json={"api_key": "sk-ops-1"})
        me_resp = auth_client.get("/auth/me")
        csrf_token = me_resp.json()["csrf_token"]
        resp = auth_client.post(
            "/api/v1/killswitch/rules",
            json={"scope": "agent", "target": "a-1"},
            headers={"X-CSRF-Token": csrf_token},
        )
        assert resp.status_code != 403

    def test_operator_mutation_via_bearer_skips_csrf(self, auth_client):
        """Bearer-authenticated requests don't need CSRF tokens."""
        resp = auth_client.post(
            "/api/v1/killswitch/rules",
            json={"scope": "agent", "target": "a-1"},
            headers={"Authorization": "Bearer sk-ops-1"},
        )
        assert resp.status_code != 403

    def test_simulator_mutation_via_cookie_requires_csrf(self, auth_client):
        """Simulator mutations via cookie also require CSRF."""
        auth_client.post("/auth/login", json={"api_key": "sk-ops-1"})
        resp = auth_client.post("/api/v1/simulator/start")
        assert resp.status_code == 403
        assert "CSRF" in resp.json().get("detail", "")

    def test_simulator_mutation_via_cookie_with_csrf_succeeds(self, auth_client):
        auth_client.post("/auth/login", json={"api_key": "sk-ops-1"})
        me_resp = auth_client.get("/auth/me")
        csrf_token = me_resp.json()["csrf_token"]
        resp = auth_client.post(
            "/api/v1/simulator/start",
            headers={"X-CSRF-Token": csrf_token},
        )
        assert resp.status_code != 403


class TestSessionSecretWarning:
    def test_warns_when_no_session_secret(self, caplog):
        """Auto-generated session secret should emit a loud warning."""
        import logging
        from monitor.app import _ensure_session_secret
        cfg = MonitorConfig()
        assert cfg.session_secret == ""
        with caplog.at_level(logging.WARNING):
            _ensure_session_secret(cfg)
        assert cfg.session_secret != ""
        assert "session_secret not configured" in caplog.text

    def test_no_warning_when_secret_configured(self, caplog):
        import logging
        from monitor.app import _ensure_session_secret
        cfg = MonitorConfig(session_secret="my-secret")
        with caplog.at_level(logging.WARNING):
            _ensure_session_secret(cfg)
        assert "session_secret not configured" not in caplog.text


from monitor.auth import verify_report_signature
from aegis.identity.attestation import generate_keypair
from aegis.monitoring.reports import CompromiseReport, TrustReport, ThreatEventReport, AgentHeartbeat


class TestReportSignatureVerification:
    def _make_config_with_key(self, agent_id, keypair):
        from monitor.config import AgentKey
        return MonitorConfig(
            agent_public_keys={
                agent_id: AgentKey(key_type=keypair.key_type, key_bytes=keypair.public_key),
            },
        )

    def test_open_mode_accepts_unverified(self):
        cfg = MonitorConfig()
        accepted, verified = verify_report_signature({"agent_id": "a"}, cfg)
        assert accepted is True
        assert verified is False

    def test_unknown_agent_accepted_unverified(self):
        from monitor.config import AgentKey
        cfg = MonitorConfig(agent_public_keys={
            "other-agent": AgentKey(key_type="hmac-sha256", key_bytes=b"\x00" * 32),
        })
        accepted, verified = verify_report_signature({"agent_id": "unknown"}, cfg)
        assert accepted is True
        assert verified is False

    def test_known_agent_valid_signature_accepted(self):
        kp = generate_keypair("hmac-sha256")
        report = CompromiseReport(
            agent_id="agent-1",
            compromised_agent_id="agent-2",
            source="test",
        )
        report.sign(kp)
        data = report.to_dict()
        cfg = self._make_config_with_key("agent-1", kp)
        accepted, verified = verify_report_signature(data, cfg)
        assert accepted is True
        assert verified is True

    def test_known_agent_invalid_signature_rejected(self):
        kp = generate_keypair("hmac-sha256")
        report = CompromiseReport(
            agent_id="agent-1",
            compromised_agent_id="agent-2",
        )
        report.sign(kp)
        data = report.to_dict()
        data["source"] = "tampered"
        cfg = self._make_config_with_key("agent-1", kp)
        accepted, verified = verify_report_signature(data, cfg)
        assert accepted is False
        assert verified is False

    def test_known_agent_missing_signature_rejected(self):
        from monitor.config import AgentKey
        cfg = MonitorConfig(agent_public_keys={
            "agent-1": AgentKey(key_type="hmac-sha256", key_bytes=b"\x00" * 32),
        })
        data = {"agent_id": "agent-1", "report_type": "compromise", "signature": ""}
        accepted, verified = verify_report_signature(data, cfg)
        assert accepted is False
        assert verified is False

    def test_key_type_mismatch_rejected(self):
        kp = generate_keypair("hmac-sha256")
        report = CompromiseReport(agent_id="agent-1")
        report.sign(kp)
        data = report.to_dict()
        from monitor.config import AgentKey
        cfg = MonitorConfig(agent_public_keys={
            "agent-1": AgentKey(key_type="ed25519", key_bytes=kp.public_key),
        })
        accepted, verified = verify_report_signature(data, cfg)
        assert accepted is False
        assert verified is False

    def test_heartbeat_report_verified(self):
        kp = generate_keypair("hmac-sha256")
        report = AgentHeartbeat(
            agent_id="agent-1",
            trust_tier=2,
            trust_score=55.0,
            edges=[],
        )
        report.sign(kp)
        data = report.to_dict()
        cfg = self._make_config_with_key("agent-1", kp)
        accepted, verified = verify_report_signature(data, cfg)
        assert accepted is True
        assert verified is True
