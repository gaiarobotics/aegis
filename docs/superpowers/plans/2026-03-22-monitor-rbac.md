# Monitor RBAC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add role-based access control to the AEGIS monitor so agents, viewers, and operators have scoped permissions.

**Architecture:** Replace the flat `api_keys: list[str]` with `api_keys: dict[str, str]` mapping keys to roles (`agent`, `viewer`, `operator`). Add cookie-based session auth for the browser dashboard with CSRF protection and login rate limiting. Wire `require_role()` into every endpoint.

**Tech Stack:** Python 3.10+, FastAPI, hmac, hashlib, secrets, time (all stdlib — no new dependencies)

**Spec:** `docs/superpowers/specs/2026-03-22-monitor-rbac-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `monitor/config.py` | Modify | `api_keys` type change, new session fields, migration logic |
| `monitor/auth.py` | Rewrite | Role resolution, `require_role()`, session tokens, CSRF, rate limiting |
| `monitor/app.py` | Modify | Wire role dependencies into all endpoints, add `/auth/*` routes, WS auth |
| `monitor/simulator/routes.py` | Modify | Wire `require_role("operator")` into all simulator endpoints |
| `tests/test_auth.py` | Create | Dedicated auth test module |
| `tests/test_app.py` | Modify | Update existing auth tests, update fixture for new config shape |

---

### Task 1: Update MonitorConfig

**Files:**
- Modify: `monitor/config.py` (entire file, 94 lines)
- Test: `tests/test_auth.py` (create)

- [ ] **Step 1: Write failing tests for new config shape**

Create `tests/test_auth.py`:

```python
"""Tests for AEGIS monitor authentication and authorization."""

import os
import pytest
from monitor.config import MonitorConfig


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py -v`
Expected: Multiple failures — `api_keys` is still `list[str]`, no `session_secret` field.

- [ ] **Step 3: Implement config changes**

Modify `monitor/config.py`:

1. Change `api_keys: list[str]` to `api_keys: dict[str, str]` (line 21)
2. Add `session_secret: str = ""` and `session_ttl_seconds: int = 28800` fields
3. In `load()`, detect list vs dict for `api_keys` in YAML and migrate lists to `{key: "operator"}` with a warning
4. Update env var parsing to handle `key:role` format, falling back to `operator` for bare keys

```python
import logging
import warnings

# In MonitorConfig dataclass:
    api_keys: dict[str, str] = field(default_factory=dict)
    session_secret: str = ""
    session_ttl_seconds: int = 28800

# In load(), replace the api_keys line in cfg = cls(...):
    raw_keys = raw.get("api_keys", {})
    if isinstance(raw_keys, list):
        warnings.warn(
            "api_keys as a list is deprecated — use dict mapping keys to roles. "
            "Treating all keys as 'operator'.",
            DeprecationWarning,
            stacklevel=2,
        )
        raw_keys = {k: "operator" for k in raw_keys}
    elif not isinstance(raw_keys, dict):
        raw_keys = {}

# Pass raw_keys to cfg constructor, add new fields:
    api_keys=raw_keys,
    session_secret=raw.get("session_secret", ""),
    session_ttl_seconds=int(raw.get("session_ttl_seconds", 28800)),

# Replace env var MONITOR_API_KEYS parsing (lines 78-79):
    if v := os.environ.get("MONITOR_API_KEYS"):
        parsed = {}
        for entry in v.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if ":" in entry:
                key, role = entry.rsplit(":", 1)
                parsed[key] = role
            else:
                warnings.warn(
                    f"MONITOR_API_KEYS entry '{entry}' has no :role suffix — treating as 'operator'.",
                    DeprecationWarning,
                    stacklevel=2,
                )
                parsed[entry] = "operator"
        cfg.api_keys = parsed

# Add env var overrides for new fields:
    if v := os.environ.get("MONITOR_SESSION_SECRET"):
        cfg.session_secret = v
    if v := os.environ.get("MONITOR_SESSION_TTL_SECONDS"):
        cfg.session_ttl_seconds = int(v)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestConfigMigration -v`
Expected: All 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add monitor/config.py tests/test_auth.py
git commit -m "feat(monitor): update MonitorConfig for role-based api_keys"
```

---

### Task 2: Rewrite auth.py — Role Resolution and require_role

**Files:**
- Modify: `monitor/auth.py` (rewrite, currently 61 lines)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing tests for role resolution**

Append to `tests/test_auth.py`:

```python
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient

from monitor.auth import verify_api_key, require_role, get_config
from monitor.config import MonitorConfig


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestRoleResolution -v`
Expected: ImportError or failures — `require_role` doesn't exist yet.

- [ ] **Step 3: Implement verify_api_key and require_role**

Rewrite `monitor/auth.py`:

```python
"""Authentication and authorization for the AEGIS monitor service."""

from __future__ import annotations

import hmac
from typing import Callable

from fastapi import Depends, HTTPException, Request

from monitor.config import MonitorConfig


def get_config(request: Request) -> MonitorConfig:
    """FastAPI dependency — retrieve the monitor config from app state."""
    return request.app.state.config


def verify_api_key(
    request: Request, config: MonitorConfig = Depends(get_config),
) -> str:
    """Resolve the caller's role from the Authorization header.

    Returns:
        Role string: ``"agent"``, ``"viewer"``, ``"operator"``, or ``"open"``.

    Raises:
        HTTPException 401: Missing or malformed Authorization header.
        HTTPException 403: Invalid API key.
    """
    if not config.api_keys:
        return "open"

    # Also accept session cookie — checked in verify_session (Task 3).
    # This function handles Bearer tokens only.
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        # Check for session cookie before rejecting
        session_role = _resolve_session_cookie(request, config)
        if session_role is not None:
            return session_role
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = auth_header[len("Bearer "):]
    for configured_key, role in config.api_keys.items():
        if hmac.compare_digest(token, configured_key):
            return role

    raise HTTPException(status_code=403, detail="Invalid API key")


def _resolve_session_cookie(request: Request, config: MonitorConfig) -> str | None:
    """Check for a valid session cookie. Returns role or None.

    Placeholder — implemented in Task 3.
    """
    return None


def require_role(*allowed_roles: str) -> Callable:
    """FastAPI dependency factory — restrict access to specific roles.

    The ``"open"`` role (when no keys are configured) is always accepted.
    """
    async def _check(role: str = Depends(verify_api_key)) -> str:
        if role == "open":
            return role
        if role not in allowed_roles:
            raise HTTPException(status_code=403, detail=f"Role '{role}' not permitted")
        return role
    return _check


def verify_report_signature(report_data: dict, config: MonitorConfig) -> bool:
    """Verify a report's cryptographic signature using agent public keys."""
    if not config.agent_public_keys:
        return True

    agent_id = report_data.get("agent_id", "")
    public_key = config.agent_public_keys.get(agent_id)
    if public_key is None:
        return False

    try:
        from aegis.monitoring.reports import ReportBase
        report = ReportBase.from_dict(report_data)
        return report.verify(public_key)
    except Exception:
        return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestRoleResolution -v`
Expected: All 10 tests pass.

- [ ] **Step 5: Commit**

```bash
git add monitor/auth.py tests/test_auth.py
git commit -m "feat(monitor): add role-based verify_api_key and require_role"
```

---

### Task 3: Session Token Auth (Sign, Verify, Cookie)

**Files:**
- Modify: `monitor/auth.py` (add session functions)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing tests for session tokens**

Append to `tests/test_auth.py`:

```python
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
        # Flip a character in the signature portion
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestSessionTokens -v`
Expected: ImportError — `create_session_token` and `verify_session_token` don't exist.

- [ ] **Step 3: Implement session token functions**

Add to `monitor/auth.py`:

```python
import hashlib
import json
import secrets
import time
import base64

def create_session_token(
    role: str, api_key: str, secret: str, *, issued_at: float | None = None,
) -> str:
    """Create an HMAC-SHA256 signed session token.

    Format: base64(payload).base64(signature)
    Payload: {"role": ..., "key_hash": sha256(api_key), "iat": ..., "nonce": ...}
    """
    payload = {
        "role": role,
        "key_hash": hashlib.sha256(api_key.encode()).hexdigest(),
        "iat": issued_at if issued_at is not None else time.time(),
        "nonce": secrets.token_hex(16),
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode()
    sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_session_token(
    token: str, secret: str, *, ttl: int, now: float | None = None,
) -> dict | None:
    """Verify and decode a session token. Returns payload dict or None."""
    try:
        payload_b64, sig = token.rsplit(".", 1)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        expected_sig = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(payload_bytes)
        current_time = now if now is not None else time.time()
        if current_time - payload.get("iat", 0) > ttl:
            return None
        return payload
    except Exception:
        return None
```

Also update `_resolve_session_cookie` to actually work:

```python
_SESSION_COOKIE_NAME = "aegis_session"


def _resolve_session_cookie(request: Request, config: MonitorConfig) -> str | None:
    """Check for a valid session cookie. Returns role or None."""
    token = request.cookies.get(_SESSION_COOKIE_NAME)
    if not token or not config.session_secret:
        return None
    payload = verify_session_token(token, config.session_secret, ttl=config.session_ttl_seconds)
    if payload is None:
        return None
    # Verify the originating API key still exists
    key_hash = payload.get("key_hash", "")
    for configured_key in config.api_keys:
        if hashlib.sha256(configured_key.encode()).hexdigest() == key_hash:
            return payload["role"]
    return None  # Key was removed — session invalid
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestSessionTokens -v`
Expected: All 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add monitor/auth.py tests/test_auth.py
git commit -m "feat(monitor): add session token create/verify with key-hash binding"
```

---

### Task 4: CSRF Token Generation and Validation

**Files:**
- Modify: `monitor/auth.py` (add CSRF functions)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing tests for CSRF**

Append to `tests/test_auth.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestCSRF -v`
Expected: ImportError.

- [ ] **Step 3: Implement CSRF functions**

Add to `monitor/auth.py`:

```python
def generate_csrf_token(secret: str, *, issued_at: float | None = None) -> str:
    """Generate a CSRF token: HMAC-signed timestamp + nonce."""
    iat = issued_at if issued_at is not None else time.time()
    nonce = secrets.token_hex(16)
    message = f"{iat}:{nonce}".encode()
    sig = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    payload = base64.urlsafe_b64encode(message).decode()
    return f"{payload}.{sig}"


def verify_csrf_token(
    token: str, secret: str, *, ttl: int, now: float | None = None,
) -> bool:
    """Verify a CSRF token is valid and not expired."""
    try:
        payload_b64, sig = token.rsplit(".", 1)
        message = base64.urlsafe_b64decode(payload_b64)
        expected_sig = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return False
        iat_str = message.decode().split(":")[0]
        current_time = now if now is not None else time.time()
        return (current_time - float(iat_str)) <= ttl
    except Exception:
        return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestCSRF -v`
Expected: All 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add monitor/auth.py tests/test_auth.py
git commit -m "feat(monitor): add CSRF token generation and verification"
```

---

### Task 5: Login Rate Limiter

**Files:**
- Modify: `monitor/auth.py` (add rate limiter)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing tests for rate limiting**

Append to `tests/test_auth.py`:

```python
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
        # 61 seconds later
        assert limiter.check("1.2.3.4", now=now + 61)

    def test_per_hour_limit(self):
        limiter = LoginRateLimiter(per_minute=100, per_hour=5)
        now = time.time()
        for i in range(5):
            # Spread across minutes to avoid per-minute limit
            assert limiter.check("1.2.3.4", now=now + i * 61)
        assert not limiter.check("1.2.3.4", now=now + 5 * 61)

    def test_different_ips_independent(self):
        limiter = LoginRateLimiter(per_minute=1, per_hour=100)
        now = time.time()
        assert limiter.check("1.1.1.1", now=now)
        assert not limiter.check("1.1.1.1", now=now)
        assert limiter.check("2.2.2.2", now=now)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestLoginRateLimiter -v`
Expected: ImportError.

- [ ] **Step 3: Implement LoginRateLimiter**

Add to `monitor/auth.py`:

```python
from collections import defaultdict


class LoginRateLimiter:
    """In-memory per-IP rate limiter for login attempts."""

    def __init__(self, per_minute: int = 10, per_hour: int = 50) -> None:
        self.per_minute = per_minute
        self.per_hour = per_hour
        self._attempts: dict[str, list[float]] = defaultdict(list)

    def check(self, ip: str, *, now: float | None = None) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        current = now if now is not None else time.time()
        attempts = self._attempts[ip]

        # Prune entries older than 1 hour
        cutoff_hour = current - 3600
        self._attempts[ip] = [t for t in attempts if t > cutoff_hour]
        attempts = self._attempts[ip]

        minute_count = sum(1 for t in attempts if t > current - 60)
        if minute_count >= self.per_minute:
            return False
        if len(attempts) >= self.per_hour:
            return False

        attempts.append(current)
        return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestLoginRateLimiter -v`
Expected: All 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add monitor/auth.py tests/test_auth.py
git commit -m "feat(monitor): add in-memory login rate limiter"
```

---

### Task 6: Auth Routes (/auth/login, /auth/logout, /auth/me)

**Files:**
- Modify: `monitor/app.py` (add auth routes)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing tests for auth routes**

Append to `tests/test_auth.py`:

```python
import os
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
        # Session cookie should be cleared
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
        # Reset limiter state for this test
        _login_limiter._attempts.clear()
        for _ in range(10):
            auth_client.post("/auth/login", json={"api_key": "sk-ops-1"})
        resp = auth_client.post("/auth/login", json={"api_key": "sk-ops-1"})
        assert resp.status_code == 429
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestAuthRoutes -v`
Expected: 404 errors — `/auth/*` routes don't exist yet.

- [ ] **Step 3: Implement auth routes in app.py**

Add to `monitor/app.py`, after the imports and before the first endpoint:

```python
from monitor.auth import (
    LoginRateLimiter,
    _SESSION_COOKIE_NAME,
    create_session_token,
    generate_csrf_token,
    require_role,
    verify_api_key,
    verify_session_token,
)

# Module-level rate limiter instance
_login_limiter = LoginRateLimiter(per_minute=10, per_hour=50)
```

Add the auth routes after the lifespan/app setup, before other endpoints:

```python
@app.post("/auth/login")
async def auth_login(request: Request, data: dict):
    config: MonitorConfig = request.app.state.config

    # Rate limit check
    client_ip = request.client.host if request.client else "unknown"
    if not _login_limiter.check(client_ip):
        raise HTTPException(status_code=429, detail="Too many login attempts")

    api_key = data.get("api_key", "")

    # Open mode
    if not config.api_keys:
        secret = config.session_secret or "ephemeral"
        token = create_session_token("open", api_key, secret)
        response = JSONResponse({"role": "open"})
        response.set_cookie(
            _SESSION_COOKIE_NAME, token,
            httponly=True, samesite="lax", secure=request.url.scheme == "https",
            max_age=config.session_ttl_seconds,
        )
        return response

    # Validate the key
    import hmac as _hmac
    matched_role = None
    for configured_key, role in config.api_keys.items():
        if _hmac.compare_digest(api_key, configured_key):
            matched_role = role
            break

    if matched_role is None:
        raise HTTPException(status_code=403, detail="Invalid API key")

    if not config.session_secret:
        raise HTTPException(status_code=500, detail="Session secret not configured")

    token = create_session_token(matched_role, api_key, config.session_secret)
    response = JSONResponse({"role": matched_role})
    response.set_cookie(
        _SESSION_COOKIE_NAME, token,
        httponly=True, samesite="lax", secure=request.url.scheme == "https",
        max_age=config.session_ttl_seconds,
    )
    return response


@app.get("/auth/me")
async def auth_me(request: Request):
    config: MonitorConfig = request.app.state.config
    cookie = request.cookies.get(_SESSION_COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")

    secret = config.session_secret or "ephemeral"
    payload = verify_session_token(cookie, secret, ttl=config.session_ttl_seconds)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # In non-open mode, verify key still exists
    if config.api_keys:
        import hashlib
        key_hash = payload.get("key_hash", "")
        found = any(
            hashlib.sha256(k.encode()).hexdigest() == key_hash
            for k in config.api_keys
        )
        if not found:
            raise HTTPException(status_code=401, detail="API key revoked")

    csrf = generate_csrf_token(secret) if config.session_secret else ""
    return {"role": payload["role"], "csrf_token": csrf}


@app.post("/auth/logout")
async def auth_logout(request: Request):
    config: MonitorConfig = request.app.state.config
    cookie = request.cookies.get(_SESSION_COOKIE_NAME)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not authenticated")

    secret = config.session_secret or "ephemeral"
    payload = verify_session_token(cookie, secret, ttl=config.session_ttl_seconds)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    response = JSONResponse({"status": "logged out"})
    response.delete_cookie(_SESSION_COOKIE_NAME)
    return response
```

Also add to imports at top of `app.py`:

```python
from fastapi.responses import HTMLResponse, JSONResponse, Response
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestAuthRoutes -v`
Expected: All 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add monitor/app.py tests/test_auth.py
git commit -m "feat(monitor): add /auth/login, /auth/logout, /auth/me routes"
```

---

### Task 7: Wire require_role into app.py Endpoints

**Files:**
- Modify: `monitor/app.py` (change all endpoint dependencies)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing tests for endpoint permissions**

Append to `tests/test_auth.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestEndpointPermissions -v`
Expected: Failures — agent key currently gets 200 on viewer endpoints (no role enforcement yet).

- [ ] **Step 3: Replace verify_api_key with require_role on all endpoints**

> **Note:** Line numbers below are from the original codebase. Earlier tasks add imports and `/auth/*` routes to `app.py`, so these will have shifted. Search for the function names instead of relying on exact line numbers.

In `monitor/app.py`, make these replacements:

**Agent endpoints** (lines 164, 346, 422, 456) — change `_key: str = Depends(verify_api_key)` to `_role: str = Depends(require_role("agent", "operator"))`:

```
receive_compromise:  line 165
receive_trust:       line 347
receive_threat:      line 423
receive_heartbeat:   line 457
```

**Viewer endpoints** (lines 680, 701, 738, 766, 773, 780, 801, 830, 934, 1022, 1131) — change to `_role: str = Depends(require_role("viewer", "operator"))`:

```
get_graph:            line 681
get_metrics:          line 702
get_threat_intel:     line 739
get_topic_clusters:   line 767
get_embeddings:       line 774
get_dendrogram:       line 781
get_trust:            line 802
killswitch_status:    line 833-834
list_killswitch_rules: line 935
quarantine_status:    line 1025-1026
list_quarantine_rules: line 1132
```

**Operator endpoints** (lines 842, 955, 1034, 1153) — change to `_role: str = Depends(require_role("operator"))`:

```
create_killswitch_rule:  line 843
delete_killswitch_rule:  line 956
create_quarantine_rule:  line 1035
delete_quarantine_rule:  line 1154
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestEndpointPermissions -v`
Expected: All 7 tests pass.

- [ ] **Step 5: Run full test suite to check for regressions**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py -v`

The existing `TestAuth` tests in `test_app.py` (lines 145-165) will need updating because `api_keys` is now a dict. Update the fixture and tests:

- `app.state.config.api_keys = ["valid-key"]` → `app.state.config.api_keys = {"valid-key": "viewer"}`
- Existing `test_auth_accepts_valid_key` should still pass since `verify_api_key` returns a role string (the old tests checked status codes, not return values)

- [ ] **Step 6: Fix any regressions in test_app.py**

Update `tests/test_app.py` `TestAuth` class to use dict format for `api_keys`.

- [ ] **Step 7: Commit**

```bash
git add monitor/app.py tests/test_auth.py tests/test_app.py
git commit -m "feat(monitor): wire require_role into all API endpoints"
```

---

### Task 8: Wire require_role into Simulator Routes

**Files:**
- Modify: `monitor/simulator/routes.py` (add auth to all endpoints)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing tests for simulator auth**

Append to `tests/test_auth.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestSimulatorPermissions -v`
Expected: agent and viewer tests fail (currently no auth on simulator).

- [ ] **Step 3: Add require_role to simulator routes**

Modify `monitor/simulator/routes.py`:

1. Add import at top:
```python
from fastapi import Depends
from monitor.auth import require_role
```

2. In `register_routes()`, add `_role: str = Depends(require_role("operator"))` as a parameter to every route handler. For routes defined as closures inside `register_routes`, this means adding the dependency to each `async def`:

```python
    @app.get("/api/v1/simulator/presets")
    async def list_presets(_role: str = Depends(require_role("operator"))) -> list[str]:
        ...
```

Apply to all HTTP endpoints under `/api/v1/simulator/*` (lines 77-264). Leave `GET /simulator` (line 289) unauthenticated — it serves the static HTML shell, same as `GET /`. The WebSocket `/ws/simulator` (line 273) will be handled in Task 9.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestSimulatorPermissions -v`
Expected: All 3 tests pass.

- [ ] **Step 5: Run simulator tests to check for regressions**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_simulator/ -v`

Fix any failures — the simulator test fixtures likely don't set up auth. Update `tests/test_simulator/test_routes.py` to either use open mode (`api_keys = {}`) or pass operator keys.

- [ ] **Step 6: Commit**

```bash
git add monitor/simulator/routes.py tests/test_auth.py tests/test_simulator/
git commit -m "feat(monitor): add operator-only auth to all simulator endpoints"
```

---

### Task 9: WebSocket Authentication

**Files:**
- Modify: `monitor/app.py` (update `/ws/dashboard`)
- Modify: `monitor/simulator/routes.py` (update `/ws/simulator`)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing tests for WebSocket auth**

Append to `tests/test_auth.py`:

```python
class TestWebSocketAuth:
    def test_dashboard_ws_accepted_with_viewer_session(self, auth_client):
        """Viewer session cookie should allow WebSocket upgrade."""
        auth_client.post("/auth/login", json={"api_key": "sk-view-1"})
        with auth_client.websocket_connect("/ws/dashboard") as ws:
            # Connection should succeed — just close cleanly
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestWebSocketAuth -v`
Expected: Failures — current WebSocket has no auth.

- [ ] **Step 3: Implement WebSocket auth**

Update the `/ws/dashboard` handler in `monitor/app.py` (line 1221):

```python
@app.websocket("/ws/dashboard")
async def ws_dashboard(ws: WebSocket):
    config: MonitorConfig = ws.app.state.config

    # In open mode, accept immediately
    if not config.api_keys:
        await ws.accept()
        app.state.ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            app.state.ws_clients.discard(ws)
        return

    # Try session cookie first
    cookie = ws.cookies.get(_SESSION_COOKIE_NAME)
    role = None
    if cookie and config.session_secret:
        payload = verify_session_token(cookie, config.session_secret, ttl=config.session_ttl_seconds)
        if payload and payload.get("role") in ("viewer", "operator", "open"):
            import hashlib
            key_hash = payload.get("key_hash", "")
            for k in config.api_keys:
                if hashlib.sha256(k.encode()).hexdigest() == key_hash:
                    role = payload["role"]
                    break

    if role:
        await ws.accept()
        app.state.ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            app.state.ws_clients.discard(ws)
        return

    # No valid cookie — accept and require first-message auth.
    # We accept first because rejecting the HTTP upgrade is not
    # well-supported by all WebSocket clients/test frameworks.
    await ws.accept()
    try:
        import asyncio
        import hmac as _hmac
        raw = await asyncio.wait_for(ws.receive_json(), timeout=10.0)
        auth_data = raw.get("auth", {})
        api_key = auth_data.get("api_key", "")
        matched_role = None
        for configured_key, r in config.api_keys.items():
            if _hmac.compare_digest(api_key, configured_key):
                matched_role = r
                break
        if matched_role not in ("viewer", "operator"):
            await ws.send_json({"authenticated": False, "error": "Insufficient permissions"})
            await ws.close(code=4003, reason="Forbidden")
            return

        await ws.send_json({"authenticated": True, "role": matched_role})
        app.state.ws_clients.add(ws)
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            app.state.ws_clients.discard(ws)
    except (asyncio.TimeoutError, Exception):
        await ws.close(code=4003, reason="Authentication required")
```

Apply similar logic to `/ws/simulator` in `monitor/simulator/routes.py` (line 273), requiring `operator` role instead of `viewer`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestWebSocketAuth -v`
Expected: All 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add monitor/app.py monitor/simulator/routes.py tests/test_auth.py
git commit -m "feat(monitor): add authentication to WebSocket endpoints"
```

---

### Task 10: CSRF Enforcement on Mutation Endpoints

**Files:**
- Modify: `monitor/app.py` (add CSRF check to operator endpoints)
- Modify: `monitor/auth.py` (add CSRF dependency)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing tests for CSRF enforcement**

Append to `tests/test_auth.py`:

```python
class TestCSRFEnforcement:
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestCSRFEnforcement -v`
Expected: First test fails (mutation succeeds without CSRF token).

- [ ] **Step 3: Implement CSRF enforcement**

Add a CSRF-checking dependency to `monitor/auth.py`:

```python
def require_csrf(request: Request, config: MonitorConfig = Depends(get_config)) -> None:
    """Enforce CSRF token for cookie-authenticated mutation requests.

    Skipped for Bearer-authenticated requests (not cookie-based).
    Skipped in open mode.
    """
    if not config.api_keys:
        return  # Open mode
    if request.headers.get("Authorization", "").startswith("Bearer "):
        return  # Bearer auth — not vulnerable to CSRF
    if not config.session_secret:
        return

    csrf_token = request.headers.get("X-CSRF-Token", "")
    if not csrf_token or not verify_csrf_token(csrf_token, config.session_secret, ttl=config.session_ttl_seconds):
        raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")
```

Add `Depends(require_csrf)` to operator mutation endpoints in `app.py`:

```python
# For each operator mutation endpoint, add require_csrf as an additional dependency:
@app.post("/api/v1/killswitch/rules")
async def create_killswitch_rule(
    data: dict,
    _role: str = Depends(require_role("operator")),
    _csrf: None = Depends(require_csrf),
):
```

Apply to: `create_killswitch_rule`, `delete_killswitch_rule`, `create_quarantine_rule`, `delete_quarantine_rule`, and all simulator mutation endpoints (`POST`/`DELETE`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestCSRFEnforcement -v`
Expected: All 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add monitor/auth.py monitor/app.py monitor/simulator/routes.py tests/test_auth.py
git commit -m "feat(monitor): enforce CSRF tokens on cookie-authenticated mutations"
```

---

### Task 11: Session Secret Startup Warning

**Files:**
- Modify: `monitor/app.py` (add warning in lifespan)
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write failing test**

Append to `tests/test_auth.py`:

```python
class TestSessionSecretWarning:
    def test_warns_when_no_session_secret(self, tmp_path, caplog):
        """Auto-generated session secret should emit a loud warning."""
        import logging
        from monitor.app import _ensure_session_secret
        cfg = MonitorConfig()
        assert cfg.session_secret == ""
        with caplog.at_level(logging.WARNING):
            _ensure_session_secret(cfg)
        assert cfg.session_secret != ""  # Auto-generated
        assert "session_secret not configured" in caplog.text

    def test_no_warning_when_secret_configured(self, tmp_path, caplog):
        import logging
        from monitor.app import _ensure_session_secret
        cfg = MonitorConfig(session_secret="my-secret")
        with caplog.at_level(logging.WARNING):
            _ensure_session_secret(cfg)
        assert "session_secret not configured" not in caplog.text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestSessionSecretWarning -v`
Expected: ImportError — `_ensure_session_secret` doesn't exist.

- [ ] **Step 3: Implement _ensure_session_secret**

Add to `monitor/app.py`:

```python
import secrets as _secrets

def _ensure_session_secret(config: MonitorConfig) -> None:
    """Auto-generate session_secret if not configured, with a warning."""
    if not config.session_secret:
        config.session_secret = _secrets.token_hex(32)
        logging.warning(
            "WARNING: session_secret not configured — sessions will not survive "
            "restarts and are invalid across instances. Set session_secret in "
            "monitor.yaml for production use."
        )
```

Call it in the lifespan function, after config is loaded:

```python
_ensure_session_secret(app.state.config)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestSessionSecretWarning -v`
Expected: Both tests pass.

- [ ] **Step 5: Commit**

```bash
git add monitor/app.py tests/test_auth.py
git commit -m "feat(monitor): warn loudly when session_secret is auto-generated"
```

---

### Task 12: Update Existing Tests and Full Regression Check

**Files:**
- Modify: `tests/test_app.py` (update fixtures and auth tests for new config shape)
- Modify: `tests/test_simulator/test_routes.py` (ensure open mode in fixtures)

- [ ] **Step 1: Update test_app.py fixture**

In `tests/test_app.py`, the `client` fixture at line 23 sets `app.state.config.api_keys = []`. Change to `app.state.config.api_keys = {}` (empty dict = open mode).

- [ ] **Step 2: Update TestAuth in test_app.py**

Update lines 145-165:

```python
class TestAuth:
    def test_open_mode_allows_all(self, client):
        resp = client.get("/api/v1/graph")
        assert resp.status_code == 200

    def test_auth_rejects_invalid_key(self, client):
        app.state.config.api_keys = {"valid-key": "viewer"}
        resp = client.get("/api/v1/graph", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 403

    def test_auth_accepts_valid_key(self, client):
        app.state.config.api_keys = {"valid-key": "viewer"}
        resp = client.get("/api/v1/graph", headers={"Authorization": "Bearer valid-key"})
        assert resp.status_code == 200

    def test_auth_rejects_missing_header(self, client):
        app.state.config.api_keys = {"valid-key": "viewer"}
        resp = client.get("/api/v1/graph")
        assert resp.status_code == 401
```

- [ ] **Step 3: Update simulator test fixtures**

Check `tests/test_simulator/test_routes.py` — ensure its fixture sets `api_keys = {}` (open mode) so existing tests continue to pass.

- [ ] **Step 4: Run full test suite**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/ -v`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add tests/
git commit -m "test(monitor): update existing tests for role-based api_keys config"
```

---

### Task 13: Final Integration Smoke Test

- [ ] **Step 1: Run the full project test suite**

Run: `cd /workspace && python -m pytest --tb=short -q`
Expected: All tests pass (including non-monitor tests).

- [ ] **Step 2: Verify no import cycles**

Run: `cd /workspace/aegis-monitor && python -c "from monitor.app import app; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit any remaining fixes**

If any fixes were needed, commit them.

- [ ] **Step 4: Final commit message**

If all tasks are complete with no remaining changes, this task is done.
