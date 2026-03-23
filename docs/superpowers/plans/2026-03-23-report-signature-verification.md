# Report Signature Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire report signature verification into the AEGIS monitor so known agents must provide valid signatures and unknown agents are accepted but flagged as unverified.

**Architecture:** Add `AgentKey` config type with YAML/env var parsing, rewrite `verify_report_signature()` with subclass dispatch returning `(accepted, verified)`, call it from all 4 report endpoints, store `verified` flag in the database.

**Tech Stack:** Python 3.10+, FastAPI, stdlib hmac/hashlib (no new dependencies)

**Spec:** `docs/superpowers/specs/2026-03-22-report-signature-verification-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `monitor/config.py` | Modify | `AgentKey` dataclass, `agent_public_keys` type change, YAML/env var parsing |
| `monitor/auth.py` | Modify | Rewrite `verify_report_signature()` with subclass dispatch |
| `monitor/models.py` | Modify | Add `verified: bool` to `CompromiseRecord` |
| `monitor/backends/_sqlite.py` | Modify | Add `verified` column migration |
| `monitor/backends/_postgres.py` | Modify | Add `verified` column migration |
| `monitor/db.py` | Modify | Include `verified` in compromise insert |
| `monitor/app.py` | Modify | Call verification in all 4 report endpoints |
| `tests/test_auth.py` | Modify | Add tests for config parsing and verification |

---

### Task 1: AgentKey Config and Parsing

**Files:**
- Modify: `monitor/config.py`
- Test: `tests/test_auth.py`

- [ ] **Step 1: Write failing tests for AgentKey config parsing**

Append to `/workspace/aegis-monitor/tests/test_auth.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestAgentKeyConfig -v`

- [ ] **Step 3: Implement AgentKey and config parsing**

In `monitor/config.py`:

1. Add `AgentKey` dataclass before `MonitorConfig`:

```python
@dataclass
class AgentKey:
    """Public key for agent report signature verification."""
    key_type: str   # "hmac-sha256" or "ed25519"
    key_bytes: bytes
```

2. Change `agent_public_keys` field type from `dict[str, bytes]` to `dict[str, AgentKey]`

3. Add static method to parse key strings:

```python
_KEY_TYPE_MAP = {"hmac": "hmac-sha256", "ed25519": "ed25519"}

@staticmethod
def _parse_agent_key(value: str) -> AgentKey:
    """Parse 'hmac:hex...' or 'ed25519:hex...' into AgentKey."""
    if ":" not in value:
        raise ValueError(f"Agent key must have type prefix (hmac: or ed25519:), got: {value!r}")
    prefix, hex_bytes = value.split(":", 1)
    key_type = MonitorConfig._KEY_TYPE_MAP.get(prefix)
    if key_type is None:
        raise ValueError(f"Unsupported key type prefix: {prefix!r}. Use 'hmac' or 'ed25519'.")
    return AgentKey(key_type=key_type, key_bytes=bytes.fromhex(hex_bytes))
```

4. In `load()`, parse `agent_public_keys` from YAML:

```python
raw_pubkeys = raw.get("agent_public_keys", {})
parsed_pubkeys = {}
if isinstance(raw_pubkeys, dict):
    for agent_id, key_str in raw_pubkeys.items():
        parsed_pubkeys[agent_id] = MonitorConfig._parse_agent_key(key_str)
```

Pass `agent_public_keys=parsed_pubkeys` to the constructor.

5. Add env var parsing after the existing env overrides:

```python
if v := os.environ.get("MONITOR_AGENT_PUBLIC_KEYS"):
    parsed = {}
    for entry in v.split(","):
        entry = entry.strip()
        if not entry:
            continue
        # Format: agent_id:type:hexbytes — exactly 3 colon-separated parts
        parts = entry.split(":")
        if len(parts) != 3:
            raise ValueError(
                f"MONITOR_AGENT_PUBLIC_KEYS entry '{entry}' has invalid format. "
                "Expected exactly: agent_id:type:hexbytes (3 colon-separated parts). "
                "Agent IDs must not contain colons."
            )
        agent_id, type_prefix, hex_bytes = parts
        key = MonitorConfig._parse_agent_key(f"{type_prefix}:{hex_bytes}")
        parsed[agent_id] = key
    cfg.agent_public_keys = parsed
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestAgentKeyConfig -v`

- [ ] **Step 5: Commit**

```bash
cd /workspace/aegis-monitor && git add monitor/config.py tests/test_auth.py && git -c commit.gpgsign=false commit -m "feat(monitor): add AgentKey config with YAML and env var parsing"
```

---

### Task 2: Rewrite verify_report_signature with Subclass Dispatch

**Files:**
- Modify: `monitor/auth.py`
- Test: `tests/test_auth.py`

- [ ] **Step 1: Write failing tests for verification logic**

Append to `/workspace/aegis-monitor/tests/test_auth.py`:

```python
from monitor.auth import verify_report_signature
from aegis.identity.attestation import generate_keypair
from aegis.monitoring.reports import CompromiseReport, TrustReport, ThreatEventReport, AgentHeartbeat


class TestReportSignatureVerification:
    def _make_config_with_key(self, agent_id, keypair):
        """Create a MonitorConfig with one agent's public key."""
        from monitor.config import AgentKey
        return MonitorConfig(
            agent_public_keys={
                agent_id: AgentKey(
                    key_type=keypair.key_type,
                    key_bytes=keypair.public_key,
                ),
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
        # Tamper with the data
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
        # Configure as ed25519 but report was signed with hmac
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestReportSignatureVerification -v`

- [ ] **Step 3: Implement verify_report_signature rewrite**

Replace `verify_report_signature` in `monitor/auth.py`:

```python
import logging

logger = logging.getLogger(__name__)

# Report type → subclass dispatch for signature verification
_REPORT_TYPE_MAP: dict[str, type] | None = None


def _get_report_type_map() -> dict[str, type]:
    """Lazy-load report subclass map to avoid import cycles."""
    global _REPORT_TYPE_MAP
    if _REPORT_TYPE_MAP is None:
        from aegis.monitoring.reports import (
            AgentHeartbeat,
            CompromiseReport,
            ThreatEventReport,
            TrustReport,
        )
        _REPORT_TYPE_MAP = {
            "compromise": CompromiseReport,
            "trust": TrustReport,
            "threat_event": ThreatEventReport,
            "heartbeat": AgentHeartbeat,
        }
    return _REPORT_TYPE_MAP


def verify_report_signature(data: dict, config: "MonitorConfig") -> tuple[bool, bool]:
    """Verify a report's cryptographic signature.

    Returns:
        (accepted, verified):
        - (True, True): known agent, valid signature
        - (True, False): unknown agent or no keys configured
        - (False, False): known agent, invalid/missing signature
    """
    # Open mode: no keys configured
    if not config.agent_public_keys:
        return (True, False)

    agent_id = data.get("agent_id", "")
    agent_key = config.agent_public_keys.get(agent_id)

    # Unknown agent: accept unverified
    if agent_key is None:
        logger.debug("Report from unknown agent %r accepted unverified", agent_id)
        return (True, False)

    # Known agent: signature must be present
    sig = data.get("signature", "")
    if not sig:
        logger.warning("Report from known agent %r rejected: missing signature", agent_id)
        return (False, False)

    # Key type must match
    report_key_type = data.get("key_type", "hmac-sha256")
    if report_key_type != agent_key.key_type:
        logger.warning(
            "Report from agent %r rejected: key_type mismatch (report=%r, config=%r)",
            agent_id, report_key_type, agent_key.key_type,
        )
        return (False, False)

    # Dispatch to correct subclass for canonical bytes
    report_type = data.get("report_type", "")
    type_map = _get_report_type_map()
    report_cls = type_map.get(report_type)
    if report_cls is None:
        logger.warning("Report from agent %r rejected: unknown report_type %r", agent_id, report_type)
        return (False, False)

    try:
        report = report_cls.from_dict(data)
        if report.verify(agent_key.key_bytes):
            return (True, True)
        logger.warning("Report from agent %r rejected: signature verification failed", agent_id)
        return (False, False)
    except Exception:
        logger.warning("Report from agent %r rejected: deserialization/verification error", agent_id, exc_info=True)
        return (False, False)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestReportSignatureVerification -v`

- [ ] **Step 5: Run all auth tests for regression**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py -v`

- [ ] **Step 6: Commit**

```bash
cd /workspace/aegis-monitor && git add monitor/auth.py tests/test_auth.py && git -c commit.gpgsign=false commit -m "feat(monitor): rewrite verify_report_signature with subclass dispatch"
```

---

### Task 3: Add verified Field to CompromiseRecord and Database

**Files:**
- Modify: `monitor/models.py`
- Modify: `monitor/backends/_sqlite.py`
- Modify: `monitor/backends/_postgres.py`
- Modify: `monitor/db.py`
- Test: `tests/test_auth.py`

- [ ] **Step 1: Write failing test for verified field persistence**

Append to `/workspace/aegis-monitor/tests/test_auth.py`:

```python
class TestVerifiedFieldPersistence:
    def test_compromise_record_has_verified_field(self):
        from monitor.models import CompromiseRecord
        record = CompromiseRecord(record_id="r1", verified=True)
        assert record.verified is True

    def test_compromise_record_defaults_unverified(self):
        from monitor.models import CompromiseRecord
        record = CompromiseRecord(record_id="r1")
        assert record.verified is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestVerifiedFieldPersistence -v`

- [ ] **Step 3: Add verified field to CompromiseRecord**

In `monitor/models.py`, add after `timestamp` field (line 60):

```python
    verified: bool = False
```

- [ ] **Step 4: Add verified column to SQLite schema**

In `monitor/backends/_sqlite.py`:

1. Add `verified` column to `_SCHEMA` in the `compromises` CREATE TABLE (after `timestamp`):
```sql
    verified         INTEGER NOT NULL DEFAULT 0
```

2. Add migration after `init_schema` to handle existing databases. Modify `init_schema()`:

```python
def init_schema(self) -> None:
    conn = self._get_conn()
    conn.executescript(_SCHEMA)
    # Migrate: add verified column if missing (existing databases)
    try:
        conn.execute("ALTER TABLE compromises ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.commit()
```

- [ ] **Step 5: Add verified column to PostgreSQL schema**

In `monitor/backends/_postgres.py`, add to `_SCHEMA_STATEMENTS` list:
```python
"ALTER TABLE compromises ADD COLUMN IF NOT EXISTS verified INTEGER NOT NULL DEFAULT 0",
```

- [ ] **Step 6: Update compromise INSERT in db.py**

In `monitor/db.py`, find `insert_compromise` (line 182). Add `verified` to the INSERT column list and values:

Change:
```sql
(record_id, reporter_agent_id, compromised_agent_id,
 source, nk_score, nk_verdict, recommended_action,
 content_hash_hex, timestamp)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
```
To:
```sql
(record_id, reporter_agent_id, compromised_agent_id,
 source, nk_score, nk_verdict, recommended_action,
 content_hash_hex, timestamp, verified)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
```

Add `int(record.verified)` to the params tuple. Also update the `ON CONFLICT` clause to include `verified = excluded.verified`.

Also update `get_compromises` (line 226-239) to read the `verified` column back:

```python
    verified=bool(r.get("verified", 0)),
```

Add this line to the `CompromiseRecord(...)` constructor call inside the list comprehension.

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestVerifiedFieldPersistence -v`

- [ ] **Step 8: Commit**

```bash
cd /workspace/aegis-monitor && git add monitor/models.py monitor/backends/_sqlite.py monitor/backends/_postgres.py monitor/db.py tests/test_auth.py && git -c commit.gpgsign=false commit -m "feat(monitor): add verified field to CompromiseRecord and database"
```

---

### Task 4: Wire Verification into Report Endpoints

**Files:**
- Modify: `monitor/app.py`
- Test: `tests/test_auth.py`

- [ ] **Step 1: Write failing tests for endpoint verification**

Append to `/workspace/aegis-monitor/tests/test_auth.py`:

```python
from aegis.identity.attestation import generate_keypair
from aegis.monitoring.reports import CompromiseReport, AgentHeartbeat


class TestEndpointSignatureVerification:
    def test_known_agent_bad_signature_rejected(self, auth_client):
        """Known agent with invalid signature should get 401."""
        from monitor.config import AgentKey
        kp = generate_keypair("hmac-sha256")
        auth_client.app.state.config.agent_public_keys = {
            "agent-1": AgentKey(key_type="hmac-sha256", key_bytes=kp.public_key),
        }
        # Send unsigned report from known agent
        resp = auth_client.post(
            "/api/v1/reports/compromise",
            json={"agent_id": "agent-1", "compromised_agent_id": "agent-2"},
            headers={"Authorization": "Bearer sk-agent-1"},
        )
        assert resp.status_code == 401

    def test_known_agent_valid_signature_accepted(self, auth_client):
        """Known agent with valid signature should be accepted."""
        from monitor.config import AgentKey
        kp = generate_keypair("hmac-sha256")
        auth_client.app.state.config.agent_public_keys = {
            "agent-1": AgentKey(key_type="hmac-sha256", key_bytes=kp.public_key),
        }
        report = CompromiseReport(
            agent_id="agent-1",
            compromised_agent_id="agent-2",
            source="test",
        )
        report.sign(kp)
        resp = auth_client.post(
            "/api/v1/reports/compromise",
            json=report.to_dict(),
            headers={"Authorization": "Bearer sk-agent-1"},
        )
        assert resp.status_code != 401

    def test_unknown_agent_accepted_without_signature(self, auth_client):
        """Unknown agent (no public key) should be accepted unverified."""
        from monitor.config import AgentKey
        auth_client.app.state.config.agent_public_keys = {
            "other-agent": AgentKey(key_type="hmac-sha256", key_bytes=b"\x00" * 32),
        }
        resp = auth_client.post(
            "/api/v1/reports/compromise",
            json={"agent_id": "agent-1", "compromised_agent_id": "agent-2"},
            headers={"Authorization": "Bearer sk-agent-1"},
        )
        assert resp.status_code != 401

    def test_open_mode_no_verification(self, auth_client):
        """No public keys configured = open mode, all accepted."""
        auth_client.app.state.config.agent_public_keys = {}
        resp = auth_client.post(
            "/api/v1/reports/compromise",
            json={"agent_id": "agent-1", "compromised_agent_id": "agent-2"},
            headers={"Authorization": "Bearer sk-agent-1"},
        )
        assert resp.status_code != 401

    def test_heartbeat_verification(self, auth_client):
        """Heartbeat endpoint also verifies signatures."""
        from monitor.config import AgentKey
        kp = generate_keypair("hmac-sha256")
        auth_client.app.state.config.agent_public_keys = {
            "agent-1": AgentKey(key_type="hmac-sha256", key_bytes=kp.public_key),
        }
        # Unsigned heartbeat from known agent
        resp = auth_client.post(
            "/api/v1/heartbeat",
            json={"agent_id": "agent-1", "operator_id": "op-1", "trust_tier": 1, "trust_score": 50, "edges": []},
            headers={"Authorization": "Bearer sk-agent-1"},
        )
        assert resp.status_code == 401
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestEndpointSignatureVerification -v`

- [ ] **Step 3: Add verification to all 4 report endpoints**

In `monitor/app.py`:

1. Add import at top:
```python
from monitor.auth import verify_report_signature
```

2. Add `Request` to fastapi imports if not already present.

3. In each of the 4 report endpoints, add verification as the first operation. Add `request: Request` parameter to access config:

**`receive_compromise`** (search for `async def receive_compromise`):
```python
@app.post("/api/v1/reports/compromise")
async def receive_compromise(request: Request, data: dict, _role: str = Depends(require_role("agent", "operator"))):
    config: MonitorConfig = request.app.state.config
    accepted, verified = verify_report_signature(data, config)
    if not accepted:
        raise HTTPException(status_code=401, detail="Invalid report signature")

    # ... rest of handler unchanged, but pass verified to CompromiseRecord:
    record = CompromiseRecord(
        ...existing fields...,
        verified=verified,
    )
```

**`receive_trust`** (search for `async def receive_trust`):
```python
async def receive_trust(request: Request, data: dict, _role: str = Depends(require_role("agent", "operator"))):
    config: MonitorConfig = request.app.state.config
    accepted, verified = verify_report_signature(data, config)
    if not accepted:
        raise HTTPException(status_code=401, detail="Invalid report signature")
    # Add verified to event payload
    # In the StoredEvent payload, add: data["verified"] = verified
```

**`receive_threat`** (search for `async def receive_threat`):
Same pattern — add verification, include `verified` in event data.

**`receive_heartbeat`** (search for `async def receive_heartbeat`):
Same pattern — add verification, include `verified` in event data.

4. Update the inline SQL in `receive_compromise`'s `_persist_compromise` to include `verified`:

The INSERT at ~line 327 needs `verified` added to columns and `int(record.verified)` added to params. Also update the `ON CONFLICT` clause.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_auth.py::TestEndpointSignatureVerification -v`

- [ ] **Step 5: Run full test suite**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/ -v`

Fix any regressions — existing tests may need `agent_public_keys={}` set explicitly if they weren't already.

- [ ] **Step 6: Commit**

```bash
cd /workspace/aegis-monitor && git add monitor/app.py tests/test_auth.py && git -c commit.gpgsign=false commit -m "feat(monitor): wire signature verification into all report endpoints"
```

---

### Task 5: Full Regression Test

- [ ] **Step 1: Run full monitor test suite**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/ -v --tb=short`

- [ ] **Step 2: Run full project test suite**

Run: `cd /workspace && python -m pytest --tb=short -q`

- [ ] **Step 3: Verify no import cycles**

Run: `cd /workspace/aegis-monitor && python -c "from monitor.app import app; print('OK')"`

- [ ] **Step 4: Commit any remaining fixes**
