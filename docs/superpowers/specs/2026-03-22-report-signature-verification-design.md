# Report Signature Verification

## Problem

The AEGIS monitor accepts reports (compromise, trust, threat, heartbeat) from agents without verifying their cryptographic signatures. The signing infrastructure exists end-to-end — `ReportBase.sign()`, `ReportBase.verify()`, `MonitoringClient._sign_and_send()`, and `verify_report_signature()` in `monitor/auth.py` — but verification is never called. Any agent (or network attacker) can forge reports for any other agent.

Additionally, `MonitorConfig.agent_public_keys` has no YAML or env var loading, making it impossible to configure public keys without modifying code.

## Design

### Verification Behavior

All four report endpoints call `verify_report_signature()` before processing:

- **Known agents** (public key in config): signature must be valid. Invalid or missing signature is rejected with 401.
- **Unknown agents** (no public key in config): report accepted but tagged `verified: false`.
- **No public keys configured** (open mode): all reports accepted, all tagged `verified: false`.

This allows incremental onboarding — operators add public keys for agents one at a time without breaking unregistered agents.

### Config Changes

#### Public Key Format

Keys in YAML use a `hmac:` or `ed25519:` prefix followed by hex-encoded bytes:

```yaml
agent_public_keys:
  "agent-1": "hmac:aabbccddee..."       # 64 hex chars = 32 bytes
  "agent-2": "ed25519:aabbccddee..."     # 64 hex chars = 32 bytes
```

Environment variable: `MONITOR_AGENT_PUBLIC_KEYS=agent-1:hmac:aabbcc...,agent-2:ed25519:aabbcc...`

The env var format uses the first `:` to split agent_id from the rest (`type:hexbytes`). Agent IDs must not contain `:`.

#### Config Field Type

`agent_public_keys` changes from `dict[str, bytes]` to `dict[str, AgentKey]`:

```python
@dataclass
class AgentKey:
    key_type: str   # "hmac-sha256" or "ed25519"
    key_bytes: bytes
```

The prefix mapping: `hmac:` → `key_type="hmac-sha256"`, `ed25519:` → `key_type="ed25519"`.

### Verification Function

`verify_report_signature()` returns a `(accepted, verified)` tuple:

```python
def verify_report_signature(data: dict, config: MonitorConfig) -> tuple[bool, bool]:
    """Verify a report's cryptographic signature.

    Returns:
        (accepted, verified):
        - (True, True): known agent, valid signature
        - (True, False): unknown agent or no keys configured
        - (False, False): known agent, invalid/missing signature
    """
```

Logic:
1. If `config.agent_public_keys` is empty → `(True, False)`
2. Look up `data["agent_id"]` in public keys
3. If agent not found → `(True, False)` (unknown agent, accepted unverified)
4. If agent found, check `data["signature"]` is present and non-empty. If missing/empty → `(False, False)` (skip deserialization overhead)
5. Check that `data["key_type"]` matches the configured key type. If they differ → `(False, False)` (type mismatch)
6. Deserialize using the correct report subclass via a factory dispatch on `data["report_type"]`:
   - `"compromise"` → `CompromiseReport.from_dict(data)`
   - `"trust"` → `TrustReport.from_dict(data)`
   - `"threat_event"` → `ThreatEventReport.from_dict(data)`
   - `"heartbeat"` → `AgentHeartbeat.from_dict(data)`
   - Unknown type → `(False, False)`

   **Why subclass dispatch is required:** `ReportBase.from_dict(data)` will fail on subclass-specific fields (e.g., `compromised_agent_id`), and even if it didn't, `_canonical_bytes()` on the base class omits `_extra_canonical_parts()`, producing a different hash than what was signed.
7. Call `report.verify(key.key_bytes)` — do NOT override `report.key_type` (it's part of the canonical bytes used during signing; changing it corrupts the hash)
8. If verification succeeds → `(True, True)`
9. If verification fails → `(False, False)`

The factory dispatch should be a simple dict lookup in `verify_report_signature`, not a new method on `ReportBase`, to avoid modifying the aegis core library.

Log rejected reports at WARNING level with agent_id. Log unverified (unknown agent) reports at DEBUG level.

### Endpoint Changes

Each report endpoint adds verification before processing:

```python
accepted, verified = verify_report_signature(data, config)
if not accepted:
    raise HTTPException(status_code=401, detail="Invalid report signature")
```

The `verified` flag is passed through to stored data. For `CompromiseRecord`, add a `verified: bool` field. For `StoredEvent`, include `"verified"` in the event data dict. For heartbeat graph updates, store as node metadata.

### Data Model Changes

- `CompromiseRecord` — add `verified: bool = False` field
- `StoredEvent` — include `verified` key in event data dict (no schema change needed, it's a dict)
- `AgentNode` — no change needed (heartbeat metadata is already a dict)

The `verified` field flows through to the dashboard via existing API responses, allowing the UI to distinguish verified vs. unverified data.

### Database Migration

The `compromises` table needs a `verified` column.

**SQLite:** Add the column in `_SCHEMA` for new databases. For existing databases, run `ALTER TABLE compromises ADD COLUMN verified INTEGER DEFAULT 0` after `CREATE TABLE IF NOT EXISTS`. Wrap in try/except to handle "duplicate column name" if the column already exists (SQLite `ADD COLUMN IF NOT EXISTS` requires 3.35.0+, which may not be available in all Python builds).

**PostgreSQL:** Use `ALTER TABLE compromises ADD COLUMN IF NOT EXISTS verified INTEGER DEFAULT 0` (natively supported).

Both are backward-compatible — existing rows default to 0 (unverified).

### Env Var Validation

Agent IDs containing `:` are rejected at parse time with a clear error message, since `:` is the separator in the env var format. YAML config does not have this restriction (YAML keys are naturally delimited).

## Files to Change

- `monitor/config.py` — `AgentKey` dataclass, `agent_public_keys` type change, YAML/env var parsing
- `monitor/auth.py` — rewrite `verify_report_signature()` with subclass dispatch and `(accepted, verified)` return type
- `monitor/app.py` — call `verify_report_signature()` in all 4 report endpoints, pass `verified` to stored data
- `monitor/models.py` — add `verified: bool = False` to `CompromiseRecord`
- `monitor/backends/_sqlite.py` — add `verified` column to `compromises` table
- `monitor/backends/_postgres.py` — same for PostgreSQL backend
- `tests/test_auth.py` — tests for config parsing, verification logic, endpoint integration

## Out of Scope

- Making signing mandatory on the client side
- Key rotation or key revocation
- Automatic public key registration (agents self-registering keys)
- UI changes to display verification status
