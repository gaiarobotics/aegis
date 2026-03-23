# AEGIS Monitor Role-Based Access Control

## Problem

The AEGIS monitor is exposed to the internet for agent reporting and dashboard viewing. Currently:

- API endpoints use `verify_api_key` but it's a no-op when `api_keys` is empty (the default)
- Dashboard (`GET /`) and WebSocket (`/ws/dashboard`) have zero authentication
- All authenticated users have identical permissions — no distinction between agents submitting reports and operators managing killswitch/quarantine rules
- API key comparison is not timing-safe

An untrusted operator or compromised agent could killswitch the entire fleet.

## Design

### Permission Model

Three independent roles (not hierarchical — each grants specific capabilities):

| Role       | Submit reports | Read endpoints | Dashboard/WS | Killswitch/Quarantine mutations | Simulator |
|------------|---------------|----------------|--------------|--------------------------------|-----------|
| `agent`    | yes           | no             | no           | no                             | no        |
| `viewer`   | no            | yes            | yes          | no                             | no        |
| `operator` | yes           | yes            | yes          | yes                            | yes       |

`agent` is for automated report submission only. `viewer` is read-only — no write access to any endpoint. `operator` has full access.

### Configuration

`MonitorConfig.api_keys` changes from `list[str]` to `dict[str, str]` (key → role):

```yaml
api_keys:
  "sk-agent-abc123": agent
  "sk-view-def456": viewer
  "sk-ops-ghi789": operator
```

Environment variable format: `MONITOR_API_KEYS=sk-agent-abc123:agent,sk-view-def456:viewer`

When no keys are configured, open mode is preserved (all requests allowed) for dev/testing. In open mode, the `/auth/*` endpoints behave as follows:
- `POST /auth/login` with any non-empty key returns a session cookie with role `"open"` (full access).
- `GET /auth/me` returns `{"role": "open"}`.
- `POST /auth/logout` clears the cookie.

When env var entries lack a `:role` suffix (old format), they are treated as `operator` with a deprecation warning, matching the YAML migration behavior.

New config fields:
- `session_secret: str` — HMAC signing key for session cookies. **Required in production.** If absent, an ephemeral secret is auto-generated at startup with a loud warning (`WARNING: session_secret not configured — sessions will not survive restarts and are invalid across instances`). Multi-instance deployments behind a load balancer must set this explicitly.
- `session_ttl_seconds: int` — session expiry, default 28800 (8 hours).

### Auth Module Changes

**`verify_api_key`** returns the resolved role string (or `"open"` in open mode) instead of the raw key. Key comparison uses `hmac.compare_digest`.

**`require_role(*allowed_roles)`** — new FastAPI dependency factory. Calls `verify_api_key`, checks the returned role against `allowed_roles`, raises 403 if unauthorized. The `"open"` role is accepted by all role checks.

**CSRF protection** — `/auth/me` includes a `csrf_token` in its response. Cookie-authenticated mutation endpoints (`POST`/`DELETE` on killswitch/quarantine rules, simulator mutations) require an `X-CSRF-Token` header matching the token. Bearer-authenticated requests (API key in `Authorization` header) are exempt from CSRF checks since they are not cookie-based.

**Login rate limiting** — `POST /auth/login` is rate-limited per source IP: maximum 10 attempts per minute, 50 per hour. Failed attempts return 429 after the limit is reached. Rate state is held in-memory (resets on restart, which is acceptable — persistent brute-force protection is an infrastructure concern at the reverse proxy layer).

### Session Tokens

Session tokens are HMAC-SHA256 signed payloads containing `{role, key_hash, issued_at, nonce}`:
- `role` — the role granted by the API key at login time.
- `key_hash` — SHA-256 of the API key used to log in. On each request, the server checks that this hash still exists in the configured `api_keys`. If the key has been removed or rotated, the session is rejected (401), forcing re-login.
- `issued_at` — Unix timestamp. Sessions older than `session_ttl_seconds` are rejected.
- `nonce` — random entropy to prevent token prediction. Not used for replay prevention (cookies are shared across tabs by design).

No server-side session store is needed. Key removal is the revocation mechanism.

### Endpoint Classification

```
AGENT (require_role("agent", "operator")):
  POST /api/v1/reports/compromise
  POST /api/v1/reports/trust
  POST /api/v1/reports/threat
  POST /api/v1/heartbeat

VIEWER (require_role("viewer", "operator")):
  GET /api/v1/graph
  GET /api/v1/metrics
  GET /api/v1/threat-intel
  GET /api/v1/topic-clusters
  GET /api/v1/embeddings
  GET /api/v1/dendrogram
  GET /api/v1/trust/{agent_id}
  GET /api/v1/killswitch/status
  GET /api/v1/killswitch/rules
  GET /api/v1/quarantine/status
  GET /api/v1/quarantine/rules

OPERATOR (require_role("operator")):
  POST   /api/v1/killswitch/rules
  DELETE /api/v1/killswitch/rules/{rule_id}
  POST   /api/v1/quarantine/rules
  DELETE /api/v1/quarantine/rules/{rule_id}

OPERATOR (require_role("operator")) — Simulator:
  All /api/v1/simulator/* endpoints
  /ws/simulator
```

### Session Auth for Dashboard

Browser clients cannot send Bearer tokens on page load, so the dashboard uses cookie-based sessions:

- `POST /auth/login` — accepts `{"api_key": "..."}`, validates the key, returns an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. Rate-limited (see above).
- `POST /auth/logout` — requires a valid session cookie. Clears the cookie.
- `GET /auth/me` — returns `{"role": "viewer", "csrf_token": "..."}` (or 401). The dashboard JS calls this on load to determine login state and available controls.

### WebSocket Auth

`/ws/dashboard` validates the session cookie on `connect`, before calling `ws.accept()`. Rejects unauthenticated or `agent`-role connections by refusing the HTTP upgrade with a 403 response (not a WebSocket close code — the connection is never established).

Non-browser WebSocket clients authenticate by sending an `{"auth": {"api_key": "..."}}` message as the first frame after connection. The server validates the key, checks the role is `viewer` or `operator`, and only then begins streaming. If the first message is not a valid auth frame or the role is insufficient, the server closes with code 4003 and a reason string.

### Unauthenticated Endpoints

These remain open:

- `GET /` — serves the static HTML shell. Login check happens client-side via `/auth/me`.
- Static assets under `/static/*`.
- `POST /auth/login` — the login endpoint itself (rate-limited).

### Migration

The config change from `list[str]` to `dict[str, str]` is breaking. To ease migration:

- If `api_keys` is a list (old format), treat each key as `operator` role and log a deprecation warning.
- If `MONITOR_API_KEYS` env var contains entries without `:role` suffix, treat as `operator` with a deprecation warning.
- Document the new format in the config example.

## Files to Change

- `monitor/config.py` — new fields (`api_keys` type change, `session_secret`, `session_ttl_seconds`), env var parsing, migration logic
- `monitor/auth.py` — `verify_api_key` rewrite, `require_role` factory, session token sign/verify, cookie helpers, CSRF token generation/validation, login rate limiter
- `monitor/app.py` — wire `require_role` into every endpoint, add `/auth/*` routes, WebSocket auth on connect
- `monitor/simulator/routes.py` — wire `require_role("operator")` into all simulator endpoints and `/ws/simulator`
- `monitor/static/` — login UI, `/auth/me` check on dashboard load, CSRF token handling
- `tests/` — auth unit tests, endpoint permission matrix tests, rate limiting tests

## Out of Scope (Future)

- HTTPS termination (expected at reverse proxy layer)
- CORS configuration
- Per-key audit logging
- User accounts / password auth
- Token refresh / sliding sessions
- Server-side session revocation store
- Separating killswitch rule visibility from viewer tier
