# Quickstart: AEGIS Monitor

This guide walks you through spinning up the AEGIS Monitor dashboard and connecting it to a live agent network. By the end you will have:

1. A running monitor service with a real-time graph dashboard
2. An AEGIS-protected agent reporting trust, threat, and compromise events to it

**Prerequisites:** Python 3.10+, pip.

---

## 1. Install the SDK and Monitor

From the repository root, install both packages in development mode:

```bash
# SDK (from repo root)
pip install -e ".[monitoring,dev]"

# Monitor (separate package)
cd aegis-monitor
pip install -e ".[dev]"
cd ..
```

The `monitoring` extra pulls in `httpx` for the SDK's HTTP client. The monitor's `[dev]` extra includes `pytest`, `httpx` (for tests), and the core deps (FastAPI, uvicorn, networkx, numpy, websockets).

If you want ML-based attack strain clustering, also install the ML extras:

```bash
cd aegis-monitor
pip install -e ".[all]"
```

---

## 2. Start the Monitor

```bash
cd aegis-monitor
uvicorn monitor.app:app --host 0.0.0.0 --port 8080 --reload
```

Open [http://localhost:8080](http://localhost:8080) in a browser. You should see the dashboard with an empty graph, all metrics at zero, and a WebSocket status indicator.

### Configuration (optional)

Create `aegis-monitor/monitor.yaml` for persistent settings:

```yaml
host: "0.0.0.0"
port: 8080
database_path: "monitor.db"
api_keys:
  - "my-secret-key"
clustering_enabled: true
r0_window_hours: 24
```

Or use environment variables:

```bash
MONITOR_PORT=9090 MONITOR_API_KEYS=my-secret-key uvicorn monitor.app:app
```

When `api_keys` is empty (the default), the monitor runs in **open mode** — all requests are accepted. For production, set at least one API key.

---

## 3. Connect an Agent

Back in the repo root, enable monitoring on an AEGIS-protected agent. There are three ways:

### Option A: Environment variables (fastest)

```bash
AEGIS_MONITORING_ENABLED=true \
AEGIS_MONITORING_SERVICE_URL=http://localhost:8080/api/v1 \
AEGIS_MONITORING_API_KEY=my-secret-key \
python examples/multi_agent_defense.py
```

### Option B: Config file

Add a `monitoring` section to your `aegis.yaml`:

```yaml
mode: enforce
agent_id: chatbot-1
operator_id: my-org

monitoring:
  enabled: true
  service_url: "http://localhost:8080/api/v1"
  api_key: "my-secret-key"
  heartbeat_interval_seconds: 30
```

Then run any script that creates a `Shield`:

```python
from aegis.shield import Shield

shield = Shield()  # picks up aegis.yaml automatically
```

### Option C: Programmatic

```python
from aegis.core.config import AegisConfig
from aegis.shield import Shield

cfg = AegisConfig(
    mode="enforce",
    agent_id="researcher-1",
    operator_id="my-org",
)
cfg.monitoring["enabled"] = True
cfg.monitoring["service_url"] = "http://localhost:8080/api/v1"
cfg.monitoring["api_key"] = "my-secret-key"

shield = Shield(config=cfg)
# The shield automatically starts a background heartbeat thread
# and reports threat/compromise events to the monitor.
```

---

## 4. See It in Action (end-to-end)

Open three terminals:

**Terminal 1 — Monitor:**
```bash
cd aegis-monitor
uvicorn monitor.app:app --port 8080
```

**Terminal 2 — Agent network:**
```bash
AEGIS_MONITORING_ENABLED=true \
AEGIS_MONITORING_SERVICE_URL=http://localhost:8080/api/v1 \
AEGIS_MONITORING_API_KEY=test-key \
python examples/multi_agent_defense.py
```

**Terminal 3 — Browser:**
```bash
open http://localhost:8080
```

As the multi-agent scenario runs, watch the dashboard:

- **Nodes** appear as agents send heartbeats (green = trusted, yellow = attested, gray = unknown, red = compromised)
- **Edges** show communication links between agents, thicker lines = more messages
- **R0 metric** estimates how fast compromises propagate
- **Active threats** counter increments when threat events arrive
- **Event log** at the bottom streams events in real time via WebSocket

Click any node to see its trust tier, score, and at-risk neighbors.

---

## 5. What Gets Reported

The monitoring layer sends **metadata only** — no user content ever leaves the agent:

| Report type | When sent | Fields |
|---|---|---|
| **Heartbeat** | Periodically (default: 60s) | trust tier, score, quarantine status, graph edges |
| **Threat event** | `scan_input()` detects a threat | threat score, match count, NK verdict |
| **Compromise** | `TrustManager.report_compromise()` called, or NK cell returns hostile | compromised agent ID, source, NK score/verdict |
| **Trust** | On-demand via client API | target agent, trust score/tier, interaction counts |

All reports are cryptographically signed using the agent's attestation keypair (HMAC-SHA256 or Ed25519).

---

## 6. Dashboard Features

| Feature | Description |
|---|---|
| **Agent graph** | Sigma.js WebGL canvas — handles 1000+ nodes. Circular layout, node color by trust tier. |
| **Metrics bar** | R0, active threats, quarantined agents, attack strain count, total agents. |
| **Sidebar filters** | Filter by trust tier, compromised status, attack strain, time range. |
| **Agent popup** | Click a node → trust tier, score, status, operator, at-risk neighbors. |
| **Event log** | Real-time stream of heartbeats, threats, and compromises via WebSocket. |
| **R0 estimation** | Epidemiological tracking: secondary infections per primary infection over a sliding window. |
| **Strain clustering** | (Requires ML extras) Groups threat events by semantic similarity using UMAP + HDBSCAN. |

---

## Next Steps

- **Learn the Shield API:** See [`examples/quickstart.py`](../examples/quickstart.py) for basic scanning, sanitization, and client wrapping.
- **Multi-agent defense:** [`examples/multi_agent_defense.py`](../examples/multi_agent_defense.py) demonstrates cascading attack containment with broker, drift detection, NK cell, and quarantine.
- **Identity and trust:** [`examples/identity_and_trust.py`](../examples/identity_and_trust.py) covers attestation, trust tiers, vouching, and compromise reporting.
- **Action brokering:** [`examples/action_brokering.py`](../examples/action_brokering.py) shows tool manifests and budget enforcement.
- **Behavioral monitoring:** [`examples/behavioral_monitoring.py`](../examples/behavioral_monitoring.py) covers drift detection and anomaly profiling.
- **Security rationale:** [`docs/rationale.md`](rationale.md) explains why content-agnostic defenses matter.
- **Monitor reference:** [`aegis-monitor/README.md`](../aegis-monitor/README.md) has the full configuration reference.
