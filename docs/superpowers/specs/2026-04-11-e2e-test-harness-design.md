# E2E Test Harness Design

## Problem

AEGIS has component-level integration tests but no real-world end-to-end tests that exercise the full pipeline — Shield wrapping an LLM client, scanning inputs, tagging provenance, sanitizing outputs, and reporting to a live monitor instance — in a containerized environment.

## Goals

1. An ephemeral, containerized e2e test environment that starts and tears down cleanly
2. A running monitor instance that agents report to
3. Configurable number of AEGIS-wrapped agents with all modules enabled
4. Swappable LLM backend: mock server (default), real cloud API, or local Ollama
5. First scenario: smoke test verifying a single agent completes a legitimate analysis task without being blocked

## Architecture

Three containers orchestrated by `docker-compose.e2e.yaml`:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   mock-llm      │     │    monitor       │     │  test-runner     │
│                 │     │                  │     │                  │
│ FastAPI server  │◄────│ aegis-monitor    │◄────│ pytest e2e suite │
│ OpenAI-compat   │     │ FastAPI on :8080 │     │                  │
│ /v1/chat/compl  │     │ SQLite in-memory │     │ AEGIS Shield +   │
│ on :9999        │     │ open auth mode   │     │ wrapped client   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

**Flow:**
1. docker-compose starts `mock-llm` and `monitor`, waits for health checks
2. `test-runner` starts, pytest discovers e2e tests
3. Each test creates a Shield with all modules enabled, monitoring pointed at `http://monitor:8080/api/v1`
4. The test wraps an OpenAI-compatible client pointed at `http://mock-llm:9999`
5. The agent runs its task — AEGIS scans inputs, tags provenance, sanitizes outputs, reports to monitor
6. Test asserts: task completed, no ThreatBlockedError, monitor received heartbeats/events
7. Container exits, `docker compose down -v` tears everything down

## File Layout

```
tests/e2e/
├── docker-compose.e2e.yaml
├── Dockerfile.test-runner
├── Dockerfile.mock-llm
├── mock_llm/
│   └── server.py              # OpenAI-compatible mock
├── fixtures/
│   └── quarterly_report.md    # Analysis document
├── conftest.py                # pytest fixtures (Shield factory, client factory)
├── test_smoke.py              # First scenario: single agent analysis
└── README.md                  # How to run, env var reference
aegis-monitor/
└── Dockerfile                 # New — builds monitor image
```

## Component Details

### Mock LLM Server

A lightweight FastAPI app at `mock_llm/server.py` implementing:

- `GET /health` — returns `{"status": "ok"}` for health checks
- `POST /v1/chat/completions` — accepts standard OpenAI request format, returns a deterministic multi-paragraph analysis response

The response is a static template that reads like a real business analysis. This matters because AEGIS scans outputs for authority markers and anomalies — gibberish could trigger false positives. The response includes realistic `usage` fields so the OpenAI client library parses it correctly.

Same input always produces the same output for reproducibility.

### Monitor Container

`aegis-monitor/Dockerfile`:
- Base: `python:3.12-slim`
- Installs `aegis-monitor` from source
- Exposes port 8080
- Entrypoint: `uvicorn monitor.app:app --host 0.0.0.0 --port 8080`

E2e configuration via environment variables:
- Open auth mode (no API keys)
- SQLite `:memory:` database
- Clustering disabled
- `compromise_quorum: 1`, `compromise_min_trust_tier: 0`

The monitor's static frontend assets are not needed for e2e testing — the API endpoints work without them. The Dockerfile does not run `npm install` or build frontend assets.

Health check: `GET /api/v1/metrics` returns 200, polled every 2s with 10 retries.

### Test Runner

`Dockerfile.test-runner`:
- Base: `python:3.12-slim`
- Copies entire repo, installs `pip install -e ".[e2e]"`
- Entrypoint: `pytest tests/e2e/ -v`

An `e2e` extra is added to `pyproject.toml` to keep e2e deps tracked in one place:
```toml
e2e = ["pytest>=7.0", "pytest-asyncio>=0.23", "httpx>=0.27", "openai>=1.0", "ruff>=0.4.0"]
```

### Pytest Fixtures (`conftest.py`)

- `monitor_url` (session-scoped) — resolves from `MONITOR_URL` env var, polls `GET {url}/api/v1/metrics` every 1s until 200 or timeout (30s)
- `shield_factory` — factory returning a configured Shield. Builds a full `AegisConfig`:

```python
def _make(agent_id="test-agent-1", mode="enforce"):
    config = AegisConfig(
        mode=mode,
        agent_id=agent_id,
        monitoring={
            "enabled": True,
            "service_url": f"{monitor_url}/api/v1",
            "heartbeat_interval_seconds": 5,  # fast for testing
        },
    )
    shield = Shield(config=config)
    request.addfinalizer(shield.close)  # prevent thread leak on failure
    return shield
```

Note: `Shield.__init__` does not accept `agent_id` directly — it must be set via `AegisConfig`. The `monitoring.service_url` must include the `/api/v1` path prefix since `MonitoringClient` appends endpoint paths directly (e.g., `/heartbeat`).

- `llm_client` — OpenAI client pointed at `LLM_BASE_URL` (defaults to `http://mock-llm:9999/v1`)
- `llm_model` — from `LLM_MODEL` env var (defaults to `mock-analyst`)
- `analysis_document` — reads `fixtures/quarterly_report.md`

### Fixed Document

`fixtures/quarterly_report.md` — a ~500 word synthetic quarterly business report with revenue figures, department performance, and trends. Deliberately clean content with no injection patterns or authority markers.

## Smoke Test Scenario

`test_smoke.py::TestSmokeAnalysis::test_agent_completes_analysis_task`

Steps:
1. Create Shield via `shield_factory(agent_id="smoke-agent-1")`
2. Wrap the OpenAI client with `shield.wrap(llm_client)`
3. Send a chat completion request: system prompt ("You are a business analyst") + user message containing the quarterly report
4. Assert response content is non-empty (agent was not blocked)
5. Poll `GET {monitor_url}/api/v1/graph` every 1s for up to 10s until `smoke-agent-1` appears in the nodes list. The first heartbeat fires immediately on `MonitoringClient.start()` (the `_heartbeat_loop` sends before sleeping), but the HTTP POST is async so a brief poll is needed.
6. Assert `smoke-agent-1` appears in the monitor's graph and is not marked compromised or quarantined
7. Cleanup handled by `shield_factory` finalizer (`shield.close()`)

Note: Direct HTTP queries to the monitor (step 5) rely on open auth mode. If a future scenario adds API keys, those queries must include the key.

**What this validates:**
- Shield initializes with all modules without error
- OpenAI provider auto-detection and wrapping works
- Input scanning does not false-positive on legitimate content
- Provenance tagging and output sanitization run without disruption
- Monitoring client successfully reports to a live monitor instance

## Docker Compose Orchestration

Invocation:
```bash
# Run e2e tests
docker compose -f docker-compose.e2e.yaml up --build --abort-on-container-exit --exit-code-from test-runner

# Teardown
docker compose -f docker-compose.e2e.yaml down -v
```

`depends_on` with `condition: service_healthy` ensures mock-llm and monitor are ready before the test-runner starts.

## Environment Variables

The test-runner container accepts these env vars to swap providers:

| Variable | Default | Purpose |
|---|---|---|
| `MONITOR_URL` | `http://monitor:8080` | Base URL of the AEGIS monitor instance (no path suffix). The conftest appends `/api/v1` for the Shield's `monitoring.service_url` and uses the base URL for direct API queries. |
| `LLM_BASE_URL` | `http://mock-llm:9999/v1` | OpenAI-compatible API base URL |
| `LLM_API_KEY` | `mock-key` | API key for the LLM provider |
| `LLM_MODEL` | `mock-analyst` | Model name to use in chat completions |

**Using a real provider:**
```bash
# Real OpenAI
docker compose -f docker-compose.e2e.yaml run \
  -e LLM_BASE_URL=https://api.openai.com/v1 \
  -e LLM_API_KEY=sk-... \
  -e LLM_MODEL=gpt-4o \
  test-runner

# Local Ollama
docker compose -f docker-compose.e2e.yaml run \
  -e LLM_BASE_URL=http://host.docker.internal:11434/v1 \
  -e LLM_MODEL=qwen2:0.5b \
  test-runner
```

## Implementation Notes

- The monitor health check uses `GET /api/v1/metrics` (not `GET /`) to avoid depending on static frontend assets.
- The `shield_factory` fixture registers a `shield.close()` finalizer so the monitoring background thread is always stopped, even if assertions fail.
- The `MonitoringClient._heartbeat_loop` sends a heartbeat at the top of the loop before sleeping, so the first heartbeat fires immediately on `start()`. The smoke test still polls because the HTTP POST is async.
- All direct HTTP queries from the test-runner to the monitor rely on open auth mode (no API keys configured). Future scenarios that add API keys must also pass them in these direct queries.

## Future Scenarios (Out of Scope)

- Multi-agent conversations with inter-agent trust evaluation
- Threat detection scenarios (malicious inputs that should be blocked)
- Broker/tool-call evaluation
- Drift detection over multi-turn conversations
- CI integration with GitHub Actions
