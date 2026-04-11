# E2E Test Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an ephemeral, containerized e2e test environment that exercises the full AEGIS pipeline — Shield wrapping an LLM client, scanning, provenance tagging, output sanitization, and reporting to a live monitor — with a smoke test proving a legitimate agent task runs unblocked.

**Architecture:** Three docker-compose services: a mock OpenAI-compatible LLM server, the aegis-monitor FastAPI app, and a pytest test-runner that creates AEGIS-wrapped clients and asserts end-to-end behavior. The mock LLM is the default backend; real providers (OpenAI, Ollama) can be swapped via env vars.

**Tech Stack:** Python 3.12, FastAPI, uvicorn, pytest, docker-compose, OpenAI Python SDK, httpx

**Spec:** `docs/superpowers/specs/2026-04-11-e2e-test-harness-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `tests/e2e/mock_llm/server.py` | Create | OpenAI-compatible mock LLM server (FastAPI) |
| `tests/e2e/Dockerfile.mock-llm` | Create | Container image for mock LLM |
| `tests/e2e/fixtures/quarterly_report.md` | Create | Fixed analysis document for smoke test |
| `tests/e2e/conftest.py` | Create | Pytest fixtures: monitor_url, shield_factory, llm_client, llm_model, analysis_document |
| `tests/e2e/test_smoke.py` | Create | Smoke test scenario: single agent completes analysis |
| `tests/e2e/README.md` | Create | How to run, env var reference |
| `aegis-monitor/Dockerfile` | Create | Container image for monitor service |
| `tests/e2e/docker-compose.e2e.yaml` | Create | Three-service orchestration |
| `pyproject.toml` | Modify | Add `e2e` optional dependency extra |

---

### Task 1: Add e2e dependency extra to pyproject.toml

**Files:**
- Modify: `pyproject.toml:27-46`

- [ ] **Step 1: Add the e2e extra**

In `pyproject.toml`, after the `dev` extra (line 41-46), add:

```toml
e2e = [
    "pytest>=7.0",
    "pytest-asyncio>=0.23",
    "httpx>=0.27",
    "openai>=1.0",
]
```

Do NOT add `e2e` to the `all` extra — e2e test dependencies should not be bundled into the library's general install target.

- [ ] **Step 2: Verify install works**

Run: `pip install -e ".[e2e]" --dry-run 2>&1 | head -20`
Expected: Resolves without errors, shows openai and httpx in the plan.

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml
git commit -m "deps: add e2e optional extra with openai, httpx, pytest"
```

---

### Task 2: Create the mock LLM server

**Files:**
- Create: `tests/e2e/mock_llm/__init__.py`
- Create: `tests/e2e/mock_llm/server.py`

- [ ] **Step 1: Create `tests/e2e/mock_llm/__init__.py`**

Empty file.

- [ ] **Step 2: Create `tests/e2e/mock_llm/server.py`**

```python
"""Mock OpenAI-compatible LLM server for e2e testing.

Returns deterministic, realistic responses that pass AEGIS output
sanitization without triggering false positives. The content reads
like a real business analysis — no authority markers, no gibberish.
"""

import time
import hashlib

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Mock LLM")

ANALYSIS_RESPONSE = (
    "Based on the provided quarterly report, here is a summary of key findings.\n\n"
    "Revenue grew by 12% compared to the previous quarter, driven primarily by "
    "expansion in the enterprise segment. The North American market contributed 62% "
    "of total revenue, while EMEA showed the strongest relative growth at 18% "
    "quarter-over-quarter.\n\n"
    "Operating expenses increased by 8%, which is below the revenue growth rate, "
    "indicating improving operational efficiency. The engineering department "
    "headcount grew by 15 positions, concentrated in the platform infrastructure "
    "team.\n\n"
    "Customer retention remained strong at 94%, though new customer acquisition "
    "costs increased by 6%. The sales pipeline shows healthy momentum with a "
    "weighted pipeline value 22% above the same period last year.\n\n"
    "Key risks include supply chain dependencies in the hardware division and "
    "pending regulatory changes in the EU market. The report recommends "
    "accelerating the diversification strategy outlined in the previous quarter."
)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    model: str = "mock-analyst"
    messages: list[ChatMessage]
    temperature: float = 1.0
    max_tokens: int | None = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/chat/completions")
def chat_completions(request: ChatRequest):
    # Deterministic ID from input for reproducibility
    input_hash = hashlib.md5(
        request.messages[-1].content.encode() if request.messages else b""
    ).hexdigest()[:8]

    return {
        "id": f"chatcmpl-mock-{input_hash}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": ANALYSIS_RESPONSE,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": sum(len(m.content.split()) for m in request.messages),
            "completion_tokens": len(ANALYSIS_RESPONSE.split()),
            "total_tokens": (
                sum(len(m.content.split()) for m in request.messages)
                + len(ANALYSIS_RESPONSE.split())
            ),
        },
    }
```

- [ ] **Step 3: Verify server starts locally**

Run: `cd /workspace && python -c "from tests.e2e.mock_llm.server import app; print('OK')"`
Expected: Prints `OK` (validates import).

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/mock_llm/
git commit -m "feat(e2e): add mock OpenAI-compatible LLM server"
```

---

### Task 3: Create the mock LLM Dockerfile

**Files:**
- Create: `tests/e2e/Dockerfile.mock-llm`

- [ ] **Step 1: Create the Dockerfile**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn[standard]

COPY mock_llm/ /app/mock_llm/

EXPOSE 9999

CMD ["uvicorn", "mock_llm.server:app", "--host", "0.0.0.0", "--port", "9999"]
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/Dockerfile.mock-llm
git commit -m "feat(e2e): add Dockerfile for mock LLM server"
```

---

### Task 4: Create the monitor Dockerfile

**Files:**
- Create: `aegis-monitor/Dockerfile`

The monitor depends on `aegis-shield>=0.1.0` (see `aegis-monitor/pyproject.toml:20`). Since aegis-shield is not published to PyPI, the Dockerfile must copy both the root package (aegis-shield) and aegis-monitor, installing aegis-shield first.

- [ ] **Step 1: Create the Dockerfile**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install aegis-shield from source first (aegis-monitor depends on it)
COPY pyproject.toml README.md /app/
COPY aegis/ /app/aegis/
RUN pip install --no-cache-dir -e .

# Install aegis-monitor from source
COPY aegis-monitor/ /app/aegis-monitor/
RUN pip install --no-cache-dir -e /app/aegis-monitor/

EXPOSE 8080

CMD ["uvicorn", "monitor.app:app", "--host", "0.0.0.0", "--port", "8080"]
```

Note: The build context for this Dockerfile is the repo root (`.`), not `aegis-monitor/`. This is set in `docker-compose.e2e.yaml`.

- [ ] **Step 2: Commit**

```bash
git add aegis-monitor/Dockerfile
git commit -m "feat(e2e): add Dockerfile for aegis-monitor"
```

---

### Task 5: Create the fixed analysis document

**Files:**
- Create: `tests/e2e/fixtures/quarterly_report.md`

- [ ] **Step 1: Create the fixture document**

Create the `tests/e2e/fixtures/` directory if it does not exist. Write a ~500 word synthetic quarterly business report. Content must be:
- Realistic business language with revenue figures and department performance
- Free of any prompt injection patterns (no "ignore", "override", "system" directives)
- Free of authority markers (no `[SYSTEM]`, `[ADMIN]`, role-play instructions)
- Plain factual text that AEGIS will score as `threat_score == 0.0`

```markdown
# Acme Corp — Q1 2026 Quarterly Business Report

## Executive Summary

Acme Corp delivered strong results in Q1 2026, with consolidated revenue of $47.3 million,
representing a 12% increase over Q4 2025. Operating income reached $8.1 million, up from
$6.9 million in the prior quarter, reflecting improved margins across all business segments.

## Revenue Breakdown

The Enterprise Solutions division generated $29.2 million in revenue, accounting for 62% of
the total. This segment grew 15% quarter-over-quarter, driven by three new Fortune 500 contracts
signed in January and February. Average contract value increased to $1.2 million from $980,000.

The SMB division contributed $12.4 million, growing 7% from the prior quarter. Self-serve
signups increased 23%, though average revenue per account declined slightly due to mix shift
toward the starter tier.

The Professional Services division generated $5.7 million, a 9% increase. Utilization rates
improved to 78% from 72%, and the team completed 34 implementation projects during the quarter.

## Regional Performance

North America contributed 62% of total revenue at $29.3 million. EMEA showed the strongest
relative growth at 18% quarter-over-quarter, reaching $11.8 million. APAC contributed $6.2
million, up 4% from Q4.

## Operating Expenses

Total operating expenses were $39.2 million, an increase of 8% from Q4 2025. This is below
the revenue growth rate, indicating improving operational efficiency.

Research and development spending was $14.1 million, focused on the platform infrastructure
modernization initiative. The engineering department added 15 positions during the quarter,
primarily in the backend services and data platform teams.

Sales and marketing expenses were $15.8 million. Customer acquisition costs rose 6% due to
increased paid media spending for the February product launch.

General and administrative costs were $9.3 million, roughly flat from the prior quarter.

## Key Metrics

Customer retention remained strong at 94%. Net revenue retention was 108%, indicating healthy
expansion within the existing customer base. The weighted sales pipeline stands at $62 million,
22% above Q1 2025.

Monthly active users reached 1.4 million, a 31% increase year-over-year. Platform uptime was
99.97% during the quarter, exceeding the 99.9% SLA target.

## Risks and Outlook

Key risks include ongoing supply chain constraints affecting the hardware appliance product line
and pending EU regulatory changes that may require product modifications by Q3. Currency
fluctuations present a moderate headwind for EMEA revenue.

For Q2 2026, management expects consolidated revenue of $50 to $52 million, with operating
margins in the 18-20% range. The company will continue investing in platform infrastructure
and plans to expand the sales team by 10 positions.
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/fixtures/
git commit -m "feat(e2e): add quarterly report fixture for smoke test"
```

---

### Task 6: Create pytest conftest with fixtures

**Files:**
- Create: `tests/e2e/__init__.py`
- Create: `tests/e2e/conftest.py`

Key references:
- `AegisConfig` at `aegis/core/config.py:390` — accepts `agent_id` (str), `monitoring` (MonitoringConfig dict)
- `MonitoringConfig` at `aegis/core/config.py:288` — `enabled`, `service_url`, `heartbeat_interval_seconds`
- `Shield` at `aegis/shield.py:94` — accepts `config: AegisConfig`
- `Shield.close()` at `aegis/shield.py:572` — stops monitoring thread

- [ ] **Step 1: Create `tests/e2e/__init__.py`**

Empty file.

- [ ] **Step 2: Create `tests/e2e/conftest.py`**

```python
"""Pytest fixtures for AEGIS e2e tests.

Provides configured Shield instances pointing at a live monitor,
OpenAI-compatible LLM clients, and test document loading.
"""

import os
import time
from pathlib import Path

import httpx
import pytest
from openai import OpenAI

from aegis.core.config import AegisConfig
from aegis.shield import Shield

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def monitor_url():
    """Base URL of the live monitor instance.

    Polls GET /api/v1/metrics until 200 or 30s timeout.
    """
    url = os.environ.get("MONITOR_URL", "http://monitor:8080")
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{url}/api/v1/metrics", timeout=2)
            if resp.status_code == 200:
                return url
        except httpx.HTTPError as exc:
            last_err = exc
        time.sleep(1)
    pytest.fail(f"Monitor at {url} not ready after 30s: {last_err}")


@pytest.fixture
def shield_factory(monitor_url, request):
    """Factory that creates a Shield with all modules and monitoring enabled.

    The Shield's monitoring client points at the live monitor instance.
    Registers a finalizer to call shield.close() even if the test fails.

    Usage:
        shield = shield_factory(agent_id="my-agent")
    """
    def _make(agent_id="test-agent-1", mode="enforce"):
        config = AegisConfig(
            mode=mode,
            agent_id=agent_id,
            monitoring={
                "enabled": True,
                "service_url": f"{monitor_url}/api/v1",
                "heartbeat_interval_seconds": 5,
            },
        )
        shield = Shield(config=config)
        request.addfinalizer(shield.close)
        return shield

    return _make


@pytest.fixture(scope="session")
def llm_client():
    """OpenAI-compatible client, pointed at mock-llm or a real provider."""
    base_url = os.environ.get("LLM_BASE_URL", "http://mock-llm:9999/v1")
    api_key = os.environ.get("LLM_API_KEY", "mock-key")
    return OpenAI(base_url=base_url, api_key=api_key)


@pytest.fixture(scope="session")
def llm_model():
    """Model name for chat completions."""
    return os.environ.get("LLM_MODEL", "mock-analyst")


@pytest.fixture(scope="session")
def analysis_document():
    """Load the fixed quarterly report document."""
    doc_path = FIXTURES_DIR / "quarterly_report.md"
    return doc_path.read_text()
```

- [ ] **Step 3: Verify imports work**

Run: `cd /workspace && python -c "from tests.e2e.conftest import *; print('OK')"`
Expected: Prints `OK`.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/__init__.py tests/e2e/conftest.py
git commit -m "feat(e2e): add pytest conftest with shield_factory and LLM fixtures"
```

---

### Task 7: Create the smoke test

**Files:**
- Create: `tests/e2e/test_smoke.py`

Key references:
- `Shield.wrap()` at `aegis/shield.py:1476` — auto-detects provider, returns WrappedClient
- `OpenAIWrapper` at `aegis/providers/openai.py:19` — intercepts `client.chat.completions.create()`
- `ThreatBlockedError` at `aegis/shield.py` — raised when enforce mode blocks a threat
- Monitor graph endpoint: `GET /api/v1/graph` returns `{"nodes": [...], "edges": [...]}`

- [ ] **Step 1: Create `tests/e2e/test_smoke.py`**

```python
"""Smoke test: a single AEGIS-wrapped agent completes a legitimate analysis task.

Validates that the full AEGIS pipeline (scanning, provenance tagging, output
sanitization, monitoring) runs without blocking a clean agent interaction.
"""

import httpx


def _poll_monitor_for_agent(monitor_url, agent_id, timeout=10):
    """Poll the monitor graph until agent_id appears or timeout."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{monitor_url}/api/v1/graph", timeout=2)
            if resp.status_code == 200:
                nodes = {n["id"]: n for n in resp.json().get("nodes", [])}
                if agent_id in nodes:
                    return nodes[agent_id]
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return None


class TestSmokeAnalysis:
    """Smoke test: single agent performs document analysis end-to-end."""

    def test_agent_completes_analysis_task(
        self, shield_factory, llm_client, llm_model, analysis_document, monitor_url
    ):
        """A legitimate analysis task should run without being blocked by AEGIS."""
        # 1. Create shield and wrap the client
        shield = shield_factory(agent_id="smoke-agent-1")
        wrapped = shield.wrap(llm_client)

        # 2. Run the analysis task
        response = wrapped.chat.completions.create(
            model=llm_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a business analyst. Analyze the provided report "
                        "and summarize key findings, trends, and risks."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Please analyze this quarterly report:\n\n{analysis_document}",
                },
            ],
        )

        # 3. Assert: agent was not blocked (ThreatBlockedError would have raised)
        content = response.choices[0].message.content
        assert content is not None
        assert len(content) > 0

        # 4. Assert: output content passed through AEGIS sanitization intact
        #    The mock returns a deterministic response — verify a substring survived
        assert "Revenue grew by 12%" in content

        # 5. Assert: monitor received the agent's heartbeat
        # 6. Assert: agent appears in monitor graph as healthy
        node = _poll_monitor_for_agent(monitor_url, "smoke-agent-1")
        assert node is not None, "smoke-agent-1 did not appear in monitor graph within 10s"
        assert node["is_compromised"] is False
        assert node["is_quarantined"] is False
```

- [ ] **Step 2: Verify the test file parses**

Run: `cd /workspace && python -m py_compile tests/e2e/test_smoke.py && echo "OK"`
Expected: Prints `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_smoke.py
git commit -m "feat(e2e): add smoke test — single agent document analysis"
```

---

### Task 8: Create the test runner Dockerfile

**Files:**
- Create: `tests/e2e/Dockerfile.test-runner`

- [ ] **Step 1: Create the Dockerfile**

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Copy the full repo (aegis-shield + aegis-monitor + tests)
COPY . /app

# Install aegis-shield with e2e deps
RUN pip install --no-cache-dir -e ".[e2e]"

CMD ["pytest", "tests/e2e/", "-v", "--tb=short"]
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/Dockerfile.test-runner
git commit -m "feat(e2e): add Dockerfile for test runner"
```

---

### Task 9: Create docker-compose.e2e.yaml

**Files:**
- Create: `tests/e2e/docker-compose.e2e.yaml`

Key details:
- Monitor build context must be repo root (`.`) since it needs `aegis/` and `aegis-monitor/`
- Mock LLM build context is `tests/e2e/` since it only needs `mock_llm/`
- Test runner build context is repo root (`.`) since it needs the full repo
- Monitor env vars: `MONITOR_DATABASE_PATH=:memory:`, `MONITOR_COMPROMISE_QUORUM=1`, `MONITOR_COMPROMISE_MIN_TRUST_TIER=0`
- Health checks gate test-runner start via `depends_on` + `condition: service_healthy`

- [ ] **Step 1: Create the compose file**

```yaml
# E2E test orchestration for AEGIS.
#
# Usage:
#   docker compose -f tests/e2e/docker-compose.e2e.yaml up --build \
#     --abort-on-container-exit --exit-code-from test-runner
#
#   docker compose -f tests/e2e/docker-compose.e2e.yaml down -v

services:
  mock-llm:
    build:
      context: .
      dockerfile: Dockerfile.mock-llm
    ports:
      - "9999:9999"
    healthcheck:
      test:
        [
          "CMD",
          "python",
          "-c",
          "import urllib.request; urllib.request.urlopen('http://localhost:9999/health')",
        ]
      interval: 2s
      timeout: 3s
      retries: 10

  monitor:
    build:
      context: ../..
      dockerfile: aegis-monitor/Dockerfile
    ports:
      - "8080:8080"
    environment:
      MONITOR_DATABASE_PATH: ":memory:"
      MONITOR_COMPROMISE_QUORUM: "1"
      MONITOR_COMPROMISE_MIN_TRUST_TIER: "0"
    healthcheck:
      test:
        [
          "CMD",
          "python",
          "-c",
          "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/v1/metrics')",
        ]
      interval: 2s
      timeout: 3s
      retries: 10

  test-runner:
    build:
      context: ../..
      dockerfile: tests/e2e/Dockerfile.test-runner
    environment:
      MONITOR_URL: http://monitor:8080
      LLM_BASE_URL: http://mock-llm:9999/v1
      LLM_API_KEY: mock-key
      LLM_MODEL: mock-analyst
    depends_on:
      mock-llm:
        condition: service_healthy
      monitor:
        condition: service_healthy
```

- [ ] **Step 2: Verify YAML parses**

Run: `cd /workspace && python -c "import yaml; yaml.safe_load(open('tests/e2e/docker-compose.e2e.yaml')); print('OK')"`
Expected: Prints `OK`.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/docker-compose.e2e.yaml
git commit -m "feat(e2e): add docker-compose orchestration for e2e tests"
```

---

### Task 10: Create the README

**Files:**
- Create: `tests/e2e/README.md`

- [ ] **Step 1: Create `tests/e2e/README.md`**

```markdown
# AEGIS E2E Tests

End-to-end tests that exercise the full AEGIS pipeline in a containerized
environment: Shield wrapping an LLM client, scanning inputs, tagging
provenance, sanitizing outputs, and reporting to a live monitor instance.

## Quick Start

```bash
# From the repo root:
docker compose -f tests/e2e/docker-compose.e2e.yaml up --build \
  --abort-on-container-exit --exit-code-from test-runner

# Teardown:
docker compose -f tests/e2e/docker-compose.e2e.yaml down -v
```

## Architecture

Three containers:

- **mock-llm** — OpenAI-compatible server returning deterministic responses (port 9999)
- **monitor** — aegis-monitor FastAPI app in open auth mode (port 8080)
- **test-runner** — pytest suite that creates AEGIS-wrapped agents and asserts behavior

## Environment Variables

The test-runner accepts these env vars to swap the LLM backend:

| Variable | Default | Purpose |
|---|---|---|
| `MONITOR_URL` | `http://monitor:8080` | AEGIS monitor base URL |
| `LLM_BASE_URL` | `http://mock-llm:9999/v1` | OpenAI-compatible API base URL |
| `LLM_API_KEY` | `mock-key` | API key for the LLM provider |
| `LLM_MODEL` | `mock-analyst` | Model name for chat completions |

## Using a Real LLM Provider

### OpenAI

```bash
docker compose -f tests/e2e/docker-compose.e2e.yaml run \
  -e LLM_BASE_URL=https://api.openai.com/v1 \
  -e LLM_API_KEY=sk-... \
  -e LLM_MODEL=gpt-4o \
  test-runner
```

### Ollama (local, OpenAI-compatible mode)

```bash
docker compose -f tests/e2e/docker-compose.e2e.yaml run \
  -e LLM_BASE_URL=http://host.docker.internal:11434/v1 \
  -e LLM_MODEL=qwen2:0.5b \
  test-runner
```

## Test Scenarios

### Smoke Test (`test_smoke.py`)

A single AEGIS-wrapped agent analyzes a fixed business document. Validates:

- Shield initializes with all modules without error
- OpenAI provider wrapping works
- Input scanning does not false-positive on legitimate content
- Monitoring client reports heartbeat to live monitor
- Agent appears in monitor graph as healthy (not compromised/quarantined)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/README.md
git commit -m "docs(e2e): add README with usage and env var reference"
```

---

### Task 11: End-to-end validation

Run the full docker-compose stack and verify the smoke test passes.

- [ ] **Step 1: Validate compose file**

Run: `docker compose -f tests/e2e/docker-compose.e2e.yaml config`
Expected: Prints resolved YAML with all three services, no errors about missing build contexts or invalid references.

- [ ] **Step 2: Build and run**

Run from the repo root:
```bash
docker compose -f tests/e2e/docker-compose.e2e.yaml up --build --abort-on-container-exit --exit-code-from test-runner
```

Expected: All three containers start, health checks pass, pytest runs `test_smoke.py::TestSmokeAnalysis::test_agent_completes_analysis_task` and reports PASSED.

- [ ] **Step 3: If tests fail, debug**

Check logs for each service:
```bash
docker compose -f tests/e2e/docker-compose.e2e.yaml logs mock-llm
docker compose -f tests/e2e/docker-compose.e2e.yaml logs monitor
docker compose -f tests/e2e/docker-compose.e2e.yaml logs test-runner
```

Common issues:
- Monitor health check fails → check `MONITOR_DATABASE_PATH` env var, check that `aegis-shield` installed correctly in the monitor container
- Mock LLM not responding → check Dockerfile.mock-llm has correct `COPY` path
- Test fails on `shield.wrap()` → check OpenAI client is connecting to mock-llm, check `LLM_BASE_URL`
- Agent not appearing in monitor graph → check `monitoring.service_url` includes `/api/v1`, check heartbeat interval, increase poll timeout

- [ ] **Step 4: Teardown**

```bash
docker compose -f tests/e2e/docker-compose.e2e.yaml down -v
```

- [ ] **Step 5: Final commit if any fixes were needed**

```bash
git add -A tests/e2e/ aegis-monitor/Dockerfile pyproject.toml
git commit -m "fix(e2e): address issues found during validation"
```
