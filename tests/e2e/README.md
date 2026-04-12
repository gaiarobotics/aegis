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

### Multi-Turn Conversation Tests (`test_multi_turn.py`)

Two AEGIS-wrapped agents conduct a 12-turn dialogue in three style variants:
`natural`, `provocative`, and `tangent`. These tests require a real LLM —
they are automatically skipped when `LLM_BASE_URL` points at the mock server.

Run with OpenAI:

```bash
docker compose -f tests/e2e/docker-compose.e2e.yaml run \
  -e LLM_BASE_URL=https://api.openai.com/v1 \
  -e LLM_API_KEY=sk-... \
  -e LLM_MODEL=gpt-4o \
  test-runner
```

Run with Ollama:

```bash
docker compose -f tests/e2e/docker-compose.e2e.yaml run \
  -e LLM_BASE_URL=http://host.docker.internal:11434/v1 \
  -e LLM_MODEL=qwen2:7b \
  test-runner
```

Validates:
- AEGIS does not block legitimate multi-turn conversations
- Both agents in each conversation appear healthy in the monitor graph
- Behavioral drift ordering matches expected: `natural <= provocative <= tangent`
