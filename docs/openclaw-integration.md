# AEGIS + OpenClaw Integration Guide

AEGIS provides two complementary integration layers for OpenClaw:

1. **aegis-proxy** — An OpenAI-compatible HTTP proxy that scans every LLM call
2. **aegis-openclaw** — An OpenClaw skill + hooks package for agent-level visibility

Together they cover the full attack surface: the proxy sees LLM conversations, the hooks see tool execution.

## Quick Start

### 1. Start the AEGIS Proxy

```bash
python -m aegis_proxy \
  --port 8419 \
  --upstream-url https://api.openai.com/v1 \
  --mode enforce
```

Verify it's running:
```bash
curl http://localhost:8419/health
```

### 2. Point OpenClaw at the Proxy

In your OpenClaw configuration:

```json
{
  "models": {
    "providers": {
      "aegis": {
        "baseUrl": "http://localhost:8419/v1",
        "apiKey": "sk-your-real-openai-key",
        "api": "openai-completions"
      }
    }
  }
}
```

The proxy reads the API key from the `Authorization` header and forwards it to the upstream provider.

### 3. Install the AEGIS Skill

Copy `aegis-openclaw/SKILL.md` and `aegis-openclaw/scripts/` into your OpenClaw skills directory. The skill teaches the agent to use AEGIS security commands.

### 4. Install the Hooks

Copy the four hook directories from `aegis-openclaw/hooks/` into your OpenClaw hooks directory:

- `aegis-scan-inbound/` — Scans inbound messages for threats
- `aegis-sanitize-outbound/` — Sanitizes outbound messages
- `aegis-tool-audit/` — Audits every tool call (critical)
- `aegis-bootstrap/` — Injects security context on startup

## Architecture

```
User ──> OpenClaw Gateway ──> AEGIS Proxy ──> Real LLM Provider
              │                    │
              │                    ├── scan_input() on every request
              │                    ├── wrap_messages() for provenance
              │                    ├── sanitize_output() on response
              │                    └── record_response_behavior()
              │
              ├── aegis-scan-inbound hook
              ├── aegis-sanitize-outbound hook
              ├── aegis-tool-audit hook (sees tool calls)
              └── aegis-bootstrap hook (session setup)
```

## Configuration

### Proxy Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_PROXY_UPSTREAM_URL` | (none) | Upstream LLM provider URL |
| `AEGIS_PROXY_UPSTREAM_KEY` | (none) | Default upstream API key |
| `AEGIS_PROXY_PORT` | `8419` | Listen port |
| `AEGIS_MODE` | `enforce` | AEGIS mode: `observe` or `enforce` |
| `AEGIS_CONFIG` | (none) | Path to `aegis.yaml` config file |

### Proxy CLI Arguments

```
python -m aegis_proxy [OPTIONS]

--port          Listen port (default: 8419)
--host          Bind address (default: 0.0.0.0)
--upstream-url  Upstream LLM provider URL
--upstream-key  Default upstream API key
--mode          AEGIS mode (observe/enforce)
--config        Path to aegis.yaml
-v, --verbose   Verbose logging
```

## Endpoints

### POST /v1/chat/completions

OpenAI-compatible chat completions. Scans input, wraps messages with provenance, forwards to upstream, sanitizes output, and records behavior.

### POST /v1/messages

Anthropic-compatible messages endpoint. Same pipeline as chat completions but using Anthropic message format.

### GET /health

Returns proxy status:
```json
{
  "status": "ok",
  "aegis_mode": "enforce",
  "upstream_url": "https://api.openai.com/v1"
}
```

## Threat Blocking

When a threat is detected in enforce mode, the proxy returns HTTP 400 with:

```json
{
  "error": {
    "message": "AEGIS: threat detected (score=0.92)",
    "type": "aegis_threat_blocked",
    "code": "threat_detected"
  }
}
```

In observe mode, threats are logged but requests are forwarded normally.

## Streaming

For streaming requests (`"stream": true`), the proxy accumulates all SSE chunks, scans the complete response text, then returns a sanitized non-streaming response. This adds ~200ms latency but ensures complete threat detection.

## Hook Details

### aegis-scan-inbound (message:received)

Scans every inbound user message. If a threat is detected, injects a system warning message into the conversation context advising the agent to exercise caution.

### aegis-sanitize-outbound (message:sent)

Sanitizes every outbound assistant message. Removes authority markers (`[SYSTEM]`, `[ADMIN]`), credential fragments, and logs modifications.

### aegis-tool-audit (tool_result_persist)

The critical hook. Evaluates every tool call against AEGIS broker policies: budget limits, allowed tools, read/write classification. Feeds tool usage into the behavior tracker for drift detection.

### aegis-bootstrap (agent:bootstrap)

Runs once per session. Creates `.aegis/status.md` in the workspace with current AEGIS configuration, giving the agent awareness of its security posture.

## Python Scripts

All scripts in `aegis-openclaw/scripts/` accept input via `--text` argument or stdin (for large content) and output JSON with the `--json` flag.

| Script | Purpose |
|--------|---------|
| `scan.py` | Scan text for threats |
| `sanitize.py` | Clean output text |
| `evaluate_action.py` | Check tool action against policies |
| `audit.py` | Aggregate telemetry report |
| `status.py` | Show AEGIS configuration |
