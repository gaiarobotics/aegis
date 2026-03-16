# AEGIS Proxy

Standalone HTTP proxy that applies AEGIS security scanning to LLM API calls. Acts as a transparent intermediary between your application and the upstream LLM provider, scanning inputs for prompt injection, wrapping messages with provenance tags, and sanitizing outputs — without requiring any per-agent AEGIS installation.

## Quick Start

```bash
# Start the proxy
python -m aegis_proxy \
  --upstream-url https://api.openai.com/v1 \
  --mode enforce \
  --port 8419

# Verify it's running
curl http://localhost:8419/health
```

Then point your application at the proxy instead of the LLM provider:

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8419/v1",
    api_key="sk-your-real-api-key",  # forwarded to upstream
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

## CLI Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--port` | `8419` | Listen port |
| `--host` | `0.0.0.0` | Bind address |
| `--upstream-url` | `""` | Upstream LLM provider URL |
| `--upstream-key` | `""` | Default upstream API key (used when client doesn't send one) |
| `--mode` | `enforce` | AEGIS mode: `enforce` or `observe` |
| `--config` | `""` | Path to `aegis.yaml` config file |
| `-v, --verbose` | `false` | Verbose logging |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_PROXY_UPSTREAM_URL` | `""` | Upstream LLM provider URL |
| `AEGIS_PROXY_UPSTREAM_KEY` | `""` | Default upstream API key |
| `AEGIS_PROXY_PORT` | `8419` | Listen port |
| `AEGIS_PROXY_HOST` | `0.0.0.0` | Bind address |
| `AEGIS_MODE` | `enforce` | AEGIS mode |
| `AEGIS_CONFIG` | `""` | Path to `aegis.yaml` |

CLI arguments take precedence over environment variables.

## Endpoints

### `GET /health`

Returns proxy status.

```json
{
  "status": "ok",
  "aegis_mode": "enforce",
  "upstream_url": "https://api.openai.com/v1"
}
```

### `POST /v1/chat/completions`

OpenAI-compatible chat completions. Scans input, wraps messages with provenance, forwards to upstream, sanitizes output, and records behavior.

### `POST /v1/messages`

Anthropic-compatible messages endpoint. Same scanning pipeline using the Anthropic message format. Uses `x-api-key` header instead of Bearer token.

## Request Flow

```
1. Client sends request (with API key in Authorization header)
2. AEGIS extracts user text from messages
3. shield.scan_input() checks for prompt injection
   → enforce mode: returns HTTP 400 if threat detected
   → observe mode: logs threat but forwards request
4. shield.check_killswitch() checks remote killswitch/quarantine
5. shield.wrap_messages() adds provenance tags
6. Request forwarded to upstream provider
7. shield.sanitize_output() cleans response (removes [SYSTEM], [ADMIN] markers)
8. Behavior recorded for drift tracking
9. Clean response returned to client
```

## Threat Blocking

In enforce mode, detected threats return HTTP 400:

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

For streaming requests (`"stream": true`), the proxy accumulates all SSE chunks, scans the complete response text, then returns a sanitized non-streaming response. This adds latency but ensures complete threat detection — partial responses cannot bypass scanning.

## Authentication

The proxy extracts the API key from the client's `Authorization: Bearer <key>` header (or `x-api-key` for Anthropic) and forwards it to the upstream provider. If the client doesn't send a key, the proxy falls back to the configured `--upstream-key`.

## OpenClaw Integration

The proxy is designed to work with OpenClaw agents. Point your OpenClaw provider configuration at the proxy:

```json
{
  "models": {
    "providers": {
      "aegis": {
        "baseUrl": "http://localhost:8419/v1",
        "apiKey": "sk-your-real-key",
        "api": "openai-completions"
      }
    }
  }
}
```

For full OpenClaw integration (including hooks and skill commands), see the [aegis-openclaw](../aegis-openclaw/) package and the [OpenClaw Integration Guide](../docs/openclaw-integration.md).

## Testing

```bash
# From the repository root
pytest tests/test_proxy/ -v
```

## License

MIT
