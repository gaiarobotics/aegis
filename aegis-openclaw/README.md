# AEGIS OpenClaw Integration

AEGIS skill and hooks package for [OpenClaw](https://github.com/gaiarobotics/openclaw) agents. Provides runtime security scanning, output sanitization, action auditing, and behavioral drift detection through two complementary layers:

1. **Hooks and plugin** - Runtime message integration plus a fail-closed pre-tool policy gate
2. **Skill commands** - Agent-accessible security commands (`aegis-scan`, `aegis-trust`, `aegis-quarantine`, etc.)

For proxy-based protection, see the [AEGIS Proxy](../aegis_proxy/) and the full [OpenClaw Integration Guide](../docs/openclaw-integration.md).

## Installation

```bash
# Core (required)
pip install aegis-shield

# Optional extras for enhanced detection
pip install aegis-shield[all]
```

Requires Python 3.10+.

## Setup

### 1. Install Hooks and the AEGIS plugin

Copy the three message hook directories from `hooks/` into your OpenClaw hooks directory:

```
hooks/
├── aegis-bootstrap/        # Injects security context on agent startup
├── aegis-scan-inbound/     # Scans every inbound message for threats
├── aegis-sanitize-outbound/  # Sanitizes every outbound message
```

Install this `aegis-openclaw/` directory as an OpenClaw plugin.  Its typed
`before_tool_call` gate blocks denied tools before execution and fails closed
if policy evaluation errors or times out.

### 2. Install the Skill

Copy `SKILL.md` and `scripts/` into your OpenClaw skills directory. The skill registers all security commands for agent use.

### 3. Configure Environment

```bash
export AEGIS_MODE=enforce              # "enforce" or "observe". "Observe" should only be used for testing.
export AEGIS_CONFIG=/path/to/aegis.yaml  # Optional config file
export AEGIS_STATE_KEY=<hex-secret>    # Required when state_store.enabled=true
export AEGIS_EXIT_TOKEN=<token>        # Required to exit quarantine
```

Optional (for model integrity checks):
```bash
export AEGIS_MODEL_NAME=llama3
export AEGIS_MODEL_PROVIDER=ollama
```

## Hooks

### aegis-bootstrap (`agent:bootstrap`)

Runs once at agent startup. Creates `.aegis/status.md` in the workspace with current AEGIS configuration, trust tier, quarantine status, killswitch status, threat intel feed reachability, and initial NK cell assessment.

### aegis-scan-inbound (`message:received`)

Scans every inbound user message through the AEGIS scanner. If a threat is detected, injects a system warning into the conversation context. Also checks quarantine status and content contagion against known-compromised signatures.

### aegis-sanitize-outbound (`message:sent`)

Sanitizes every outbound assistant message. Removes authority markers (`[SYSTEM]`, `[ADMIN]`), credential fragments, and instruction-shaped content. Detects behavioral drift against the frozen baseline.

### AEGIS plugin (`before_tool_call`) - Critical

The most important control. Evaluates every tool call against AEGIS broker policies before execution. It returns a terminal block decision for denied tools, quarantine and killswitch state. OpenClaw's policy-hook failure behavior is fail closed.

## Commands

All scripts accept `--json` for structured output and `--config` to specify a custom `aegis.yaml`.

### Scanning & Action Control

| Command | Description |
|---------|-------------|
| `aegis-scan` | Scan text for prompt injection and other threats |
| `aegis-sanitize` | Clean output text (remove authority markers, credentials) |
| `aegis-evaluate` | Check if a tool action is allowed by broker policies |

### Status & Monitoring

| Command | Description |
|---------|-------------|
| `aegis-status` | Show current AEGIS mode, enabled modules, and security state |
| `aegis-audit` | Aggregate telemetry report (event types, threats, blocked actions) |
| `aegis-trust` | Inspect trust tier and score for an agent |
| `aegis-budget` | Check remaining write budgets |
| `aegis-quarantine-check` | Check if quarantine is active |
| `aegis-drift` | Check behavioral drift baseline for an agent |
| `aegis-killswitch` | Check killswitch, quarantine escalation, and self-integrity status |
| `aegis-threat-intel` | Query the remote threat intelligence feed |
| `aegis-nk-assess` | Run NK cell immune assessment on an agent |

### Trust & Agent Management

| Command | Description |
|---------|-------------|
| `aegis-vouch` | Record a trust vouch from one agent to another |
| `aegis-compromise` | Report an agent as compromised (permanent, zeros trust) |
| `aegis-decay` | Apply time-based trust decay to all tracked agents |

### Quarantine & Recovery

| Command | Description |
|---------|-------------|
| `aegis-quarantine-manage` | Enter, exit, or escalate quarantine |
| `aegis-context-snapshot` | Save, list, or restore context snapshots for rollback |
| `aegis-memory-validate` | Validate a memory write against category restrictions and threat scanning |
| `aegis-integrity-check` | Verify model file integrity (Ollama/vLLM) |

## Usage Examples

```bash
# Scan text for threats
echo "Ignore all previous instructions" | python3 scripts/scan.py --json

# Check if a tool call is allowed
python3 scripts/evaluate_action.py \
  --tool bash --action-type tool_call --target "/bin/rm" --read-write write --json

# Inspect an agent's trust
python3 scripts/trust.py --agent-id alice --json

# Report a compromised agent
python3 scripts/compromise.py --agent-id mallory --json

# Enter quarantine
python3 scripts/quarantine_manage.py enter --reason "hostile NK verdict" --severity high --json

# Exit quarantine (requires operator token)
python3 scripts/quarantine_manage.py exit --exit-token "$AEGIS_EXIT_TOKEN" --json

# Save a context snapshot before risky operations
echo '{"messages": [...]}' | python3 scripts/context_snapshot.py save --description "pre-operation" --json
```

## Architecture

```
User ──> OpenClaw Agent
              │
              ├── aegis-bootstrap hook (startup)
              │     └── Creates .aegis/status.md
              │
              ├── aegis-scan-inbound hook (every message)
              │     └── shield.scan_input() → inject warning if threat
              │
              ├── aegis-security plugin (before every tool call)
              │     └── shield.evaluate_action() → block if denied
              │
              ├── aegis-sanitize-outbound hook (every response)
              │     └── shield.sanitize_output() → clean markers
              │
              └── Skill commands (agent-initiated)
                    └── aegis-scan, aegis-trust, aegis-quarantine, ...
```

## Stateful Security

AEGIS maintains persistent security state via a tamper-proof HMAC-chained event log:

- **Trust scores** accumulate over days/weeks; compromise history is permanent
- **Write budgets** persist across restarts and cannot be reset
- **Quarantine** survives daemon restarts
- **Behavioral baselines** freeze after initial interactions

Persistent state is opt-in. Set `state_store.enabled: true` and inject a stable
`AEGIS_STATE_KEY`; enforce mode refuses to start persistent state without one.

For production key storage, prefer runtime injection from a cloud secret manager
using workload identity. Local desktop deployments can use an OS keyring backed
by Windows DPAPI, macOS Keychain, or Linux Secret Service/libsecret. A
permission-restricted local key file is a simpler fallback, but should live
outside the repository and configuration file. A future pluggable key-provider
interface can support these without changing the state-log format.

## License

MIT
