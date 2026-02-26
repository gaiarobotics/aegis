# Pre-Emptive Contagion Avoidance

## Problem

The contagion detection system detects when an agent's content hash resembles a known-compromised agent and auto-quarantines it. But this is reactive — the agent has already processed the compromised input by the time quarantine takes effect. The most powerful defense is rejecting suspicious content *before* the LLM sees it.

## Two Levers

1. **Sender reputation**: Is the sending agent compromised or quarantined? If so, refuse their input.
2. **Content signature**: Does the incoming message's content hash resemble known-compromised hashes? If so, refuse it.

Both signals are checked pre-inference. Either alone can trigger blocking.

## Design Decisions

- **Local cache, not on-demand queries.** The agent periodically pulls a threat intelligence payload from the monitor and checks locally. No per-message network latency. Mirrors the killswitch/quarantine polling pattern.
- **Mode-dependent action.** Enforce mode blocks inference (raises `ThreatBlockedError`). Observe mode logs the detection but allows inference to proceed. Consistent with existing AEGIS semantics.
- **Single poller, single endpoint.** One `RemoteThreatIntel` class polls one `GET /api/v1/threat-intel` endpoint that returns both compromised agents and compromised hashes. Keeps complexity low.

## Architecture

### Monitor: `GET /api/v1/threat-intel`

New endpoint aggregates existing data sources:

```json
{
  "compromised_agents": ["bad-agent-1"],
  "compromised_hashes": ["abcdef01abcdef01abcdef01abcdef01"],
  "quarantined_agents": ["victim-agent-1"],
  "generated_at": 1709000000.0
}
```

Data sources already exist:
- Compromised agents: `AgentNode.is_compromised` in DB/graph
- Compromised hashes: `ContagionDetector._compromised` dict
- Quarantined agents: `AgentNode.is_quarantined` in DB/graph

### Agent: `RemoteThreatIntel` class

File: `aegis/core/remote_threat_intel.py`

- Daemon thread polls every `threat_intel_poll_interval` seconds (default 30s)
- Local cache: `_compromised_agents: set[str]`, `_compromised_hashes: set[int]`, `_quarantined_agents: set[str]`
- Thread-safe reads under lock
- Fail-last on network error (stale cache preserved)

Public API:
- `is_agent_compromised(agent_id) -> bool`
- `is_agent_quarantined(agent_id) -> bool`
- `check_hash(hash_hex, threshold=0.85) -> tuple[bool, float]` — returns `(is_suspicious, max_similarity)`

Hash comparison uses Hamming distance on 128-bit LSH integers, same math as the monitor's `ContagionDetector`. The utility functions (`hamming_distance`, `hex_to_int`) are duplicated rather than importing from the monitor package.

### Shield: pre-emptive filter in `scan_input()`

`scan_input()` already runs pre-inference in the provider wrappers. New behavior:

1. **Sender check**: If `source_agent_id` is provided (new optional parameter), check `threat_intel.is_agent_compromised()` and `is_agent_quarantined()`.
2. **Content hash check**: Take the hash computed by the existing `ContentHashTracker` and call `threat_intel.check_hash()`.
3. **Action**: In enforce mode, raise `ThreatBlockedError`. In observe mode, log and annotate `ScanResult.details["contagion"]`.

`ScanResult.details` gets a `"contagion"` key when triggered:
```python
{"contagion": {"source": "content_hash", "score": 0.92, "blocked": True}}
```

### Config

Two new fields on `MonitoringConfig`:
- `threat_intel_poll_interval: float = 30`
- `contagion_similarity_threshold: float = 0.85`

## Testing

**Agent unit tests** (`tests/test_core/test_remote_threat_intel.py`):
- Default empty caches
- Poll populates agents and hashes
- `is_agent_compromised` / `is_agent_quarantined` correctness
- `check_hash` similarity scoring and threshold
- Network failure preserves cache
- Thread lifecycle

**Monitor endpoint test** (`aegis-monitor/tests/test_app.py`):
- Empty response with no compromises
- Compromised agent appears after marking
- Compromised hashes appear
- Quarantined agents appear

**Shield integration** (`tests/test_shield.py`):
- Compromised sender + enforce → ThreatBlockedError
- Compromised sender + observe → no error, details in ScanResult
- Suspicious hash + enforce → ThreatBlockedError
- Clean input with threat intel active → no interference

## File Summary

| File | Action |
|------|--------|
| `aegis/core/remote_threat_intel.py` | CREATE |
| `aegis/core/config.py` | MODIFY — add 2 fields to MonitoringConfig |
| `aegis/shield.py` | MODIFY — init threat intel, extend scan_input |
| `aegis-monitor/monitor/app.py` | MODIFY — add threat-intel endpoint |
| `tests/test_core/test_remote_threat_intel.py` | CREATE |
| `aegis-monitor/tests/test_app.py` | MODIFY — endpoint tests |
| `tests/test_shield.py` | MODIFY — integration tests |
