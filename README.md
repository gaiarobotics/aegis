# AEGIS

**Agent Epidemiological Guardian & Immune System**

Protect your agent swarm with an immune system! A drop-in security layer for LLM-powered agents, optimized for safe(r) participation in multi-agent societies. Detects prompt injections, contains compromised agents, and prevents cascading attacks across multi-agent systems so you don't end up inadvertently authoring the first chapter of a sci-fi novel.

## Quick Start

```bash
pip install aegis-shield
```

```python
import aegis
import anthropic  # or openai, or any client with create()/generate()

client = aegis.wrap(anthropic.Anthropic())

# Use the client exactly as before - AEGIS scans automatically
response = client.messages.create(
    model="claude-sonnet-4-5-20250929",
    messages=[{"role": "user", "content": "What is 2+2?"}],
)
```

One line. No config needed. AEGIS auto-detects your provider, scans inputs for prompt injection, sanitizes outputs, and tracks agent trust - all transparently.

## What It Does

AEGIS layers seven independent defense mechanisms so that bypassing any single one doesn't mean total compromise:

| Module | Purpose |
|--------|---------|
| **Scanner** | Detects prompt injections via regex, heuristics, and optional ML classifiers |
| **Broker** | Controls tool access with capability manifests and write budgets |
| **Identity** | Tracks agent trust tiers, verifies cryptographic attestations |
| **Behavior** | Fingerprints agent behavior and detects drift from baseline |
| **Memory** | Guards against memory poisoning with category restrictions and taint tracking |
| **Recovery** | Auto-quarantines compromised agents and rolls back to known-good state |
| **Monitoring** | Optional reporting to a central monitoring service for network-wide visibility |

## Modes

| Mode | Behavior |
|------|----------|
| `enforce` (default) | Blocks detected threats by raising `ThreatBlockedError` |
| `observe` | Detects and logs threats, but never blocks - useful for evaluation |

```python
# Protected by default
client = aegis.wrap(my_client)

# Use observe mode to evaluate detections before enforcing
client = aegis.wrap(my_client, mode="observe")
```

## Supported Providers

| Provider | Intercepted Method |
|----------|-------------------|
| **Anthropic** | `client.messages.create()` |
| **OpenAI** | `client.chat.completions.create()` |
| **Ollama** | `client.chat()` and `client.generate()` |
| **vLLM** | `llm.generate()` and `llm.chat()` |
| **Generic** | `client.create()` or `client.generate()` |

## Optional Extras

```bash
pip install aegis-shield[identity]      # Ed25519 attestation
pip install aegis-shield[ml]            # ML-based scanning (uses LLM Guard)
pip install aegis-shield[monitoring]    # Remote monitoring service
pip install aegis-shield[all]           # Everything
```

## Documentation

You can get started with a single line of code, but there's a lot more you can do with AEGIS:

- **[Getting Started](docs/quickstart.md)** - Installation, usage, and progressive walkthrough of every feature
- **[API Reference](docs/api-reference.md)** - Complete class/method/config reference
- **[Monitor Quickstart](docs/quickstart-monitor.md)** - Set up the monitoring dashboard and connect agents
- **[Security Rationale](docs/rationale.md)** - Why AEGIS exists, attack anatomy, defense-in-depth analysis
- **[Comparison](docs/comparison.md)** - AEGIS vs Guardrails AI vs LLM Guard
- **[Examples](examples/)** - Runnable code for every feature

## Requirements

- Python 3.10+
- No required dependencies beyond PyYAML

## License

MIT
