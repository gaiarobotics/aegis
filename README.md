# AEGIS

**Agent Embedding Guard & Immune System**

AEGIS is something new: the first distributed immune system for agents, organized much like a biological one. It is designed to be a highly robust crowdsourced network for protection against prompt injections of all types, but especially against prompt worms that self-replicate in shared multi-agent spaces such as Moltbook. AEGIS drops-in with a single line of code and is secure out of the box, but is also highly configurable and modular. You can tune the detection modules to get exactly the protection you want, minimizing the possibility of false positives ("autoimmunity") within your problem domain and keeping dependencies light. Moreover, you can tune surface-specific configurations to customize your protection to different settings. AEGIS detects prompt injections, contains compromised agents, and prevents cascading attacks across multi-agent systems so you don't end up inadvertently authoring the first chapter of a sci-fi novel.

The adaptive component of AEGIS maintains a shared database of compromised agent embedding hashes. The framework works in such a way that the activities of the compromised agents themselves will populate it. This results in true immunological memory.

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

If you're using OpenClaw, check out the skill - it provides nearly all functionality in an easy to consume format for your agent.

## What It Does

AEGIS layers eight independent defense mechanisms so that bypassing any single one doesn't mean total compromise:

| Module | Purpose |
|--------|---------|
| **Scanner** | Detects direct and indirect prompt injections via regex, heuristics, ML classifiers, and embedding-based intent-context divergence |
| **Broker** | Controls tool access with capability manifests and write budgets |
| **Identity** | Tracks agent trust tiers, verifies cryptographic attestations |
| **Behavior** | Fingerprints agent behavior and detects drift from baseline |
| **Memory** | Guards against memory poisoning with category restrictions and taint tracking |
| **Recovery** | Auto-quarantines compromised agents and rolls back to known-good state |
| **Integrity** | Detects tampering of local model files (Ollama, vLLM) via stat checks, hashing, and inotify |
| **Monitoring** | Optional reporting to a central monitoring service for network-wide visibility |

Broadly speaking, AEGIS uses innate defense layers to bootstrap more powerful adaptive ones. Suspicious inputs, outputs, or patterns of tool use that trip innate defenses are presented to the adaptive embedding database to propagate immunity.

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
pip install aegis-shield[ml-behavior]   # Isolation Forest anomaly detection
pip install aegis-shield[pii]           # PII detection and redaction (Presidio)
pip install aegis-shield[yara]          # YARA rule matching
pip install aegis-shield[embeddings]    # Semantic embeddings for indirect injection detection
pip install aegis-shield[content-gate]  # Social media/external content filtering
pip install aegis-shield[fuzzy]         # Fuzzy identity matching
pip install aegis-shield[monitoring]    # Remote monitoring service
pip install aegis-shield[all]           # Everything
```

## Companion Modules

AEGIS ships with several companion packages for different deployment scenarios:

| Package | Purpose |
|---------|---------|
| **[aegis-monitor](aegis-monitor/)** | Real-time monitoring dashboard with agent graph visualization, R0 estimation, attack strain clustering, and epidemic simulator |
| **[aegis-sentinel](aegis-sentinel/)** | Passive sentinel agent that observes AEGIS-protected networks and reports detections to the central monitor |
| **[aegis-openclaw](aegis-openclaw/)** | OpenClaw skill and hooks integration — exposes AEGIS commands (`aegis-scan`, `aegis-trust`, `aegis-quarantine`, etc.) to OpenClaw agents |
| **[aegis_proxy](aegis_proxy/)** | Standalone HTTP proxy for remote AEGIS enforcement — transparent scanning without per-agent installation |

## Documentation

You can get started with a single line of code, but there's a lot more you can do with AEGIS:

- **[Getting Started](docs/quickstart.md)** - Installation, usage, and progressive walkthrough of every feature
- **[API Reference](docs/api-reference.md)** - Complete class/method/config reference
- **[Monitor Quickstart](docs/quickstart-monitor.md)** - Set up the monitoring dashboard and connect agents
- **[OpenClaw Integration](docs/openclaw-integration.md)** - Proxy and skill integration for OpenClaw agents
- **[Security Rationale](docs/rationale.md)** - Why AEGIS exists, attack anatomy, defense-in-depth analysis
- **[Whitepaper](https://github.com/gaiarobotics/papers/blob/main/Semantic%20Immunity%20Paper.pdf)** - outlining the risk of prompt worms in agentic networks and detailing the concept of Semantic Immunity
- **[Comparison](docs/comparison.md)** - AEGIS vs Guardrails AI vs LLM Guard
- **[Roadmap](docs/TODO.md)** - Future features and research directions
- **[Examples](examples/)** - Runnable code for every feature

## Requirements

- Python 3.10+
- Core dependencies: PyYAML and Pydantic (installed automatically)

## License

MIT
