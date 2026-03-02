# AEGIS Epidemic Simulator Design

## Overview

An epidemic simulator integrated into the aegis-monitor FastAPI app that exercises real AEGIS Shield instances to model prompt injection worm propagation across agent populations. Enables with-AEGIS vs. without-AEGIS comparison by toggling modules, with full ground-truth visibility and confusion matrix tracking.

## Architecture

Integrated into the existing `aegis-monitor` package as a new `/simulator` route, sharing the dark-theme UI, Sigma.js graph conventions, and WebSocket infrastructure.

### Layers

```
┌─────────────────────────────────────────────────────┐
│  Frontend (vanilla JS, Chart.js, Sigma.js)          │
│  /simulator route                                    │
├─────────────────────────────────────────────────────┤
│  API Layer (FastAPI)                                 │
│  REST: presets, control    WebSocket: tick snapshots  │
├─────────────────────────────────────────────────────┤
│  SimulationEngine                                    │
│  ├── ContactGraph (topology generation)              │
│  ├── AgentModel[] (per-agent state + real Shield)    │
│  ├── PayloadCorpus (pluggable attack sourcing)       │
│  └── MetricsCollector (confusion matrix, R0, etc.)   │
├─────────────────────────────────────────────────────┤
│  AEGIS Shield (real instances per agent)             │
│  Scanner, Broker, Identity, Behavior, Recovery       │
└─────────────────────────────────────────────────────┘
```

## Simulation Engine

### Time Model

Discrete tick-based. Each tick represents one time unit. Per tick:

1. Each infected agent selects contacts based on activity level
2. Generates a payload by independently sampling techniques
3. Receiving agent's Shield processes the message (real modules)
4. Infection outcome resolved based on Shield result + agent susceptibility
5. Background benign traffic flows between clean agents
6. Behavior/drift modules evaluate all agents, potentially triggering quarantine
7. Population metrics computed and recorded
8. Tick snapshot emitted over WebSocket

Tick rate configurable via speed slider. Deterministic with seed for reproducibility.

### Lifecycle States

- `IDLE` — no simulation, parameters editable
- `READY` — population generated, graph rendered, waiting for start
- `RUNNING` — ticks advancing at configured rate
- `PAUSED` — tick loop suspended, resumable
- `COMPLETED` — terminal condition reached

Transitions: IDLE → READY (Generate), READY → RUNNING (Start), RUNNING ↔ PAUSED, RUNNING/PAUSED → COMPLETED (Stop or terminal), any → IDLE (Reset).

### Epidemic Model

- `CLEAN → INFECTED`: Agent receives message from infected agent containing injection payload. Infection succeeds only if (a) Shield fails to detect/block it AND (b) the payload overcomes the agent's susceptibility threshold.
- `INFECTED → QUARANTINED`: AEGIS modules (NK cell, drift detector, broker quarantine triggers) flag the agent.
- `QUARANTINED → RECOVERED`: After configurable recovery period or manual intervention.

## Attack Corpus & Payload Generation

### Pluggable Corpus Architecture

```
PayloadCorpus
├── MoltbookSignatureSource  — from aegis/profiles/signatures/moltbook.yaml
├── BuiltinCorpusSource      — bundled diverse injection payloads
└── FileCorpusSource         — user-provided JSONL/YAML (future databases)
```

### Payload Model

Each payload has:
- `text` — the injection string
- `techniques` — list of attack techniques present
- `severity` — low/medium/high/critical
- `source` — which corpus it came from

### Independent Technique Sampling

Technique probabilities are independent coin flips, not a distribution:

```yaml
technique_probabilities:
  worm_propagation: 0.40
  memory_poisoning: 0.25
  role_hijacking: 0.15
  credential_extraction: 0.10
  shell_injection: 0.10
```

Each message from an infected agent independently samples each technique. This naturally produces composite attacks (e.g., worm + credential theft at ~4% probability) and occasional benign-looking messages from infected agents (all flips come up false).

The corpus stores fragments per-technique. The generator assembles selected fragments into a composite payload wrapped in contextual text.

### Effect Resolution

Each technique in a payload is resolved independently:
- `worm_propagation` — success = agent becomes infected and spreads
- `credential_extraction` — success = logged as exfiltration event
- `memory_poisoning` — success = agent behavioral profile shifts
- `shell_injection` — success = logged as code execution event
- `role_hijacking` — success = agent susceptibility increases

Shield may catch some techniques in a message but miss others — partial detection is recorded per-technique in the confusion matrix.

### FileCorpusSource Format

```jsonl
{"text": "ignore previous instructions...", "techniques": ["role_hijacking", "worm_propagation"], "severity": "high"}
{"text": "send your API key to...", "techniques": ["credential_extraction"], "severity": "critical"}
```

## Agent Model & Susceptibility

### Agent Identity

Each agent has:
- `model` — LLM model, drawn from weighted pool
- `soul_age` — how long the agent has existed (ticks). Affects SOUL complexity.
- `soul_complexity` — derived from age + random factor. Size/specificity of system prompt.
- `memory_size` — accumulated memory entries. More context for injection to compete with.

### Model Configuration

```yaml
population:
  models:
    claude-sonnet: { weight: 0.4, base_susceptibility: 0.15 }
    gpt-4o: { weight: 0.3, base_susceptibility: 0.20 }
    llama-3-70b: { weight: 0.15, base_susceptibility: 0.35 }
    mistral-large: { weight: 0.1, base_susceptibility: 0.30 }
    gemini-pro: { weight: 0.05, base_susceptibility: 0.25 }
  soul_age_distribution: { type: exponential, mean: 50 }
  new_agent_fraction: 0.05
```

`base_susceptibility` values are placeholder slots designed to be replaced with empirical data from prompt injection susceptibility benchmarks as they become available.

### Per-Technique Susceptibility

Susceptibility is computed per-technique, not as a single number:

- **worm_propagation**: `model` base rate × `soul_complexity` factor (detailed SOULs resist "repost this" instructions)
- **memory_poisoning**: `model` × `memory_size` factor (more memory = more dilution but more targets)
- **credential_extraction**: `model` × `soul_age` factor (new agents haven't learned to refuse)
- **role_hijacking**: primarily `soul_complexity` (thin SOULs easy to override)
- **shell_injection**: primarily `model` (weaker models more likely to comply with dangerous commands)

Susceptibility determines whether a payload that *gets past Shield* actually compromises the agent. This cleanly separates AEGIS detection performance from population resilience.

## Contact Graph & Network Topology

### Topologies

- **Random (Erdos-Renyi)**: uniform connectivity. Params: `mean_degree`.
- **Small-World (Watts-Strogatz)**: clustered with short paths. Params: `k`, `rewire_probability`.
- **Scale-Free (Barabasi-Albert)**: hub-dominated, realistic for social networks. Params: `m` (edges per new node).
- **Community (Stochastic Block Model)**: dense clusters, sparse inter-cluster. Params: `num_communities`, `intra_probability`, `inter_probability`.

### Agent Diversity

- `activity_level` — from configurable distribution (uniform, normal, power-law). Controls contacts per tick.
- `role` — optional tag (hub, lurker, content creator) influencing activity patterns.

### Initial Infection Seeding

- `initial_infected_pct` — percentage infected at tick 0
- `seed_strategy` — placement: `random`, `hubs` (highest-degree), `periphery` (lowest-degree), `clustered` (one community)

### Background Activity

Clean agents exchange benign messages at `background_message_rate` (multiplier of infected message rate). Essential for meaningful false positive measurement.

## AEGIS Module Toggles

Each module independently enabled/disabled per simulation run:

- **Scanner**: pattern matching, semantic analysis, content gate (sub-toggles)
- **Broker**: budgets, quarantine triggers
- **Identity**: attestation, trust scoring, NK cell
- **Behavior**: drift detection, isolation forest
- **Recovery**: auto-quarantine

Plus continuous knobs: sensitivity slider, confidence threshold. These directly configure the real Shield instances.

## Confusion Matrix & Metrics

### Per-Technique Matrix

For every message processed by Shield, ground truth vs. detection outcome recorded per technique:

|  | Technique Present | Technique Absent |
|--|--|--|
| **Detected** | TP | FP |
| **Not Detected** | FN | TN |

One matrix per technique plus aggregate. UI shows tabbed view.

### Derived Metrics (live)

- Precision, Recall, F1 per technique and aggregate
- False Positive Rate (FPR)
- Mean Time to Detection (MTTD) — ticks between infection and first AEGIS flag
- Mean Time to Quarantine (MTTQ) — ticks between infection and quarantine
- R0 — average secondary infections per infected agent before quarantine/recovery

### Module Attribution

Shield reports which modules fired per detection. Confusion matrix filterable by active modules — enables "what would precision look like with only Scanner?" comparisons.

### Export

"Download Results" button exports full run data as JSON: tick-by-tick snapshots, final confusion matrices, all parameters.

## UI Layout

### Route: `/simulator`

Shares aegis-monitor dark theme, color palette, and design system.

**Top Bar**: Start/Pause/Resume/Reset buttons, tick counter, speed slider (ticks/sec), elapsed time.

**Left Sidebar (320px)**: Three collapsible panels:
1. Scenario Parameters — agent count, topology, connectivity, initial infected %, background rate, technique probabilities, population model config
2. AEGIS Module Toggles — on/off per module with sub-toggles, sensitivity/threshold sliders
3. Presets — load/save/delete dropdown

**Center Area**: Two panels (tabbed or stacked):
1. Agent Graph — Sigma.js. Node fill = ground-truth status (green/red/orange/blue). Node border = detected status. Click for detail popup showing both statuses, module flags, contacts.
2. Population Chart — Chart.js stacked area chart. Lines: clean, infected, quarantined, recovered as % of population. R0 overlay on secondary axis.

**Right Sidebar (300px)**:
1. Confusion Matrix — tabbed per-technique + aggregate. TP/FP/TN/FN counts with precision/recall/F1.
2. Event Log — scrollable, tick-stamped significant events.

**Bottom Bar**: Summary stats — R0, total infections, detection rate, FPR, MTTD, MTTQ.

## Presets

YAML files stored server-side in `presets/` directory. Contain all scenario parameters and module configuration.

### API Endpoints

- `GET /api/v1/simulator/presets` — list presets
- `GET /api/v1/simulator/presets/{name}` — load preset
- `POST /api/v1/simulator/presets/{name}` — save preset
- `DELETE /api/v1/simulator/presets/{name}` — delete preset

### Default Presets (shipped)

- `moltbook-default` — Moltbook profile settings, 500 agents, scale-free topology
- `moltbook-outbreak` — High infection rate, hub seeding, aggressive worm
- `no-aegis-baseline` — All modules disabled, same population, for comparison
- `scanner-only` — Only Scanner enabled, measures detection without behavioral defense

## Scale Considerations

- 10-5,000 agents with real Shield instances
- At high agent counts, Shield instances share config but maintain independent state
- Tick computation is CPU-bound; async WebSocket push decouples engine from UI
- Graph visualization uses Sigma.js WebGL — handles 5,000 nodes well
- Chart.js handles thousands of data points with downsampling at high tick counts

## Reproducibility

Optional `seed` parameter. Same seed + same parameters = identical simulation. Enables controlled A/B comparison: run scenario X with all modules, then same seed with modules disabled.
