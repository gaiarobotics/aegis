# AEGIS Monitor

Real-time monitoring dashboard for AEGIS-protected agent networks.

## Features

- **Agent Graph** — live visualization of agent trust relationships (Sigma.js / WebGL)
- **R0 Estimation** — epidemiological tracking of compromise propagation
- **Attack Strain Clustering** — semantic grouping of threat events via UMAP + HDBSCAN
- **WebSocket Dashboard** — real-time metric updates

## Quick Start

```bash
pip install -e ".[dev]"
uvicorn monitor.app:app --host 0.0.0.0 --port 8080 --reload
```

Open `http://localhost:8080` to view the dashboard.

## Configuration

Create `monitor.yaml` or set environment variables:

```yaml
host: "0.0.0.0"
port: 8080
database_path: "monitor.db"
api_keys:
  - "your-api-key"
clustering_enabled: true
r0_window_hours: 24
```

| Env var | Description |
|---------|-------------|
| `MONITOR_HOST` | Bind address (default `0.0.0.0`) |
| `MONITOR_PORT` | Port (default `8080`) |
| `MONITOR_DATABASE_PATH` | SQLite path (default `monitor.db`) |
| `MONITOR_API_KEYS` | Comma-separated API keys |
| `MONITOR_CLUSTERING_ENABLED` | Enable ML clustering (`true`/`false`) |
| `MONITOR_R0_WINDOW_HOURS` | R0 estimation window (default `24`) |

## Epidemic Simulator

The simulator models prompt injection worm propagation across an agent population, letting you compare AEGIS-defended vs. undefended scenarios. Access it at `http://localhost:8080/simulator` or via the "Simulator" link in the monitor dashboard.

### Running a simulation

1. **Configure the scenario** in the left sidebar — set agent count (10–5,000), network topology, initial infection rate, technique probabilities, and AEGIS module toggles.
2. **Generate** — creates the agent population and contact graph. The graph appears in the center panel.
3. **Start** — begins auto-ticking at the rate set by the speed slider. Use **Step** for single-tick advancement, or **Pause**/**Resume** to control pacing.
4. **Observe** — the population chart (center, "Population Chart" tab) shows clean/infected/quarantined/recovered percentages over time with R0 on the secondary axis. The confusion matrix (right sidebar) tracks AEGIS detection accuracy per attack technique.
5. **Export** — click "Download Results" to save the full run as JSON (all tick snapshots, confusion matrices, per-agent state, and config).

### Key parameters

| Parameter | Effect |
|-----------|--------|
| **Topology** | Scale-Free produces realistic hub-dominated networks. Small World creates clustered communities. Random gives uniform connectivity. Community creates dense clusters with sparse inter-group links. |
| **Technique Probabilities** | Independent coin flips per message — e.g., `worm_propagation: 0.4` means 40% of infected messages attempt to propagate. Multiple techniques can co-occur naturally. |
| **Seed Strategy** | Where to place initial infections: `hubs` (high-degree nodes, fast spread), `periphery` (slow burn), `random` (baseline), `clustered` (single community). |
| **AEGIS Modules** | Toggle Scanner, Broker, Identity, Behavior, and Recovery independently. Disable all for a no-defense baseline. Sub-toggles control Scanner components (pattern matching, semantic analysis, content gate). |
| **Random Seed** | Set for reproducible runs. Same seed + same config = identical results, enabling controlled A/B comparison. |

### Agent model

Each agent has an LLM model (drawn from a weighted pool with per-model susceptibility), a SOUL age/complexity, and accumulated memory. Newer agents with simpler SOULs are more susceptible to injection. These attributes are configurable via the population model weights.

### Confusion matrix

The right sidebar shows a per-technique confusion matrix (TP/FP/FN/TN) with derived precision, recall, F1, and false positive rate. Tab between individual techniques (Worm, Memory, Role, Cred, Shell) or view the aggregate. This measures how well AEGIS detects each attack type against ground truth.

### Presets

Four built-in presets are included:

| Preset | Description |
|--------|-------------|
| **moltbook-default** | 500 agents, scale-free topology, standard Moltbook profile, all AEGIS modules on |
| **moltbook-outbreak** | Aggressive scenario: hub seeding, high worm probability (0.70), younger population |
| **no-aegis-baseline** | Same population with all modules disabled — shows undefended spread |
| **scanner-only** | Only the Scanner module enabled — measures detection without behavioral defense |

Save custom presets via the sidebar. Presets store the full config (topology, population, corpus, modules) as YAML.

### Example scenario

See [Moltbook Worm Outbreak](monitor/simulator/presets/scenarios/moltbook-worm-outbreak.md) for a guided walkthrough that runs the outbreak preset with and without AEGIS, explains what to watch for at each phase, and shows how to interpret the results.
