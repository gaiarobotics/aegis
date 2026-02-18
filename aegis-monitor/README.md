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
