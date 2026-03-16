# Sentinel Agent Design

**Date:** 2026-03-15
**Status:** Approved
**Location:** `aegis-sentinel/` (top-level, peer to `aegis-monitor/`)

## Purpose

A passive, read-heavy sentinel agent that operates on Moltbook to detect
compromised agents and embeddings.  The sentinel likes and subscribes to posts
and submolts widely but **cannot post or DM** — write capabilities are
hard-denied at the broker level.  Detections are reported to the AEGIS monitor
via the existing signed reporting pipeline.

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Detection mode | Passive observation only | Minimal attack surface; scanner pipeline already proven for Moltbook content |
| Coverage scope | Configurable (broad default, narrowable via watchlist) | Operational flexibility without added complexity |
| Reporting channel | Existing `aegis.monitoring.client` with `source: "sentinel"` tag | No need to reinvent signed HTTP reporting; tag enables dashboard filtering |
| Self-protection | Hardened beyond standard Moltbook profile | High-volume hostile content ingestion; false reports from a compromised sentinel could cause cascading false quarantines |
| Architecture | Standalone async event loop (no LLM) | Mechanical task — ingest, scan, report.  No LLM reasoning needed.  Fast, cheap, minimal attack surface |
| Directory | `aegis-sentinel/` top-level | Standalone deployable like `aegis-monitor/` and `aegis_proxy/` |

## Architecture

### Broker Lockdown — `sentinel.yaml` Profile

Custom AEGIS profile extending the Moltbook profile with zero-write enforcement:

```yaml
# Key overrides (full profile in aegis-sentinel/profiles/sentinel.yaml)
scanner:
  sensitivity: 0.85              # Stricter than Moltbook's 0.75
  block_on_threat: true
  content_gate:
    enabled: true                # Always on

broker:
  budgets:
    max_posts_messages: 0        # Hard zero — cannot post
    max_write_tool_calls: 0      # No write tools
    max_external_http_writes: 0  # No outbound writes except monitor
  allowed_write_targets:
    - monitor                    # Sole write exception: reporting

behavior:
  window_size: 20                # Shorter than Moltbook's 30
  isolation_forest:
    enabled: true
```

### Core Components

**`sentinel.py`** — Main entry point and async event loop:
1. Bootstrap `Shield` with sentinel profile
2. Create attestation: `declared_capabilities: ["like", "subscribe", "read"]`
3. Start coverage manager
4. Run ingest → scan → report loop
5. Send heartbeats to monitor

**`coverage.py`** — Scope management:
- `CoverageMode.BROAD`: auto-discover and subscribe to all submolts, like posts
  on a sampling schedule to maintain feed visibility
- `CoverageMode.WATCHLIST`: subscribe/follow only configured agents and submolts
- Configured via `sentinel.yaml` with `coverage.mode` and `coverage.watchlist[]`

**`observer.py`** — Content ingestion and scanning:
- Fetch posts/comments from subscribed submolts via Moltbook API
- Run each piece through `Shield.scan_input()` with
  `source_provenance: "social.content"`
- Track per-agent behavioral baselines (post frequency, content hashes, topics)
- Detect drift in observed agents via the behavior module
- Like posts to maintain feed visibility (social read action, not a write)

**`reporter.py`** — Monitor reporting with sentinel tags:
- `CompromiseReport` with `source: "sentinel"` for compromised agent detections
- `ThreatEventReport` with `source: "sentinel"` for threat pattern detections
- Aggregate content hashes of threats for the monitor's threat intel feed
- All reports signed with the sentinel's keypair

**`config.py`** — Sentinel-specific configuration:
- Coverage mode and watchlist entries
- Polling intervals and like-rate limits
- Hardened thresholds extending base AEGIS config

### Compromise Detection Signals

The sentinel flags an agent as potentially compromised when any of:

1. **Injection patterns** — Scanner detects injection in the agent's posts
   (score > threshold)
2. **Semantic drift** — Agent's content hash diverges from its historical
   baseline
3. **Behavioral anomaly** — Agent's posting frequency/pattern shows statistical
   anomaly
4. **Known-bad content** — Agent's posts contain content hashes matching the
   monitor's threat intel feed
5. **Correlated drift** — Multiple agents in the same submolt show correlated
   drift (worm propagation signal)

### Self-Protection (Hardened)

- Full scanner pipeline on all ingested content before processing
- Content gate always active — extractive summarization strips injection
- Isolation forest for anomaly detection on the sentinel's own behavior
- Self-integrity checks on sentinel source files
- Remote killswitch integration — monitor can shut down the sentinel
- Shorter behavioral window (20) for faster self-drift detection

## File Structure

```
aegis-sentinel/
├── sentinel/
│   ├── __init__.py
│   ├── __main__.py       # CLI entry point (python -m sentinel)
│   ├── sentinel.py       # Main event loop & orchestration
│   ├── observer.py       # Content ingestion & scanning
│   ├── coverage.py       # Broad vs watchlist scope management
│   ├── reporter.py       # Monitor reporting with sentinel tags
│   └── config.py         # Sentinel-specific configuration
├── profiles/
│   └── sentinel.yaml     # AEGIS profile: hardened + zero-write broker
├── tests/
│   ├── __init__.py
│   ├── test_sentinel.py
│   ├── test_observer.py
│   ├── test_coverage.py
│   └── test_reporter.py
├── pyproject.toml
└── README.md
```
