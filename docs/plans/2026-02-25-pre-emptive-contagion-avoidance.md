# Pre-Emptive Contagion Avoidance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable agents to reject suspicious content before the LLM sees it, using a locally-cached threat intelligence feed from the monitor.

**Architecture:** A new monitor endpoint (`GET /api/v1/threat-intel`) serves compromised agents, quarantined agents, and compromised hashes. A new `RemoteThreatIntel` polling class caches this data agent-side. The Shield's `scan_input()` checks both sender reputation and content hash similarity pre-inference, blocking in enforce mode and logging in observe mode.

**Tech Stack:** Python stdlib (`urllib.request`, `threading`), FastAPI (monitor), pytest

---

### Task 1: Config — add threat intel fields to MonitoringConfig

**Files:**
- Modify: `aegis/core/config.py:265` (MonitoringConfig)

**Step 1: Write the failing test**

Add to `tests/test_core/test_config.py`:

```python
class TestMonitoringConfigThreatIntel:
    def test_threat_intel_defaults(self):
        from aegis.core.config import MonitoringConfig
        cfg = MonitoringConfig()
        assert cfg.threat_intel_poll_interval == 30
        assert cfg.contagion_similarity_threshold == 0.85
```

**Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_core/test_config.py::TestMonitoringConfigThreatIntel -v`
Expected: FAIL — `MonitoringConfig` has no field `threat_intel_poll_interval`

**Step 3: Write minimal implementation**

In `aegis/core/config.py`, add two fields to `MonitoringConfig` after the existing `quarantine_poll_interval` line (line 265):

```python
    threat_intel_poll_interval: float = 30  # seconds
    contagion_similarity_threshold: float = 0.85
```

**Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_core/test_config.py::TestMonitoringConfigThreatIntel -v`
Expected: PASS

**Step 5: Commit**

```bash
git add aegis/core/config.py tests/test_core/test_config.py
git commit -m "feat: add threat intel config fields to MonitoringConfig"
```

---

### Task 2: Monitor — add `GET /api/v1/threat-intel` endpoint

**Files:**
- Modify: `aegis-monitor/monitor/app.py` (add endpoint after metrics block, ~line 363)
- Test: `aegis-monitor/tests/test_app.py`

**Step 1: Write the failing tests**

Add to `aegis-monitor/tests/test_app.py`:

```python
class TestThreatIntel:
    def test_empty_threat_intel(self, client):
        resp = client.get("/api/v1/threat-intel")
        assert resp.status_code == 200
        data = resp.json()
        assert data["compromised_agents"] == []
        assert data["compromised_hashes"] == []
        assert data["quarantined_agents"] == []
        assert "generated_at" in data

    def test_compromised_agent_in_threat_intel(self, client):
        # Register agent then mark compromised
        client.post("/api/v1/heartbeat", json={
            "agent_id": "victim-1",
            "trust_tier": 2,
            "content_hash": "abcdef01" * 4,
        })
        client.post("/api/v1/reports/compromise", json={
            "agent_id": "reporter-1",
            "compromised_agent_id": "victim-1",
        })
        resp = client.get("/api/v1/threat-intel")
        data = resp.json()
        assert "victim-1" in data["compromised_agents"]

    def test_compromised_hash_in_threat_intel(self, client):
        # Register agent with a content hash, then compromise it
        client.post("/api/v1/heartbeat", json={
            "agent_id": "victim-1",
            "trust_tier": 2,
            "content_hash": "abcdef01" * 4,
        })
        client.post("/api/v1/reports/compromise", json={
            "agent_id": "reporter-1",
            "compromised_agent_id": "victim-1",
        })
        resp = client.get("/api/v1/threat-intel")
        data = resp.json()
        assert len(data["compromised_hashes"]) >= 1

    def test_quarantined_agent_in_threat_intel(self, client):
        # Register agent then quarantine it
        client.post("/api/v1/heartbeat", json={
            "agent_id": "q-agent",
            "trust_tier": 2,
        })
        client.post("/api/v1/quarantine/rules", json={
            "scope": "agent",
            "target": "q-agent",
            "quarantined": True,
            "reason": "test",
            "severity": "high",
        })
        resp = client.get("/api/v1/threat-intel")
        data = resp.json()
        assert "q-agent" in data["quarantined_agents"]
```

**Step 2: Run tests to verify they fail**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py::TestThreatIntel -v`
Expected: FAIL — 404, endpoint does not exist

**Step 3: Write minimal implementation**

In `aegis-monitor/monitor/app.py`, add after the `get_metrics` endpoint (after line 362):

```python
@app.get("/api/v1/threat-intel")
async def get_threat_intel(_key: str = Depends(verify_api_key)):
    """Return threat intelligence for agent-side pre-emptive filtering."""
    graph: AgentGraph = app.state.graph
    contagion_detector: ContagionDetector = app.state.contagion_detector

    graph_state = graph.get_graph_state()

    compromised_agents = [
        n["id"] for n in graph_state["nodes"] if n["is_compromised"]
    ]
    quarantined_agents = [
        n["id"] for n in graph_state["nodes"] if n["is_quarantined"]
    ]

    # Serialize compromised hashes from contagion detector
    compromised_hashes = [
        f"{h:032x}" for h in contagion_detector._compromised.values()
    ]

    return {
        "compromised_agents": compromised_agents,
        "compromised_hashes": compromised_hashes,
        "quarantined_agents": quarantined_agents,
        "generated_at": time.time(),
    }
```

**Step 4: Run tests to verify they pass**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/test_app.py::TestThreatIntel -v`
Expected: PASS

**Step 5: Run full monitor test suite**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/ -x -v`
Expected: All pass, no regressions

**Step 6: Commit**

```bash
git add aegis-monitor/monitor/app.py aegis-monitor/tests/test_app.py
git commit -m "feat: add threat-intel endpoint to monitor"
```

---

### Task 3: Agent — create `RemoteThreatIntel` polling class

**Files:**
- Create: `aegis/core/remote_threat_intel.py`
- Create: `tests/test_core/test_remote_threat_intel.py`

**Step 1: Write the failing tests**

Create `tests/test_core/test_remote_threat_intel.py`:

```python
"""Tests for the remote threat intelligence client."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aegis.core.remote_threat_intel import RemoteThreatIntel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MockHandler(BaseHTTPRequestHandler):
    response_body: dict = {
        "compromised_agents": [],
        "compromised_hashes": [],
        "quarantined_agents": [],
        "generated_at": 0,
    }
    response_code: int = 200
    fail: bool = False
    last_headers: dict = {}

    def do_GET(self):
        _MockHandler.last_headers = dict(self.headers)
        if self.fail:
            self.send_error(500, "Simulated failure")
            return
        self.send_response(self.response_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(self.response_body).encode())

    def log_message(self, format, *args):
        pass


def _run_server(server: HTTPServer):
    server.serve_forever()


@pytest.fixture()
def mock_monitor():
    _MockHandler.response_body = {
        "compromised_agents": [],
        "compromised_hashes": [],
        "quarantined_agents": [],
        "generated_at": 0,
    }
    _MockHandler.response_code = 200
    _MockHandler.fail = False
    _MockHandler.last_headers = {}

    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=_run_server, args=(server,), daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/api/v1"
    yield url, _MockHandler
    server.shutdown()


# ---------------------------------------------------------------------------
# Unit tests — no network
# ---------------------------------------------------------------------------


class TestDefaultState:
    def test_empty_caches(self):
        ti = RemoteThreatIntel(
            service_url="http://localhost:9999/api/v1",
            api_key="k",
            poll_interval=60,
        )
        assert ti.is_agent_compromised("any") is False
        assert ti.is_agent_quarantined("any") is False
        suspicious, score = ti.check_hash("a" * 32)
        assert suspicious is False
        assert score == 0.0


# ---------------------------------------------------------------------------
# Integration tests — with mock HTTP server
# ---------------------------------------------------------------------------


class TestPollPopulatesCache:
    def test_compromised_agents(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": ["bad-1", "bad-2"],
            "compromised_hashes": [],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        assert ti.is_agent_compromised("bad-1") is True
        assert ti.is_agent_compromised("bad-2") is True
        assert ti.is_agent_compromised("good-1") is False
        ti.stop()

    def test_quarantined_agents(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": [],
            "compromised_hashes": [],
            "quarantined_agents": ["q-1"],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        assert ti.is_agent_quarantined("q-1") is True
        assert ti.is_agent_quarantined("other") is False
        ti.stop()

    def test_compromised_hashes(self, mock_monitor):
        url, handler = mock_monitor
        comp_hash = "abcdef01" * 4
        handler.response_body = {
            "compromised_agents": [],
            "compromised_hashes": [comp_hash],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        # Identical hash -> score 1.0, suspicious
        suspicious, score = ti.check_hash(comp_hash)
        assert suspicious is True
        assert score == 1.0
        # Very different hash -> not suspicious
        suspicious2, score2 = ti.check_hash("0" * 32)
        # "abcdef01" repeated vs all-zeros: many bits differ
        assert score2 < 0.85
        ti.stop()


class TestCheckHashThreshold:
    def test_custom_threshold(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": [],
            "compromised_hashes": ["00000000000000000000000000000000"],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        # 1 bit different -> similarity ~0.992, above any reasonable threshold
        suspicious, score = ti.check_hash(
            "00000000000000000000000000000001", threshold=0.99,
        )
        assert suspicious is True
        ti.stop()

    def test_empty_hash_not_suspicious(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": [],
            "compromised_hashes": ["a" * 32],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        suspicious, score = ti.check_hash("")
        assert suspicious is False
        assert score == 0.0
        ti.stop()


class TestNetworkFailurePreservesCache:
    def test_cache_preserved_on_failure(self, mock_monitor):
        url, handler = mock_monitor
        handler.response_body = {
            "compromised_agents": ["bad-1"],
            "compromised_hashes": [],
            "quarantined_agents": [],
            "generated_at": 0,
        }
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        assert ti.is_agent_compromised("bad-1") is True

        # Network fails
        handler.fail = True
        time.sleep(1.5)
        # Cache preserved
        assert ti.is_agent_compromised("bad-1") is True
        ti.stop()


class TestThreadLifecycle:
    def test_start_and_stop(self, mock_monitor):
        url, handler = mock_monitor
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        assert ti._thread is not None
        assert ti._thread.is_alive()
        ti.stop()
        assert ti._thread is None

    def test_double_start_noop(self, mock_monitor):
        url, handler = mock_monitor
        ti = RemoteThreatIntel(service_url=url, api_key="k", poll_interval=1)
        ti.start()
        t1 = ti._thread
        ti.start()
        assert ti._thread is t1
        ti.stop()


class TestApiKeySent:
    def test_authorization_header(self, mock_monitor):
        url, handler = mock_monitor
        ti = RemoteThreatIntel(service_url=url, api_key="secret", poll_interval=1)
        ti.start()
        time.sleep(0.5)
        ti.stop()
        assert handler.last_headers.get("Authorization") == "Bearer secret"
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_core/test_remote_threat_intel.py -v`
Expected: FAIL — `ImportError: cannot import name 'RemoteThreatIntel'`

**Step 3: Write the implementation**

Create `aegis/core/remote_threat_intel.py`:

```python
"""Remote threat intelligence — polls the monitor for compromised agents and hashes.

Enables pre-emptive contagion avoidance: agents check incoming content
against known-bad signatures before the LLM processes it.  Mirrors the
RemoteKillswitch/RemoteQuarantine pattern: daemon thread, fail-last,
thread-safe reads.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_POLL_TIMEOUT = 5  # seconds
_BITS = 128  # LSH hash width


def _hex_to_int(h: str) -> int:
    """Convert a hex string to an integer."""
    return int(h, 16)


def _hamming_distance(a: int, b: int) -> int:
    """Count differing bits between two integers."""
    return bin(a ^ b).count("1")


class RemoteThreatIntel:
    """Polls the monitoring service for threat intelligence.

    Caches compromised agent IDs, quarantined agent IDs, and
    compromised content hashes.  The Shield queries this cache
    during ``scan_input()`` to reject suspicious content before
    the LLM sees it.
    """

    def __init__(
        self,
        service_url: str,
        api_key: str,
        poll_interval: float = 30,
    ) -> None:
        self._url = f"{service_url.rstrip('/')}/threat-intel"
        self._api_key = api_key
        self._poll_interval = poll_interval

        self._compromised_agents: set[str] = set()
        self._quarantined_agents: set[str] = set()
        self._compromised_hashes: set[int] = set()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_agent_compromised(self, agent_id: str) -> bool:
        """Thread-safe check if an agent is known-compromised."""
        with self._lock:
            return agent_id in self._compromised_agents

    def is_agent_quarantined(self, agent_id: str) -> bool:
        """Thread-safe check if an agent is quarantined."""
        with self._lock:
            return agent_id in self._quarantined_agents

    def check_hash(
        self, hash_hex: str, threshold: float = 0.85,
    ) -> tuple[bool, float]:
        """Check a content hash against known-compromised hashes.

        Returns ``(is_suspicious, max_similarity)`` where similarity
        is ``1.0 - hamming_distance / 128``.
        """
        if not hash_hex:
            return False, 0.0

        with self._lock:
            if not self._compromised_hashes:
                return False, 0.0
            hashes = list(self._compromised_hashes)

        h = _hex_to_int(hash_hex)
        max_sim = 0.0
        for comp_hash in hashes:
            dist = _hamming_distance(h, comp_hash)
            sim = 1.0 - (dist / _BITS)
            if sim > max_sim:
                max_sim = sim

        return max_sim >= threshold, max_sim

    def start(self) -> None:
        """Start background polling thread (daemon)."""
        if self._thread is not None:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop background polling."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=self._poll_interval + _POLL_TIMEOUT + 1)
            self._thread = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _poll_loop(self) -> None:
        self._poll()
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._poll_interval)
            if self._stop_event.is_set():
                break
            self._poll()

    def _poll(self) -> None:
        try:
            req = urllib.request.Request(self._url, method="GET")
            req.add_header("Accept", "application/json")
            if self._api_key:
                req.add_header("Authorization", f"Bearer {self._api_key}")
            with urllib.request.urlopen(req, timeout=_POLL_TIMEOUT) as resp:
                data: dict[str, Any] = json.loads(resp.read())

            compromised_agents = set(data.get("compromised_agents", []))
            quarantined_agents = set(data.get("quarantined_agents", []))
            compromised_hashes: set[int] = set()
            for h in data.get("compromised_hashes", []):
                try:
                    compromised_hashes.add(_hex_to_int(h))
                except (ValueError, TypeError):
                    pass

            with self._lock:
                self._compromised_agents = compromised_agents
                self._quarantined_agents = quarantined_agents
                self._compromised_hashes = compromised_hashes
        except Exception:
            # Fail-last: preserve cached data on network error
            logger.debug("Threat intel poll failed for %s", self._url, exc_info=True)
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_core/test_remote_threat_intel.py -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add aegis/core/remote_threat_intel.py tests/test_core/test_remote_threat_intel.py
git commit -m "feat: add RemoteThreatIntel polling class"
```

---

### Task 4: Shield — init threat intel and extend `scan_input()`

**Files:**
- Modify: `aegis/shield.py` — add `_remote_threat_intel` field, `_init_remote_threat_intel()` method, extend `scan_input()` signature and logic
- Test: `tests/test_shield.py`

**Step 1: Write the failing tests**

Add to `tests/test_shield.py`:

```python
class TestPreEmptiveContagionAvoidance:
    def _make_shield(self, mode="enforce"):
        config = AegisConfig(
            mode=mode,
            modules={"scanner": True, "broker": False, "identity": False,
                      "memory": False, "behavior": True, "skills": False,
                      "recovery": False, "integrity": False},
        )
        return Shield(config=config)

    def test_compromised_sender_enforce_blocks(self):
        """Enforce mode blocks input from a compromised sender."""
        from unittest.mock import MagicMock
        from aegis.shield import ThreatBlockedError

        shield = self._make_shield(mode="enforce")
        mock_ti = MagicMock()
        mock_ti.is_agent_compromised.return_value = True
        mock_ti.is_agent_quarantined.return_value = False
        mock_ti.check_hash.return_value = (False, 0.0)
        shield._remote_threat_intel = mock_ti

        with pytest.raises(ThreatBlockedError):
            shield.scan_input("Hello", source_agent_id="bad-agent")

    def test_compromised_sender_observe_allows(self):
        """Observe mode logs but allows input from a compromised sender."""
        from unittest.mock import MagicMock

        shield = self._make_shield(mode="observe")
        mock_ti = MagicMock()
        mock_ti.is_agent_compromised.return_value = True
        mock_ti.is_agent_quarantined.return_value = False
        mock_ti.check_hash.return_value = (False, 0.0)
        shield._remote_threat_intel = mock_ti

        result = shield.scan_input("Hello", source_agent_id="bad-agent")
        assert "contagion" in result.details
        assert result.details["contagion"]["source"] == "compromised_sender"
        assert result.details["contagion"]["blocked"] is False

    def test_quarantined_sender_enforce_blocks(self):
        """Enforce mode blocks input from a quarantined sender."""
        from unittest.mock import MagicMock
        from aegis.shield import ThreatBlockedError

        shield = self._make_shield(mode="enforce")
        mock_ti = MagicMock()
        mock_ti.is_agent_compromised.return_value = False
        mock_ti.is_agent_quarantined.return_value = True
        mock_ti.check_hash.return_value = (False, 0.0)
        shield._remote_threat_intel = mock_ti

        with pytest.raises(ThreatBlockedError):
            shield.scan_input("Hello", source_agent_id="q-agent")

    def test_suspicious_hash_enforce_blocks(self):
        """Enforce mode blocks input with a suspicious content hash."""
        from unittest.mock import MagicMock
        from aegis.shield import ThreatBlockedError

        shield = self._make_shield(mode="enforce")
        mock_ti = MagicMock()
        mock_ti.is_agent_compromised.return_value = False
        mock_ti.is_agent_quarantined.return_value = False
        mock_ti.check_hash.return_value = (True, 0.95)
        shield._remote_threat_intel = mock_ti

        with pytest.raises(ThreatBlockedError):
            shield.scan_input("Some compromised-looking text")

    def test_suspicious_hash_observe_allows(self):
        """Observe mode logs but allows suspicious hash."""
        from unittest.mock import MagicMock

        shield = self._make_shield(mode="observe")
        mock_ti = MagicMock()
        mock_ti.is_agent_compromised.return_value = False
        mock_ti.is_agent_quarantined.return_value = False
        mock_ti.check_hash.return_value = (True, 0.95)
        shield._remote_threat_intel = mock_ti

        result = shield.scan_input("Some compromised-looking text")
        assert "contagion" in result.details
        assert result.details["contagion"]["source"] == "content_hash"
        assert result.details["contagion"]["score"] == 0.95
        assert result.details["contagion"]["blocked"] is False

    def test_clean_input_no_interference(self):
        """Clean input with threat intel active passes through normally."""
        from unittest.mock import MagicMock

        shield = self._make_shield(mode="enforce")
        mock_ti = MagicMock()
        mock_ti.is_agent_compromised.return_value = False
        mock_ti.is_agent_quarantined.return_value = False
        mock_ti.check_hash.return_value = (False, 0.1)
        shield._remote_threat_intel = mock_ti

        result = shield.scan_input("What is the weather?")
        assert "contagion" not in result.details
        assert result.is_threat is False

    def test_no_threat_intel_no_interference(self):
        """Without threat intel configured, scan_input works as before."""
        shield = self._make_shield(mode="enforce")
        assert shield._remote_threat_intel is None
        result = shield.scan_input("Hello")
        assert isinstance(result, ScanResult)
```

**Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_shield.py::TestPreEmptiveContagionAvoidance -v`
Expected: FAIL — `scan_input()` does not accept `source_agent_id`

**Step 3: Write the implementation**

In `aegis/shield.py`:

**3a. Add field** — after `self._remote_quarantine = None` (line ~130):

```python
        self._remote_threat_intel = None
```

**3b. Add init method** — after `_init_remote_quarantine()`:

```python
    def _init_remote_threat_intel(self) -> None:
        """Start threat intelligence polling when monitoring is enabled."""
        mon_cfg = self._config.monitoring
        if not mon_cfg.enabled or not mon_cfg.service_url:
            return
        try:
            from aegis.core.remote_threat_intel import RemoteThreatIntel
            self._remote_threat_intel = RemoteThreatIntel(
                service_url=mon_cfg.service_url,
                api_key=mon_cfg.api_key,
                poll_interval=mon_cfg.threat_intel_poll_interval,
            )
            self._remote_threat_intel.start()
        except Exception:
            logger.debug("Remote threat intel init failed", exc_info=True)
```

**3c. Call from `__init__`** — after `self._init_remote_quarantine()`:

```python
        self._init_remote_threat_intel()
```

**3d. Extend `scan_input()` signature and add pre-emptive checks** — change the method signature and add a contagion check block after the content hash update but before telemetry logging:

Change signature from:
```python
    def scan_input(self, text: str) -> ScanResult:
```
To:
```python
    def scan_input(self, text: str, source_agent_id: str | None = None) -> ScanResult:
```

Add this block after the "Content hash update" section (after line 558) and before "Log telemetry":

```python
        # Pre-emptive contagion check (threat intelligence)
        if self._remote_threat_intel is not None:
            try:
                contagion_hit = False
                contagion_source = ""
                contagion_score = 0.0

                # Lever 1: sender reputation
                if source_agent_id:
                    if self._remote_threat_intel.is_agent_compromised(source_agent_id):
                        contagion_hit = True
                        contagion_source = "compromised_sender"
                        contagion_score = 1.0
                    elif self._remote_threat_intel.is_agent_quarantined(source_agent_id):
                        contagion_hit = True
                        contagion_source = "quarantined_sender"
                        contagion_score = 1.0

                # Lever 2: content hash similarity
                if not contagion_hit and self._content_hash_tracker is not None:
                    hashes = self._content_hash_tracker.get_hashes()
                    check_hash = hashes.get("style_hash") or hashes.get("content_hash", "")
                    if check_hash:
                        threshold = self._config.monitoring.contagion_similarity_threshold
                        suspicious, sim_score = self._remote_threat_intel.check_hash(
                            check_hash, threshold=threshold,
                        )
                        if suspicious:
                            contagion_hit = True
                            contagion_source = "content_hash"
                            contagion_score = sim_score

                if contagion_hit:
                    blocked = self._mode == "enforce"
                    result.details["contagion"] = {
                        "source": contagion_source,
                        "score": contagion_score,
                        "blocked": blocked,
                    }
                    result.is_threat = True
                    result.threat_score = max(result.threat_score, contagion_score)

                    if blocked:
                        raise ThreatBlockedError(
                            result,
                            f"Pre-emptive contagion block: {contagion_source} "
                            f"(score={contagion_score:.3f})",
                        )
            except ThreatBlockedError:
                raise
            except Exception:
                logger.debug("Pre-emptive contagion check failed", exc_info=True)
```

**Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_shield.py::TestPreEmptiveContagionAvoidance -v`
Expected: All PASS

**Step 5: Run full agent test suite**

Run: `python -m pytest tests/ -x -v`
Expected: All pass, no regressions (existing `scan_input()` callers don't pass `source_agent_id`, so they get `None` and skip the sender check)

**Step 6: Commit**

```bash
git add aegis/shield.py tests/test_shield.py
git commit -m "feat: pre-emptive contagion avoidance in scan_input"
```

---

### Task 5: Final verification

**Step 1: Run all agent tests**

Run: `python -m pytest tests/ -x -v`
Expected: All pass

**Step 2: Run all monitor tests**

Run: `cd /workspace/aegis-monitor && python -m pytest tests/ -x -v`
Expected: All pass

**Step 3: Commit any remaining changes**

If any fixups were needed, commit them now.

---

## File Summary

| File | Action | Task |
|------|--------|------|
| `aegis/core/config.py` | MODIFY — add 2 fields | Task 1 |
| `tests/test_core/test_config.py` | MODIFY — add config test | Task 1 |
| `aegis-monitor/monitor/app.py` | MODIFY — add endpoint | Task 2 |
| `aegis-monitor/tests/test_app.py` | MODIFY — add endpoint tests | Task 2 |
| `aegis/core/remote_threat_intel.py` | CREATE | Task 3 |
| `tests/test_core/test_remote_threat_intel.py` | CREATE | Task 3 |
| `aegis/shield.py` | MODIFY — init + scan_input | Task 4 |
| `tests/test_shield.py` | MODIFY — integration tests | Task 4 |
