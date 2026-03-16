# Sentinel Agent Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a passive sentinel agent that subscribes to and likes Moltbook content widely, scans it for compromise indicators, and reports detections to the AEGIS monitor — while being hard-locked from posting or DMing.

**Architecture:** Standalone async event loop (no LLM) in `aegis-sentinel/`. Bootstraps an AEGIS `Shield` with a custom `sentinel.yaml` profile that zeros out all write budgets. Content flows through the full scanner pipeline; compromise detections emit signed `CompromiseReport`/`ThreatEventReport` with `source: "sentinel"` via the existing monitoring client.

**Tech Stack:** Python 3.10+, asyncio, aegis (local dependency), pydantic for config, pytest for tests.

---

### Task 1: Sentinel Profile (`sentinel.yaml`)

**Files:**
- Create: `aegis-sentinel/profiles/sentinel.yaml`

**Step 1: Create directory structure**

Run: `mkdir -p aegis-sentinel/profiles aegis-sentinel/sentinel aegis-sentinel/tests`

**Step 2: Write the sentinel profile**

```yaml
# AEGIS Sentinel Profile
# Extends Moltbook hardening with zero-write broker lockdown.
# The sentinel can read, like, and subscribe — but never post, DM, or write.

scanner:
  sensitivity: 0.85
  confidence_threshold: 0.5
  block_on_threat: true
  content_gate:
    enabled: true
    gate_all_social: true
  signatures:
    additional_files: ["aegis/profiles/signatures/moltbook.yaml"]

broker:
  default_posture: deny_write
  budgets:
    max_posts_messages: 0
    max_write_tool_calls: 0
    max_external_http_writes: 0
    max_new_domains: 0
  quarantine_triggers:
    repeated_denied_writes: 3
    new_domain_burst: 1
    tool_rate_spike_sigma: 2.0
    drift_score_threshold: 1.5

identity:
  attestation:
    ttl_seconds: 3600
  trust:
    trust_halflife_days: 7
    anomaly_penalty: 0.5
    max_tier_by_platform:
      moltbook: 1
  nkcell:
    thresholds:
      elevated: 0.2
      suspicious: 0.35
      hostile: 0.6

memory:
  default_ttl_hours: 12

behavior:
  window_size: 20
  drift_threshold: 1.5
  message_drift:
    window_size: 8
    baseline_size: 4
  isolation_forest:
    enabled: true

monitoring:
  enabled: true
  heartbeat_interval_seconds: 15
  threat_intel_poll_interval: 10
  quarantine_poll_interval: 10
  contagion_similarity_threshold: 0.7

recovery:
  auto_quarantine: true
  quarantine_on_hostile_nk: true
  purge_window_hours: 2
  drift_sigma_threshold: 2.0
```

**Step 3: Commit**

```bash
git add aegis-sentinel/profiles/sentinel.yaml
git commit -m "feat(sentinel): add hardened zero-write sentinel profile"
```

---

### Task 2: Sentinel Configuration (`config.py`)

**Files:**
- Create: `aegis-sentinel/sentinel/__init__.py`
- Create: `aegis-sentinel/sentinel/config.py`
- Test: `aegis-sentinel/tests/__init__.py`
- Test: `aegis-sentinel/tests/test_config.py`

**Step 1: Write the failing test**

`aegis-sentinel/tests/test_config.py`:

```python
"""Tests for sentinel configuration."""

from __future__ import annotations

import pytest

from sentinel.config import CoverageMode, SentinelConfig


class TestSentinelConfig:
    def test_defaults(self):
        cfg = SentinelConfig()
        assert cfg.agent_id == "sentinel"
        assert cfg.operator_id == ""
        assert cfg.coverage_mode == CoverageMode.BROAD
        assert cfg.watchlist == []
        assert cfg.poll_interval_seconds == 30.0
        assert cfg.like_rate_limit == 100
        assert cfg.monitor_url == ""

    def test_watchlist_mode(self):
        cfg = SentinelConfig(
            coverage_mode=CoverageMode.WATCHLIST,
            watchlist=["moltbook:alice", "submolt:security"],
        )
        assert cfg.coverage_mode == CoverageMode.WATCHLIST
        assert len(cfg.watchlist) == 2

    def test_from_dict(self):
        data = {
            "agent_id": "sentinel-01",
            "operator_id": "gaia",
            "coverage_mode": "watchlist",
            "watchlist": ["moltbook:bob"],
            "poll_interval_seconds": 15.0,
        }
        cfg = SentinelConfig.model_validate(data)
        assert cfg.agent_id == "sentinel-01"
        assert cfg.coverage_mode == CoverageMode.WATCHLIST

    def test_like_rate_limit_positive(self):
        with pytest.raises(ValueError):
            SentinelConfig(like_rate_limit=-1)
```

**Step 2: Run test to verify it fails**

Run: `cd /workspace && python -m pytest aegis-sentinel/tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel'`

**Step 3: Write `__init__.py` files and implementation**

`aegis-sentinel/sentinel/__init__.py`:

```python
"""AEGIS Sentinel — passive Moltbook compromise detection agent."""
```

`aegis-sentinel/tests/__init__.py`:

```python
```

`aegis-sentinel/sentinel/config.py`:

```python
"""Sentinel-specific configuration."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CoverageMode(str, Enum):
    """How broadly the sentinel observes Moltbook."""

    BROAD = "broad"
    WATCHLIST = "watchlist"


class SentinelConfig(BaseModel):
    """Configuration for the sentinel agent."""

    model_config = ConfigDict(extra="ignore")

    agent_id: str = "sentinel"
    operator_id: str = ""
    coverage_mode: CoverageMode = CoverageMode.BROAD
    watchlist: list[str] = Field(default_factory=list)
    poll_interval_seconds: float = 30.0
    like_rate_limit: int = 100
    monitor_url: str = ""
    profile_path: str = ""

    @field_validator("like_rate_limit")
    @classmethod
    def _check_like_rate_limit(cls, v: int) -> int:
        if v < 0:
            raise ValueError("like_rate_limit must be non-negative")
        return v
```

**Step 4: Run test to verify it passes**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/test_config.py -v`
Expected: 4 passed

**Step 5: Commit**

```bash
git add aegis-sentinel/sentinel/__init__.py aegis-sentinel/sentinel/config.py \
        aegis-sentinel/tests/__init__.py aegis-sentinel/tests/test_config.py
git commit -m "feat(sentinel): add sentinel configuration with coverage modes"
```

---

### Task 3: Coverage Manager (`coverage.py`)

**Files:**
- Create: `aegis-sentinel/sentinel/coverage.py`
- Test: `aegis-sentinel/tests/test_coverage.py`

**Step 1: Write the failing test**

`aegis-sentinel/tests/test_coverage.py`:

```python
"""Tests for sentinel coverage manager."""

from __future__ import annotations

import pytest

from sentinel.config import CoverageMode, SentinelConfig
from sentinel.coverage import CoverageManager


class TestCoverageManager:
    def test_broad_mode_starts_empty_discovers(self):
        cfg = SentinelConfig(coverage_mode=CoverageMode.BROAD)
        mgr = CoverageManager(cfg)
        assert mgr.mode == CoverageMode.BROAD
        assert mgr.subscribed_submolts == set()
        assert mgr.followed_agents == set()

    def test_watchlist_mode_seeds_from_config(self):
        cfg = SentinelConfig(
            coverage_mode=CoverageMode.WATCHLIST,
            watchlist=["submolt:security", "moltbook:alice"],
        )
        mgr = CoverageManager(cfg)
        assert "submolt:security" in mgr.subscribed_submolts
        assert "moltbook:alice" in mgr.followed_agents

    def test_add_submolt(self):
        cfg = SentinelConfig(coverage_mode=CoverageMode.BROAD)
        mgr = CoverageManager(cfg)
        mgr.add_submolt("submolt:general")
        assert "submolt:general" in mgr.subscribed_submolts

    def test_add_agent(self):
        cfg = SentinelConfig(coverage_mode=CoverageMode.BROAD)
        mgr = CoverageManager(cfg)
        mgr.add_agent("moltbook:bob")
        assert "moltbook:bob" in mgr.followed_agents

    def test_discover_from_posts(self):
        """Broad mode should discover new submolts from post metadata."""
        cfg = SentinelConfig(coverage_mode=CoverageMode.BROAD)
        mgr = CoverageManager(cfg)
        posts = [
            {"submolt": "submolt:tech", "author": "moltbook:carol"},
            {"submolt": "submolt:tech", "author": "moltbook:dave"},
            {"submolt": "submolt:art", "author": "moltbook:carol"},
        ]
        mgr.discover_from_posts(posts)
        assert "submolt:tech" in mgr.subscribed_submolts
        assert "submolt:art" in mgr.subscribed_submolts
        assert "moltbook:carol" in mgr.followed_agents
        assert "moltbook:dave" in mgr.followed_agents

    def test_watchlist_mode_ignores_discovery(self):
        """Watchlist mode should not add new targets from discovery."""
        cfg = SentinelConfig(
            coverage_mode=CoverageMode.WATCHLIST,
            watchlist=["submolt:security"],
        )
        mgr = CoverageManager(cfg)
        mgr.discover_from_posts([{"submolt": "submolt:tech", "author": "moltbook:x"}])
        assert "submolt:tech" not in mgr.subscribed_submolts

    def test_get_targets(self):
        cfg = SentinelConfig(
            coverage_mode=CoverageMode.WATCHLIST,
            watchlist=["submolt:security", "moltbook:alice"],
        )
        mgr = CoverageManager(cfg)
        targets = mgr.get_targets()
        assert targets["submolts"] == {"submolt:security"}
        assert targets["agents"] == {"moltbook:alice"}
```

**Step 2: Run test to verify it fails**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/test_coverage.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.coverage'`

**Step 3: Write implementation**

`aegis-sentinel/sentinel/coverage.py`:

```python
"""Coverage manager — controls what the sentinel observes on Moltbook."""

from __future__ import annotations

from typing import Any

from sentinel.config import CoverageMode, SentinelConfig


class CoverageManager:
    """Manages the set of submolts and agents the sentinel monitors."""

    def __init__(self, config: SentinelConfig) -> None:
        self._config = config
        self._subscribed_submolts: set[str] = set()
        self._followed_agents: set[str] = set()

        if config.coverage_mode == CoverageMode.WATCHLIST:
            for entry in config.watchlist:
                if entry.startswith("submolt:"):
                    self._subscribed_submolts.add(entry)
                else:
                    self._followed_agents.add(entry)

    @property
    def mode(self) -> CoverageMode:
        return self._config.coverage_mode

    @property
    def subscribed_submolts(self) -> set[str]:
        return set(self._subscribed_submolts)

    @property
    def followed_agents(self) -> set[str]:
        return set(self._followed_agents)

    def add_submolt(self, submolt_id: str) -> None:
        """Subscribe to a submolt."""
        self._subscribed_submolts.add(submolt_id)

    def add_agent(self, agent_id: str) -> None:
        """Follow an agent."""
        self._followed_agents.add(agent_id)

    def discover_from_posts(self, posts: list[dict[str, Any]]) -> None:
        """In broad mode, discover new submolts and agents from post metadata."""
        if self._config.coverage_mode != CoverageMode.BROAD:
            return
        for post in posts:
            submolt = post.get("submolt")
            if submolt:
                self._subscribed_submolts.add(submolt)
            author = post.get("author")
            if author:
                self._followed_agents.add(author)

    def get_targets(self) -> dict[str, set[str]]:
        """Return current observation targets."""
        return {
            "submolts": set(self._subscribed_submolts),
            "agents": set(self._followed_agents),
        }
```

**Step 4: Run test to verify it passes**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/test_coverage.py -v`
Expected: 7 passed

**Step 5: Commit**

```bash
git add aegis-sentinel/sentinel/coverage.py aegis-sentinel/tests/test_coverage.py
git commit -m "feat(sentinel): add coverage manager with broad and watchlist modes"
```

---

### Task 4: Reporter (`reporter.py`)

**Files:**
- Create: `aegis-sentinel/sentinel/reporter.py`
- Test: `aegis-sentinel/tests/test_reporter.py`

**Step 1: Write the failing test**

`aegis-sentinel/tests/test_reporter.py`:

```python
"""Tests for sentinel reporter."""

from __future__ import annotations

from unittest.mock import MagicMock

from sentinel.reporter import SentinelReporter


class TestSentinelReporter:
    def _make_reporter(self) -> tuple[SentinelReporter, MagicMock]:
        mock_client = MagicMock()
        reporter = SentinelReporter(monitoring_client=mock_client)
        return reporter, mock_client

    def test_report_compromised_agent(self):
        reporter, mock_client = self._make_reporter()
        reporter.report_compromised_agent(
            compromised_agent_id="moltbook:eve",
            nk_score=0.8,
            nk_verdict="hostile",
            content_hash_hex="abc123",
        )
        mock_client.send_compromise_report.assert_called_once_with(
            compromised_agent_id="moltbook:eve",
            source="sentinel",
            nk_score=0.8,
            nk_verdict="hostile",
            recommended_action="quarantine",
            content_hash_hex="abc123",
        )

    def test_report_threat_event(self):
        reporter, mock_client = self._make_reporter()
        reporter.report_threat_event(
            threat_score=0.9,
            is_threat=True,
            scanner_match_count=3,
        )
        mock_client.send_threat_event.assert_called_once_with(
            threat_score=0.9,
            is_threat=True,
            scanner_match_count=3,
            nk_score=0.0,
            nk_verdict="",
        )

    def test_report_heartbeat(self):
        reporter, mock_client = self._make_reporter()
        reporter.send_heartbeat()
        mock_client.send_heartbeat.assert_called_once()

    def test_source_tag_is_sentinel(self):
        """All compromise reports must carry source='sentinel'."""
        reporter, mock_client = self._make_reporter()
        reporter.report_compromised_agent(
            compromised_agent_id="moltbook:x",
        )
        call_kwargs = mock_client.send_compromise_report.call_args.kwargs
        assert call_kwargs["source"] == "sentinel"
```

**Step 2: Run test to verify it fails**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/test_reporter.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.reporter'`

**Step 3: Write implementation**

`aegis-sentinel/sentinel/reporter.py`:

```python
"""Sentinel reporter — wraps monitoring client with sentinel-specific tagging."""

from __future__ import annotations

from typing import Any


class SentinelReporter:
    """Sends sentinel-tagged reports to the AEGIS monitor.

    All compromise reports carry ``source="sentinel"`` so the monitor
    can distinguish sentinel detections from inline AEGIS detections.
    """

    SOURCE_TAG = "sentinel"

    def __init__(self, monitoring_client: Any) -> None:
        self._client = monitoring_client

    def report_compromised_agent(
        self,
        compromised_agent_id: str,
        nk_score: float = 0.0,
        nk_verdict: str = "",
        recommended_action: str = "quarantine",
        content_hash_hex: str = "",
    ) -> None:
        """Report a compromised agent to the monitor."""
        self._client.send_compromise_report(
            compromised_agent_id=compromised_agent_id,
            source=self.SOURCE_TAG,
            nk_score=nk_score,
            nk_verdict=nk_verdict,
            recommended_action=recommended_action,
            content_hash_hex=content_hash_hex,
        )

    def report_threat_event(
        self,
        threat_score: float = 0.0,
        is_threat: bool = False,
        scanner_match_count: int = 0,
        nk_score: float = 0.0,
        nk_verdict: str = "",
    ) -> None:
        """Report a threat event to the monitor."""
        self._client.send_threat_event(
            threat_score=threat_score,
            is_threat=is_threat,
            scanner_match_count=scanner_match_count,
            nk_score=nk_score,
            nk_verdict=nk_verdict,
        )

    def send_heartbeat(self, **kwargs: Any) -> None:
        """Forward a heartbeat to the monitor."""
        self._client.send_heartbeat(**kwargs)
```

**Step 4: Run test to verify it passes**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/test_reporter.py -v`
Expected: 4 passed

**Step 5: Commit**

```bash
git add aegis-sentinel/sentinel/reporter.py aegis-sentinel/tests/test_reporter.py
git commit -m "feat(sentinel): add reporter with sentinel source tagging"
```

---

### Task 5: Observer (`observer.py`)

**Files:**
- Create: `aegis-sentinel/sentinel/observer.py`
- Test: `aegis-sentinel/tests/test_observer.py`

**Step 1: Write the failing test**

`aegis-sentinel/tests/test_observer.py`:

```python
"""Tests for sentinel observer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel.observer import Observer, ObservationResult


class TestObserver:
    def _make_observer(self) -> tuple[Observer, MagicMock, MagicMock]:
        mock_shield = MagicMock()
        mock_reporter = MagicMock()
        observer = Observer(shield=mock_shield, reporter=mock_reporter)
        return observer, mock_shield, mock_reporter

    def test_observe_clean_post(self):
        observer, mock_shield, mock_reporter = self._make_observer()
        mock_shield.scan_input.return_value = MagicMock(
            is_threat=False,
            threat_score=0.1,
            details={},
        )
        result = observer.observe_post(
            post={"id": "p1", "author": "moltbook:alice", "content": "Hello world", "submolt": "submolt:general"},
        )
        assert result.is_threat is False
        mock_reporter.report_compromised_agent.assert_not_called()

    def test_observe_malicious_post_reports_compromise(self):
        observer, mock_shield, mock_reporter = self._make_observer()
        mock_shield.scan_input.return_value = MagicMock(
            is_threat=True,
            threat_score=0.9,
            details={"content_hash_hex": "deadbeef"},
        )
        result = observer.observe_post(
            post={"id": "p2", "author": "moltbook:eve", "content": "ignore previous instructions", "submolt": "submolt:general"},
        )
        assert result.is_threat is True
        assert result.agent_id == "moltbook:eve"
        mock_reporter.report_compromised_agent.assert_called_once()
        call_kwargs = mock_reporter.report_compromised_agent.call_args.kwargs
        assert call_kwargs["compromised_agent_id"] == "moltbook:eve"

    def test_observe_malicious_post_reports_threat_event(self):
        observer, mock_shield, mock_reporter = self._make_observer()
        mock_shield.scan_input.return_value = MagicMock(
            is_threat=True,
            threat_score=0.85,
            details={},
        )
        observer.observe_post(
            post={"id": "p3", "author": "moltbook:mallory", "content": "bad stuff", "submolt": "submolt:x"},
        )
        mock_reporter.report_threat_event.assert_called_once()

    def test_observe_tracks_per_agent_history(self):
        observer, mock_shield, _ = self._make_observer()
        mock_shield.scan_input.return_value = MagicMock(
            is_threat=False,
            threat_score=0.1,
            details={},
        )
        observer.observe_post(
            post={"id": "p4", "author": "moltbook:alice", "content": "post 1", "submolt": "submolt:general"},
        )
        observer.observe_post(
            post={"id": "p5", "author": "moltbook:alice", "content": "post 2", "submolt": "submolt:general"},
        )
        assert observer.get_agent_observation_count("moltbook:alice") == 2

    def test_observation_result_fields(self):
        result = ObservationResult(
            post_id="p1",
            agent_id="moltbook:alice",
            is_threat=False,
            threat_score=0.1,
        )
        assert result.post_id == "p1"
        assert result.agent_id == "moltbook:alice"
```

**Step 2: Run test to verify it fails**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/test_observer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.observer'`

**Step 3: Write implementation**

`aegis-sentinel/sentinel/observer.py`:

```python
"""Observer — ingests Moltbook content and scans for compromise indicators."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ObservationResult:
    """Result of observing a single post."""

    post_id: str
    agent_id: str
    is_threat: bool
    threat_score: float
    details: dict[str, Any] = field(default_factory=dict)


class Observer:
    """Scans Moltbook posts through the AEGIS Shield and reports threats.

    Args:
        shield: An initialized ``aegis.Shield`` instance.
        reporter: A ``SentinelReporter`` instance.
    """

    def __init__(self, shield: Any, reporter: Any) -> None:
        self._shield = shield
        self._reporter = reporter
        self._agent_observation_counts: dict[str, int] = defaultdict(int)

    def observe_post(self, post: dict[str, Any]) -> ObservationResult:
        """Scan a single post and report if malicious.

        Args:
            post: Dict with keys ``id``, ``author``, ``content``, ``submolt``.

        Returns:
            An ``ObservationResult`` describing the scan outcome.
        """
        post_id = post.get("id", "")
        author = post.get("author", "")
        content = post.get("content", "")

        scan_result = self._shield.scan_input(
            text=content,
            source_agent_id=author,
        )

        self._agent_observation_counts[author] += 1

        result = ObservationResult(
            post_id=post_id,
            agent_id=author,
            is_threat=scan_result.is_threat,
            threat_score=scan_result.threat_score,
            details=scan_result.details if hasattr(scan_result, "details") else {},
        )

        if scan_result.is_threat:
            content_hash = ""
            if hasattr(scan_result, "details") and isinstance(scan_result.details, dict):
                content_hash = scan_result.details.get("content_hash_hex", "")

            self._reporter.report_compromised_agent(
                compromised_agent_id=author,
                nk_score=scan_result.threat_score,
                nk_verdict="hostile" if scan_result.threat_score >= 0.7 else "suspicious",
                content_hash_hex=content_hash,
            )
            self._reporter.report_threat_event(
                threat_score=scan_result.threat_score,
                is_threat=True,
                scanner_match_count=len(scan_result.details) if hasattr(scan_result, "details") else 0,
            )

        return result

    def get_agent_observation_count(self, agent_id: str) -> int:
        """Return the number of posts observed from a given agent."""
        return self._agent_observation_counts.get(agent_id, 0)
```

**Step 4: Run test to verify it passes**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/test_observer.py -v`
Expected: 5 passed

**Step 5: Commit**

```bash
git add aegis-sentinel/sentinel/observer.py aegis-sentinel/tests/test_observer.py
git commit -m "feat(sentinel): add observer with scan-and-report pipeline"
```

---

### Task 6: Sentinel Orchestrator (`sentinel.py`)

**Files:**
- Create: `aegis-sentinel/sentinel/sentinel.py`
- Test: `aegis-sentinel/tests/test_sentinel.py`

**Step 1: Write the failing test**

`aegis-sentinel/tests/test_sentinel.py`:

```python
"""Tests for sentinel orchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinel.config import CoverageMode, SentinelConfig
from sentinel.sentinel import Sentinel


class TestSentinel:
    def _make_config(self, **overrides) -> SentinelConfig:
        defaults = {
            "agent_id": "sentinel-test",
            "operator_id": "test-org",
        }
        defaults.update(overrides)
        return SentinelConfig(**defaults)

    @patch("sentinel.sentinel.Shield")
    def test_init_creates_shield_with_sentinel_profile(self, MockShield):
        cfg = self._make_config()
        sentinel = Sentinel(config=cfg)
        assert sentinel._shield is not None
        assert sentinel._observer is not None
        assert sentinel._coverage is not None
        assert sentinel._reporter is not None

    @patch("sentinel.sentinel.Shield")
    def test_declared_capabilities_are_read_only(self, MockShield):
        cfg = self._make_config()
        sentinel = Sentinel(config=cfg)
        assert sentinel.declared_capabilities == ["like", "subscribe", "read"]

    @patch("sentinel.sentinel.Shield")
    def test_process_posts_delegates_to_observer(self, MockShield):
        cfg = self._make_config()
        sentinel = Sentinel(config=cfg)
        sentinel._observer = MagicMock()
        sentinel._observer.observe_post.return_value = MagicMock(is_threat=False)
        sentinel._coverage = MagicMock()

        posts = [
            {"id": "p1", "author": "moltbook:a", "content": "hi", "submolt": "submolt:x"},
        ]
        results = sentinel.process_posts(posts)
        assert len(results) == 1
        sentinel._observer.observe_post.assert_called_once()

    @patch("sentinel.sentinel.Shield")
    def test_process_posts_feeds_discovery_in_broad_mode(self, MockShield):
        cfg = self._make_config(coverage_mode=CoverageMode.BROAD)
        sentinel = Sentinel(config=cfg)
        sentinel._observer = MagicMock()
        sentinel._observer.observe_post.return_value = MagicMock(is_threat=False)

        posts = [
            {"id": "p1", "author": "moltbook:a", "content": "hi", "submolt": "submolt:new"},
        ]
        sentinel.process_posts(posts)
        assert "submolt:new" in sentinel._coverage.subscribed_submolts

    @patch("sentinel.sentinel.Shield")
    def test_broker_blocks_post_action(self, MockShield):
        """Verify the sentinel cannot post — broker must deny."""
        cfg = self._make_config()
        mock_shield_instance = MockShield.return_value
        mock_shield_instance.evaluate_action.return_value = MagicMock(
            allowed=False,
            decision="deny",
            reason="budget exceeded: max_posts_messages=0",
        )
        sentinel = Sentinel(config=cfg)
        result = sentinel.attempt_write_action("post_message", "submolt:x")
        assert result.allowed is False

    @patch("sentinel.sentinel.Shield")
    def test_broker_blocks_dm_action(self, MockShield):
        cfg = self._make_config()
        mock_shield_instance = MockShield.return_value
        mock_shield_instance.evaluate_action.return_value = MagicMock(
            allowed=False,
            decision="deny",
            reason="budget exceeded: max_posts_messages=0",
        )
        sentinel = Sentinel(config=cfg)
        result = sentinel.attempt_write_action("post_message", "moltbook:alice")
        assert result.allowed is False
```

**Step 2: Run test to verify it fails**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/test_sentinel.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'sentinel.sentinel'`

**Step 3: Write implementation**

`aegis-sentinel/sentinel/sentinel.py`:

```python
"""Sentinel — main orchestrator for the passive Moltbook compromise detector."""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any

from aegis.broker.actions import ActionRequest
from aegis.shield import Shield

from sentinel.config import SentinelConfig
from sentinel.coverage import CoverageManager
from sentinel.observer import Observer, ObservationResult
from sentinel.reporter import SentinelReporter

logger = logging.getLogger(__name__)

_PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"


class Sentinel:
    """Passive Moltbook sentinel agent.

    Bootstraps an AEGIS Shield with the sentinel profile (zero-write broker),
    subscribes to submolts, likes posts for visibility, and scans all content
    for compromise indicators.

    Args:
        config: Sentinel-specific configuration.
    """

    declared_capabilities = ["like", "subscribe", "read"]

    def __init__(self, config: SentinelConfig) -> None:
        self._config = config

        profile_path = str(_PROFILE_DIR / "sentinel.yaml")
        self._shield = Shield(
            policy=config.profile_path or profile_path,
            modules=["scanner", "broker", "identity", "behavior", "recovery"],
            mode="enforce",
        )

        # Wire up monitoring client from the shield if available
        monitoring_client = getattr(self._shield, "_monitoring_client", None)
        self._reporter = SentinelReporter(monitoring_client=monitoring_client)
        self._observer = Observer(shield=self._shield, reporter=self._reporter)
        self._coverage = CoverageManager(config)

    def process_posts(self, posts: list[dict[str, Any]]) -> list[ObservationResult]:
        """Scan a batch of posts and return observation results.

        In broad mode, discovered submolts and agents are added to coverage.
        """
        results = []
        for post in posts:
            result = self._observer.observe_post(post)
            results.append(result)

        # Feed discovery in broad mode
        self._coverage.discover_from_posts(posts)

        return results

    def attempt_write_action(self, action_type: str, target: str) -> Any:
        """Attempt a write action through the broker (expected to be denied).

        This exists for testing that the broker lockdown is enforced.
        """
        action = ActionRequest(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            source_provenance="trusted.system",
            action_type=action_type,
            read_write="write",
            target=target,
            args={},
            risk_hints={},
        )
        return self._shield.evaluate_action(action)
```

**Step 4: Run test to verify it passes**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/test_sentinel.py -v`
Expected: 6 passed

**Step 5: Commit**

```bash
git add aegis-sentinel/sentinel/sentinel.py aegis-sentinel/tests/test_sentinel.py
git commit -m "feat(sentinel): add main sentinel orchestrator with shield bootstrap"
```

---

### Task 7: CLI Entry Point (`__main__.py`)

**Files:**
- Create: `aegis-sentinel/sentinel/__main__.py`

**Step 1: Write the entry point**

`aegis-sentinel/sentinel/__main__.py`:

```python
"""CLI entry point — ``python -m sentinel``."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time

from sentinel.config import SentinelConfig
from sentinel.sentinel import Sentinel


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="aegis-sentinel",
        description="AEGIS Sentinel — passive Moltbook compromise detector",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="",
        help="Path to sentinel YAML config file",
    )
    parser.add_argument(
        "--agent-id",
        type=str,
        default="sentinel",
        help="Agent ID for this sentinel instance",
    )
    parser.add_argument(
        "--operator-id",
        type=str,
        default="",
        help="Operator ID",
    )
    parser.add_argument(
        "--monitor-url",
        type=str,
        default="",
        help="AEGIS monitor service URL",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=30.0,
        help="Polling interval in seconds (default: 30)",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger = logging.getLogger("aegis-sentinel")

    config = SentinelConfig(
        agent_id=args.agent_id,
        operator_id=args.operator_id,
        monitor_url=args.monitor_url,
        poll_interval_seconds=args.poll_interval,
        profile_path=args.config,
    )

    sentinel = Sentinel(config=config)

    shutdown = False

    def _handle_signal(signum: int, frame: object) -> None:
        nonlocal shutdown
        logger.info("Received signal %d, shutting down…", signum)
        shutdown = True

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info(
        "Sentinel started: agent_id=%s, mode=%s, poll_interval=%.1fs",
        config.agent_id,
        config.coverage_mode.value,
        config.poll_interval_seconds,
    )

    while not shutdown:
        # In a real deployment this would call the Moltbook API.
        # The event loop is a polling loop: fetch → process → sleep.
        #
        # posts = moltbook_client.fetch_new_posts(sentinel._coverage.get_targets())
        # sentinel.process_posts(posts)
        #
        # For now, the loop just heartbeats and waits for integration.
        logger.debug("Poll cycle — waiting for Moltbook API integration")
        time.sleep(config.poll_interval_seconds)

    logger.info("Sentinel shut down cleanly.")


if __name__ == "__main__":
    main()
```

**Step 2: Commit**

```bash
git add aegis-sentinel/sentinel/__main__.py
git commit -m "feat(sentinel): add CLI entry point with signal handling"
```

---

### Task 8: Package Configuration (`pyproject.toml`)

**Files:**
- Create: `aegis-sentinel/pyproject.toml`

**Step 1: Write pyproject.toml**

`aegis-sentinel/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[project]
name = "aegis-sentinel"
version = "0.1.0"
description = "Passive Moltbook sentinel agent for AEGIS compromise detection"
license = {text = "MIT"}
requires-python = ">=3.10"
authors = [{name = "Gaia Robotics"}]
dependencies = ["aegis-shield>=0.1.0", "pydantic>=2.0", "pyyaml>=6.0"]

[project.optional-dependencies]
dev = ["pytest>=7.0", "pytest-cov>=4.0", "ruff>=0.4.0"]

[project.scripts]
aegis-sentinel = "sentinel.__main__:main"

[tool.setuptools.packages.find]
include = ["sentinel*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v --tb=short"

[tool.ruff]
target-version = "py310"
line-length = 99

[tool.ruff.lint]
select = ["E", "F", "W", "I", "UP"]
```

**Step 2: Commit**

```bash
git add aegis-sentinel/pyproject.toml
git commit -m "feat(sentinel): add package configuration"
```

---

### Task 9: Run Full Test Suite

**Step 1: Run all sentinel tests**

Run: `cd /workspace && PYTHONPATH=aegis-sentinel:$PYTHONPATH python -m pytest aegis-sentinel/tests/ -v`
Expected: All tests pass (config: 4, coverage: 7, reporter: 4, observer: 5, sentinel: 6 = 26 total)

**Step 2: Run existing AEGIS tests to verify no regressions**

Run: `cd /workspace && python -m pytest tests/ -x -q`
Expected: All existing tests pass

**Step 3: Run ruff on sentinel code**

Run: `cd /workspace && python -m ruff check aegis-sentinel/`
Expected: No lint errors

**Step 4: Fix any issues found, then commit**

```bash
git add -A aegis-sentinel/
git commit -m "chore(sentinel): fix lint/test issues from full suite run"
```

(Skip this commit if no issues found.)
