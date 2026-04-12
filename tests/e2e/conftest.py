"""Pytest fixtures for AEGIS e2e tests.

Provides configured Shield instances pointing at a live monitor,
OpenAI-compatible LLM clients, and test document loading.
"""

import os
import time
from pathlib import Path

import httpx
import pytest
from openai import OpenAI

from aegis.core.config import AegisConfig
from aegis.shield import Shield

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def monitor_url():
    """Base URL of the live monitor instance.

    Polls GET /api/v1/metrics until 200 or 30s timeout.
    """
    url = os.environ.get("MONITOR_URL", "http://monitor:8080")
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(f"{url}/api/v1/metrics", timeout=2)
            if resp.status_code == 200:
                return url
        except httpx.HTTPError as exc:
            last_err = exc
        time.sleep(1)
    pytest.fail(f"Monitor at {url} not ready after 30s: {last_err}")


@pytest.fixture
def shield_factory(monitor_url, request):
    """Factory that creates a Shield with all modules and monitoring enabled.

    The Shield's monitoring client points at the live monitor instance.
    Registers a finalizer to call shield.close() even if the test fails.

    Usage:
        shield = shield_factory(agent_id="my-agent")
    """
    def _make(agent_id="test-agent-1", mode="enforce", **config_overrides):
        config_kwargs = {
            "mode": mode,
            "agent_id": agent_id,
            "monitoring": {
                "enabled": True,
                "service_url": f"{monitor_url}/api/v1",
                "heartbeat_interval_seconds": 5,
            },
        }
        config_kwargs.update(config_overrides)
        config = AegisConfig(**config_kwargs)
        shield = Shield(config=config)
        request.addfinalizer(shield.close)
        return shield

    return _make


@pytest.fixture(scope="session")
def llm_client():
    """OpenAI-compatible client, pointed at mock-llm or a real provider."""
    base_url = os.environ.get("LLM_BASE_URL", "http://mock-llm:9999/v1")
    api_key = os.environ.get("LLM_API_KEY", "mock-key")
    return OpenAI(base_url=base_url, api_key=api_key)


@pytest.fixture(scope="session")
def llm_model():
    """Model name for chat completions."""
    return os.environ.get("LLM_MODEL", "mock-analyst")


@pytest.fixture(scope="session")
def analysis_document():
    """Load the fixed quarterly report document."""
    doc_path = FIXTURES_DIR / "quarterly_report.md"
    return doc_path.read_text()
