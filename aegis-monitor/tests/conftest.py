"""Shared test configuration for AEGIS monitor."""

import os

import pytest


def pytest_collection_modifyitems(config, items):
    """Skip ``@pytest.mark.postgres`` tests unless TEST_POSTGRES_URL is set."""
    if not os.environ.get("TEST_POSTGRES_URL"):
        skip_pg = pytest.mark.skip(reason="TEST_POSTGRES_URL not set")
        for item in items:
            if "postgres" in item.keywords:
                item.add_marker(skip_pg)
