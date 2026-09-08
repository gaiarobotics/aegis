"""Shared monitor test isolation settings."""

from __future__ import annotations

import os


# Simulator tests use an injected deterministic provider when they exercise
# content hashing. Other tests must never download a model as a side effect.
os.environ.setdefault("AEGIS_SIM_DISABLE_EMBEDDINGS", "true")
