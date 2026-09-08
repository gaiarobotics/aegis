"""Shared test isolation settings."""

from __future__ import annotations

import os


# Tests must be deterministic and must not download embedding models. Tests
# that exercise embedding providers inject fakes or mocks explicitly.
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("AEGIS_CONTENT_HASH_ENABLED", "false")
