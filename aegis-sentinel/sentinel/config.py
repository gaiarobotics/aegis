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
