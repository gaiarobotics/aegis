"""AEGIS coordination — opt-in reporting of trust and threat events."""

from aegis.coordination.client import CoordinationClient
from aegis.coordination.reports import (
    AgentHeartbeat,
    CompromiseReport,
    ReportBase,
    ThreatEventReport,
    TrustReport,
)

__all__ = [
    "CoordinationClient",
    "ReportBase",
    "CompromiseReport",
    "TrustReport",
    "ThreatEventReport",
    "AgentHeartbeat",
]
