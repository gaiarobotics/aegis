"""AEGIS dendritic processing — antigen presentation analogue for prompt injection defense.

Sentinel agents detect injections, strip malicious payloads (proteolysis),
and retransmit cleaned fragments with danger signals (MHC-II presentation)
to activate human-in-the-loop escalation (T-cell co-stimulation).
"""

from aegis.dendritic.alert import DangerSignal, DendriticAlert, build_alert
from aegis.dendritic.channel import AlertChannel
from aegis.dendritic.processor import DendriticProcessor, DendriticResult

__all__ = [
    "DangerSignal",
    "DendriticAlert",
    "DendriticProcessor",
    "DendriticResult",
    "AlertChannel",
    "build_alert",
]
