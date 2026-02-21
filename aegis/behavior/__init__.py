"""AEGIS Behavior module — tracking and drift detection."""

from aegis.behavior.drift import DriftDetector, DriftResult
from aegis.behavior.message_drift import MessageDriftDetector, MessageProfile
from aegis.behavior.prompt_monitor import PromptMonitor
from aegis.behavior.tracker import BehaviorEvent, BehaviorFingerprint, BehaviorTracker

__all__ = [
    "BehaviorEvent",
    "BehaviorFingerprint",
    "BehaviorTracker",
    "DriftDetector",
    "DriftResult",
    "MessageDriftDetector",
    "MessageProfile",
    "PromptMonitor",
]
