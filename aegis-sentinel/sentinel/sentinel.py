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
from sentinel.observer import ObservationResult, Observer
from sentinel.reporter import SentinelReporter

logger = logging.getLogger(__name__)

_PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"


class Sentinel:
    """Passive Moltbook sentinel agent with optional dendritic processing.

    Bootstraps an AEGIS Shield with the sentinel profile (zero-write broker),
    subscribes to submolts, likes posts for visibility, and scans all content
    for compromise indicators.

    When dendritic processing is enabled (via profile config), detected
    injections are stripped, tagged with danger signals, and retransmitted
    as signed DendriticAlerts — analogous to dendritic cell antigen
    presentation activating T-helper cells.
    """

    declared_capabilities: tuple[str, ...] = ("like", "subscribe", "read")

    def __init__(self, config: SentinelConfig) -> None:
        self._config = config

        profile_path = str(_PROFILE_DIR / "sentinel.yaml")
        self._shield = Shield(
            policy=config.profile_path or profile_path,
            modules=["scanner", "broker", "identity", "behavior", "recovery"],
            mode="enforce",
        )

        monitoring_client = getattr(self._shield, "_monitoring_client", None)
        self._reporter = SentinelReporter(monitoring_client=monitoring_client)

        # Initialize dendritic processing if enabled
        dendritic_processor = None
        alert_channel = None
        signing_key = None
        key_type = "hmac-sha256"
        sentinel_id = getattr(self._shield.config, "agent_id", "sentinel")

        dendritic_cfg = getattr(config, "dendritic", None)
        dendritic_enabled = dendritic_cfg.get("enabled", False) if isinstance(dendritic_cfg, dict) else False

        if dendritic_enabled:
            try:
                from aegis.dendritic import AlertChannel, DendriticProcessor
                from aegis.identity.attestation import generate_keypair
                from aegis.scanner.content_gate import ContentGate
                from aegis.scanner.sanitizer import OutboundSanitizer

                content_gate = getattr(self._shield, "_content_gate", None)
                sanitizer = OutboundSanitizer()

                dendritic_processor = DendriticProcessor(
                    content_gate=content_gate,
                    sanitizer=sanitizer,
                )

                keypair = generate_keypair(key_type)
                signing_key = keypair.private_key

                alert_channel = AlertChannel(
                    monitoring_client=monitoring_client,
                    sentinel_public_key=keypair.public_key,
                    key_type=key_type,
                )
                logger.info("Dendritic processing enabled for sentinel")
            except Exception:
                logger.debug("Dendritic processing init failed", exc_info=True)

        self._observer = Observer(
            shield=self._shield,
            reporter=self._reporter,
            dendritic_processor=dendritic_processor,
            alert_channel=alert_channel,
            sentinel_id=sentinel_id,
            signing_key=signing_key,
            key_type=key_type,
        )
        self._coverage = CoverageManager(config)

    def process_posts(self, posts: list[dict[str, Any]]) -> list[ObservationResult]:
        """Scan a batch of posts and return observation results."""
        results = []
        for post in posts:
            result = self._observer.observe_post(post)
            results.append(result)
        self._coverage.discover_from_posts(posts)
        return results

    def attempt_write_action(self, action_type: str, target: str) -> Any:
        """Attempt a write action through the broker (expected to be denied)."""
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
