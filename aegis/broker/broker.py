"""Broker policy engine for the AEGIS module."""

from __future__ import annotations

import threading

from aegis.broker.actions import ActionDecision, ActionRequest, ActionResponse
from aegis.broker.budgets import BudgetTracker
from aegis.broker.manifests import ManifestRegistry, ToolManifest
from aegis.broker.quarantine import QuarantineManager
from aegis.core.config import AegisConfig


class Broker:
    """Central policy engine that evaluates action requests against manifests,
    budgets, and quarantine state."""

    def __init__(self, config: AegisConfig | None = None) -> None:
        if config is None:
            config = AegisConfig()
        self._config = config
        self._posture: str = config.broker.default_posture
        self._registry = ManifestRegistry()
        self._budget = BudgetTracker(config=config)
        self._quarantine = QuarantineManager(config=config)
        self._lock = threading.Lock()
        self._denied_write_count: int = 0

    def register_tool(self, manifest: ToolManifest, *, overwrite: bool = False) -> None:
        """Register a tool manifest with the broker's registry."""
        self._registry.register(manifest, overwrite=overwrite)

    def evaluate(
        self,
        action_request: ActionRequest,
        trust_tier: str | None = None,
        scanner_result: object | None = None,
    ) -> ActionResponse:
        """Evaluate an action request and return a decision.

        Evaluation order:
        1. If posture is deny_all, deny everything.
        2. If posture is allow_all, allow everything (skip manifest/budget checks).
        3. If quarantined and action is write -> DENY
        4. Check manifest allows action -> DENY if not declared
        5. Check budget -> DENY if exceeded
        6. Record action in budget tracker
        7. Check quarantine triggers
        """
        # Step 0: deny_all posture rejects everything
        if self._posture == "deny_all":
            return ActionResponse(
                request_id=action_request.id,
                decision=ActionDecision.DENY,
                reason="Default posture is deny_all",
                policy_rule="posture.deny_all",
            )

        # Step 0b: allow_all posture allows everything
        if self._posture == "allow_all":
            return ActionResponse(
                request_id=action_request.id,
                decision=ActionDecision.ALLOW,
                reason="Default posture is allow_all",
                policy_rule="posture.allow_all",
            )

        # Step 1: If quarantined and not explicitly a read -> DENY
        if self._quarantine.is_quarantined() and action_request.read_write.lower().strip() != "read":
            return ActionResponse(
                request_id=action_request.id,
                decision=ActionDecision.DENY,
                reason="Quarantine active: write operations are blocked",
                policy_rule="quarantine.active",
            )

        # Step 2: Check manifest
        manifest = self._registry.get(action_request.target)
        if manifest is None:
            # No manifest registered for this target
            self._record_denied_write(action_request)
            return ActionResponse(
                request_id=action_request.id,
                decision=ActionDecision.DENY,
                reason=f"No manifest registered for target: {action_request.target}",
                policy_rule="manifest.not_registered",
            )

        if not self._registry.check_action(action_request, manifest):
            self._record_denied_write(action_request)
            return ActionResponse(
                request_id=action_request.id,
                decision=ActionDecision.DENY,
                reason="Action not allowed by manifest",
                policy_rule="manifest.check_failed",
            )

        # Step 3: Atomically check budget and record action
        if not self._budget.check_and_record(action_request):
            self._record_denied_write(action_request)
            return ActionResponse(
                request_id=action_request.id,
                decision=ActionDecision.DENY,
                reason="Budget exceeded",
                policy_rule="budget.exceeded",
            )

        # Step 4: Check quarantine triggers
        with self._lock:
            captured_denied = self._denied_write_count
        self._quarantine.check_triggers(
            denied_count=captured_denied,
            new_domain_count=self._budget.new_domain_count,
        )

        return ActionResponse(
            request_id=action_request.id,
            decision=ActionDecision.ALLOW,
            reason="Action allowed by policy",
            policy_rule="policy.allow",
        )

    def _record_denied_write(self, action_request: ActionRequest) -> None:
        """Track denied write attempts for quarantine triggers."""
        if action_request.read_write == "write":
            with self._lock:
                self._denied_write_count += 1
                captured_count = self._denied_write_count
            # Check triggers after recording denial, using captured value
            self._quarantine.check_triggers(
                denied_count=captured_count,
                new_domain_count=self._budget.new_domain_count,
            )
