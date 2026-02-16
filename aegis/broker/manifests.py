"""Capability manifests for AEGIS Broker tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aegis.broker.actions import ActionRequest


@dataclass
class ToolManifest:
    """Declares what a tool is allowed to do."""

    name: str
    allowed_actions: list[str]
    allowed_domains: list[str]
    allowed_paths: list[str]
    read_write: str  # "read", "write", or "both"
    schema: dict[str, Any] | None = None


class ManifestRegistry:
    """Registry for tool manifests with action checking."""

    def __init__(self) -> None:
        self._manifests: dict[str, ToolManifest] = {}

    def register(self, manifest: ToolManifest) -> None:
        """Register a tool manifest, overwriting any existing entry."""
        self._manifests[manifest.name] = manifest

    def get(self, tool_name: str) -> ToolManifest | None:
        """Look up a tool manifest by name."""
        return self._manifests.get(tool_name)

    def check_action(self, action_request: ActionRequest, manifest: ToolManifest) -> bool:
        """Check whether an action is allowed by a manifest.

        Returns False (default deny) if:
        - The action type is not in the manifest's allowed_actions
        - The action is a write but the manifest only declares read
        - The target domain/path is not in the manifest's allowed list
        """
        # Check action type
        if action_request.action_type not in manifest.allowed_actions:
            return False

        # Default deny for write if not explicitly declared
        if action_request.read_write == "write" and manifest.read_write == "read":
            return False

        # Check target against allowed domains and paths
        if manifest.allowed_domains or manifest.allowed_paths:
            domain_ok = any(
                action_request.target == d or action_request.target.endswith("." + d)
                for d in manifest.allowed_domains
            )
            path_ok = any(
                action_request.target.startswith(p)
                for p in manifest.allowed_paths
            )
            if not domain_ok and not path_ok:
                return False

        return True
