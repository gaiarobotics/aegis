"""Capability manifests for AEGIS Broker tools."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

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

    def register(self, manifest: ToolManifest, *, overwrite: bool = False) -> None:
        """Register a tool manifest.

        Raises ``ValueError`` if *manifest.name* is already registered
        unless *overwrite* is ``True``.
        """
        if manifest.name in self._manifests and not overwrite:
            raise ValueError(
                f"Manifest already registered for tool: {manifest.name}"
            )
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
            # Extract hostname from URL targets for domain comparison
            parsed = urlparse(action_request.target)
            hostname = parsed.hostname or action_request.target

            domain_ok = any(
                hostname == d or hostname.endswith("." + d)
                for d in manifest.allowed_domains
            )

            # Use normpath + trailing separator for safe prefix matching
            norm_target = os.path.normpath(action_request.target)
            path_ok = any(
                norm_target == os.path.normpath(p)
                or norm_target.startswith(os.path.normpath(p) + os.sep)
                for p in manifest.allowed_paths
            )
            if not domain_ok and not path_ok:
                return False

        return True
