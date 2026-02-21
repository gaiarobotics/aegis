"""Skill manifest loading and validation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SkillManifest:
    """Describes a skill's metadata, capabilities, and integrity information."""

    name: str
    version: str
    publisher: str
    hashes: dict[str, str]  # filename -> sha256
    signature: str | None
    capabilities: dict[str, Any]  # network, filesystem, tools, read_write
    secrets: list[str]
    budgets: dict | None
    sandbox: bool


@dataclass
class ValidationResult:
    """Result of manifest validation."""

    valid: bool
    errors: list[str] = field(default_factory=list)


def load_manifest(path: str | Path) -> SkillManifest:
    """Load a SkillManifest from a JSON file.

    Args:
        path: Path to the manifest JSON file.

    Returns:
        A SkillManifest populated from the file contents.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
        KeyError: If required fields are missing.
    """
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    return SkillManifest(
        name=data["name"],
        version=data["version"],
        publisher=data["publisher"],
        hashes=data.get("hashes", {}),
        signature=data.get("signature"),
        capabilities=data.get("capabilities", {}),
        secrets=data.get("secrets", []),
        budgets=data.get("budgets"),
        sandbox=data.get("sandbox", True),
    )


def validate_manifest(manifest: SkillManifest) -> ValidationResult:
    """Validate that a manifest has all required fields properly set.

    Checks:
    - name is non-empty
    - version is non-empty

    Args:
        manifest: The SkillManifest to validate.

    Returns:
        A ValidationResult indicating whether the manifest is valid.
    """
    errors: list[str] = []

    if not manifest.name:
        errors.append("Name must be non-empty")

    if not manifest.version:
        errors.append("Version must be non-empty")

    if not manifest.publisher:
        errors.append("Publisher must be non-empty")

    if not isinstance(manifest.hashes, dict) or not manifest.hashes:
        errors.append("Hashes must be a non-empty dict")

    if not isinstance(manifest.capabilities, dict):
        errors.append("Capabilities must be a dict")

    if not isinstance(manifest.sandbox, bool):
        errors.append("Sandbox must be a bool")

    return ValidationResult(
        valid=len(errors) == 0,
        errors=errors,
    )
