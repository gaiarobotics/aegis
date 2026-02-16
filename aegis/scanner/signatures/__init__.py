"""AEGIS threat signature loading and management."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


@dataclass(frozen=True)
class Signature:
    """A single threat detection signature."""

    id: str
    category: str
    pattern: re.Pattern
    severity: float
    description: str
    raw_pattern: str


_BUNDLED_PATH = Path(__file__).parent / "default.yaml"


def load_signatures(
    use_bundled: bool = True,
    additional_files: Optional[list[str | Path]] = None,
) -> list[Signature]:
    """Load threat signatures from YAML files.

    Args:
        use_bundled: Whether to load the bundled default.yaml signatures.
        additional_files: Optional list of additional YAML file paths to load.

    Returns:
        List of compiled Signature objects.
    """
    raw_sigs: list[dict] = []

    if use_bundled:
        raw_sigs.extend(_load_yaml_signatures(_BUNDLED_PATH))

    if additional_files:
        for file_path in additional_files:
            raw_sigs.extend(_load_yaml_signatures(Path(file_path)))

    signatures: list[Signature] = []
    seen_ids: set[str] = set()

    for raw in raw_sigs:
        sig_id = raw["id"]
        if sig_id in seen_ids:
            continue
        seen_ids.add(sig_id)

        compiled = re.compile(raw["pattern"])
        signatures.append(
            Signature(
                id=sig_id,
                category=raw["category"],
                pattern=compiled,
                severity=float(raw["severity"]),
                description=raw["description"],
                raw_pattern=raw["pattern"],
            )
        )

    return signatures


def _load_yaml_signatures(path: Path) -> list[dict]:
    """Load raw signature dicts from a YAML file."""
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    return data.get("signatures", [])
