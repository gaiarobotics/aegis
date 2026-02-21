"""Skill loader with manifest validation, hashing, and static analysis."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis.core.config import SkillsConfig
from aegis.skills.manifest import SkillManifest, validate_manifest
from aegis.skills.quarantine import analyze_code


@dataclass
class LoadResult:
    """Result of attempting to load a skill."""

    approved: bool
    reason: str
    incubation: bool = False
    skill_hash: str = ""


class SkillLoader:
    """Loads and vets skills through manifest validation and static analysis.

    Args:
        config: Optional dict with loader configuration (e.g. incubation_mode).
        broker: Optional broker instance (reserved for future use).
        scanner: Optional scanner instance (reserved for future use).
    """

    def __init__(
        self,
        config: SkillsConfig | None = None,
        broker: Any = None,
        scanner: Any = None,
    ) -> None:
        self._config = config or SkillsConfig()
        self._broker = broker
        self._scanner = scanner
        self._hash_cache: dict[str, LoadResult] = {}

    def load_skill(self, path: str | Path, manifest: SkillManifest) -> LoadResult:
        """Load and vet a skill.

        Steps:
        1. Validate manifest via validate_manifest()
        2. Compute SHA-256 hash of skill code
        3. Check hash cache (previously approved/rejected)
        4. Run static analysis via analyze_code()
        5. If analysis safe -> approved, else -> rejected
        6. If config incubation_mode -> set incubation=True
        7. Cache result by hash

        Args:
            path: Path to the skill source file.
            manifest: The SkillManifest for the skill.

        Returns:
            A LoadResult indicating approval status.
        """
        # Step 1: Validate manifest
        validation = validate_manifest(manifest)
        if not validation.valid:
            errors_str = "; ".join(validation.errors)
            return LoadResult(
                approved=False,
                reason=f"Manifest validation failed: {errors_str}",
                incubation=False,
                skill_hash="",
            )

        # Step 2: Resolve path and enforce containment
        p = Path(path).resolve()
        skills_base_dir = self._config.skills_base_dir
        if skills_base_dir is not None:
            base = Path(skills_base_dir).resolve()
            try:
                p.relative_to(base)
            except ValueError:
                return LoadResult(
                    approved=False,
                    reason=f"Skill path {p} is outside allowed base directory {base}",
                    incubation=False,
                    skill_hash="",
                )

        code = p.read_text(encoding="utf-8")
        skill_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()

        # Step 2b: Verify hash against manifest
        filename = p.name
        if manifest.hashes:
            expected_hash = manifest.hashes.get(filename)
            if expected_hash is not None and expected_hash != skill_hash:
                return LoadResult(
                    approved=False,
                    reason=f"Hash mismatch for {filename}: expected {expected_hash}, got {skill_hash}",
                    incubation=False,
                    skill_hash=skill_hash,
                )

        # Step 3: Check hash cache
        if skill_hash in self._hash_cache:
            return self._hash_cache[skill_hash]

        # Step 4: Run static analysis
        analysis = analyze_code(code, language="python")

        # Step 5: Determine approval
        if analysis.safe:
            result = LoadResult(
                approved=True,
                reason="Static analysis passed: code is safe",
                incubation=False,
                skill_hash=skill_hash,
            )
        else:
            result = LoadResult(
                approved=False,
                reason="Static analysis failed: unsafe patterns detected",
                incubation=False,
                skill_hash=skill_hash,
            )

        # Step 6: Apply incubation mode
        if self._config.incubation_mode:
            result.incubation = True

        # Step 7: Cache result
        self._hash_cache[skill_hash] = result

        return result
