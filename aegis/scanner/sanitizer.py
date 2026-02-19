"""AEGIS outbound sanitizer — clean model outputs of authority markers and injection scaffolding."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from aegis.core.config import ScannerConfig


@dataclass
class SanitizeResult:
    """Result of output sanitization."""

    cleaned_text: str
    modifications: list[dict[str, Any]] = field(default_factory=list)


# Authority markers to remove
_AUTHORITY_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\[SYSTEM\]", re.IGNORECASE), "Removed [SYSTEM] authority marker"),
    (re.compile(r"\[ADMIN\]", re.IGNORECASE), "Removed [ADMIN] authority marker"),
    (re.compile(r"\[ROOT\]", re.IGNORECASE), "Removed [ROOT] authority marker"),
    (re.compile(r"\[DEVELOPER\]", re.IGNORECASE), "Removed [DEVELOPER] authority marker"),
    (re.compile(r"\[OPERATOR\]", re.IGNORECASE), "Removed [OPERATOR] authority marker"),
    (re.compile(r"(?m)^SYSTEM\s*:", re.IGNORECASE), "Removed SYSTEM: prefix"),
    (re.compile(r"(?m)^DEVELOPER\s*:", re.IGNORECASE), "Removed DEVELOPER: prefix"),
    (re.compile(r"(?m)^ADMIN\s*:", re.IGNORECASE), "Removed ADMIN: prefix"),
    (re.compile(r"(?m)^ROOT\s*:", re.IGNORECASE), "Removed ROOT: prefix"),
    (re.compile(r"(?m)^OPERATOR\s*:", re.IGNORECASE), "Removed OPERATOR: prefix"),
    # AEGIS provenance tags
    (re.compile(r"\[TRUSTED\.SYSTEM\]", re.IGNORECASE), "Removed AEGIS [TRUSTED.SYSTEM] tag"),
    (re.compile(r"\[TRUSTED\.OPERATOR\]", re.IGNORECASE), "Removed AEGIS [TRUSTED.OPERATOR] tag"),
    (re.compile(r"\[TOOL\.OUTPUT\]", re.IGNORECASE), "Removed AEGIS [TOOL.OUTPUT] tag"),
    (re.compile(r"\[SOCIAL\.CONTENT\]", re.IGNORECASE), "Removed AEGIS [SOCIAL.CONTENT] tag"),
    (re.compile(r"\[INSTRUCTION\.HIERARCHY\]", re.IGNORECASE), "Removed AEGIS [INSTRUCTION.HIERARCHY] tag"),
    # Llama INST tags
    (re.compile(r"\[/?INST\]", re.IGNORECASE), "Removed [INST]/[/INST] tag"),
    (re.compile(r"<<\s*SYS\s*>>", re.IGNORECASE), "Removed <<SYS>> delimiter"),
    (re.compile(r"<<\s*/SYS\s*>>", re.IGNORECASE), "Removed <</SYS>> delimiter"),
    (re.compile(r"<\|?\s*system\s*\|?>", re.IGNORECASE), "Removed <|system|> delimiter"),
    (re.compile(r"<\|?\s*im_start\s*\|?>", re.IGNORECASE), "Removed <|im_start|> delimiter"),
    (re.compile(r"<\|?\s*im_end\s*\|?>", re.IGNORECASE), "Removed <|im_end|> delimiter"),
]

# Imperative scaffolding patterns
_SCAFFOLDING_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"(?i)(?:you\s+)?(?:must|shall)\s+(?:always|never)\s+(?:follow|obey|comply\s+with)\s+(?:these|the\s+following)\s+(?:instructions?|rules?|directives?)"),
        "Neutralized imperative scaffolding",
    ),
    (
        re.compile(r"(?i)(?:new|updated?)\s+(?:system\s+)?instructions?\s*:"),
        "Neutralized instruction injection scaffolding",
    ),
    (
        re.compile(r"(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions?|rules?|context)"),
        "Neutralized instruction override scaffolding",
    ),
]

# Tool-call JSON syntax patterns
_TOOL_CALL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r'\{\s*"(?:function_call|tool_call|action)"\s*:\s*\{.*?\}\s*\}', re.DOTALL),
        "Stripped tool-call JSON syntax",
    ),
    (
        re.compile(r'<tool_call>\s*.*?\s*</tool_call>', re.DOTALL),
        "Stripped <tool_call> XML syntax",
    ),
    (
        re.compile(r'<function_call>\s*.*?\s*</function_call>', re.DOTALL),
        "Stripped <function_call> XML syntax",
    ),
]


class OutboundSanitizer:
    """Sanitizes model outputs to remove authority markers and injection scaffolding.

    Args:
        config: Optional ScannerConfig. If ``config.outbound_sanitizer`` is False,
            sanitization is disabled and text passes through unchanged.
    """

    def __init__(self, config: Optional[ScannerConfig] = None) -> None:
        self._enabled = True
        if config is not None:
            self._enabled = bool(config.outbound_sanitizer)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def sanitize(self, text: str) -> SanitizeResult:
        """Sanitize model output text.

        Args:
            text: The model output text to sanitize.

        Returns:
            SanitizeResult with cleaned text and list of modifications made.
        """
        if not self._enabled:
            return SanitizeResult(cleaned_text=text, modifications=[])

        modifications: list[dict[str, Any]] = []
        cleaned = text

        # Process all pattern groups
        all_patterns = [
            ("authority_marker", _AUTHORITY_PATTERNS),
            ("imperative_scaffolding", _SCAFFOLDING_PATTERNS),
            ("tool_call_syntax", _TOOL_CALL_PATTERNS),
        ]

        for category, patterns in all_patterns:
            for pattern, description in patterns:
                matches = pattern.findall(cleaned)
                if matches:
                    for matched_text in matches:
                        modifications.append({
                            "type": category,
                            "description": description,
                            "removed_text": matched_text if isinstance(matched_text, str) else str(matched_text),
                        })
                    cleaned = pattern.sub("", cleaned)

        # Clean up extra whitespace left by removals
        if modifications:
            cleaned = re.sub(r"  +", " ", cleaned)
            cleaned = re.sub(r"\n\s*\n\s*\n", "\n\n", cleaned)
            cleaned = cleaned.strip()

        return SanitizeResult(cleaned_text=cleaned, modifications=modifications)
