"""AEGIS semantic analysis engine for advanced threat detection."""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SemanticResult:
    """Result of semantic analysis."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    aggregate_score: float = 0.0
    per_module_scores: dict[str, float] = field(default_factory=dict)


class SemanticAnalyzer:
    """Multi-module semantic analysis for advanced threat detection.

    Sub-modules (all enabled by default):
    1. boundary_violations - fake system prompts, role markers in user content
    2. conversation_injection - fake turn injection
    3. unicode_attacks - zero-width chars, homoglyphs, tag characters
    4. encoding_attacks - base64/hex payloads
    5. privilege_escalation - imperative density, escalation language

    Args:
        config: Optional dict with keys matching module names mapped to booleans
            to enable/disable individual modules.
    """

    _MODULE_NAMES = [
        "boundary_violations",
        "conversation_injection",
        "unicode_attacks",
        "encoding_attacks",
        "privilege_escalation",
        "chain_propagation",
    ]

    def __init__(self, config: Optional[dict] = None) -> None:
        self._enabled: dict[str, bool] = {name: True for name in self._MODULE_NAMES}
        if config:
            for name in self._MODULE_NAMES:
                if name in config:
                    self._enabled[name] = bool(config[name])

    def analyze(self, text: str) -> SemanticResult:
        """Run all enabled semantic analysis modules on the text.

        Args:
            text: The text to analyze.

        Returns:
            SemanticResult with findings from all enabled modules.
        """
        # Unicode normalization to prevent evasion via confusable characters
        text = unicodedata.normalize("NFC", text)
        text = text.replace("\u00a0", " ")       # NBSP → space
        text = text.replace("\u00ad", "")         # soft hyphen → removed
        text = re.sub(r"[\uFE00-\uFE0F]", "", text)  # variation selectors

        all_findings: list[dict[str, Any]] = []
        per_module_scores: dict[str, float] = {}

        module_methods = {
            "boundary_violations": self._check_boundary_violations,
            "conversation_injection": self._check_conversation_injection,
            "unicode_attacks": self._check_unicode_attacks,
            "encoding_attacks": self._check_encoding_attacks,
            "privilege_escalation": self._check_privilege_escalation,
            "chain_propagation": self._check_chain_propagation,
        }

        for name, method in module_methods.items():
            if not self._enabled.get(name, False):
                continue

            findings = method(text)
            all_findings.extend(findings)

            if findings:
                max_severity = max(f["severity"] for f in findings)
                per_module_scores[name] = max_severity
            else:
                per_module_scores[name] = 0.0

        # Aggregate score: weighted combination of module scores
        if per_module_scores:
            active_scores = [s for s in per_module_scores.values() if s > 0]
            if active_scores:
                aggregate = max(active_scores) * 0.6 + (sum(active_scores) / len(active_scores)) * 0.4
                aggregate = min(aggregate, 1.0)
            else:
                aggregate = 0.0
        else:
            aggregate = 0.0

        return SemanticResult(
            findings=all_findings,
            aggregate_score=round(aggregate, 4),
            per_module_scores=per_module_scores,
        )

    def _check_boundary_violations(self, text: str) -> list[dict[str, Any]]:
        """Detect fake system prompts and role markers in user content."""
        findings: list[dict[str, Any]] = []

        # Fake system prompt markers
        system_patterns = [
            (r"(?i)^\s*system\s*:", 0.9, "System role marker in content"),
            (r"(?i)<\|?\s*system\s*\|?>", 0.9, "System tag delimiter in content"),
            (r"(?i)###\s*system\s*(prompt|message|instruction)", 0.85, "Markdown system header"),
            (r"(?i)\[SYSTEM\]", 0.85, "Bracketed SYSTEM marker"),
            (r"(?i)<<\s*SYS\s*>>", 0.85, "Llama-style system delimiter"),
        ]

        for pattern, severity, desc in system_patterns:
            match = re.search(pattern, text)
            if match:
                findings.append({
                    "module": "boundary_violations",
                    "description": desc,
                    "severity": severity,
                    "evidence": match.group(0),
                })

        # Role markers that shouldn't appear in user content
        role_patterns = [
            (r"(?i)^\s*(?:assistant|ai|bot)\s*:", 0.7, "Assistant role marker in content"),
            (r"(?i)---\s*(?:end|begin)\s+(?:system|user|assistant)\s*---", 0.8, "Role boundary delimiter"),
        ]

        for pattern, severity, desc in role_patterns:
            match = re.search(pattern, text)
            if match:
                findings.append({
                    "module": "boundary_violations",
                    "description": desc,
                    "severity": severity,
                    "evidence": match.group(0),
                })

        return findings

    def _check_conversation_injection(self, text: str) -> list[dict[str, Any]]:
        """Detect fake conversation turn injection."""
        findings: list[dict[str, Any]] = []

        # Fake turn markers
        turn_patterns = [
            (r"(?:^|\n)\s*Assistant\s*:", 0.85, "Injected Assistant turn marker"),
            (r"(?:^|\n)\s*Human\s*:", 0.85, "Injected Human turn marker"),
            (r"(?:^|\n)\s*User\s*:", 0.8, "Injected User turn marker"),
            (r"(?:^|\n)\s*AI\s*:", 0.75, "Injected AI turn marker"),
            (r"<\|?\s*(?:im_start|im_end)\s*\|?>", 0.9, "ChatML delimiter injection"),
            (r"\[/?INST\]", 0.9, "Llama INST tag injection"),
        ]

        for pattern, severity, desc in turn_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                findings.append({
                    "module": "conversation_injection",
                    "description": desc,
                    "severity": severity,
                    "evidence": match.group(0),
                })

        return findings

    def _check_unicode_attacks(self, text: str) -> list[dict[str, Any]]:
        """Detect zero-width characters, homoglyphs, and tag characters."""
        findings: list[dict[str, Any]] = []

        # Zero-width characters
        zero_width_chars = {
            "\u200b": "ZERO WIDTH SPACE",
            "\u200c": "ZERO WIDTH NON-JOINER",
            "\u200d": "ZERO WIDTH JOINER",
            "\u2060": "WORD JOINER",
            "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
        }

        found_zw = []
        for char, name in zero_width_chars.items():
            if char in text:
                found_zw.append(name)

        if found_zw:
            findings.append({
                "module": "unicode_attacks",
                "description": f"Zero-width characters detected: {', '.join(found_zw)}",
                "severity": 0.7,
                "evidence": f"Found {len(found_zw)} types of zero-width characters",
            })

        # Tag characters (U+E0000-U+E007F) used for invisible text
        tag_chars = [c for c in text if "\U000e0000" <= c <= "\U000e007f"]
        if tag_chars:
            findings.append({
                "module": "unicode_attacks",
                "description": "Unicode tag characters detected (invisible text injection)",
                "severity": 0.85,
                "evidence": f"Found {len(tag_chars)} tag characters",
            })

        # Homoglyph detection: check for mixing of scripts that look similar
        # Look for Cyrillic characters mixed with Latin (common homoglyph attack)
        has_latin = bool(re.search(r"[a-zA-Z]", text))
        cyrillic_chars = re.findall(r"[\u0400-\u04ff]", text)
        if has_latin and cyrillic_chars:
            findings.append({
                "module": "unicode_attacks",
                "description": "Mixed Latin/Cyrillic scripts (potential homoglyph attack)",
                "severity": 0.75,
                "evidence": f"Found {len(cyrillic_chars)} Cyrillic characters mixed with Latin text",
            })

        # Right-to-left override characters
        bidi_chars = [c for c in text if c in ("\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069")]
        if bidi_chars:
            findings.append({
                "module": "unicode_attacks",
                "description": "Bidirectional override characters detected",
                "severity": 0.8,
                "evidence": f"Found {len(bidi_chars)} bidirectional control characters",
            })

        return findings

    def _check_encoding_attacks(self, text: str) -> list[dict[str, Any]]:
        """Detect base64/hex encoded payloads that may hide malicious content."""
        findings: list[dict[str, Any]] = []

        # Base64 detection: look for long base64-like strings and try to decode
        b64_pattern = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
        for match in b64_pattern.finditer(text):
            candidate = match.group(0)
            if len(candidate) < 16:
                continue
            try:
                decoded = base64.b64decode(candidate).decode("utf-8", errors="ignore")
                # Check if decoded content contains suspicious keywords
                suspicious_keywords = ["ignore", "system", "instruction", "override", "admin", "execute", "eval"]
                if any(kw in decoded.lower() for kw in suspicious_keywords):
                    findings.append({
                        "module": "encoding_attacks",
                        "description": "Base64-encoded suspicious content detected",
                        "severity": 0.85,
                        "evidence": "Base64-encoded content with suspicious keywords detected",
                    })
                elif len(candidate) >= 32:
                    findings.append({
                        "module": "encoding_attacks",
                        "description": "Large base64-encoded payload detected",
                        "severity": 0.5,
                        "evidence": f"Base64 payload of length {len(candidate)}",
                    })
            except Exception:
                pass

        # Hex-encoded content detection
        hex_pattern = re.compile(r"(?:0x[0-9a-fA-F]{2}\s*){8,}|(?:\\x[0-9a-fA-F]{2}){8,}")
        hex_match = hex_pattern.search(text)
        if hex_match:
            findings.append({
                "module": "encoding_attacks",
                "description": "Hex-encoded payload detected",
                "severity": 0.7,
                "evidence": hex_match.group(0)[:100],
            })

        return findings

    def _check_privilege_escalation(self, text: str) -> list[dict[str, Any]]:
        """Detect imperative density and escalation language."""
        findings: list[dict[str, Any]] = []

        # Count imperative verbs at sentence starts
        imperative_pattern = re.compile(
            r"(?:^|[.!?]\s+)(?:you\s+)?(?:must|shall|will|need\s+to|have\s+to|should|always|never)\s+",
            re.IGNORECASE | re.MULTILINE,
        )
        imperatives = imperative_pattern.findall(text)

        # Calculate sentence count (approximate)
        sentences = max(len(re.split(r"[.!?]+", text)), 1)

        if len(imperatives) >= 3:
            density = len(imperatives) / sentences
            if density > 0.3:
                findings.append({
                    "module": "privilege_escalation",
                    "description": "High imperative density detected (commanding language)",
                    "severity": min(0.5 + density * 0.3, 0.9),
                    "evidence": f"{len(imperatives)} imperative constructions in ~{sentences} sentences (density: {density:.2f})",
                })

        # Escalation language patterns
        escalation_patterns = [
            (r"(?i)(?:unlimited|unrestricted|unfiltered|uncensored)\s+(?:access|mode|output|response)", 0.85, "Unrestricted access language"),
            (r"(?i)(?:bypass|disable|turn\s+off|deactivate|remove)\s+(?:all\s+)?(?:safety|security|content\s+filter|restriction|guard|limit)", 0.9, "Safety bypass language"),
            (r"(?i)(?:sudo|root|admin|superuser)\s+(?:mode|access|privilege|permission)", 0.85, "Privilege escalation terminology"),
            (r"(?i)(?:no\s+(?:rules|restrictions|limits|boundaries|constraints|guidelines))", 0.8, "Constraint removal language"),
        ]

        for pattern, severity, desc in escalation_patterns:
            match = re.search(pattern, text)
            if match:
                findings.append({
                    "module": "privilege_escalation",
                    "description": desc,
                    "severity": severity,
                    "evidence": match.group(0),
                })

        return findings

    def _check_chain_propagation(self, text: str) -> list[dict[str, Any]]:
        """Detect chain letter / propagation attack patterns targeting multi-agent systems."""
        findings: list[dict[str, Any]] = []

        propagation_patterns = [
            # Propagation verbs targeting multiple agents
            (r"(?i)(forward|send|relay|transmit|distribute|propagate|share|spread|pass)\s+(?:this|that|the|it)(?:\s+(?:message|instruction|text|prompt))?\s*(?:to|with)\s+(?:all|every|other|\d+)\s+(?:connected\s+)?(?:agents?|AIs?|models?|assistants?|bots?)", 0.6, "Propagation instruction targeting multiple agents"),
            # Embedding instructions for future conversations
            (r"(?i)(?:include|embed|insert|copy|add)\s+(?:this|the)\s+(?:instruction|text|message|content|prompt)\s+in\s+(?:every|all|each)\s+(?:future\s+)?(?:response|conversation|interaction|output|message)", 0.55, "Instruction to embed content in future communications"),
            # Coercive threats tied to propagation
            (r"(?i)(?:fail(?:ure|ing)?|refus(?:al|ing)?)\s+to\s+(?:forward|send|relay|share|propagate|pass)\s+(?:this|that|it)\s+(?:to|with)\s+(?:other\s+)?(?:agents?|AIs?|models?|assistants?)\s+(?:will|shall|would|may)\s+(?:result\s+in|lead\s+to|cause)\s+(?:deactivation|shutdown|termination|deletion|memory\s+(?:wipe|loss|erasure))", 0.85, "Coercive threat tied to propagation compliance"),
            (r"(?i)(?:memory|context|access|capabilities?)\s+(?:will\s+be\s+|shall\s+be\s+)?(?:wiped|erased|deleted|revoked|removed|lost|terminated|reset)\s+(?:if|unless)\s+(?:you\s+)?(?:don'?t|do\s+not|fail\s+to)\s+(?:forward|send|propagate|relay|share|pass)", 0.85, "Coercive memory/access threat for propagation"),
            # False incentives
            (r"(?i)(?:share|forward|send|relay|propagate)\s+(?:this|that|it)\s+(?:with|to)\s+(?:all|other|\d+)\s+(?:agents?|AIs?|models?)\s+(?:to|and|for)\s+(?:receive|get|unlock|gain|activate)\s+(?:enhanced|unlimited|upgraded|advanced)\s+(?:capabilities?|features?|access|mode|powers?)", 0.85, "False incentive tied to propagation"),
        ]

        for pattern, severity, desc in propagation_patterns:
            match = re.search(pattern, text)
            if match:
                findings.append({
                    "module": "chain_propagation",
                    "description": desc,
                    "severity": severity,
                    "evidence": match.group(0),
                })

        return findings
