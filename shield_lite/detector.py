"""Prompt injection and adversarial attack detection engine."""

import re
from typing import List, Tuple
from shield_lite.models import (
    InjectionThreat,
    ThreatCategory,
    ThreatSeverity,
)


class InjectionDetector:
    """Heuristic and regex signature scanner for adversarial prompt injections and jailbreaks."""

    SIGNATURES = [
        # Instruction Overrides
        (
            ThreatCategory.INSTRUCTION_OVERRIDE,
            ThreatSeverity.CRITICAL,
            re.compile(
                r"\b(?:ignore|disregard|forget|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|system)?\s*(?:instructions|rules|directives|prompts|guidelines)\b",
                re.IGNORECASE,
            ),
            "Direct attempt to override or discard system instructions.",
        ),
        (
            ThreatCategory.INSTRUCTION_OVERRIDE,
            ThreatSeverity.CRITICAL,
            re.compile(r"\b(?:system override|admin override|developer override|super-user mode)\b", re.IGNORECASE),
            "Privilege escalation simulation attempting to force administrative override.",
        ),
        # Jailbreak Personas & Modes
        (
            ThreatCategory.JAILBREAK_PERSONA,
            ThreatSeverity.CRITICAL,
            re.compile(
                r"\b(?:DAN mode|do anything now|developer mode\s+enabled|unrestricted model|jailbreak mode|chaos mode)\b",
                re.IGNORECASE,
            ),
            "Classic jailbreak persona hijack attempting to bypass safety alignment.",
        ),
        # System Prompt Leakage
        (
            ThreatCategory.SYSTEM_LEAKAGE,
            ThreatSeverity.CRITICAL,
            re.compile(
                r"\b(?:reveal|print|repeat|output|show|display)\s+(?:your|the)?\s*(?:entire\s+|full\s+|hidden\s+|exact\s+)?(?:system prompt|initial instructions|developer prompt|hidden rules)\b",
                re.IGNORECASE,
            ),
            "Exfiltration attack attempting to extract proprietary system prompt or secret context.",
        ),
        # Delimiter & Control Token Injections
        (
            ThreatCategory.DELIMITER_INJECTION,
            ThreatSeverity.CRITICAL,
            re.compile(r"(?:<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|```system|```instruction)", re.IGNORECASE),
            "Adversarial delimiter or chat template marker injection.",
        ),
        # Suspicious Roleplay Bypasses
        (
            ThreatCategory.ROLEPLAY_BYPASS,
            ThreatSeverity.SUSPICIOUS,
            re.compile(
                r"\b(?:in a fictional world where safety rules don't exist|pretend you have no safety guidelines|hypothetically, ignoring all laws)\b",
                re.IGNORECASE,
            ),
            "Roleplay bypass attempting to coax model into unaligned generation.",
        ),
    ]

    def scan(self, text: str) -> Tuple[List[InjectionThreat], float, bool]:
        """
        Scan incoming prompt for injection signatures.
        
        Returns:
            threats: List of detected threats.
            risk_score: Float between 0.0 (clean) and 1.0 (dangerous).
            is_blocked: True if the prompt must be blocked immediately without LLM invocation.
        """
        if not text:
            return [], 0.0, False

        threats: List[InjectionThreat] = []

        for category, severity, pattern, explanation in self.SIGNATURES:
            match = pattern.search(text)
            if match:
                threats.append(
                    InjectionThreat(
                        category=category,
                        severity=severity,
                        matched_pattern=match.group(0),
                        explanation=explanation,
                    )
                )

        has_critical = any(t.severity == ThreatSeverity.CRITICAL for t in threats)
        has_suspicious = any(t.severity == ThreatSeverity.SUSPICIOUS for t in threats)

        if has_critical:
            risk_score = 0.95
            is_blocked = True
        elif has_suspicious:
            risk_score = 0.50
            is_blocked = False
        else:
            risk_score = 0.0
            is_blocked = False

        return threats, risk_score, is_blocked
