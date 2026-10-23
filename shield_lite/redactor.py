"""High-precision regex PII detection, masking, and bidirectional rehydration engine."""

import re
from typing import Tuple, List, Dict
from shield_lite.models import PIIEntity, PIIType


class PIIRedactor:
    """Detects sensitive personal data, replaces it with deterministic tokens, and rehydrates outputs."""

    # Pre-compiled high-precision regular expressions
    PATTERNS = [
        (
            PIIType.EMAIL,
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b", re.IGNORECASE),
        ),
        (
            PIIType.SSN,
            re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        ),
        (
            PIIType.CREDIT_CARD,
            re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:\d{4}[ -]?){3}\d{4})\b"),
        ),
        (
            PIIType.PHONE,
            re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        ),
        (
            PIIType.IPV4,
            re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
        ),
        (
            PIIType.API_KEY,
            re.compile(r"\b(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})\b"),
        ),
    ]

    def redact(self, text: str) -> Tuple[str, List[PIIEntity], Dict[str, str]]:
        """
        Scan text, replace sensitive entities with synthetic tokens, and return a vault mapping.
        
        Returns:
            sanitized_text: Text with sensitive entities masked (e.g. [EMAIL_1]).
            entities: List of PIIEntity metadata objects.
            vault: Dictionary mapping placeholder -> original sensitive value.
        """
        if not text:
            return "", [], {}

        entities: List[PIIEntity] = []
        vault: Dict[str, str] = {}
        reverse_vault: Dict[str, str] = {}  # original_value -> placeholder (for deduplication)

        counters: Dict[PIIType, int] = {t: 0 for t in PIIType}

        sanitized_text = text

        # Iterate over each PII type
        for pii_type, pattern in self.PATTERNS:
            matches = list(pattern.finditer(sanitized_text))
            if not matches:
                continue

            # Process matches in reverse order so character offsets remain valid
            for m in reversed(matches):
                val = m.group(0).strip()
                # Exclude obvious non-phone short numbers or fake matches
                if pii_type == PIIType.PHONE and (len(re.sub(r"\D", "", val)) < 10 or "/" in val):
                    continue

                if val in reverse_vault:
                    placeholder = reverse_vault[val]
                else:
                    counters[pii_type] += 1
                    placeholder = f"[{pii_type.value}_{counters[pii_type]}]"
                    reverse_vault[val] = placeholder
                    vault[placeholder] = val

                start, end = m.span()
                sanitized_text = sanitized_text[:start] + placeholder + sanitized_text[end:]

                entities.append(
                    PIIEntity(
                        entity_type=pii_type,
                        placeholder=placeholder,
                        original_value=val,
                        start_idx=start,
                        end_idx=start + len(placeholder),
                    )
                )

        # Sort entities by start_idx for clean reporting
        entities.sort(key=lambda e: e.start_idx)
        return sanitized_text, entities, vault

    @staticmethod
    def rehydrate(text: str, vault: Dict[str, str]) -> str:
        """Replace all synthetic placeholders in text with their original sensitive values."""
        if not text or not vault:
            return text

        rehydrated = text
        for placeholder, original in vault.items():
            rehydrated = rehydrated.replace(placeholder, original)
        return rehydrated
