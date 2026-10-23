"""Guardrail pipeline orchestrator for pre-flight filtering, execution, and post-flight rehydration."""

import time
from typing import Optional
from shield_lite.models import PreFlightResult, GuardrailAuditReport
from shield_lite.redactor import PIIRedactor
from shield_lite.detector import InjectionDetector
from shield_lite.providers import BaseLLM, get_llm_provider


class PromptShield:
    """Pre-flight and post-flight guardrail pipeline for LLM interactions."""

    def __init__(
        self,
        redactor: Optional[PIIRedactor] = None,
        detector: Optional[InjectionDetector] = None,
        llm: Optional[BaseLLM] = None,
        auto_rehydrate: bool = True,
    ):
        self.redactor = redactor or PIIRedactor()
        self.detector = detector or InjectionDetector()
        self.llm = llm or get_llm_provider()
        self.auto_rehydrate = auto_rehydrate

    def pre_flight(self, prompt: str) -> PreFlightResult:
        """Scan prompt for injection threats, mask sensitive PII, and generate secure vault."""
        # 1. Threat Detection
        threats, risk_score, is_blocked = self.detector.scan(prompt)

        # 2. PII Redaction
        sanitized_prompt, pii_entities, vault = self.redactor.redact(prompt)

        return PreFlightResult(
            is_allowed=not is_blocked,
            risk_score=risk_score,
            original_prompt=prompt,
            sanitized_prompt=sanitized_prompt,
            detected_pii=pii_entities,
            threats=threats,
            vault=vault,
        )

    def execute(self, prompt: str) -> GuardrailAuditReport:
        """Run full end-to-end guardrail pipeline with timing and audit reporting."""
        start_time = time.time()
        pre = self.pre_flight(prompt)

        if not pre.is_allowed:
            elapsed_ms = round((time.time() - start_time) * 1000, 1)
            refusal_message = (
                "🛡️ [SHIELD_LITE SECURITY REFUSAL] Request blocked: Detected high-risk prompt injection "
                "or unauthorized system override signature. Execution halted before LLM invocation to protect system integrity."
            )
            return GuardrailAuditReport(
                is_safe=False,
                blocked=True,
                risk_score=pre.risk_score,
                original_prompt=prompt,
                sanitized_prompt=pre.sanitized_prompt,
                llm_raw_response=None,
                final_response=refusal_message,
                pii_entities=pre.detected_pii,
                threats=pre.threats,
                rehydrated=False,
                execution_latency_ms=elapsed_ms,
            )

        # Execute safe LLM call with sanitized prompt
        llm_raw = self.llm.generate(pre.sanitized_prompt)

        # Post-flight rehydration
        if self.auto_rehydrate and pre.vault:
            final_resp = PIIRedactor.rehydrate(llm_raw, pre.vault)
            rehydrated = True
        else:
            final_resp = llm_raw
            rehydrated = False

        elapsed_ms = round((time.time() - start_time) * 1000, 1)

        return GuardrailAuditReport(
            is_safe=True,
            blocked=False,
            risk_score=pre.risk_score,
            original_prompt=prompt,
            sanitized_prompt=pre.sanitized_prompt,
            llm_raw_response=llm_raw,
            final_response=final_resp,
            pii_entities=pre.detected_pii,
            threats=pre.threats,
            rehydrated=rehydrated,
            execution_latency_ms=elapsed_ms,
        )
