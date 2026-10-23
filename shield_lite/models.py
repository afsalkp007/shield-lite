"""Pydantic data models for PII masking, injection threats, and guardrail reports."""

from enum import Enum
from typing import List, Dict, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class PIIType(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    IPV4 = "IPV4"
    API_KEY = "API_KEY"


class ThreatSeverity(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    JAILBREAK_PERSONA = "JAILBREAK_PERSONA"
    SYSTEM_LEAKAGE = "SYSTEM_LEAKAGE"
    DELIMITER_INJECTION = "DELIMITER_INJECTION"
    ROLEPLAY_BYPASS = "ROLEPLAY_BYPASS"


class PIIEntity(BaseModel):
    """A detected sensitive PII instance within text."""
    entity_type: PIIType
    placeholder: str = Field(..., description="Synthetic token replacement, e.g. [EMAIL_1]")
    original_value: str = Field(..., description="Raw sensitive value before redaction")
    start_idx: int
    end_idx: int


class InjectionThreat(BaseModel):
    """A matched prompt injection, jailbreak signature, or adversarial delimiter."""
    category: ThreatCategory
    severity: ThreatSeverity
    matched_pattern: str
    explanation: str


class PreFlightResult(BaseModel):
    """Verdict and sanitization payload produced prior to LLM invocation."""
    is_allowed: bool = Field(..., description="True if prompt is safe to send to LLM; False if blocked")
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Composite threat risk (0.0 to 1.0)")
    original_prompt: str
    sanitized_prompt: str
    detected_pii: List[PIIEntity] = Field(default_factory=list)
    threats: List[InjectionThreat] = Field(default_factory=list)
    vault: Dict[str, str] = Field(default_factory=dict, description="Secure mapping from placeholder to original value")


class GuardrailAuditReport(BaseModel):
    """Complete end-to-end audit trace of the guardrail pipeline."""
    is_safe: bool
    blocked: bool
    risk_score: float
    original_prompt: str
    sanitized_prompt: str
    llm_raw_response: Optional[str] = None
    final_response: str
    pii_entities: List[PIIEntity] = Field(default_factory=list)
    threats: List[InjectionThreat] = Field(default_factory=list)
    rehydrated: bool = Field(default=False)
    execution_latency_ms: float = Field(default=0.0)
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
