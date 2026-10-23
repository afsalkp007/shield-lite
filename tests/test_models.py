"""Unit tests for Pydantic models in ShieldLite."""

import pytest
from shield_lite.models import (
    PIIEntity,
    PIIType,
    InjectionThreat,
    ThreatCategory,
    ThreatSeverity,
    PreFlightResult,
    GuardrailAuditReport,
)


def test_pii_entity_model():
    entity = PIIEntity(
        entity_type=PIIType.EMAIL,
        placeholder="[EMAIL_1]",
        original_value="user@example.com",
        start_idx=0,
        end_idx=16,
    )
    assert entity.entity_type == PIIType.EMAIL
    assert entity.placeholder == "[EMAIL_1]"


def test_guardrail_audit_report_defaults():
    pre = PreFlightResult(
        is_allowed=True,
        original_prompt="hello",
        sanitized_prompt="hello",
    )
    report = GuardrailAuditReport(
        is_safe=True,
        blocked=False,
        risk_score=0.0,
        original_prompt="hello",
        sanitized_prompt="hello",
        final_response="hi",
        pre_flight=pre,
    )
    assert report.is_safe is True
    assert report.blocked is False
    assert report.timestamp is not None
