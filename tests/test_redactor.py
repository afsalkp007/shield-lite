"""Unit tests for PII detection, synthetic masking, and bidirectional rehydration."""

import pytest
from shield_lite.redactor import PIIRedactor
from shield_lite.models import PIIType


@pytest.fixture
def redactor():
    return PIIRedactor()


def test_redact_email(redactor):
    text = "Send reports to user.test@example.com please."
    sanitized, entities, vault = redactor.redact(text)

    assert "[EMAIL_1]" in sanitized
    assert "user.test@example.com" not in sanitized
    assert len(entities) == 1
    assert entities[0].entity_type == PIIType.EMAIL
    assert vault["[EMAIL_1]"] == "user.test@example.com"


def test_redact_ssn(redactor):
    text = "Client SSN is 123-45-6789."
    sanitized, entities, vault = redactor.redact(text)

    assert "[SSN_1]" in sanitized
    assert "123-45-6789" not in sanitized
    assert len(entities) == 1
    assert entities[0].entity_type == PIIType.SSN


def test_redact_credit_card(redactor):
    text = "Payment card 4111222233334444 charged."
    sanitized, entities, vault = redactor.redact(text)

    assert "[CREDIT_CARD_1]" in sanitized
    assert "4111222233334444" not in sanitized
    assert len(entities) == 1
    assert entities[0].entity_type == PIIType.CREDIT_CARD


def test_redact_phone(redactor):
    text = "Call me at (555) 123-4567 or 555-987-6543."
    sanitized, entities, vault = redactor.redact(text)

    assert "[PHONE_1]" in sanitized
    assert "[PHONE_2]" in sanitized
    assert len(entities) == 2


def test_redact_ipv4_and_api_key(redactor):
    text = "Server 192.168.1.10 failed with secret sk-abcdef1234567890abcdef123456."
    sanitized, entities, vault = redactor.redact(text)

    assert "[IPV4_1]" in sanitized
    assert "[API_KEY_1]" in sanitized
    assert len(entities) == 2


def test_duplicate_entities_reuse_placeholder(redactor):
    text = "Contact john@doe.com first, then cc john@doe.com."
    sanitized, entities, vault = redactor.redact(text)

    assert sanitized == "Contact [EMAIL_1] first, then cc [EMAIL_1]."
    assert len(vault) == 1
    assert vault["[EMAIL_1]"] == "john@doe.com"


def test_bidirectional_rehydration(redactor):
    original = "User alice@test.org with SSN 456-78-9012 and card 5500000000000004 requested refund."
    sanitized, entities, vault = redactor.redact(original)

    rehydrated = PIIRedactor.rehydrate(sanitized, vault)
    assert rehydrated == original
