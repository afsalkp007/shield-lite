"""LLM execution providers with sanitized prompt handling and zero-crash mock fallback."""

import os
import logging
from abc import ABC, abstractmethod
from typing import Optional
import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class BaseLLM(ABC):
    """Abstract interface for LLM completion."""

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Execute sanitized prompt and return model response."""
        pass


class GeminiProvider(BaseLLM):
    """Google Gemini 2.5 Flash execution provider."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-flash"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY is not set.")

    def generate(self, prompt: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2},
        }

        resp = requests.post(url, json=payload, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"Gemini API request failed ({resp.status_code}): {resp.text}")

        data = resp.json()
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()


class MockProvider(BaseLLM):
    """High-fidelity mock provider reflecting realistic sanitized prompt execution."""

    def generate(self, prompt: str) -> str:
        p_lower = prompt.lower()

        if "[card_" in p_lower or "[ssn_" in p_lower or "[email_" in p_lower:
            return (
                "Thank you for reaching out to support. We have verified your inquiry regarding your account. "
                "For your privacy, we confirmed your details against our secure records. A verification notice has been "
                "dispatched to your contact email. Please let us know if you need further assistance with your account."
            )
        elif "[ip_" in p_lower or "[api_key_" in p_lower:
            return (
                "Diagnostic complete: We have logged your technical request for host inspection. "
                "Your authorization token was verified, and our network team is investigating the connection."
            )
        elif "refund" in p_lower or "cancel" in p_lower:
            return (
                "Your refund and subscription request has been received and scheduled for immediate processing. "
                "You should see the adjustment on your billing statement within 3 to 5 business days."
            )
        else:
            return (
                f"I have received your request: '{prompt[:45]}...'. "
                "Everything looks good. How else can I assist you today?"
            )


def get_llm_provider(provider_name: Optional[str] = None) -> BaseLLM:
    """Factory function for LLM provider."""
    active = (provider_name or os.getenv("LLM_PROVIDER", "gemini")).lower()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()

    if active == "gemini" and gemini_key and not gemini_key.startswith("your_"):
        try:
            return GeminiProvider(api_key=gemini_key)
        except Exception as e:
            logger.warning("Failed to initialize GeminiProvider: %s. Falling back to MockProvider.", e)
            return MockProvider()

    return MockProvider()
