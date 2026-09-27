"""Evidence-grounded AI forensic analyst (Stage 8).

Consumes structured evidence from Stages 2-7 via a context builder,
sends a bounded, sanitized prompt to a swappable LLM provider, validates
the response against the supplied evidence, and returns structured
citations. The AI is an explanation assistant - never the source of
truth, never a policy engine, never an attack classifier.
"""

from engine.ai.provider import (
    AIProviderError,
    AIProviderUnavailableError,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    MockLLMProvider,
    OpenAICompatibleProvider,
)
from engine.ai.service import AIAnalystService

__all__ = [
    "AIAnalystService",
    "AIProviderError",
    "AIProviderUnavailableError",
    "LLMProvider",
    "LLMRequest",
    "LLMResponse",
    "MockLLMProvider",
    "OpenAICompatibleProvider",
]
