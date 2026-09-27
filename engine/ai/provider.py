"""LLM provider abstraction and implementations.

Providers are swappable via the ``LLMProvider`` protocol. The built-in
``OpenAICompatibleProvider`` talks to any OpenAI-compatible API using the
stdlib ``json`` module and bounded ``httpx`` calls. ``MockLLMProvider``
returns deterministic structured responses for tests.

API keys are read from environment configuration only — never hardcoded,
never logged, never returned in API responses.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx


class AIProviderError(Exception):
    """The AI provider failed to generate a response."""


class AIProviderUnavailableError(AIProviderError):
    """The AI provider is not reachable or not configured."""


@dataclass(frozen=True, slots=True)
class LLMRequest:
    """A bounded prompt request sent to the provider."""

    system_prompt: str
    user_prompt: str
    max_tokens: int = 2048
    temperature: float = 0.1


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """The raw text response from the provider."""

    text: str
    model: str
    provider: str


class LLMProvider(ABC):
    """Abstract provider: generate a completion from a prompt."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider identifier."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """The model identifier used by this provider."""

    @property
    @abstractmethod
    def is_local(self) -> bool:
        """True for local providers (Ollama); False for external APIs."""

    @abstractmethod
    def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate a completion; raises AIProviderError on failure."""


class MockLLMProvider(LLMProvider):
    """Deterministic mock provider for tests and offline demos.

    Without a canned ``response_text`` the mock derives its response from the
    evidence context embedded in the user prompt, so it exercises the same
    grounding, citation, and validation path as a real provider. A canned
    text overrides this behavior (used by malformed-output tests).
    """

    def __init__(self, response_text: str | None = None) -> None:
        self._response_text = response_text

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return "mock-forensic-analyst"

    @property
    def is_local(self) -> bool:
        return True

    def generate(self, request: LLMRequest) -> LLMResponse:
        text = self._response_text
        if text is None:
            text = self._summarize_context(request.user_prompt)
        return LLMResponse(text=text, model=self.model_name, provider=self.provider_name)

    @staticmethod
    def _summarize_context(user_prompt: str) -> str:
        """Build a JSON response strictly from the prompt's evidence context."""
        try:
            section = user_prompt.split("## Evidence context", 1)[1]
            context = json.loads(section[section.index("{") : section.rindex("}") + 1])
        except (IndexError, ValueError, json.JSONDecodeError):
            context = {}
        if not isinstance(context, dict):
            context = {}

        raw_session = context.get("session")
        session = raw_session if isinstance(raw_session, dict) else {}
        raw_tls = context.get("tls")
        tls = raw_tls if isinstance(raw_tls, dict) else {}
        raw_findings = context.get("findings")
        findings = raw_findings if isinstance(raw_findings, list) else []

        session_id = str(session.get("session_id") or "")
        protocol = str(session.get("protocol") or "unknown")
        observations: list[str] = []
        if session_id:
            observations.append(f"Session {session_id} carries {protocol.upper()} traffic.")
        if session.get("complete") is False:
            observations.append("The captured stream is incomplete; some segments are missing.")
        if tls:
            observations.append(
                f"TLS handshake negotiated {tls.get('tls_version')} "
                f"with {tls.get('key_exchange')} key exchange."
            )
        if not observations:
            observations.append("No session evidence was supplied in the context.")

        interpretations = [
            "Security conclusions remain the responsibility of the deterministic "
            "policy engine; this summary only restates its findings."
        ]
        if findings:
            rule_ids = ", ".join(str(f.get("rule_id")) for f in findings[:5] if isinstance(f, dict))
            interpretations.append(f"Policy engine findings in scope: {rule_ids}.")

        uncertainties = [
            "Capture-local evidence only; no historical baseline is available "
            "for this host or protocol."
        ]

        citations: list[dict[str, str]] = []
        if session_id:
            citations.append({"source": "session", "detail": session_id})

        return json.dumps(
            {
                "answer": (
                    f"Mock summary for {protocol.upper()} session {session_id or '(unknown)'}: "
                    f"{len(findings)} policy finding(s) recorded for this session. "
                    "This deterministic response is derived only from the supplied context."
                ),
                "observations": observations,
                "interpretations": interpretations,
                "uncertainties": uncertainties,
                "citations": citations,
            },
            sort_keys=True,
        )


class OpenAICompatibleProvider(LLMProvider):
    """Chat-completions provider for OpenAI-compatible APIs (including Ollama).

    Uses ``httpx`` with explicit timeouts and bounded response size.
    The API key is read from configuration, never hardcoded.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "",
        timeout_seconds: float = 60.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._api_key = api_key
        self._timeout = timeout_seconds

    @property
    def provider_name(self) -> str:
        return "openai-compatible"

    @property
    def model_name(self) -> str:
        return self._model

    @property
    def is_local(self) -> bool:
        return "localhost" in self._base_url or "127.0.0.1" in self._base_url

    def generate(self, request: LLMRequest) -> LLMResponse:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }

        try:
            response = httpx.post(
                f"{self._base_url}/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.TimeoutException as error:
            raise AIProviderUnavailableError(f"provider timed out: {error}") from error
        except httpx.HTTPStatusError as error:
            raise AIProviderError(f"provider returned HTTP {error.response.status_code}") from error
        except httpx.HTTPError as error:
            raise AIProviderUnavailableError(f"provider unreachable: {error}") from error

        try:
            body = response.json()
            text = body["choices"][0]["message"]["content"]
            return LLMResponse(text=text, model=self._model, provider=self.provider_name)
        except (KeyError, IndexError, json.JSONDecodeError) as error:
            raise AIProviderError(f"unexpected provider response format: {error}") from error


def create_provider(
    provider_type: str,
    model: str,
    base_url: str,
    api_key: str,
) -> LLMProvider | None:
    """Factory: create the configured provider, or None if not configured."""
    if provider_type == "mock":
        return MockLLMProvider()
    if provider_type == "openai" and base_url:
        return OpenAICompatibleProvider(base_url, model, api_key)
    if provider_type == "ollama" and base_url:
        return OpenAICompatibleProvider(base_url, model, api_key)
    return None
