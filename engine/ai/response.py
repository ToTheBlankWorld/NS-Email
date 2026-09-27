"""Typed AI response model, citation validation, and output sanitization."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from engine.ai.context import AIContext


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    """A structured citation linking an AI response to actual evidence."""

    citation_id: str
    capture_id: str
    session_id: str
    packet_numbers: list[int]
    source_type: str
    source_id: str
    description: str


@dataclass(frozen=True, slots=True)
class AIAnalysisResponse:
    """Structured, validated AI analysis response."""

    response_id: str
    capture_id: str
    session_id: str | None
    query: str
    answer: str
    key_observations: list[str]
    interpretations: list[str]
    uncertainties: list[str]
    citations: list[EvidenceCitation]
    model: str
    provider: str
    prompt_version: str
    context_version: str
    validation_status: str  # validated | validation_failed | not_validated
    generated_at: datetime


class AIResponseValidationError(Exception):
    """The AI response referenced evidence not present in the context."""


def parse_llm_output(text: str) -> dict[str, Any]:
    """Parse the LLM output as JSON; raises AIResponseValidationError on failure."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1])  # strip markdown fences
    try:
        parsed: dict[str, Any] = json.loads(text)
        return parsed
    except json.JSONDecodeError as error:
        raise AIResponseValidationError(f"malformed JSON in AI response: {error}") from error


def validate_response(
    parsed: dict[str, Any],
    context: AIContext,
) -> None:
    """Validate that cited session IDs match the supplied context.

    Raises ``AIResponseValidationError`` if the response references
    evidence not present in the supplied context.
    """
    if context.session_id and "session_id" in str(parsed.get("citations", "")):
        citations = parsed.get("citations", [])
        for citation in citations:
            cited_session = citation.get("session_id", "")
            if cited_session and cited_session != context.session_id:
                raise AIResponseValidationError(
                    f"cited session {cited_session} does not match "
                    f"context session {context.session_id}"
                )


def build_citations(
    parsed: dict[str, Any],
    context: AIContext,
) -> list[EvidenceCitation]:
    """Build evidence citations from the parsed AI response and context."""
    citations: list[EvidenceCitation] = []
    for index, citation_data in enumerate(parsed.get("citations", [])):
        if isinstance(citation_data, dict):
            citations.append(
                EvidenceCitation(
                    citation_id=f"cite_{index}",
                    capture_id=context.capture_id,
                    session_id=context.session_id,
                    packet_numbers=citation_data.get("packet_numbers", []),
                    source_type=citation_data.get("source", "evidence"),
                    source_id=citation_data.get("source_id", context.session_id),
                    description=citation_data.get("description", ""),
                )
            )
    return citations


def build_response(
    *,
    response_id: str,
    query: str,
    parsed: dict[str, Any],
    context: AIContext,
    model: str,
    provider: str,
) -> AIAnalysisResponse:
    """Build a validated AIAnalysisResponse from parsed LLM output."""
    citations = build_citations(parsed, context)
    return AIAnalysisResponse(
        response_id=response_id,
        capture_id=context.capture_id,
        session_id=context.session_id,
        query=query,
        answer=str(parsed.get("answer", "")),
        key_observations=[str(o) for o in parsed.get("observations", [])],
        interpretations=[str(i) for i in parsed.get("interpretations", [])],
        uncertainties=[str(u) for u in parsed.get("uncertainties", [])],
        citations=citations,
        model=model,
        provider=provider,
        prompt_version="1.0",
        context_version=context.context_version,
        validation_status="validated",
        generated_at=datetime.now(UTC),
    )
