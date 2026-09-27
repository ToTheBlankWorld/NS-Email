"""AI analyst service: retrieval → context → provider → validation → citations.

Orchestrates the full pipeline from an analyst question to a validated,
evidence-grounded response. If no provider is configured or the provider
fails, the service reports the status without crashing the main pipeline.
"""

import logging
from typing import Any

from engine.ai.context import build_ai_context
from engine.ai.prompts import build_system_prompt, build_user_prompt
from engine.ai.provider import (
    AIProviderError,
    AIProviderUnavailableError,
    LLMProvider,
    LLMRequest,
)
from engine.ai.response import (
    build_response,
    parse_llm_output,
    validate_response,
)
from engine.graph.builder import build_investigation_context

logger = logging.getLogger("ns_email.ai")


class AIAnalystService:
    """Evidence-grounded AI forensic analyst."""

    def __init__(
        self,
        provider: LLMProvider | None,
        analysis_service: Any,  # CaptureAnalysisService
    ) -> None:
        self._provider = provider
        self._analysis = analysis_service

    @property
    def is_configured(self) -> bool:
        return self._provider is not None

    def query_session(
        self,
        session_id: str,
        question: str,
    ) -> dict[str, Any]:
        """Answer a question about one session using evidence-grounded AI.

        Returns a dict with the validated response or a structured error.
        """
        if self._provider is None:
            return {"status": "not_configured", "error": "No AI provider is configured."}

        session = self._analysis.session(session_id)
        if session is None:
            return {"status": "not_found", "error": "Session not found."}

        findings = self._analysis.findings_for_session(session_id)
        anomaly = self._analysis.anomaly_for_session(session_id)
        all_sessions = self._analysis.sessions_for(session.capture_id)
        all_findings = self._analysis.findings_for_capture(session.capture_id)
        posture = self._analysis.posture_snapshot(session.capture_id)

        investigation = build_investigation_context(
            session,
            findings,
            [anomaly] if anomaly else [],
            [f.get("factor", "") for f in (posture or {}).get("factors", [])],
            all_sessions,
            all_findings,
        )

        ai_context = build_ai_context(
            session,
            investigation,
            findings,
            {
                "state": (posture or {}).get("posture_state"),
                "score": (posture or {}).get("overall_score"),
            },
        )

        system_prompt = build_system_prompt()
        user_prompt = build_user_prompt(question, ai_context.context_json)

        try:
            llm_response = self._provider.generate(
                LLMRequest(system_prompt=system_prompt, user_prompt=user_prompt)
            )
        except AIProviderUnavailableError as error:
            return {"status": "provider_unavailable", "error": str(error)}
        except AIProviderError as error:
            return {"status": "model_error", "error": str(error)}

        try:
            parsed = parse_llm_output(llm_response.text)
            validate_response(parsed, ai_context)
        except Exception as error:
            logger.warning("AI response validation failed: %s", error)
            return {
                "status": "validation_failed",
                "error": f"AI response failed validation: {error}",
                "raw_text": llm_response.text[:500],
            }

        response = build_response(
            response_id=f"ai_{format(hash(session_id + question) & 0xFFFFFFFFFFFFFFFF, '012x')}",
            query=question,
            parsed=parsed,
            context=ai_context,
            model=llm_response.model,
            provider=llm_response.provider,
        )

        from dataclasses import asdict

        result = asdict(response)
        result["status"] = "completed"
        return result
