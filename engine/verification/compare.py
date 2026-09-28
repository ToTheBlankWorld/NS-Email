"""Deterministic baseline/verification comparison (Stage 13).

Compares an original finding's structured evidence against a later
verification capture:

- session-scoped finding → match candidate sessions in the
  verification capture by server endpoint + protocol (the relevant
  evidence identifying the condition). No candidate → INCONCLUSIVE.
  Rule present in a candidate → FAILED. Rule absent → VERIFIED.
- capture-level finding (no session) → rule presence in the
  verification capture decides FAILED vs VERIFIED.
- incomplete relevant evidence on either side → INCONCLUSIVE.

Posture snapshots are quoted verbatim from the Stage 5 model and only
differenced arithmetically, with neutral wording. No new posture
formula, no causality claims, no probabilistic language.
"""

from engine.verification.model import (
    FindingView,
    PostureView,
    SessionView,
    VerificationComparison,
    VerificationMethod,
    VerificationOutcome,
)


def _session_evidence(session: SessionView | None) -> dict[str, object]:
    if session is None:
        return {}
    return {
        "session_id": session.session_id,
        "protocol": session.protocol,
        "server_endpoint": (
            f"{session.server_ip}:{session.server_port}"
            if session.server_ip is not None and session.server_port is not None
            else None
        ),
        "tls_version": session.tls_version,
        "cipher_suite": session.cipher_suite,
        "key_exchange": session.key_exchange,
        "handshake_complete": session.handshake_complete,
        "certificate_fingerprint": session.certificate_fingerprint,
        "certificate_subject": session.certificate_subject,
        "certificate_valid": session.certificate_valid,
        "signature_algorithm": session.signature_algorithm,
    }


def _posture_evidence(posture: PostureView | None) -> dict[str, object]:
    if posture is None:
        return {"available": False}
    return {
        "available": True,
        "posture_state": posture.posture_state,
        "overall_score": posture.overall_score,
    }


def _posture_delta(before: PostureView | None, after: PostureView | None) -> int | None:
    if before is None or after is None:
        return None
    if before.overall_score is None or after.overall_score is None:
        return None
    return after.overall_score - before.overall_score


def _relevance_key(session: SessionView) -> tuple[str | None, str | None, int | None]:
    """Identity of the condition: protocol + server endpoint."""
    return (session.protocol, session.server_ip, session.server_port)


def compare_rule(
    *,
    baseline_finding: FindingView,
    baseline_session: SessionView | None,
    baseline_posture: PostureView | None,
    verification_capture_id: str,
    verification_sessions: list[SessionView],
    verification_findings: list[FindingView],
    verification_posture: PostureView | None,
) -> VerificationComparison:
    """Deterministically compare one rule against a verification capture."""
    rule_id = baseline_finding.rule_id
    method = VerificationMethod.EVIDENCE
    posture_before = _posture_evidence(baseline_posture)
    posture_after = _posture_evidence(verification_posture)
    delta = _posture_delta(baseline_posture, verification_posture)

    if baseline_finding.session_id is None or baseline_session is None:
        # Capture-level condition: rule presence decides.
        present = any(f.rule_id == rule_id for f in verification_findings)
        if present:
            outcome = VerificationOutcome.FAILED
            statement = (
                f"Rule {rule_id} was still observed in verification "
                f"capture {verification_capture_id}."
            )
        else:
            outcome = VerificationOutcome.VERIFIED
            statement = (
                f"Rule {rule_id} was not observed in verification "
                f"capture {verification_capture_id}."
            )
        return VerificationComparison(
            outcome=outcome,
            method=method,
            rule_id=rule_id,
            baseline_capture_id=baseline_finding.capture_id,
            verification_capture_id=verification_capture_id,
            baseline_session_id=baseline_finding.session_id,
            verification_session_id=None,
            session_match="not_session_scoped",
            rule_present_in_verification=present,
            baseline_evidence=_session_evidence(baseline_session),
            verification_evidence={},
            posture_before=posture_before,
            posture_after=posture_after,
            posture_delta_points=delta,
            statement=statement,
        )

    # Session-scoped condition: match the relevant session first.
    wanted = _relevance_key(baseline_session)
    if wanted[1] is None or wanted[2] is None:
        return VerificationComparison(
            outcome=VerificationOutcome.INCONCLUSIVE,
            method=method,
            rule_id=rule_id,
            baseline_capture_id=baseline_finding.capture_id,
            verification_capture_id=verification_capture_id,
            baseline_session_id=baseline_session.session_id,
            verification_session_id=None,
            session_match="incomplete_evidence",
            rule_present_in_verification=None,
            baseline_evidence=_session_evidence(baseline_session),
            verification_evidence={},
            posture_before=posture_before,
            posture_after=posture_after,
            posture_delta_points=delta,
            statement=(
                f"Rule {rule_id} could not be verified: the baseline session "
                "lacks endpoint evidence to match against."
            ),
        )
    candidates = [s for s in verification_sessions if _relevance_key(s) == wanted]
    if not candidates:
        return VerificationComparison(
            outcome=VerificationOutcome.INCONCLUSIVE,
            method=method,
            rule_id=rule_id,
            baseline_capture_id=baseline_finding.capture_id,
            verification_capture_id=verification_capture_id,
            baseline_session_id=baseline_session.session_id,
            verification_session_id=None,
            session_match="no_matching_session",
            rule_present_in_verification=None,
            baseline_evidence=_session_evidence(baseline_session),
            verification_evidence={},
            posture_before=posture_before,
            posture_after=posture_after,
            posture_delta_points=delta,
            statement=(
                f"Rule {rule_id} could not be verified: verification capture "
                f"{verification_capture_id} does not contain the relevant session."
            ),
        )
    candidate_ids = {s.session_id for s in candidates}
    present = any(
        f.rule_id == rule_id and f.session_id in candidate_ids for f in verification_findings
    )
    matched = sorted(candidate_ids)[0]
    matched_session = next(s for s in candidates if s.session_id == matched)
    if present:
        outcome = VerificationOutcome.FAILED
        statement = (
            f"Rule {rule_id} was still observed in verification capture "
            f"{verification_capture_id} for the relevant session."
        )
    else:
        outcome = VerificationOutcome.VERIFIED
        statement = (
            f"Rule {rule_id} was not observed in verification capture "
            f"{verification_capture_id} for the relevant session."
        )
    return VerificationComparison(
        outcome=outcome,
        method=method,
        rule_id=rule_id,
        baseline_capture_id=baseline_finding.capture_id,
        verification_capture_id=verification_capture_id,
        baseline_session_id=baseline_session.session_id,
        verification_session_id=matched,
        session_match="matched",
        rule_present_in_verification=present,
        baseline_evidence=_session_evidence(baseline_session),
        verification_evidence=_session_evidence(matched_session),
        posture_before=posture_before,
        posture_after=posture_after,
        posture_delta_points=delta,
        statement=statement,
    )


__all__ = ["compare_rule"]
