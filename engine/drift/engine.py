"""Deterministic longitudinal comparison engine (Stage 14).

Pure functions over immutable observation views: no stores, no I/O,
no wall-clock time. The engine compares a baseline observation
against a later observation (with intermediates for recurrence),
classifies finding lifecycles, diffs posture/TLS/certificate/
protocol/anomaly/correlation dimensions, and emits drift records.

Ordering of observations is the caller's responsibility (the service
uses case-attachment order, which is analyst-driven and fully
deterministic). Complexity is linear in observations and indexed
lookups — never pairwise across unrelated evidence.
"""

import hashlib
import json
from typing import Any

from engine.drift.model import (
    CertObservation,
    ComparisonResult,
    DriftRecord,
    DriftType,
    FindingLifecycle,
    LifecycleRow,
    ObservationView,
    RulePresence,
    TlsConfigObservation,
    drift_id,
)
from engine.graph.model import tls_config_fingerprint

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_MAX_IDS_PER_MAPPING = 200


def _endpoint_key(protocol: str | None, server_ip: str, server_port: int) -> str:
    return f"{protocol or 'unknown'}|{server_ip}|{server_port}"


def _strongest_severity(severities: list[str | None]) -> str | None:
    ranked = sorted(
        (str(severity).lower() for severity in severities if severity),
        key=lambda severity: _SEVERITY_RANK.get(severity, -1),
        reverse=True,
    )
    return ranked[0] if ranked else None


def build_observation(
    *,
    case_id: str,
    capture_id: str,
    analyzed: bool,
    analysis_status: str,
    analyzed_at: str | None,
    sessions: list[Any],
    findings: list[Any],
    posture: dict[str, Any] | None,
    anomaly_summary: dict[str, int] | None,
) -> ObservationView:
    """Assemble a deterministic snapshot from immutable analysis output.

    Sessions and findings are engine objects; posture and anomaly data
    are plain store payloads. ``analyzed_at`` doubles as ``created_at``
    so no wall-clock time enters derived payloads.
    """
    rules: dict[str, dict[str, Any]] = {}
    for finding in findings:
        entry = rules.setdefault(
            finding.rule_id, {"severities": [], "titles": [], "ids": [], "sessions": []}
        )
        entry["severities"].append(finding.severity.value if finding.severity else None)
        entry["titles"].append(finding.title)
        entry["ids"].append(finding.id)
        if finding.session_id:
            entry["sessions"].append(finding.session_id)
    rule_presence: list[RulePresence] = []
    rule_sessions: list[tuple[str, tuple[str, ...]]] = []
    for rule_id in sorted(rules):
        entry = rules[rule_id]
        session_ids = tuple(sorted(set(entry["sessions"]))[:_MAX_IDS_PER_MAPPING])
        titles = sorted({title for title in entry["titles"] if title})
        rule_presence.append(
            RulePresence(
                rule_id=rule_id,
                severity=_strongest_severity(entry["severities"]),
                title=titles[0] if titles else None,
                count=len(entry["ids"]),
                finding_ids=tuple(sorted(set(entry["ids"]))[:_MAX_IDS_PER_MAPPING]),
            )
        )
        rule_sessions.append((rule_id, session_ids))

    protocols: set[str] = set()
    tls_versions: set[str] = set()
    cipher_suites: set[str] = set()
    key_exchanges: set[str] = set()
    tls_detail: dict[str, dict[str, str | None]] = {}
    tls_sessions: dict[str, set[str]] = {}
    cert_detail: dict[str, dict[str, Any]] = {}
    cert_sessions: dict[str, set[str]] = {}
    cert_times: dict[str, list[str]] = {}
    session_endpoints: list[tuple[str, str]] = []
    for session in sessions:
        protocol = session.protocol.value if session.protocol else "unknown"
        protocols.add(protocol)
        endpoint = _endpoint_key(
            session.protocol.value if session.protocol else None,
            str(session.server_ip),
            session.server_port,
        )
        session_endpoints.append((session.id, endpoint))
        handshake = session.handshake
        if handshake is not None:
            version = handshake.tls_version.value if handshake.tls_version else None
            cipher = handshake.cipher_suite
            exchange = handshake.key_exchange.value if handshake.key_exchange else None
            if version:
                tls_versions.add(version)
            if cipher:
                cipher_suites.add(cipher)
            if exchange:
                key_exchanges.add(exchange)
            if version and cipher and exchange:
                fingerprint = tls_config_fingerprint(version, cipher, exchange)
                tls_detail[fingerprint] = {
                    "tls_version": version,
                    "cipher_suite": cipher,
                    "key_exchange": exchange,
                }
                tls_sessions.setdefault(fingerprint, set()).add(session.id)
        for certificate in session.certificates or []:
            fingerprint = certificate.fingerprint_sha256 or certificate.id
            cert_sessions.setdefault(fingerprint, set()).add(session.id)
            if session.started_at is not None:
                cert_times.setdefault(fingerprint, []).append(session.started_at.isoformat())
            info = cert_detail.setdefault(
                fingerprint,
                {
                    "subject": certificate.subject,
                    "issuer": certificate.issuer,
                    "signature_algorithm": certificate.signature_algorithm,
                    "valid": None,
                },
            )
            # Validity is judged at the earliest carrying-session instant
            # (packet time, therefore evidence-derived and deterministic).
            stamps = sorted(cert_times.get(fingerprint, []))
            if stamps:
                earliest = stamps[0]
                valid = (
                    certificate.not_before.isoformat()
                    <= earliest
                    <= certificate.not_after.isoformat()
                )
                info["valid"] = valid
    tls_configs = tuple(
        TlsConfigObservation(
            fingerprint=fingerprint,
            tls_version=detail["tls_version"],
            cipher_suite=detail["cipher_suite"],
            key_exchange=detail["key_exchange"],
        )
        for fingerprint, detail in sorted(tls_detail.items())
    )
    certificates = tuple(
        CertObservation(
            fingerprint=fingerprint,
            subject=str(detail["subject"]) if detail["subject"] else None,
            issuer=str(detail["issuer"]) if detail["issuer"] else None,
            valid=detail["valid"] if isinstance(detail["valid"], bool) else None,
            signature_algorithm=str(detail["signature_algorithm"])
            if detail["signature_algorithm"]
            else None,
        )
        for fingerprint, detail in sorted(cert_detail.items())
    )

    posture_score = posture.get("overall_score") if posture else None
    posture_state = posture.get("posture_state") if posture else None
    bands: tuple[tuple[str, int], ...] | None = None
    if anomaly_summary is not None:
        bands = tuple(sorted((str(band), int(count)) for band, count in anomaly_summary.items()))

    digest = hashlib.sha256(
        json.dumps(
            {
                "rules": sorted(
                    (rule.rule_id, rule.severity, rule.count) for rule in rule_presence
                ),
                "posture": [posture_state, posture_score],
                "sessions": len(sessions),
                "protocols": sorted(protocols),
                "tls": sorted(tls_detail),
                "certs": sorted(cert_detail),
                "bands": list(bands) if bands is not None else None,
            },
            sort_keys=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    from engine.drift.model import observation_id

    return ObservationView(
        observation_id=observation_id(case_id, capture_id, digest),
        case_id=case_id,
        capture_id=capture_id,
        analyzed=analyzed,
        analysis_status=analysis_status,
        analyzed_at=analyzed_at,
        created_at=analyzed_at,
        posture_score=posture_score if isinstance(posture_score, int) else None,
        posture_state=str(posture_state) if posture_state else None,
        session_count=len(sessions),
        finding_rules=tuple(rule_presence),
        protocols=tuple(sorted(protocols)),
        tls_versions=tuple(sorted(tls_versions)),
        cipher_suites=tuple(sorted(cipher_suites)),
        key_exchanges=tuple(sorted(key_exchanges)),
        tls_config_fingerprints=tls_configs,
        certificates=certificates,
        anomaly_bands=bands,
        evidence_digest=digest,
        rule_sessions=tuple(sorted(rule_sessions)),
        session_endpoints=tuple(sorted(session_endpoints)),
        tls_config_sessions=tuple(
            sorted(
                (fingerprint, tuple(sorted(ids)[:_MAX_IDS_PER_MAPPING]))
                for fingerprint, ids in tls_sessions.items()
            )
        ),
        cert_sessions=tuple(
            sorted(
                (fingerprint, tuple(sorted(ids)[:_MAX_IDS_PER_MAPPING]))
                for fingerprint, ids in cert_sessions.items()
            )
        ),
    )


def _rule_map(observation: ObservationView) -> dict[str, RulePresence]:
    return {rule.rule_id: rule for rule in observation.finding_rules}


def _comparable(rule_id: str, baseline: ObservationView, observation: ObservationView) -> bool:
    """Whether an observation can speak to a baseline rule.

    Session-scoped rules require a session with the same protocol and
    server endpoint (Stage 13 relevance semantics); capture-level
    rules (no baseline sessions) require completed analysis. An
    unrelated capture is never treated as proof of resolution.
    """
    if not observation.analyzed:
        return False
    baseline_sessions = dict(baseline.rule_sessions).get(rule_id, ())
    if not baseline_sessions:
        return True
    baseline_endpoints = {
        endpoint
        for session_id, endpoint in baseline.session_endpoints
        if session_id in set(baseline_sessions)
    }
    if not baseline_endpoints:
        return False
    observed_endpoints = {endpoint for _, endpoint in observation.session_endpoints}
    return bool(baseline_endpoints & observed_endpoints)


def classify_lifecycle(
    rule_id: str,
    baseline_present: bool,
    intermediates: list[tuple[bool, bool]],
    target_present: bool,
    target_comparable: bool,
) -> FindingLifecycle:
    """Classify one rule over an ordered presence trace.

    ``intermediates`` holds (present, comparable) pairs strictly
    between the baseline and the target observation.
    """
    if not target_comparable:
        return FindingLifecycle.NOT_COMPARABLE
    prior_present = baseline_present or any(present for present, _ in intermediates)
    gap_after_presence = False
    seen_presence = baseline_present
    for present, comparable in intermediates:
        if not present and comparable and seen_presence:
            gap_after_presence = True
        if present:
            seen_presence = True
    if target_present and gap_after_presence:
        return FindingLifecycle.RECURRED
    if target_present and not baseline_present:
        return FindingLifecycle.NEW
    if target_present:
        return FindingLifecycle.PERSISTENT
    if prior_present:
        return FindingLifecycle.RESOLVED
    return FindingLifecycle.NOT_COMPARABLE


def posture_trend(observations: list[ObservationView]) -> list[dict[str, Any]]:
    """Chronological posture points with quoted deltas (no new formula)."""
    trend: list[dict[str, Any]] = []
    previous_score: int | None = None
    for observation in observations:
        score = observation.posture_score
        delta: int | None = None
        if score is not None and previous_score is not None:
            delta = score - previous_score
        if score is not None:
            previous_score = score
        trend.append(
            {
                "capture_id": observation.capture_id,
                "analyzed_at": observation.analyzed_at,
                "posture_score": score,
                "posture_state": observation.posture_state,
                "score_change_points": delta,
            }
        )
    return trend


def summarize_drift(
    case_id: str,
    baseline_capture_id: str | None,
    observation_count: int,
    drift_records: list[DriftRecord],
) -> dict[str, Any]:
    """Counts only — never a score."""
    counts = {
        "posture_changes": 0,
        "new_findings": 0,
        "resolved_findings": 0,
        "recurring_findings": 0,
        "configuration_changes": 0,
        "anomaly_changes": 0,
    }
    by_type: dict[str, int] = {}
    for record in drift_records:
        drift_type = record.drift_type.value
        by_type[drift_type] = by_type.get(drift_type, 0) + 1
        if drift_type == "posture_change":
            counts["posture_changes"] += 1
        elif drift_type == "finding_introduced":
            counts["new_findings"] += 1
        elif drift_type == "finding_resolved":
            counts["resolved_findings"] += 1
        elif drift_type == "finding_recurred":
            counts["recurring_findings"] += 1
        elif drift_type in (
            "tls_configuration_changed",
            "certificate_changed",
            "certificate_validity_changed",
            "protocol_behavior_changed",
        ):
            counts["configuration_changes"] += 1
        elif drift_type == "anomaly_state_changed":
            counts["anomaly_changes"] += 1
    return {
        "case_id": case_id,
        "observations": observation_count,
        "baseline_capture_id": baseline_capture_id,
        "drift_count": len(drift_records),
        "posture_changes": counts["posture_changes"],
        "new_findings": counts["new_findings"],
        "resolved_findings": counts["resolved_findings"],
        "recurring_findings": counts["recurring_findings"],
        "configuration_changes": counts["configuration_changes"],
        "anomaly_changes": counts["anomaly_changes"],
        "by_type": dict(sorted(by_type.items())),
    }


def _bounded_refs(refs: list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    from engine.drift.model import MAX_EVIDENCE_REFS_PER_DRIFT

    return tuple(refs[:MAX_EVIDENCE_REFS_PER_DRIFT])


def _finding_refs(
    anchor: ObservationView, later: ObservationView, rule_id: str
) -> tuple[list[str], list[dict[str, Any]]]:
    """Baseline + latest finding ids and evidence references for a rule."""
    anchor_map = _rule_map(anchor)
    later_map = _rule_map(later)
    anchor_presence = anchor_map.get(rule_id)
    later_presence = later_map.get(rule_id)
    anchor_ids = list(anchor_presence.finding_ids) if anchor_presence is not None else []
    later_ids = list(later_presence.finding_ids) if later_presence is not None else []
    refs: list[dict[str, Any]] = [
        {"capture_id": anchor.capture_id, "finding_id": finding_id} for finding_id in anchor_ids
    ]
    refs.extend(
        {"capture_id": later.capture_id, "finding_id": finding_id} for finding_id in later_ids
    )
    return sorted(set(anchor_ids + later_ids)), refs


def compare_pair(
    *,
    case_id: str,
    anchor: ObservationView,
    previous: ObservationView,
    later: ObservationView,
    intermediates: list[ObservationView],
    correlation_presence: dict[tuple[str, str], set[str]] | None = None,
    correlation_ids: dict[tuple[str, str], str] | None = None,
) -> tuple[ComparisonResult, list[DriftRecord]]:
    """Compare one ordered observation pair with lifecycle context.

    ``anchor`` is the lifecycle reference (case baseline, else the
    pair's first capture); ``intermediates`` holds observations strictly
    between anchor and later in canonical order. Both pair members must
    be analyzed; anything else is rejected rather than guessed.
    """
    if not previous.analyzed or not later.analyzed:
        raise ValueError("drift comparison requires analyzed observations on both sides")
    presence = correlation_presence or {}
    corr_ids = correlation_ids or {}
    records: list[DriftRecord] = []

    def make_record(
        drift_type: DriftType,
        evidence_key: str,
        before: dict[str, Any],
        after: dict[str, Any],
        refs: list[dict[str, Any]],
        statement: str,
        related_finding_ids: list[str] | None = None,
        related_correlations: list[dict[str, Any]] | None = None,
    ) -> DriftRecord:
        return DriftRecord(
            drift_id=drift_id(
                case_id, anchor.capture_id, later.capture_id, drift_type.value, evidence_key
            ),
            case_id=case_id,
            drift_type=drift_type,
            evidence_key=evidence_key,
            baseline_capture_id=anchor.capture_id,
            comparison_capture_id=later.capture_id,
            before=before,
            after=after,
            evidence_refs=_bounded_refs(refs),
            related_finding_ids=tuple(related_finding_ids or []),
            related_correlations=tuple(related_correlations or []),
            statement=statement,
        )

    # -- posture ------------------------------------------------------------
    posture_before = {
        "posture_state": previous.posture_state,
        "overall_score": previous.posture_score,
    }
    posture_after = {
        "posture_state": later.posture_state,
        "overall_score": later.posture_score,
    }
    delta: int | None = None
    if previous.posture_score is not None and later.posture_score is not None:
        delta = later.posture_score - previous.posture_score
    posture_changed = previous.posture_state != later.posture_state or (
        delta is not None and delta != 0
    )
    posture_available = previous.posture_state is not None and later.posture_state is not None
    if posture_available and posture_changed:
        parts = []
        if previous.posture_state != later.posture_state:
            parts.append(
                f"Posture state changed from {previous.posture_state} to {later.posture_state}."
            )
        if delta:
            parts.append(
                f"Posture score changed from {previous.posture_score} to {later.posture_score}."
            )
        records.append(
            make_record(
                DriftType.POSTURE_CHANGE,
                f"posture|{previous.posture_state}:{previous.posture_score}"
                f"->{later.posture_state}:{later.posture_score}",
                posture_before,
                posture_after,
                [
                    {"capture_id": previous.capture_id},
                    {"capture_id": later.capture_id},
                ],
                " ".join(parts),
            )
        )
    posture_statement = ""
    if posture_available:
        if delta:
            posture_statement = (
                f"Posture score changed from {previous.posture_score} to {later.posture_score}."
            )
        else:
            posture_statement = (
                f"Posture score unchanged at {later.posture_score} ({later.posture_state})."
            )

    # -- finding lifecycle ----------------------------------------------------
    anchor_map = _rule_map(anchor)
    later_map = _rule_map(later)
    rows: list[LifecycleRow] = []
    for rule_id in sorted(set(anchor_map) | set(later_map)):
        baseline_present = rule_id in anchor_map
        target_present = rule_id in later_map
        comparable = _comparable(rule_id, anchor, later)
        intermediate_states: list[tuple[bool, bool]] = []
        for intermediate in intermediates:
            present = rule_id in _rule_map(intermediate)
            intermediate_states.append((present, _comparable(rule_id, anchor, intermediate)))
        lifecycle = classify_lifecycle(
            rule_id, baseline_present, intermediate_states, target_present, comparable
        )
        anchor_presence = anchor_map.get(rule_id)
        later_presence = later_map.get(rule_id)
        preferred = anchor_presence or later_presence
        baseline_ids = list(anchor_presence.finding_ids) if anchor_presence else []
        latest_ids = list(later_presence.finding_ids) if later_presence else []
        rows.append(
            LifecycleRow(
                rule_id=rule_id,
                title=preferred.title if preferred else None,
                baseline_present=baseline_present,
                current_present=target_present,
                lifecycle=lifecycle,
                severity=preferred.severity if preferred else None,
                baseline_finding_id=baseline_ids[0] if baseline_ids else None,
                latest_finding_id=latest_ids[0] if latest_ids else None,
                comparable=comparable,
            )
        )
        related_ids, refs = _finding_refs(anchor, later, rule_id)
        if lifecycle == FindingLifecycle.NEW:
            records.append(
                make_record(
                    DriftType.FINDING_INTRODUCED,
                    f"finding-rule|{rule_id.lower()}",
                    {"present": False},
                    {
                        "present": True,
                        "severity": later_presence.severity if later_presence else None,
                        "count": later_presence.count if later_presence else 0,
                    },
                    refs,
                    f"Rule {rule_id} was first observed in capture "
                    f"{later.capture_id} (absent from baseline capture {anchor.capture_id}).",
                    related_finding_ids=related_ids,
                )
            )
        elif lifecycle == FindingLifecycle.RESOLVED:
            records.append(
                make_record(
                    DriftType.FINDING_RESOLVED,
                    f"finding-rule|{rule_id.lower()}",
                    {
                        "present": True,
                        "severity": anchor_presence.severity if anchor_presence else None,
                        "count": anchor_presence.count if anchor_presence else 0,
                    },
                    {"present": False},
                    refs,
                    f"Rule {rule_id} observed in baseline capture {anchor.capture_id} "
                    f"was not observed in capture {later.capture_id}.",
                    related_finding_ids=related_ids,
                )
            )
        elif lifecycle == FindingLifecycle.RECURRED:
            absent_intermediates = sorted(
                intermediate.capture_id
                for intermediate in intermediates
                if rule_id not in _rule_map(intermediate)
                and _comparable(rule_id, anchor, intermediate)
            )
            anchor_presence_rec = anchor_map.get(rule_id)
            records.append(
                make_record(
                    DriftType.FINDING_RECURRED,
                    f"finding-rule|{rule_id.lower()}",
                    {
                        "present": True,
                        "severity": anchor_presence_rec.severity if anchor_presence_rec else None,
                        "absent_in": absent_intermediates,
                    },
                    {
                        "present": True,
                        "severity": later_presence.severity if later_presence else None,
                        "count": later_presence.count if later_presence else 0,
                    },
                    refs,
                    f"Rule {rule_id} was observed again in capture {later.capture_id} "
                    f"after being absent in "
                    f"{', '.join(absent_intermediates) or 'an intermediate observation'}.",
                    related_finding_ids=related_ids,
                )
            )

    # -- TLS configuration ------------------------------------------------------
    previous_tls = {config.fingerprint: config for config in previous.tls_config_fingerprints}
    later_tls = {config.fingerprint: config for config in later.tls_config_fingerprints}
    previous_tls_sessions = dict(previous.tls_config_sessions)
    later_tls_sessions = dict(later.tls_config_sessions)
    for fingerprint in sorted(set(previous_tls) | set(later_tls)):
        in_previous = fingerprint in previous_tls
        in_later = fingerprint in later_tls
        if in_previous == in_later:
            continue
        tls_detail = (later_tls if in_later else previous_tls)[fingerprint]
        session_ids = sorted(
            (later_tls_sessions if in_later else previous_tls_sessions).get(fingerprint, ())
        )
        refs = [
            {
                "capture_id": later.capture_id if in_later else previous.capture_id,
                "session_id": session_id,
            }
            for session_id in session_ids
        ]
        records.append(
            make_record(
                DriftType.TLS_CONFIGURATION_CHANGED,
                f"tls-config|{fingerprint}",
                (
                    {
                        "present": True,
                        "tls_version": tls_detail.tls_version,
                        "cipher_suite": tls_detail.cipher_suite,
                        "key_exchange": tls_detail.key_exchange,
                    }
                    if in_previous
                    else {"present": False}
                ),
                (
                    {
                        "present": True,
                        "tls_version": tls_detail.tls_version,
                        "cipher_suite": tls_detail.cipher_suite,
                        "key_exchange": tls_detail.key_exchange,
                    }
                    if in_later
                    else {"present": False}
                ),
                refs,
                f"TLS configuration {fingerprint} was observed in capture "
                f"{later.capture_id if in_later else previous.capture_id} but not in capture "
                f"{previous.capture_id if in_later else later.capture_id}.",
            )
        )

    # -- certificates -------------------------------------------------------------
    previous_certs = {cert.fingerprint: cert for cert in previous.certificates}
    later_certs = {cert.fingerprint: cert for cert in later.certificates}
    previous_cert_sessions = dict(previous.cert_sessions)
    later_cert_sessions = dict(later.cert_sessions)
    for fingerprint in sorted(set(previous_certs) | set(later_certs)):
        in_previous = fingerprint in previous_certs
        in_later = fingerprint in later_certs
        cert_detail = (later_certs if in_later else previous_certs)[fingerprint]
        session_ids = sorted(
            (later_cert_sessions if in_later else previous_cert_sessions).get(fingerprint, ())
        )
        refs = [
            {
                "capture_id": later.capture_id if in_later else previous.capture_id,
                "session_id": session_id,
            }
            for session_id in session_ids
        ]
        if in_previous != in_later:
            records.append(
                make_record(
                    DriftType.CERTIFICATE_CHANGED,
                    f"certificate|{fingerprint}",
                    (
                        {
                            "present": True,
                            "subject": cert_detail.subject,
                            "issuer": cert_detail.issuer,
                        }
                        if in_previous
                        else {"present": False}
                    ),
                    (
                        {
                            "present": True,
                            "subject": cert_detail.subject,
                            "issuer": cert_detail.issuer,
                        }
                        if in_later
                        else {"present": False}
                    ),
                    refs,
                    f"Certificate {fingerprint} was observed in capture "
                    f"{later.capture_id if in_later else previous.capture_id} but not in capture "
                    f"{previous.capture_id if in_later else later.capture_id}.",
                )
            )
        elif (
            isinstance(previous_certs[fingerprint].valid, bool)
            and isinstance(later_certs[fingerprint].valid, bool)
            and previous_certs[fingerprint].valid != later_certs[fingerprint].valid
        ):
            records.append(
                make_record(
                    DriftType.CERTIFICATE_VALIDITY_CHANGED,
                    f"certificate-validity|{fingerprint}",
                    {"valid": previous_certs[fingerprint].valid, "subject": cert_detail.subject},
                    {"valid": later_certs[fingerprint].valid, "subject": cert_detail.subject},
                    refs,
                    f"Certificate {fingerprint} validity status changed between capture "
                    f"{previous.capture_id} and capture {later.capture_id}.",
                )
            )

    # -- protocols ------------------------------------------------------------------
    for protocol in sorted(set(previous.protocols) | set(later.protocols)):
        in_previous = protocol in set(previous.protocols)
        in_later = protocol in set(later.protocols)
        if in_previous == in_later:
            continue
        records.append(
            make_record(
                DriftType.PROTOCOL_BEHAVIOR_CHANGED,
                f"protocol|{protocol}",
                {"present": True} if in_previous else {"present": False},
                {"present": True} if in_later else {"present": False},
                [
                    {"capture_id": previous.capture_id},
                    {"capture_id": later.capture_id},
                ],
                f"Protocol {protocol} was observed in capture "
                f"{later.capture_id if in_later else previous.capture_id} but not in capture "
                f"{previous.capture_id if in_later else later.capture_id}.",
            )
        )

    # -- anomalies --------------------------------------------------------------------
    previous_bands = dict(previous.anomaly_bands) if previous.anomaly_bands is not None else None
    later_bands = dict(later.anomaly_bands) if later.anomaly_bands is not None else None
    if previous_bands is not None and later_bands is not None and previous_bands != later_bands:
        records.append(
            make_record(
                DriftType.ANOMALY_STATE_CHANGED,
                "anomaly-bands",
                {"bands": previous_bands},
                {"bands": later_bands},
                [
                    {"capture_id": previous.capture_id},
                    {"capture_id": later.capture_id},
                ],
                f"Anomaly band distribution changed between capture "
                f"{previous.capture_id} and capture {later.capture_id}.",
            )
        )

    # -- correlations -------------------------------------------------------------------
    for (correlation_type, evidence_key), capture_ids in sorted(presence.items()):
        in_previous = previous.capture_id in capture_ids
        in_later = later.capture_id in capture_ids
        if in_previous == in_later:
            continue
        related = []
        if (correlation_type, evidence_key) in corr_ids:
            related.append(
                {
                    "correlation_type": correlation_type,
                    "evidence_key": evidence_key,
                    "correlation_id": corr_ids[(correlation_type, evidence_key)],
                }
            )
        direction = "observed" if in_later else "no longer observed"
        records.append(
            make_record(
                DriftType.CORRELATION_PATTERN_CHANGED,
                f"correlation|{correlation_type}|{evidence_key}",
                {"observed": in_previous},
                {"observed": in_later},
                [
                    {"capture_id": previous.capture_id},
                    {"capture_id": later.capture_id},
                ],
                f"Shared evidence {correlation_type} ({evidence_key}) is {direction} "
                f"in capture {later.capture_id if in_later else previous.capture_id}.",
                related_correlations=related,
            )
        )

    records.sort(key=lambda record: (record.drift_type.value, record.evidence_key))
    comparison = ComparisonResult(
        baseline_capture_id=anchor.capture_id,
        comparison_capture_id=later.capture_id,
        previous_capture_id=previous.capture_id,
        lifecycle_anchor_capture_id=anchor.capture_id,
        posture_before={
            "posture_state": previous.posture_state,
            "overall_score": previous.posture_score,
        },
        posture_after={
            "posture_state": later.posture_state,
            "overall_score": later.posture_score,
        },
        posture_delta_points=(
            later.posture_score - previous.posture_score
            if previous.posture_score is not None and later.posture_score is not None
            else None
        ),
        posture_statement=posture_statement,
        finding_lifecycle=tuple(rows),
        tls_before={
            "tls_versions": list(previous.tls_versions),
            "cipher_suites": list(previous.cipher_suites),
            "key_exchanges": list(previous.key_exchanges),
            "configurations": len(previous.tls_config_fingerprints),
        },
        tls_after={
            "tls_versions": list(later.tls_versions),
            "cipher_suites": list(later.cipher_suites),
            "key_exchanges": list(later.key_exchanges),
            "configurations": len(later.tls_config_fingerprints),
        },
        certificates_before={
            "count": len(previous.certificates),
            "fingerprints": sorted(cert.fingerprint for cert in previous.certificates),
        },
        certificates_after={
            "count": len(later.certificates),
            "fingerprints": sorted(cert.fingerprint for cert in later.certificates),
        },
        protocols_before=previous.protocols,
        protocols_after=later.protocols,
        anomaly_bands_before=previous_bands,
        anomaly_bands_after=later_bands,
        drift_ids=tuple(record.drift_id for record in records),
    )
    return comparison, records


def lifecycle_at(
    rule_id: str,
    anchor: ObservationView,
    intermediates: list[ObservationView],
    target: ObservationView,
) -> dict[str, Any]:
    """Classify one rule at a target observation with full history.

    Used for remediation regression views outside pairwise comparison.
    """
    anchor_map = _rule_map(anchor)
    target_map = _rule_map(target)
    baseline_present = rule_id in anchor_map
    target_present = rule_id in target_map
    comparable = _comparable(rule_id, anchor, target)
    states: list[tuple[bool, bool]] = []
    for intermediate in intermediates:
        present = rule_id in _rule_map(intermediate)
        states.append((present, _comparable(rule_id, anchor, intermediate)))
    lifecycle = classify_lifecycle(rule_id, baseline_present, states, target_present, comparable)
    preferred = anchor_map.get(rule_id) or target_map.get(rule_id)
    return {
        "rule_id": rule_id,
        "lifecycle": lifecycle.value,
        "baseline_present": baseline_present,
        "current_present": target_present,
        "comparable": comparable,
        "severity": preferred.severity if preferred else None,
        "title": preferred.title if preferred else None,
    }
