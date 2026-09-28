"""Index-based multi-capture correlation engine (Stage 12).

The engine makes exactly one pass over the case evidence, filing every
session, certificate, finding, and anomaly observation into keyed
indexes (endpoint, host, certificate, TLS configuration, finding rule,
protocol, ...). Relationships are then generated from keys observed in
two or more captures — approximately O(N + relationships), never
pairwise O(N²) session comparison.

Only structured evidence already present in SecureMailScope is used.
Findings keep their deterministic rule ids, TLS configurations reuse
the Stage 7 fingerprint, and certificate identity is the SHA-256
fingerprint. Language throughout is neutral: shared evidence and
repeated observations, never attribution or intent.
"""

from dataclasses import dataclass, field
from typing import TypedDict

from engine.core.findings import SecurityFinding
from engine.core.session import Session
from engine.correlation.model import (
    MAX_CORRELATIONS_PER_CASE,
    MAX_OCCURRENCES_PER_CORRELATION,
    Correlation,
    CorrelationReport,
    CorrelationStrength,
    CorrelationType,
    Occurrence,
    correlation_id,
)
from engine.correlation.normalize import (
    normalize_evidence_key,
    normalize_fingerprint,
    normalize_hostname,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_subject,
    normalize_token,
)
from engine.graph.model import tls_config_fingerprint

#: Anomaly bands that justify a deterministic pattern correlation.
#: "normal", "insufficient_evidence", "not_evaluated", and "model_error"
#: are baseline states or non-results — correlating them would be noise.
FLAGGED_ANOMALY_BANDS: frozenset[str] = frozenset({"unusual", "anomalous", "highly_anomalous"})


class AnomalyView(TypedDict, total=False):
    """Minimal anomaly shape the engine correlates on (store-agnostic)."""

    anomaly_id: str
    session_id: str
    band: str | None
    status: str


@dataclass
class CaptureCorrelationInput:
    """Structured evidence of one capture, as held by the case."""

    capture_id: str
    sessions: list[Session] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    anomalies: list[AnomalyView] = field(default_factory=list)


@dataclass
class _IndexEntry:
    correlation_type: CorrelationType
    strength: CorrelationStrength
    evidence_key: str
    evidence: dict[str, object]
    occurrence: Occurrence


def _session_time(session: Session) -> str | None:
    started = session.started_at
    return started.isoformat() if started else None


def _starttls_state(session: Session) -> str:
    starttls = session.starttls
    if starttls is None:
        return "none"
    return (
        f"adv={int(starttls.advertised)}"
        f":req={int(starttls.requested)}"
        f":resp={int(starttls.response_seen)}"
    )


def _index_session(capture_id: str, session: Session, out: list[_IndexEntry]) -> None:
    """File one session's structured observations into the indexes."""
    at = _session_time(session)
    server_ip = normalize_ip(str(session.server_ip))
    server_port = normalize_port(session.server_port)
    protocol = normalize_protocol(session.protocol.value if session.protocol else None)
    handshake = session.handshake
    tls_version = normalize_token(handshake.tls_version.value) if handshake else None
    cipher = normalize_token(handshake.cipher_suite) if handshake else None
    key_exchange = normalize_token(handshake.key_exchange.value) if handshake else None

    if server_ip is not None:
        host_key = normalize_evidence_key(f"host|{server_ip}")
        if host_key is not None:
            out.append(
                _IndexEntry(
                    CorrelationType.SHARED_HOST,
                    CorrelationStrength.DIRECT,
                    host_key,
                    {"ip": server_ip},
                    Occurrence(capture_id, session.id, observed_at=at),
                )
            )
        if server_port is not None:
            endpoint_key = normalize_evidence_key(f"endpoint|{server_ip}|{server_port}")
            if endpoint_key is not None:
                out.append(
                    _IndexEntry(
                        CorrelationType.SHARED_ENDPOINT,
                        CorrelationStrength.DIRECT,
                        endpoint_key,
                        {"ip": server_ip, "port": server_port},
                        Occurrence(capture_id, session.id, observed_at=at),
                    )
                )

    if protocol is not None:
        protocol_key = normalize_evidence_key(f"protocol|{protocol}")
        if protocol_key is not None:
            out.append(
                _IndexEntry(
                    CorrelationType.SHARED_PROTOCOL,
                    CorrelationStrength.DERIVED,
                    protocol_key,
                    {"protocol": protocol},
                    Occurrence(capture_id, session.id, observed_at=at),
                )
            )

    if handshake is not None and tls_version and cipher and key_exchange:
        config_fp = tls_config_fingerprint(tls_version, cipher, key_exchange)
        config_key = normalize_evidence_key(f"tls-config|{config_fp}")
        if config_key is not None:
            out.append(
                _IndexEntry(
                    CorrelationType.SHARED_TLS_CONFIGURATION,
                    CorrelationStrength.DIRECT,
                    config_key,
                    {
                        "tls_version": tls_version,
                        "cipher_suite": cipher,
                        "key_exchange": key_exchange,
                        "config_fingerprint": config_fp,
                    },
                    Occurrence(capture_id, session.id, observed_at=at),
                )
            )
        sni = normalize_hostname(handshake.sni_server_name)
        if sni is not None:
            sni_key = normalize_evidence_key(f"sni|{sni}")
            if sni_key is not None:
                out.append(
                    _IndexEntry(
                        CorrelationType.SHARED_EVIDENCE,
                        CorrelationStrength.DERIVED,
                        sni_key,
                        {"subtype": "server_name_indication", "server_name": sni},
                        Occurrence(capture_id, session.id, observed_at=at),
                    )
                )

    pattern_key = normalize_evidence_key(
        "session-pattern|"
        f"{protocol or 'unknown'}|"
        f"implicit={session.implicit_tls}|"
        f"starttls={_starttls_state(session)}|"
        f"tls={tls_version or 'none'}|"
        f"complete={handshake.handshake_complete if handshake else 'none'}"
    )
    if pattern_key is not None:
        out.append(
            _IndexEntry(
                CorrelationType.REPEATED_SESSION_PATTERN,
                CorrelationStrength.DERIVED,
                pattern_key,
                {
                    "protocol": protocol or "unknown",
                    "implicit_tls": session.implicit_tls,
                    "starttls": _starttls_state(session),
                    "tls_version": tls_version or "none",
                    "handshake_complete": handshake.handshake_complete if handshake else None,
                },
                Occurrence(capture_id, session.id, observed_at=at),
            )
        )

    for certificate in session.certificates:
        fingerprint = normalize_fingerprint(certificate.fingerprint_sha256)
        if fingerprint is not None:
            cert_key = normalize_evidence_key(f"certificate|{fingerprint}")
            if cert_key is not None:
                out.append(
                    _IndexEntry(
                        CorrelationType.SHARED_CERTIFICATE,
                        CorrelationStrength.DIRECT,
                        cert_key,
                        {
                            "fingerprint_sha256": fingerprint,
                            "subject": certificate.subject,
                            "issuer": certificate.issuer,
                        },
                        Occurrence(capture_id, session.id, observed_at=at),
                    )
                )
        subject = normalize_subject(certificate.subject)
        if subject is not None:
            subject_key = normalize_evidence_key(f"certificate-subject|{subject}")
            if subject_key is not None:
                out.append(
                    _IndexEntry(
                        CorrelationType.SHARED_CERTIFICATE_SUBJECT,
                        CorrelationStrength.DERIVED,
                        subject_key,
                        {"subject": subject},
                        Occurrence(capture_id, session.id, observed_at=at),
                    )
                )
        issuer = normalize_subject(certificate.issuer)
        if issuer is not None:
            issuer_key = normalize_evidence_key(f"certificate-issuer|{issuer}")
            if issuer_key is not None:
                out.append(
                    _IndexEntry(
                        CorrelationType.SHARED_EVIDENCE,
                        CorrelationStrength.DERIVED,
                        issuer_key,
                        {"subtype": "certificate_issuer", "issuer": issuer},
                        Occurrence(capture_id, session.id, observed_at=at),
                    )
                )


def _index_finding(capture_id: str, finding: SecurityFinding, out: list[_IndexEntry]) -> None:
    """File one finding's deterministic rule identity into the indexes."""
    rule = (finding.rule_id or "").strip()
    if not rule or len(rule) > 128:
        return
    rule_key = normalize_evidence_key(f"finding-rule|{rule.lower()}")
    if rule_key is None:
        return
    capture = finding.capture_id or capture_id
    out.append(
        _IndexEntry(
            CorrelationType.SHARED_FINDING,
            CorrelationStrength.DIRECT,
            rule_key,
            {"rule_id": finding.rule_id, "severity": finding.severity.value},
            Occurrence(
                capture,
                finding.session_id or "",
                finding_id=finding.id,
                observed_at=(finding.detected_at.isoformat() if finding.detected_at else None),
            ),
        )
    )


def _index_anomaly(capture_id: str, anomaly: AnomalyView, out: list[_IndexEntry]) -> None:
    """File one flagged anomaly band into the indexes."""
    band = (anomaly.get("band") or anomaly.get("status") or "").strip().lower()
    if band not in FLAGGED_ANOMALY_BANDS:
        return
    band_key = normalize_evidence_key(f"anomaly-band|{band}")
    if band_key is None:
        return
    out.append(
        _IndexEntry(
            CorrelationType.SHARED_ANOMALY_PATTERN,
            CorrelationStrength.DERIVED,
            band_key,
            {"band": band},
            Occurrence(
                capture_id,
                anomaly.get("session_id", ""),
                anomaly_id=anomaly.get("anomaly_id"),
            ),
        )
    )


def _merge_evidence(entries: list[_IndexEntry]) -> dict[str, object]:
    """Combine per-occurrence evidence notes into one bounded summary."""
    merged: dict[str, object] = {}
    multi: dict[str, set[str]] = {}
    for entry in entries:
        for key, value in entry.evidence.items():
            if value is None:
                continue
            text = str(value)
            if key not in merged:
                merged[key] = text
            elif merged[key] != text:
                multi.setdefault(key, {str(merged[key])}).add(text)
    for key, values in multi.items():
        merged[f"{key}_observed"] = sorted(values)[:25]
    return merged


def correlate_case(case_id: str, captures: list[CaptureCorrelationInput]) -> CorrelationReport:
    """Correlate structured evidence across a case's captures.

    Single indexing pass over every record, then one relationship per
    index key observed in two or more captures. Deterministic: identical
    evidence always yields identical correlations in identical order.
    """
    entries: list[_IndexEntry] = []
    sessions_scanned = 0
    for capture in captures:
        for session in capture.sessions:
            sessions_scanned += 1
            _index_session(capture.capture_id, session, entries)
        for finding in capture.findings:
            _index_finding(capture.capture_id, finding, entries)
        for anomaly in capture.anomalies:
            _index_anomaly(capture.capture_id, anomaly, entries)

    grouped: dict[tuple[str, str], list[_IndexEntry]] = {}
    for entry in entries:
        grouped.setdefault((entry.correlation_type.value, entry.evidence_key), []).append(entry)

    correlations: list[Correlation] = []
    for (type_value, evidence_key), group in grouped.items():
        capture_ids = sorted({e.occurrence.capture_id for e in group})
        if len(capture_ids) < 2:
            continue  # single-capture pivots belong to the Stage 7 graph
        first = group[0]
        ordered = sorted(group, key=lambda e: (e.occurrence.capture_id, e.occurrence.session_id))
        source_ids = sorted(
            {
                "|".join(
                    part
                    for part in (
                        e.occurrence.capture_id,
                        e.occurrence.session_id,
                        e.occurrence.finding_id or "",
                        e.occurrence.anomaly_id or "",
                    )
                    if part
                )
                for e in group
            }
        )
        session_ids = sorted({e.occurrence.session_id for e in group if e.occurrence.session_id})
        stamps = sorted(
            {stamp for stamp in (e.occurrence.observed_at for e in group) if stamp is not None}
        )
        correlations.append(
            Correlation(
                correlation_id=correlation_id(case_id, type_value, evidence_key, source_ids),
                case_id=case_id,
                correlation_type=first.correlation_type,
                strength=first.strength,
                evidence_key=evidence_key,
                evidence=_merge_evidence(group),
                occurrence_count=len(group),
                capture_count=len(capture_ids),
                session_count=len(session_ids),
                source_capture_ids=tuple(capture_ids),
                source_session_ids=tuple(session_ids),
                occurrences=tuple(e.occurrence for e in ordered[:MAX_OCCURRENCES_PER_CORRELATION]),
                first_observed_at=stamps[0] if stamps else None,
                last_observed_at=stamps[-1] if stamps else None,
            )
        )

    correlations.sort(key=lambda c: (c.correlation_type.value, c.evidence_key))
    bounded = correlations[:MAX_CORRELATIONS_PER_CASE]
    return CorrelationReport(
        case_id=case_id,
        capture_ids=tuple(sorted({c.capture_id for c in captures})),
        correlations=tuple(bounded),
        sessions_scanned=sessions_scanned,
        index_keys=len(grouped),
    )


__all__ = [
    "FLAGGED_ANOMALY_BANDS",
    "AnomalyView",
    "CaptureCorrelationInput",
    "correlate_case",
]
