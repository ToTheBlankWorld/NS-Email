"""Posture model tests: scoring, correlation, determinism, edge cases.

Reference values (from the documented formula, ADR 005):

    severity weights: critical 40, high 25, medium 12, low 5, info 0
    confidence mult:  high 1.0, medium 0.75, low 0.5, unknown 0.25
    prevalence mult:  0.5 + 0.5 x (affected / total)
    factor deduction: max + 25% breadth over remaining conditions
    score:            round(100 - sum of factor deductions), clamped
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from engine.core.findings import (
    EvidenceRef,
    FindingCategory,
    FindingSeverity,
    Remediation,
    SecurityFinding,
    StandardReference,
)
from engine.core.session import Confidence, EmailProtocol, Session
from engine.detection import load_builtin_policy
from engine.detection.posture import (
    ANALYSIS_VERSION,
    PostureState,
    build_posture,
)

POLICY = load_builtin_policy()
CAPTURE_ID = "capture_aaaaaaaaaaaa"
T0 = datetime(2024, 9, 27, 9, 40, 0, tzinfo=UTC)


def make_session(
    session_id: str = "session_" + "a" * 16,
    server_ip: str = "198.51.100.7",
    protocol: EmailProtocol | None = EmailProtocol.SMTP,
    **overrides: Any,
) -> Session:
    defaults: dict[str, Any] = {
        "id": session_id,
        "capture_id": CAPTURE_ID,
        "client_ip": "10.10.0.23",
        "server_ip": server_ip,
        "client_port": 49152,
        "server_port": 587,
        "protocol": protocol,
        "started_at": T0,
        "ended_at": T0 + timedelta(seconds=10),
    }
    defaults.update(overrides)
    return Session(**defaults)


def make_finding(
    rule_id: str,
    severity: FindingSeverity,
    *,
    session_id: str = "session_" + "a" * 16,
    observed_value: str = "observed",
    confidence: Confidence = Confidence.HIGH,
    packets: list[int] | None = None,
    protocol: str | None = "smtp",
) -> SecurityFinding:
    return SecurityFinding(
        capture_id=CAPTURE_ID,
        session_id=session_id,
        protocol=protocol,
        title=f"Finding {rule_id}",
        description="Deterministic test finding.",
        severity=severity,
        confidence=confidence,
        category=FindingCategory.OTHER,
        rule_id=rule_id,
        evidence_refs=[EvidenceRef(source="ServerHello", packet_numbers=packets or [7])],
        observed_value=observed_value,
        expected_value=None,
        remediation=Remediation(action="Fix it", target=None, rationale=None, priority=None),
        standard_reference=StandardReference(name="Test"),
        first_packet=(packets or [7])[0],
        last_packet=(packets or [7])[-1],
        detected_at=T0 + timedelta(seconds=5),
    )


# ---------------------------------------------------------------------------
# Deterministic posture
# ---------------------------------------------------------------------------


def test_same_input_produces_identical_snapshot() -> None:
    sessions = [make_session(), make_session(session_id="session_" + "b" * 16)]
    findings = [make_finding("TLS-VERSION-001", FindingSeverity.HIGH)]

    first = build_posture(CAPTURE_ID, sessions, findings, POLICY)
    second = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    assert first == second  # full dataclass equality, including generated_at


def test_posture_carries_versions_and_identity() -> None:
    posture = build_posture(CAPTURE_ID, [make_session()], [], POLICY)

    assert posture.analysis_version == ANALYSIS_VERSION
    assert posture.policy_id == "securemailscope-baseline"
    assert posture.policy_version == "1.0"
    assert posture.capture_id == CAPTURE_ID


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def test_no_findings_scores_healthy_100() -> None:
    posture = build_posture(CAPTURE_ID, [make_session()], [], POLICY)

    assert posture.overall_score == 100
    assert posture.posture_state == PostureState.HEALTHY.value
    assert posture.affected_sessions == 0


def test_single_high_finding_one_of_two_sessions() -> None:
    sessions = [make_session(), make_session(session_id="session_" + "b" * 16)]
    findings = [make_finding("TLS-VERSION-001", FindingSeverity.HIGH)]
    # deduction = 25 (high) x 1.0 (confidence) x (0.5 + 0.5 x 0.5) = 18.75

    posture = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    assert posture.overall_score == 100 - round(18.75)
    assert posture.posture_state == PostureState.ACCEPTABLE.value
    assert posture.affected_sessions == 1
    assert posture.affected_hosts == 1


def test_full_prevalence_amplifies_the_deduction() -> None:
    # 1/1 sessions affected (100% prevalence) costs more than 1/2 (50%).
    single_sessions = [make_session()]
    single_findings = [
        make_finding(
            "TLS-VERSION-001",
            FindingSeverity.HIGH,
            session_id=single_sessions[0].id,
        )
    ]
    both_sessions = [
        make_session(),
        make_session(session_id="session_" + "b" * 16),
    ]
    both_findings = [
        make_finding(
            "TLS-VERSION-001",
            FindingSeverity.HIGH,
            session_id=both_sessions[0].id,
        )
    ]

    single = build_posture(CAPTURE_ID, single_sessions, single_findings, POLICY)
    both = build_posture(CAPTURE_ID, both_sessions, both_findings, POLICY)

    assert single.overall_score is not None and both.overall_score is not None
    assert both.overall_score > single.overall_score  # 50% prevalence costs less
    # documented values: 25 x 0.75 = 18.75 vs 25 x 1.0 = 25
    assert single.overall_score == 75
    assert both.overall_score == 81


def test_all_critical_sessions_reach_critical_exposure() -> None:
    sessions = [
        make_session(session_id=f"session_{chr(97 + i) * 16}", server_ip=f"10.0.0.{i}")
        for i in range(4)
    ]
    findings = [
        make_finding(
            "CERT-SIG-001",
            FindingSeverity.CRITICAL,
            session_id=session.id,
            observed_value="md5 signature",  # one shared condition, 4 sessions
        )
        for session in sessions
    ]

    posture = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    assert posture.overall_score is not None
    assert posture.overall_score < 40
    assert posture.posture_state == PostureState.CRITICAL_EXPOSURE.value


def test_all_informational_findings_keep_healthy_score() -> None:
    sessions = [make_session()]
    findings = [make_finding("FS-001", FindingSeverity.INFO, observed_value="unknown")]

    posture = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    assert posture.overall_score == 100
    assert posture.posture_state == PostureState.HEALTHY.value


def test_low_confidence_finding_deduction_is_reduced() -> None:
    sessions = [make_session()]
    high_conf = make_finding("CERT-VALIDITY-001", FindingSeverity.HIGH, confidence=Confidence.HIGH)
    low_conf = make_finding(
        "CERT-VALIDITY-001",
        FindingSeverity.HIGH,
        confidence=Confidence.LOW,
        observed_value="observed-low",
    )

    full = build_posture(CAPTURE_ID, sessions, [high_conf], POLICY)
    reduced = build_posture(CAPTURE_ID, sessions, [low_conf], POLICY)

    assert full.overall_score is not None and reduced.overall_score is not None
    assert full.overall_score < reduced.overall_score  # low confidence costs less


def test_score_is_clamped_at_zero() -> None:
    sessions = [make_session()]
    findings = [
        make_finding(
            "CERT-SIG-001",
            FindingSeverity.CRITICAL,
            observed_value=f"md5-{i}",
        )
        for i in range(10)  # far more deduction weight than the 100-point budget
    ]

    posture = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    assert posture.overall_score == 0
    assert posture.posture_state == PostureState.CRITICAL_EXPOSURE.value


# ---------------------------------------------------------------------------
# Correlation (factor breadth)
# ---------------------------------------------------------------------------


def test_correlated_conditions_cost_less_than_their_sum() -> None:
    sessions = [make_session()]
    tls_version = make_finding("TLS-VERSION-001", FindingSeverity.HIGH)
    legacy_cipher = make_finding(
        "CIPHER-SELECTED-001",
        FindingSeverity.LOW,
        observed_value="legacy-cipher",
    )

    with_version = build_posture(CAPTURE_ID, sessions, [tls_version], POLICY)
    with_both = build_posture(CAPTURE_ID, sessions, [tls_version, legacy_cipher], POLICY)

    assert with_version.overall_score is not None
    assert with_both.overall_score is not None
    added_cost = with_version.overall_score - with_both.overall_score
    # full price of the low finding would be 5 points; the 25% breadth rule
    # costs 1.25 which rounds to 1 at the integer score
    assert added_cost == 1


def test_correlated_findings_share_one_factor() -> None:
    sessions = [make_session()]
    findings = [
        make_finding("TLS-VERSION-001", FindingSeverity.HIGH),
        make_finding(
            "CIPHER-SELECTED-001",
            FindingSeverity.LOW,
            observed_value="legacy-cipher",
        ),
    ]

    posture = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    tls_factors = [f for f in posture.factors if f.factor == "tls_configuration"]
    assert len(tls_factors) == 1
    assert tls_factors[0].score_contribution > 0
    assert len(tls_factors[0].contributing_finding_ids) == 2


def test_independent_factors_sum() -> None:
    sessions = [make_session()]
    tls_version = make_finding("TLS-VERSION-001", FindingSeverity.HIGH)
    weak_key = make_finding(
        "CERT-KEY-001",
        FindingSeverity.HIGH,
        observed_value="RSA 1024 bits",
    )

    posture = build_posture(CAPTURE_ID, sessions, [tls_version, weak_key], POLICY)

    assert posture.overall_score == 100 - 25 - 25  # different factors sum fully
    factors = {f.factor: f.score_contribution for f in posture.factors}
    assert factors["tls_configuration"] == 25.0
    assert factors["certificates"] == 25.0


# ---------------------------------------------------------------------------
# Aggregations
# ---------------------------------------------------------------------------


def test_host_aggregation_by_server_endpoint() -> None:
    sessions = [
        make_session(),
        make_session(session_id="session_" + "b" * 16),
        make_session(
            session_id="session_" + "c" * 16,
            server_ip="198.51.100.8",
        ),
    ]
    findings = [
        make_finding("TLS-VERSION-001", FindingSeverity.HIGH),
        make_finding(
            "TLS-VERSION-001",
            FindingSeverity.HIGH,
            session_id="session_" + "b" * 16,
            observed_value="observed-b",
        ),
    ]

    posture = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    assert posture.total_hosts == 2
    assert posture.affected_hosts == 1
    host_a = next(h for h in posture.hosts if h.ip == "198.51.100.7")
    assert host_a.sessions == 2
    assert host_a.findings_count == 2
    assert host_a.highest_severity == "high"
    assert host_a.affected is True
    host_b = next(h for h in posture.hosts if h.ip == "198.51.100.8")
    assert host_b.findings_count == 0
    assert host_b.highest_severity is None
    assert host_b.affected is False


def test_protocol_aggregation() -> None:
    sessions = [
        make_session(),
        make_session(session_id="session_" + "b" * 16, protocol=EmailProtocol.IMAP),
    ]
    findings = [
        make_finding("TLS-VERSION-001", FindingSeverity.HIGH),
        make_finding(
            "PLAINTEXT-001",
            FindingSeverity.MEDIUM,
            session_id="session_" + "b" * 16,
            observed_value="no TLS",
            protocol="imap",
        ),
    ]

    posture = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    by_protocol = {p.protocol: p for p in posture.protocols}
    assert by_protocol["smtp"].sessions == 1
    assert by_protocol["smtp"].findings == 1
    assert by_protocol["imap"].sessions == 1
    assert by_protocol["imap"].findings == 1
    assert by_protocol["imap"].affected_sessions == 1


def test_unknown_protocol_sessions_excluded_from_protocol_breakdown() -> None:
    session = make_session(protocol=None)

    posture = build_posture(CAPTURE_ID, [session], [], POLICY)

    assert posture.protocols == []


# ---------------------------------------------------------------------------
# Priority model
# ---------------------------------------------------------------------------


def test_priorities_consider_prevalence_not_severity_alone() -> None:
    sessions = [make_session(), make_session(session_id="session_" + "b" * 16)]
    prevalent_high = make_finding(
        "TLS-VERSION-001", FindingSeverity.HIGH, session_id=sessions[1].id
    )
    isolated_medium = make_finding(
        "PLAINTEXT-001",
        FindingSeverity.MEDIUM,
        session_id=sessions[1].id,
        observed_value="no TLS",
        protocol="smtp",
    )

    posture = build_posture(CAPTURE_ID, sessions, [prevalent_high, isolated_medium], POLICY)

    top = posture.priorities[0]
    assert top.rule_id == "TLS-VERSION-001"  # high + 50% prevalence outranks
    assert top.priority_score >= posture.priorities[1].priority_score
    assert "prevalence" in top.explanation
    assert f"{top.affected_sessions}/{top.total_sessions}" in top.explanation


def test_priorities_are_deterministic_and_tie_break_by_rule() -> None:
    sessions = [make_session()]
    findings = [
        make_finding(
            "PLAINTEXT-001", FindingSeverity.MEDIUM, observed_value="no TLS", protocol="smtp"
        ),
        make_finding(
            "CERT-KEY-001",
            FindingSeverity.MEDIUM,
            observed_value="RSA 1024 bits",
            protocol="smtp",
        ),
    ]

    first = build_posture(CAPTURE_ID, sessions, findings, POLICY)
    second = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    order_first = [p.rule_id for p in first.priorities]
    order_second = [p.rule_id for p in second.priorities]
    assert order_first == order_second
    assert [p.priority_score for p in first.priorities] == [
        p.priority_score for p in second.priorities
    ]


# ---------------------------------------------------------------------------
# Explanations
# ---------------------------------------------------------------------------


def test_explanation_cites_factors_and_priorities() -> None:
    sessions = [make_session()]
    findings = [
        make_finding(
            "AUTH-PLAINTEXT-001",
            FindingSeverity.HIGH,
            observed_value="AUTH",
        )
    ]

    posture = build_posture(CAPTURE_ID, sessions, findings, POLICY)

    assert any("Authentication" in line for line in posture.explanation)
    assert any(line.startswith("Priority 1:") for line in posture.explanation)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_zero_sessions_is_insufficient_evidence() -> None:
    posture = build_posture(CAPTURE_ID, [], [], POLICY)

    assert posture.posture_state == PostureState.INSUFFICIENT_EVIDENCE.value
    assert posture.overall_score is None
    assert posture.total_sessions == 0


def test_one_session_minimum_viable_posture() -> None:
    posture = build_posture(CAPTURE_ID, [make_session()], [], POLICY)

    assert posture.total_sessions == 1
    assert posture.overall_score == 100
    assert posture.posture_state == PostureState.HEALTHY.value


def test_missing_session_timestamps_do_not_crash() -> None:
    session = make_session(started_at=None, ended_at=None)
    finding = make_finding("TLS-VERSION-001", FindingSeverity.HIGH)

    posture = build_posture(CAPTURE_ID, [session], [finding], POLICY)

    assert posture.overall_score is not None
