"""Stage 14 tests: longitudinal drift detection.

Covers the deterministic drift engine (ids, lifecycle, comparison
dimensions), observation/baseline model, the drift API (observations,
baseline, comparisons, drift, summary, remediation view), report and
export integration (schema 1.3 with 1.0-1.2 compatibility), AI
boundaries, security validation, evidence integrity, and a
performance regression.
"""

import json
from datetime import UTC, datetime

import pytest
from engine.core.certificate import CertificateEvidence
from engine.core.findings import FindingCategory, FindingSeverity, SecurityFinding
from engine.core.session import EmailProtocol, Session
from engine.core.tls import KeyExchange, TLSHandshake, TLSVersion
from engine.drift import (
    DriftRecord,
    DriftType,
    FindingLifecycle,
    build_observation,
    classify_lifecycle,
    compare_pair,
    drift_id,
    observation_id,
    posture_trend,
    summarize_drift,
)

_FP_A = "aa" * 32
_FP_B = "bb" * 32


def _session(
    index: int,
    capture_id: str,
    server_ip: str = "198.51.100.20",
    server_port: int = 25,
    protocol: EmailProtocol | None = EmailProtocol.SMTP,
    version: TLSVersion = TLSVersion.TLS_1_2,
    cipher: str = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    fingerprint: str | None = _FP_A,
    started: datetime | None = None,
) -> Session:
    handshake = TLSHandshake(
        session_id=f"session_{index:016x}",
        tls_version=version,
        cipher_suite=cipher,
        key_exchange=KeyExchange.ECDHE,
        handshake_complete=True,
    )
    certificates = []
    if fingerprint is not None:
        certificates.append(
            CertificateEvidence(
                session_id=f"session_{index:016x}",
                subject="mail.example.org",
                issuer="Synthetic Mail CA",
                serial_number="1000",
                not_before=datetime(2024, 1, 1, tzinfo=UTC),
                not_after=datetime(2040, 1, 1, tzinfo=UTC),
                signature_algorithm="sha256WithRSAEncryption",
                fingerprint_sha256=fingerprint,
            )
        )
    return Session(
        id=f"session_{index:016x}",
        capture_id=capture_id,
        client_ip="203.0.113.10",
        server_ip=server_ip,
        client_port=50000 + index,
        server_port=server_port,
        protocol=protocol,
        handshake=handshake,
        certificates=certificates,
        started_at=started or datetime(2024, 9, 27, 9, 0, index % 60, tzinfo=UTC),
    )


def _finding(
    index: int,
    capture_id: str,
    rule_id: str = "TLS-VERSION-001",
    session_index: int | None = None,
    severity: FindingSeverity = FindingSeverity.HIGH,
) -> SecurityFinding:
    # Fixed detected_at: the default is wall-clock time, which would make
    # determinism assertions meaningless on coarse host clocks. A None
    # session_index builds a capture-level finding (no session scope).
    return SecurityFinding(
        id=f"finding_{index:016x}",
        capture_id=capture_id,
        session_id=f"session_{session_index:016x}" if session_index is not None else None,
        title=f"Finding {rule_id}",
        description="Synthetic finding.",
        severity=severity,
        category=FindingCategory.HANDSHAKE,
        rule_id=rule_id,
        detected_at=datetime(2024, 9, 27, 9, 0, 0, tzinfo=UTC),
    )


def _observation(
    capture_id: str,
    sessions: list | None = None,
    findings: list | None = None,
    score: int | None = 80,
    state: str | None = "acceptable",
    bands: dict[str, int] | None = None,
):
    return build_observation(
        case_id="case_0123456789abcdef",
        capture_id=capture_id,
        analyzed=True,
        analysis_status="completed",
        analyzed_at="2024-09-27T09:00:00+00:00",
        sessions=sessions if sessions is not None else [],
        findings=findings if findings is not None else [],
        posture=({"posture_state": state, "overall_score": score} if state is not None else None),
        anomaly_summary=bands,
    )


class TestDriftModel:
    def test_drift_id_stable_and_scoped(self) -> None:
        first = drift_id("case_1", "cap_a", "cap_b", "posture_change", "posture|x->y")
        assert first.startswith("drift_")
        assert len(first) == len("drift_") + 16
        assert drift_id("case_1", "cap_a", "cap_b", "posture_change", "posture|x->y") == first
        assert drift_id("case_2", "cap_a", "cap_b", "posture_change", "posture|x->y") != first
        assert drift_id("case_1", "cap_a", "cap_c", "posture_change", "posture|x->y") != first
        assert drift_id("case_1", "cap_a", "cap_b", "posture_change", "posture|x->z") != first

    def test_observation_id_stable(self) -> None:
        first = observation_id("case_1", "cap_a", "digest")
        assert first.startswith("obs_")
        assert observation_id("case_1", "cap_a", "digest") == first
        assert observation_id("case_1", "cap_a", "other") != first

    def test_drift_type_vocabulary(self) -> None:
        assert {t.value for t in DriftType} == {
            "posture_change",
            "finding_introduced",
            "finding_resolved",
            "finding_recurred",
            "tls_configuration_changed",
            "certificate_changed",
            "certificate_validity_changed",
            "protocol_behavior_changed",
            "anomaly_state_changed",
            "correlation_pattern_changed",
        }
        assert {stage.value for stage in FindingLifecycle} == {
            "new",
            "persistent",
            "resolved",
            "recurred",
            "not_comparable",
        }


class TestLifecycleClassification:
    def test_matrix(self) -> None:
        assert classify_lifecycle("R", False, [], True, True) == FindingLifecycle.NEW
        assert classify_lifecycle("R", True, [], True, True) == FindingLifecycle.PERSISTENT
        assert classify_lifecycle("R", True, [], False, True) == FindingLifecycle.RESOLVED
        assert classify_lifecycle("R", False, [], False, True) == FindingLifecycle.NOT_COMPARABLE
        assert classify_lifecycle("R", True, [], True, False) == FindingLifecycle.NOT_COMPARABLE
        # Absent intermediate between two presences recurs.
        assert (
            classify_lifecycle("R", True, [(False, True)], True, True) == FindingLifecycle.RECURRED
        )
        # Non-comparable gaps do not establish recurrence.
        assert (
            classify_lifecycle("R", True, [(False, False)], True, True)
            == FindingLifecycle.PERSISTENT
        )
        # Intermediate presence without baseline presence is still new at target.
        assert classify_lifecycle("R", False, [(True, True)], True, True) == FindingLifecycle.NEW
        # Absent intermediate after a later re-observation still recurs.
        assert (
            classify_lifecycle("R", False, [(True, True), (False, True)], True, True)
            == FindingLifecycle.RECURRED
        )


class TestBuildObservation:
    def test_empty_capture(self) -> None:
        observation = _observation("capture_aaaaaaaaaaaa", sessions=[], findings=[])
        assert observation.finding_rules == ()
        assert observation.protocols == ()
        assert observation.tls_config_fingerprints == ()
        assert observation.certificates == ()
        assert observation.anomaly_bands is None
        assert observation.session_count == 0
        assert observation.observation_id.startswith("obs_")

    def test_grouping_and_strongest_severity(self) -> None:
        sessions = [_session(1, "capture_aaaaaaaaaaaa")]
        findings = [
            _finding(1, "capture_aaaaaaaaaaaa", "RULE-X", 1, FindingSeverity.LOW),
            _finding(2, "capture_aaaaaaaaaaaa", "RULE-X", 1, FindingSeverity.HIGH),
        ]
        observation = _observation("capture_aaaaaaaaaaaa", sessions, findings)
        assert len(observation.finding_rules) == 1
        rule = observation.finding_rules[0]
        assert rule.rule_id == "RULE-X"
        assert rule.severity == "high"
        assert rule.count == 2
        assert observation.protocols == ("smtp",)
        assert len(observation.tls_config_fingerprints) == 1
        assert len(observation.certificates) == 1

    def test_certificate_validity_reference(self) -> None:
        valid = _session(1, "capture_aaaaaaaaaaaa")
        expired = _session(
            2,
            "capture_bbbbbbbbbbbb",
            started=datetime(2041, 1, 1, tzinfo=UTC),
        )
        valid_obs = _observation("capture_aaaaaaaaaaaa", [valid], [])
        expired_obs = _observation("capture_bbbbbbbbbbbb", [expired], [])
        assert valid_obs.certificates[0].valid is True
        assert expired_obs.certificates[0].valid is False
        missing = _session(3, "capture_cccccccccccc")
        object.__setattr__(missing, "started_at", None)
        missing_obs = _observation("capture_cccccccccccc", [missing], [])
        assert missing_obs.certificates[0].valid is None

    def test_digest_stability(self) -> None:
        first = _observation(
            "capture_aaaaaaaaaaaa", [_session(1, "capture_aaaaaaaaaaaa")], [], bands={"normal": 1}
        )
        second = _observation(
            "capture_aaaaaaaaaaaa", [_session(1, "capture_aaaaaaaaaaaa")], [], bands={"normal": 1}
        )
        assert first.evidence_digest == second.evidence_digest
        assert first.observation_id == second.observation_id
        assert first.anomaly_bands == (("normal", 1),)


class TestComparePair:
    def _pair(self, later_sessions=None, later_findings=None, **kwargs):
        baseline = _observation(
            "capture_aaaaaaaaaaaa",
            [_session(1, "capture_aaaaaaaaaaaa")],
            [_finding(1, "capture_aaaaaaaaaaaa", "TLS-VERSION-001", 1)],
        )
        later = _observation(
            "capture_bbbbbbbbbbbb",
            later_sessions if later_sessions is not None else [_session(2, "capture_bbbbbbbbbbbb")],
            later_findings if later_findings is not None else [],
            **kwargs,
        )
        return compare_pair(
            case_id="case_0123456789abcdef",
            anchor=baseline,
            previous=baseline,
            later=later,
            intermediates=[],
            correlation_presence={},
            correlation_ids={},
        )

    def test_posture_change_and_statement(self) -> None:
        comparison, records = self._pair(score=100, state="healthy")
        kinds = {record.drift_type.value for record in records}
        assert "posture_change" in kinds
        posture = next(r for r in records if r.drift_type.value == "posture_change")
        assert posture.before == {"posture_state": "acceptable", "overall_score": 80}
        assert posture.after == {"posture_state": "healthy", "overall_score": 100}
        assert "changed from 80 to 100" in posture.statement
        assert comparison.posture_delta_points == 20
        assert "caused" not in comparison.posture_statement.lower()
        assert "improved" not in comparison.posture_statement.lower()

    def test_no_posture_change_when_equal(self) -> None:
        comparison, records = self._pair()
        assert comparison.posture_delta_points == 0
        assert "posture_change" not in {r.drift_type.value for r in records}

    def test_missing_posture_skips_dimension(self) -> None:
        comparison, records = self._pair(score=None, state=None)
        assert comparison.posture_delta_points is None
        assert "posture_change" not in {r.drift_type.value for r in records}

    def test_finding_lifecycle_rounds(self) -> None:
        # Introduced.
        _, introduced = self._pair(
            later_findings=[_finding(9, "capture_bbbbbbbbbbbb", "NEW-RULE", 2)]
        )
        assert any(
            r.drift_type.value == "finding_introduced" and r.evidence_key == "finding-rule|new-rule"
            for r in introduced
        )
        # Resolved (baseline rule absent later).
        comparison, resolved = self._pair(later_findings=[])
        assert any(r.drift_type.value == "finding_resolved" for r in resolved)
        rows = {row.rule_id: row.lifecycle.value for row in comparison.finding_lifecycle}
        assert rows["TLS-VERSION-001"] == "resolved"
        # Persistent rules are classified but emit no drift record.
        same = _finding(9, "capture_bbbbbbbbbbbb", "TLS-VERSION-001", 2)
        _, persistent = self._pair(later_findings=[same])
        assert "finding_recurred" not in {r.drift_type.value for r in persistent}
        assert "finding_introduced" not in {r.drift_type.value for r in persistent}
        assert "finding_resolved" not in {r.drift_type.value for r in persistent}

    def test_recurred_with_intermediate(self) -> None:
        anchor = _observation(
            "capture_aaaaaaaaaaaa",
            [_session(1, "capture_aaaaaaaaaaaa")],
            [_finding(1, "capture_aaaaaaaaaaaa", "TLS-VERSION-001", 1)],
        )
        middle = _observation("capture_bbbbbbbbbbbb", [_session(2, "capture_bbbbbbbbbbbb")], [])
        later = _observation(
            "capture_cccccccccccc",
            [_session(3, "capture_cccccccccccc")],
            [_finding(3, "capture_cccccccccccc", "TLS-VERSION-001", 3)],
        )
        _, records = compare_pair(
            case_id="case_0123456789abcdef",
            anchor=anchor,
            previous=middle,
            later=later,
            intermediates=[middle],
            correlation_presence={},
            correlation_ids={},
        )
        recurred = [r for r in records if r.drift_type.value == "finding_recurred"]
        assert len(recurred) == 1
        assert "may require review" not in recurred[0].statement
        assert recurred[0].regression_after_verification is False

    def test_not_comparable_unrelated(self) -> None:
        other = _session(
            2,
            "capture_bbbbbbbbbbbb",
            server_ip="198.51.100.99",
            server_port=993,
            protocol=EmailProtocol.IMAP,
        )
        comparison, records = self._pair(later_sessions=[other], later_findings=[])
        rows = {row.rule_id: row.lifecycle.value for row in comparison.finding_lifecycle}
        assert rows["TLS-VERSION-001"] == "not_comparable"
        assert "finding_resolved" not in {r.drift_type.value for r in records}

    def test_capture_level_rule(self) -> None:
        baseline = _observation(
            "capture_aaaaaaaaaaaa",
            [_session(1, "capture_aaaaaaaaaaaa")],
            [_finding(1, "capture_aaaaaaaaaaaa", "CAP-RULE", None)],
        )
        later = _observation("capture_bbbbbbbbbbbb", [_session(2, "capture_bbbbbbbbbbbb")], [])
        _, records = compare_pair(
            case_id="case_0123456789abcdef",
            anchor=baseline,
            previous=baseline,
            later=later,
            intermediates=[],
            correlation_presence={},
            correlation_ids={},
        )
        assert any(r.drift_type.value == "finding_resolved" for r in records)

    def test_tls_certificate_protocol_anomaly_dimensions(self) -> None:
        other = _session(
            2,
            "capture_bbbbbbbbbbbb",
            server_ip="198.51.100.20",
            server_port=25,
            version=TLSVersion.TLS_1_3,
            cipher="TLS_AES_128_GCM_SHA256",
            fingerprint=_FP_B,
        )
        records = self._pair(later_sessions=[other], later_findings=[])[1]
        kinds = {r.drift_type.value for r in records}
        assert "tls_configuration_changed" in kinds
        assert "certificate_changed" in kinds
        assert "protocol_behavior_changed" not in kinds  # smtp on both sides
        assert "anomaly_state_changed" not in kinds  # no summaries on either side
        tls_record = next(
            r
            for r in records
            if r.drift_type.value == "tls_configuration_changed" and r.after.get("present")
        )
        assert tls_record.after["tls_version"] == "TLS 1.3"

    def test_anomaly_distribution_change(self) -> None:
        _, records = self._pair(later_findings=[], bands={"normal": 9, "unusual": 1})
        # Baseline bands None -> skipped (unknown is not speculation).
        assert "anomaly_state_changed" not in {r.drift_type.value for r in records}
        baseline = _observation(
            "capture_aaaaaaaaaaaa", [_session(1, "capture_aaaaaaaaaaaa")], [], bands={"normal": 1}
        )
        later = _observation(
            "capture_bbbbbbbbbbbb",
            [_session(2, "capture_bbbbbbbbbbbb")],
            [],
            bands={"normal": 9, "unusual": 1},
        )
        _, fired = compare_pair(
            case_id="case_0123456789abcdef",
            anchor=baseline,
            previous=baseline,
            later=later,
            intermediates=[],
            correlation_presence={},
            correlation_ids={},
        )
        assert {r.drift_type.value for r in fired} == {"anomaly_state_changed"}
        anomaly = next(r for r in fired if r.drift_type.value == "anomaly_state_changed")
        assert anomaly.before["bands"] == {"normal": 1}
        assert anomaly.after["bands"] == {"normal": 9, "unusual": 1}

    def test_certificate_validity_change(self) -> None:
        early = _session(1, "capture_aaaaaaaaaaaa", started=datetime(2024, 1, 2, tzinfo=UTC))
        late = _session(2, "capture_bbbbbbbbbbbb", started=datetime(2041, 6, 1, tzinfo=UTC))
        baseline = _observation("capture_aaaaaaaaaaaa", [early], [])
        later = _observation("capture_bbbbbbbbbbbb", [late], [])
        assert baseline.certificates[0].valid is True
        assert later.certificates[0].valid is False
        _, records = compare_pair(
            case_id="case_0123456789abcdef",
            anchor=baseline,
            previous=baseline,
            later=later,
            intermediates=[],
            correlation_presence={},
            correlation_ids={},
        )
        validity = [r for r in records if r.drift_type.value == "certificate_validity_changed"]
        assert len(validity) == 1
        assert validity[0].before["valid"] is True
        assert validity[0].after["valid"] is False

    def test_correlation_pattern_change(self) -> None:
        baseline = _observation("capture_aaaaaaaaaaaa", [_session(1, "capture_aaaaaaaaaaaa")], [])
        later = _observation("capture_bbbbbbbbbbbb", [_session(2, "capture_bbbbbbbbbbbb")], [])
        presence = {("shared_certificate", "certificate|abc"): {"capture_aaaaaaaaaaaa"}}
        _, records = compare_pair(
            case_id="case_0123456789abcdef",
            anchor=baseline,
            previous=baseline,
            later=later,
            intermediates=[],
            correlation_presence=presence,
            correlation_ids={("shared_certificate", "certificate|abc"): "corr_0123456789abcdef"},
        )
        assert len(records) == 1
        record = records[0]
        assert record.drift_type.value == "correlation_pattern_changed"
        assert "no longer observed" in record.statement
        assert record.related_correlations[0]["correlation_id"] == "corr_0123456789abcdef"

    def test_unanalyzed_rejected(self) -> None:
        baseline = _observation("capture_aaaaaaaaaaaa", [_session(1, "capture_aaaaaaaaaaaa")], [])
        later = _observation("capture_bbbbbbbbbbbb", [], [])
        object.__setattr__(later, "analyzed", False)
        with pytest.raises(ValueError):
            compare_pair(
                case_id="case_0123456789abcdef",
                anchor=baseline,
                previous=baseline,
                later=later,
                intermediates=[],
                correlation_presence={},
                correlation_ids={},
            )

    def test_neutral_statements(self) -> None:
        comparison, records = self._pair(score=100, state="healthy")
        blob = json.dumps([r.to_dict() for r in records] + [comparison.to_dict()]).lower()
        for word in ("attacker", "malicious", "compromise", "threat", "caused", "secure"):
            assert word not in blob, word

    def test_deterministic_ordering(self) -> None:
        first = self._pair(score=100, state="healthy")[1]
        second = self._pair(score=100, state="healthy")[1]
        assert [r.drift_id for r in first] == [r.drift_id for r in second]
        keys = [(r.drift_type.value, r.evidence_key) for r in first]
        assert keys == sorted(keys)


class TestPostureTrend:
    def test_deltas_and_missing_scores(self) -> None:
        trend = posture_trend(
            [
                _observation("capture_aaaaaaaaaaaa", [], [], score=74, state="degraded"),
                _observation("capture_bbbbbbbbbbbb", [], [], score=100, state="healthy"),
                _observation("capture_cccccccccccc", [], [], score=None, state=None),
            ]
        )
        assert [t["score_change_points"] for t in trend] == [None, 26, None]
        assert [t["capture_id"] for t in trend] == [
            "capture_aaaaaaaaaaaa",
            "capture_bbbbbbbbbbbb",
            "capture_cccccccccccc",
        ]


def _upload_analyze_attach(client, case_id: str, name: str, pcap: bytes) -> str:
    """Upload, analyze, and attach one capture; returns its capture id."""
    created = client.post(
        "/api/captures",
        files={"file": (name, pcap, "application/octet-stream")},
    )
    assert created.status_code in (200, 201), created.text
    capture_id = created.json()["id"]
    analysis = client.post(f"/api/captures/{capture_id}/analyze")
    assert analysis.status_code == 200, analysis.text
    assert analysis.json()["status"] == "completed"
    attached = client.post(f"/api/cases/{case_id}/captures", json={"capture_id": capture_id})
    assert attached.status_code == 200, attached.text
    return capture_id


def _make_case(client, title: str = "Drift case") -> str:
    response = client.post(
        "/api/cases",
        json={"title": title, "description": "Stage 14 test case", "priority": "HIGH"},
    )
    assert response.status_code == 200, response.text
    return response.json()["case_id"]


def _make_three_capture_case(client) -> tuple[str, str, str, str]:
    """Deterministic A/B/C longitudinal case over the real pipeline."""
    from scripts.drift_fixtures import load_drift_scenarios

    case_id = _make_case(client)
    scenarios = {s.scenario_id: s for s in load_drift_scenarios()}
    aid = _upload_analyze_attach(
        client, case_id, scenarios["drift-capture-a"].filename, scenarios["drift-capture-a"].pcap
    )
    bid = _upload_analyze_attach(
        client, case_id, scenarios["drift-capture-b"].filename, scenarios["drift-capture-b"].pcap
    )
    cid = _upload_analyze_attach(
        client, case_id, scenarios["drift-capture-c"].filename, scenarios["drift-capture-c"].pcap
    )
    return case_id, aid, bid, cid


class TestDriftAPI:
    def test_observations_shape_and_order(self, make_api) -> None:
        client = make_api()
        case_id, aid, bid, cid = _make_three_capture_case(client)
        body = client.get(f"/api/cases/{case_id}/observations").json()
        assert body["case_id"] == case_id
        assert [o["capture_id"] for o in body["observations"]] == [aid, bid, cid]
        for observation in body["observations"]:
            assert observation["observation_id"].startswith("obs_")
            assert observation["analyzed"] is True
            assert observation["analysis_status"] == "completed"
            assert observation["posture_score"] is not None
            assert observation["posture_state"] is not None
        rules = {
            o["capture_id"]: sorted(r["rule_id"] for r in o["finding_rules"])
            for o in body["observations"]
        }
        assert rules[aid] == ["CERT-CHAIN-001", "CIPHER-SELECTED-001", "TLS-VERSION-001"]
        assert rules[bid] == []
        assert rules[cid] == [
            "CERT-CHAIN-001",
            "CERT-VALIDITY-001",
            "CIPHER-SELECTED-001",
            "TLS-VERSION-001",
        ]

    def test_baseline_select_read_clear(self, make_api) -> None:
        client = make_api()
        case_id, aid, _, _ = _make_three_capture_case(client)
        assert (
            client.get(f"/api/cases/{case_id}/observations/baseline").json()["baseline_capture_id"]
            is None
        )
        selected = client.post(
            f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid}
        )
        assert selected.status_code == 200, selected.text
        assert selected.json()["baseline_capture_id"] == aid
        assert (
            client.get(f"/api/cases/{case_id}/observations/baseline").json()["baseline_capture_id"]
            == aid
        )
        cleared = client.delete(f"/api/cases/{case_id}/observations/baseline")
        assert cleared.status_code == 204, cleared.text
        assert (
            client.get(f"/api/cases/{case_id}/observations/baseline").json()["baseline_capture_id"]
            is None
        )
        assert client.delete(f"/api/cases/{case_id}/observations/baseline").status_code == 404

    def test_baseline_rejects_unattached_and_unknown(self, make_api) -> None:
        client = make_api()
        case_id, _, _, _ = _make_three_capture_case(client)
        other = _make_case(client, "Other case")
        garbage = b"\xd4\xc3\xb2\xa1" + b"\x00" * 64
        foreign = client.post(
            "/api/captures",
            files={"file": ("foreign.pcap", garbage, "application/octet-stream")},
        )
        # Unregistered id format is rejected as unknown capture.
        assert (
            client.post(
                f"/api/cases/{case_id}/observations/baseline",
                json={"capture_id": "capture_0123456789ab"},
            ).status_code
            == 404
        )
        # A registered but unattached capture is rejected as invalid.
        from tests import tcp_fixtures as tf

        created = client.post(
            "/api/captures",
            files={"file": ("plain.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        ).json()
        client.post(f"/api/captures/{created['id']}/analyze")
        assert (
            client.post(
                f"/api/cases/{case_id}/observations/baseline",
                json={"capture_id": created["id"]},
            ).status_code
            == 422
        )
        assert foreign.status_code in (200, 201, 400, 413, 422)
        assert other.startswith("case_")

    def test_comparison_chain_and_explicit_pair(self, make_api) -> None:
        client = make_api()
        case_id, aid, bid, cid = _make_three_capture_case(client)
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        chain = client.get(f"/api/cases/{case_id}/comparisons").json()["comparisons"]
        assert [(c["previous_capture_id"], c["comparison_capture_id"]) for c in chain] == [
            (aid, bid),
            (bid, cid),
        ]
        for comparison in chain:
            assert comparison["lifecycle_anchor_capture_id"] == aid
            assert comparison["baseline_capture_id"] == aid
        lifecycle = {
            row["rule_id"]: row["lifecycle"]
            for row in next(c for c in chain if c["comparison_capture_id"] == cid)[
                "finding_lifecycle"
            ]
        }
        assert lifecycle == {
            "TLS-VERSION-001": "recurred",
            "CIPHER-SELECTED-001": "recurred",
            "CERT-CHAIN-001": "recurred",
            "CERT-VALIDITY-001": "new",
        }
        posted = client.post(
            f"/api/cases/{case_id}/comparisons",
            json={"baseline_capture_id": aid, "comparison_capture_id": cid},
        )
        assert posted.status_code == 200, posted.text
        validity = [
            d for d in posted.json()["drift"] if d["drift_type"] == "certificate_validity_changed"
        ]
        assert len(validity) == 1

    def test_comparison_rejections(self, make_api) -> None:
        client = make_api()
        case_id, aid, bid, _ = _make_three_capture_case(client)
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        assert (
            client.post(
                f"/api/cases/{case_id}/comparisons",
                json={"baseline_capture_id": aid, "comparison_capture_id": aid},
            ).status_code
            == 422
        )
        other = _make_case(client, "Other")
        from tests import tcp_fixtures as tf

        foreign = client.post(
            "/api/captures",
            files={"file": ("f.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        ).json()
        client.post(f"/api/captures/{foreign['id']}/analyze")
        client.post(f"/api/cases/{other}/captures", json={"capture_id": foreign["id"]})
        assert (
            client.post(
                f"/api/cases/{case_id}/comparisons",
                json={"baseline_capture_id": aid, "comparison_capture_id": foreign["id"]},
            ).status_code
            == 422
        )
        # Unanalyzed attachment cannot anchor a comparison.
        fresh = client.post(
            "/api/captures",
            files={"file": ("g.pcap", tf.imap_pcap(), "application/octet-stream")},
        ).json()
        if fresh["id"] != foreign["id"]:
            client.post(f"/api/cases/{case_id}/captures", json={"capture_id": fresh["id"]})
            assert (
                client.post(
                    f"/api/cases/{case_id}/comparisons",
                    json={"baseline_capture_id": aid, "comparison_capture_id": fresh["id"]},
                ).status_code
                == 422
            )
        assert bid.startswith("capture_")

    def test_drift_list_filters_pagination_and_detail(self, make_api) -> None:
        client = make_api()
        case_id, aid, bid, cid = _make_three_capture_case(client)
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        full = client.get(f"/api/cases/{case_id}/drift").json()
        assert full["total"] == len(full["drift"]) == 33
        recurred = client.get(
            f"/api/cases/{case_id}/drift", params={"type": "finding_recurred"}
        ).json()
        assert recurred["total"] == 3
        assert all(d["drift_type"] == "finding_recurred" for d in recurred["drift"])
        scoped = client.get(
            f"/api/cases/{case_id}/drift", params={"comparison_capture_id": bid}
        ).json()
        assert scoped["total"] == 16
        assert all(d["comparison_capture_id"] == bid for d in scoped["drift"])
        page = client.get(f"/api/cases/{case_id}/drift", params={"limit": 5, "offset": 5}).json()
        assert page["total"] == 33
        assert len(page["drift"]) == 5
        assert [d["drift_id"] for d in page["drift"]] == [d["drift_id"] for d in full["drift"]][
            5:10
        ]
        assert client.get(f"/api/cases/{case_id}/drift", params={"type": "nope"}).status_code == 422
        assert client.get(f"/api/cases/{case_id}/drift", params={"limit": 9999}).status_code == 422
        assert client.get(f"/api/cases/{case_id}/drift", params={"offset": -1}).status_code == 422
        sample = next(
            d
            for d in full["drift"]
            if d["drift_type"] == "finding_recurred"
            and d["evidence_key"] == "finding-rule|tls-version-001"
        )
        detail = client.get(f"/api/cases/{case_id}/drift/{sample['drift_id']}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["statement"] == sample["statement"]
        assert detail.json()["linked_remediations"] == []
        assert client.get(f"/api/cases/{case_id}/drift/drift_zzzz").status_code == 404
        assert client.get(f"/api/cases/{case_id}/drift/drift_0123456789abcdef").status_code == 404
        assert cid.startswith("capture_")

    def test_drift_summary_shape_and_counts(self, make_api) -> None:
        client = make_api()
        case_id, aid, _, _ = _make_three_capture_case(client)
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        summary = client.get(f"/api/cases/{case_id}/drift/summary").json()
        assert summary == {
            "case_id": case_id,
            "observations": 3,
            "baseline_capture_id": aid,
            "drift_count": 33,
            "posture_changes": 2,
            "new_findings": 1,
            "resolved_findings": 3,
            "recurring_findings": 3,
            "configuration_changes": 10,
            "anomaly_changes": 0,
            "by_type": summary["by_type"],
        }
        assert "risk" not in json.dumps(summary).lower()
        assert "threat" not in json.dumps(summary).lower()
        assert "score" not in set(summary)

    def test_remediation_regression_view(self, make_api) -> None:
        client = make_api()
        case_id, aid, bid, _ = _make_three_capture_case(client)
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        findings = client.get(f"/api/captures/{aid}/findings").json()
        target = next(f for f in findings if f["rule_id"] == "TLS-VERSION-001")
        remediation = client.post(
            f"/api/cases/{case_id}/remediations/from-finding",
            json={"finding_id": target["id"], "owner": "netops"},
        ).json()
        rid = remediation["remediation_id"]
        for status in ("PLANNED", "IN_PROGRESS"):
            assert (
                client.patch(
                    f"/api/cases/{case_id}/remediations/{rid}", json={"status": status}
                ).status_code
                == 200
            )
        verified = client.post(
            f"/api/cases/{case_id}/remediations/{rid}/verify",
            json={"mode": "evidence", "verification_capture_id": bid},
        ).json()
        assert verified["result"] == "VERIFIED"
        view = client.get(f"/api/cases/{case_id}/remediations/{rid}/drift").json()
        assert view["baseline_capture_id"] == aid
        assert view["verification_captures"] == [bid]
        assert view["current_lifecycle"] == "recurred"
        assert view["regression_detected"] is True
        assert view["related_drift_ids"]
        drift = client.get(f"/api/cases/{case_id}/drift").json()["drift"]
        recurred = next(
            d
            for d in drift
            if d["drift_type"] == "finding_recurred"
            and d["evidence_key"] == "finding-rule|tls-version-001"
        )
        assert rid in recurred["related_remediation_ids"]
        assert recurred["regression_after_verification"] is True
        assert "may require review" in recurred["statement"]
        detail = client.get(f"/api/cases/{case_id}/drift/{recurred['drift_id']}").json()
        assert detail["linked_remediations"][0]["remediation_id"] == rid
        # Remediation state itself is untouched by drift reads.
        assert client.get(f"/api/cases/{case_id}/remediations/{rid}").json()["status"] in (
            "IN_PROGRESS",
            "COMPLETED",
        )

    def test_correlation_pattern_change_present(self, make_api) -> None:
        client = make_api()
        case_id, aid, _, _ = _make_three_capture_case(client)
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        drift = client.get(f"/api/cases/{case_id}/drift").json()["drift"]
        pattern = [d for d in drift if d["drift_type"] == "correlation_pattern_changed"]
        assert len(pattern) == 14
        assert all(d["related_correlations"] for d in pattern)

    def test_report_export_bundle_integration(self, make_api) -> None:
        import io as _io
        import zipfile as _zipfile

        client = make_api()
        case_id, aid, _, _ = _make_three_capture_case(client)
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        report = client.get(f"/api/cases/{case_id}/report.json").json()
        assert report["longitudinal"]["drift_summary"]["recurring_findings"] == 3
        assert len(report["longitudinal"]["drift"]) == 33
        assert len(report["longitudinal"]["posture_trend"]) == 3
        assert "does not prove causality" in report["longitudinal"]["notice"]
        assert client.get(f"/api/cases/{case_id}/report.html").status_code == 200
        assert client.get(f"/api/cases/{case_id}/report.pdf").status_code == 200
        export = client.get(f"/api/cases/{case_id}/export").json()
        assert export["schema_version"] == "1.3"
        assert export["baseline"]["baseline_capture_id"] == aid
        assert len(export["observations"]) == 3
        assert len(export["drift"]) == 33
        assert len(export["comparisons"]) == 2
        bundle = client.get(f"/api/cases/{case_id}/bundle").content
        names = set(_zipfile.ZipFile(_io.BytesIO(bundle)).namelist())
        assert names == {
            "case.json",
            "README.txt",
            "evidence-manifest.json",
            "reports/case-report.json",
        }
        imported = client.post("/api/cases/import", json=export)
        assert imported.status_code == 200, imported.text
        fresh = client.get(f"/api/cases/{imported.json()['case_id']}/export").json()
        assert fresh["baseline"]["baseline_capture_id"] == aid
        assert len(fresh["drift"]) == 33
        assert all(not d.get("related_remediation_ids") for d in fresh["drift"])
        # Malformed imported drift sections are rejected, never trusted.
        bad = dict(export)
        bad["drift"] = "not-a-list"
        assert client.post("/api/cases/import", json=bad).status_code == 422


class TestDriftSecurity:
    _TRAVERSAL: tuple[str, ...] = (
        "../registry.sqlite3",
        "..\\registry.sqlite3",
        "case_' OR '1'='1",
        "case_<script>",
        "capture_abc",
        "CASE_DEADBEEFDEADBEEF",
    )

    def test_malformed_ids_are_structured_404s(self, make_api) -> None:
        client = make_api()
        case_id, aid, _, _ = _make_three_capture_case(client)
        for bad in self._TRAVERSAL:
            for path in (
                f"/api/cases/{bad}/observations",
                f"/api/cases/{bad}/drift/summary",
                f"/api/cases/{bad}/comparisons",
            ):
                response = client.get(path)
                assert response.status_code == 404, (path, response.text)
                # Ids containing path separators never match a route and
                # surface the generic shape; all other malformed ids map
                # to the structured case error.
                assert response.json()["error"]["code"] in ("case_not_found", "not_found")
            response = client.get(f"/api/cases/{case_id}/drift/{bad}")
            assert response.status_code == 404, (bad, response.text)
            assert response.json()["error"]["code"] in ("drift_not_found", "not_found")
        assert aid.startswith("capture_")

    def test_oversized_and_hostile_inputs_rejected(self, make_api) -> None:
        client = make_api()
        case_id, aid, _, _ = _make_three_capture_case(client)
        assert client.post(
            f"/api/cases/{case_id}/observations/baseline",
            json={"capture_id": "x" * 5000},
        ).status_code in (404, 422)
        assert (
            client.get(f"/api/cases/{case_id}/drift", params={"type": "x" * 5000}).status_code
            == 422
        )
        assert (
            client.post(
                f"/api/cases/{case_id}/comparisons",
                json={"baseline_capture_id": aid, "comparison_capture_id": "x" * 5000},
            ).status_code
            == 422
        )

    def test_no_secret_or_payload_leakage(self, make_api) -> None:
        client = make_api()
        case_id, aid, _, _ = _make_three_capture_case(client)
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        blob = json.dumps(
            {
                "observations": client.get(f"/api/cases/{case_id}/observations").json(),
                "drift": client.get(f"/api/cases/{case_id}/drift").json(),
                "summary": client.get(f"/api/cases/{case_id}/drift/summary").json(),
                "comparisons": client.get(f"/api/cases/{case_id}/comparisons").json(),
                "export": client.get(f"/api/cases/{case_id}/export").json(),
            },
            default=str,
        ).lower()
        for marker in (
            "password",
            "passwd",
            "api_key",
            "apikey",
            "secret",
            "private key",
            "begin rsa",
            "traceback",
            "select ",
            "/app/",
            "body must not appear",
        ):
            assert marker not in blob, marker

    def test_comparison_language_stays_neutral(self, make_api) -> None:
        from tests import tcp_fixtures as tf

        client = make_api()
        case_id = _make_case(client)
        first = _upload_analyze_attach(client, case_id, "a.pcap", tf.unknown_protocol_pcap())
        second = _upload_analyze_attach(client, case_id, "b.pcap", tf.smtp_plain_pcap())
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": first})
        posted = client.post(
            f"/api/cases/{case_id}/comparisons",
            json={"baseline_capture_id": first, "comparison_capture_id": second},
        )
        assert posted.status_code == 200, posted.text
        blob = json.dumps(posted.json(), default=str).lower()
        for word in ("attacker", "malicious", "compromise", "threat", "caused", "secure"):
            assert word not in blob, word
        # Posture values are quoted verbatim from the Stage 5 snapshots.
        comparison = posted.json()
        for capture_id in (first, second):
            quoted = client.get(f"/api/captures/{capture_id}/posture").json()
            side = (
                comparison["posture_before"]
                if comparison["previous_capture_id"] == capture_id
                else comparison["posture_after"]
            )
            assert side["overall_score"] == quoted["overall_score"]
            assert side["posture_state"] == quoted["posture_state"]


class TestDriftIntegrity:
    def test_longitudinal_reads_leave_evidence_identical(self, make_api) -> None:
        client = make_api()
        case_id, aid, bid, cid = _make_three_capture_case(client)

        def snapshot():
            state = {}
            for capture_id in (aid, bid, cid):
                state[capture_id] = {
                    "findings": client.get(f"/api/captures/{capture_id}/findings").json(),
                    "posture": client.get(f"/api/captures/{capture_id}/posture").json(),
                    "anomalies": client.get(f"/api/captures/{capture_id}/anomalies").json(),
                    "graph": client.get(f"/api/captures/{capture_id}/graph").json(),
                }
            return json.dumps(state, sort_keys=True, default=str)

        before = snapshot()
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        client.get(f"/api/cases/{case_id}/observations")
        client.get(f"/api/cases/{case_id}/comparisons")
        client.post(
            f"/api/cases/{case_id}/comparisons",
            json={"baseline_capture_id": aid, "comparison_capture_id": cid},
        )
        client.get(f"/api/cases/{case_id}/drift")
        client.get(f"/api/cases/{case_id}/drift/summary")
        client.get(f"/api/cases/{case_id}/report.json")
        client.get(f"/api/cases/{case_id}/export")
        client.get(f"/api/cases/{case_id}/bundle")
        assert snapshot() == before

    def test_ai_history_never_becomes_drift_evidence(self, make_api) -> None:
        client = make_api()
        case_id, aid, _, _ = _make_three_capture_case(client)
        client_ai = make_api(ai_provider="mock")
        assert client_ai is not None  # isolated app honors provider wiring
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid})
        before = client.get(f"/api/cases/{case_id}/drift").json()
        sessions = client.get(f"/api/captures/{aid}/sessions").json()
        answered = client.post(
            "/api/ai/query",
            json={"session_id": sessions[0]["id"], "question": "Explain this session."},
        )
        assert answered.status_code == 200, answered.text
        after = client.get(f"/api/cases/{case_id}/drift").json()
        assert before == after


class TestDriftPerformance:
    def test_indexed_chain_scales_linearly(self, make_api) -> None:
        """Controlled regression: N observations -> N-1 comparisons, bounded time."""
        import time as _time

        from tests.tcp_fixtures import FrameConversation

        def variant(port: int) -> bytes:
            b = FrameConversation(client=("10.10.0.23", port))
            (
                b.syn()
                .synack()
                .ack()
                .s(b"220 mail.example.org ESMTP Postfix\r\n")
                .c(b"EHLO client.example.net\r\n")
                .s(b"250-mail.example.org\r\n250-PIPELINING\r\n250 8BITMIME\r\n")
                .c(b"MAIL FROM:<alice@example.net>\r\n")
                .s(b"250 2.1.0 Ok\r\n")
                .c(b"RCPT TO:<bob@example.org>\r\n")
                .s(b"250 2.1.5 Ok\r\n")
                .c(b"DATA\r\n")
                .s(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                .c(b"Subject: Perf\r\n\r\nBody must not appear in evidence.\r\n.\r\n")
                .s(b"250 2.0.0 Ok: queued\r\n")
                .c(b"QUIT\r\n")
                .s(b"221 2.0.0 Bye\r\n")
                .fin_c()
                .fin_s()
            )
            return b.to_pcap()

        client = make_api()
        case_id = _make_case(client, "Perf case")
        count = 8
        ids = [
            _upload_analyze_attach(client, case_id, f"perf-{index}.pcap", variant(41000 + index))
            for index in range(count)
        ]
        client.post(f"/api/cases/{case_id}/observations/baseline", json={"capture_id": ids[0]})
        started = _time.perf_counter()
        comparisons = client.get(f"/api/cases/{case_id}/comparisons").json()["comparisons"]
        drift = client.get(f"/api/cases/{case_id}/drift").json()
        duration_ms = (_time.perf_counter() - started) * 1000
        assert len(comparisons) == count - 1
        assert drift["total"] == len(drift["drift"])
        assert duration_ms < 5000, f"drift chain took {duration_ms:.1f}ms"
        assert len({c["comparison_capture_id"] for c in comparisons}) == count - 1


class TestSummarizeDrift:
    def test_counts_and_keys(self) -> None:
        records = [
            DriftRecord(
                drift_id="drift_1",
                case_id="case_1",
                drift_type=DriftType.POSTURE_CHANGE,
                evidence_key="posture|x",
                baseline_capture_id="a",
                comparison_capture_id="b",
            ),
            DriftRecord(
                drift_id="drift_2",
                case_id="case_1",
                drift_type=DriftType.FINDING_RECURRED,
                evidence_key="finding-rule|x",
                baseline_capture_id="a",
                comparison_capture_id="b",
            ),
        ]
        summary = summarize_drift("case_1", "a", 3, records)
        assert summary == {
            "case_id": "case_1",
            "observations": 3,
            "baseline_capture_id": "a",
            "drift_count": 2,
            "posture_changes": 1,
            "new_findings": 0,
            "resolved_findings": 0,
            "recurring_findings": 1,
            "configuration_changes": 0,
            "anomaly_changes": 0,
            "by_type": {"finding_recurred": 1, "posture_change": 1},
        }
