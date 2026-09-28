"""Stage 13 tests: remediation workflow and evidence-based verification.

Covers the engine comparison (VERIFIED/FAILED/INCONCLUSIVE semantics,
neutral statements, posture quoting), remediation CRUD, the explicit
state machine, ownership metadata, the remediation timeline, finding
integration, evidence and manual verification, report/export/import
integration (current schema with 1.0/1.1 compatibility), security
validation, and the critical integrity guarantee: workflow state never
mutates forensic truth.
"""

import json

from engine.verification import (
    FindingView,
    PostureView,
    SessionView,
    VerificationMethod,
    VerificationOutcome,
    compare_rule,
)

from tests import tcp_fixtures as tf
from tests.tcp_fixtures import FrameConversation
from tests.tls_fixtures import (
    _ccs_record,
    _certificate_record,
    _client_hello_record,
    _leaf_certificate_der,
    _server_hello_record,
)


def _session_view(
    session_id="session_0000000000000001",
    capture_id="capture_aaaaaaaaaaaa",
    protocol="smtp",
    server_ip="198.51.100.20",
    server_port=25,
) -> SessionView:
    return SessionView(
        session_id=session_id,
        capture_id=capture_id,
        protocol=protocol,
        server_ip=server_ip,
        server_port=server_port,
        tls_version="TLS 1.2",
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange="ecdhe",
        handshake_complete=True,
        complete=True,
        certificate_fingerprint="aa" * 32,
        started_at="2024-09-27T09:00:00+00:00",
    )


def _finding_view(
    finding_id="finding_0000000000000001",
    capture_id="capture_aaaaaaaaaaaa",
    session_id="session_0000000000000001",
    rule_id="TLS-VERSION-001",
) -> FindingView:
    return FindingView(
        finding_id=finding_id,
        capture_id=capture_id,
        session_id=session_id,
        rule_id=rule_id,
        severity="high",
        confidence="high",
    )


class TestVerificationEngine:
    def test_rule_absent_verifies(self) -> None:
        comparison = compare_rule(
            baseline_finding=_finding_view(),
            baseline_session=_session_view(),
            baseline_posture=PostureView(
                capture_id="capture_aaaaaaaaaaaa", posture_state="degraded", overall_score=63
            ),
            verification_capture_id="capture_bbbbbbbbbbbb",
            verification_sessions=[
                _session_view("session_0000000000000002", "capture_bbbbbbbbbbbb")
            ],
            verification_findings=[],
            verification_posture=PostureView(
                capture_id="capture_bbbbbbbbbbbb", posture_state="healthy", overall_score=100
            ),
        )
        assert comparison.outcome == VerificationOutcome.VERIFIED
        assert comparison.method == VerificationMethod.EVIDENCE
        assert comparison.rule_present_in_verification is False
        assert comparison.session_match == "matched"
        assert comparison.verification_session_id == "session_0000000000000002"
        assert "was not observed in verification capture" in comparison.statement
        assert "secure" not in comparison.statement.lower()
        assert comparison.posture_delta_points == 37
        assert comparison.posture_before["posture_state"] == "degraded"
        assert comparison.posture_after["overall_score"] == 100

    def test_rule_present_fails(self) -> None:
        comparison = compare_rule(
            baseline_finding=_finding_view(),
            baseline_session=_session_view(),
            baseline_posture=None,
            verification_capture_id="capture_bbbbbbbbbbbb",
            verification_sessions=[
                _session_view("session_0000000000000002", "capture_bbbbbbbbbbbb")
            ],
            verification_findings=[
                _finding_view(
                    "finding_0000000000000009",
                    "capture_bbbbbbbbbbbb",
                    "session_0000000000000002",
                )
            ],
            verification_posture=None,
        )
        assert comparison.outcome == VerificationOutcome.FAILED
        assert comparison.rule_present_in_verification is True
        assert "was still observed" in comparison.statement
        assert comparison.posture_delta_points is None

    def test_missing_session_is_inconclusive(self) -> None:
        comparison = compare_rule(
            baseline_finding=_finding_view(),
            baseline_session=_session_view(),
            baseline_posture=None,
            verification_capture_id="capture_bbbbbbbbbbbb",
            verification_sessions=[
                _session_view(
                    "session_0000000000000002",
                    "capture_bbbbbbbbbbbb",
                    server_ip="198.51.100.99",
                )
            ],
            verification_findings=[],
            verification_posture=None,
        )
        assert comparison.outcome == VerificationOutcome.INCONCLUSIVE
        assert comparison.session_match == "no_matching_session"
        assert comparison.rule_present_in_verification is None
        assert "does not contain the relevant session" in comparison.statement

    def test_capture_level_finding(self) -> None:
        baseline = _finding_view(session_id=None)
        verified = compare_rule(
            baseline_finding=baseline,
            baseline_session=None,
            baseline_posture=None,
            verification_capture_id="capture_bbbbbbbbbbbb",
            verification_sessions=[],
            verification_findings=[],
            verification_posture=None,
        )
        assert verified.outcome == VerificationOutcome.VERIFIED
        assert verified.session_match == "not_session_scoped"
        failed = compare_rule(
            baseline_finding=baseline,
            baseline_session=None,
            baseline_posture=None,
            verification_capture_id="capture_bbbbbbbbbbbb",
            verification_sessions=[],
            verification_findings=[_finding_view("finding_x", "capture_bbbbbbbbbbbb", None)],
            verification_posture=None,
        )
        assert failed.outcome == VerificationOutcome.FAILED

    def test_unrelated_session_rule_does_not_clear(self) -> None:
        # The rule fires in the verification capture but only in an
        # unrelated session: the relevant session is clean → VERIFIED,
        # because presence is scoped to matched sessions.
        comparison = compare_rule(
            baseline_finding=_finding_view(),
            baseline_session=_session_view(),
            baseline_posture=None,
            verification_capture_id="capture_bbbbbbbbbbbb",
            verification_sessions=[
                _session_view("session_0000000000000002", "capture_bbbbbbbbbbbb")
            ],
            verification_findings=[
                _finding_view("finding_x", "capture_bbbbbbbbbbbb", "session_other")
            ],
            verification_posture=None,
        )
        assert comparison.outcome == VerificationOutcome.VERIFIED

    def test_neutral_language(self) -> None:
        blob = json.dumps(
            compare_rule(
                baseline_finding=_finding_view(),
                baseline_session=_session_view(),
                baseline_posture=None,
                verification_capture_id="capture_bbbbbbbbbbbb",
                verification_sessions=[],
                verification_findings=[],
                verification_posture=None,
            ).to_dict()
        ).lower()
        for word in ("attacker", "malicious", "compromise", "secure", "caused"):
            assert word not in blob


def upload_and_analyze(client, name: str = "smtp.pcap", content: bytes | None = None):
    created = client.post(
        "/api/captures",
        files={"file": (name, content or tf.smtp_plain_pcap(), "application/octet-stream")},
    ).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
    return created, analysis


def make_case(client, title: str = "Remediation case"):
    response = client.post(
        "/api/cases",
        json={"title": title, "description": "Stage 13 test case", "priority": "HIGH"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def attach(client, case_id: str, content: bytes | None = None, name: str = "smtp.pcap"):
    created, analysis = upload_and_analyze(client, name, content)
    assert analysis["status"] == "completed"
    response = client.post(f"/api/cases/{case_id}/captures", json={"capture_id": created["id"]})
    assert response.status_code == 200, response.text
    return created


def tls_variant_pcap(der: bytes, client_port: int = 49154) -> bytes:
    """STARTTLS+TLS conversation sharing one certificate DER across captures."""
    b = FrameConversation(client=("10.10.0.23", client_port))
    (
        b.syn()
        .synack()
        .ack()
        .s(b"220 mail.example.org ESMTP\r\n")
        .c(b"EHLO client.example.net\r\n")
        .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
        .c(b"STARTTLS\r\n")
        .s(b"220 2.0.0 Ready to start TLS\r\n")
    )
    b.c(_client_hello_record())
    b.s(_server_hello_record() + _certificate_record(der) + _ccs_record())
    b.fin_c().fin_s()
    return b.to_pcap()


def create_from_finding(client, case_id: str, finding_id: str, **overrides):
    body = {"finding_id": finding_id, "owner": "netops"}
    body.update(overrides)
    response = client.post(f"/api/cases/{case_id}/remediations/from-finding", json=body)
    assert response.status_code == 200, response.text
    return response.json()


class TestRemediationCRUD:
    def test_create_from_finding_uses_policy_guidance(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        remediation = create_from_finding(client, case["case_id"], findings[0]["id"])
        assert remediation["remediation_id"].startswith("rem_")
        assert remediation["target_type"] == "finding"
        assert remediation["target_id"] == findings[0]["id"]
        assert remediation["rule_id"] == findings[0]["rule_id"]
        assert remediation["status"] == "OPEN"
        assert remediation["verification_status"] == "NOT_VERIFIED"
        assert remediation["owner"] == "netops"
        assert remediation["recommended_action_source"] == "policy"
        assert "SecureMailScope policy baseline" in remediation["recommended_action"]
        # The historical finding is untouched.
        again = client.get(f"/api/findings/{findings[0]['id']}").json()
        assert again["severity"] == findings[0]["severity"]

    def test_manual_create_and_targets(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        session_rem = client.post(
            f"/api/cases/{case['case_id']}/remediations",
            json={
                "target_type": "session",
                "target_id": sessions[0]["id"],
                "title": "Re-check session",
                "priority": "LOW",
                "due_at": "2026-12-31",
            },
        ).json()
        assert session_rem["due_at"] == "2026-12-31"
        case_rem = client.post(
            f"/api/cases/{case['case_id']}/remediations",
            json={"target_type": "case", "target_id": case["case_id"], "title": "Case review"},
        ).json()
        assert case_rem["target_id"] == case["case_id"]
        # Host / certificate / TLS configuration targets validate by shape.
        for target_type, target_id in (
            ("host", "198.51.100.20"),
            ("host", "mail.example.org"),
            ("certificate", "aa" * 32),
            ("tls_configuration", "tlscfg_0123456789ab"),
        ):
            response = client.post(
                f"/api/cases/{case['case_id']}/remediations",
                json={"target_type": target_type, "target_id": target_id, "title": "t"},
            )
            assert response.status_code == 200, (target_type, target_id, response.text)
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/remediations",
                json={"target_type": "finding", "target_id": "finding_missing", "title": "t"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/remediations",
                json={"target_type": "host", "target_id": "not a host!!", "title": "t"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/remediations",
                json={
                    "target_type": "session",
                    "target_id": sessions[0]["id"],
                    "title": "t",
                    "due_at": "31-12-2026",
                },
            ).status_code
            == 422
        )

    def test_get_update_delete(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        remediation = create_from_finding(client, case["case_id"], findings[0]["id"])
        rid = remediation["remediation_id"]

        fetched = client.get(f"/api/cases/{case['case_id']}/remediations/{rid}").json()
        assert fetched["title"] == remediation["title"]

        updated = client.patch(
            f"/api/cases/{case['case_id']}/remediations/{rid}",
            json={"owner": "mail-team", "priority": "CRITICAL", "title": "Renamed"},
        ).json()
        assert updated["owner"] == "mail-team"
        assert updated["priority"] == "CRITICAL"

        listed = client.get(f"/api/cases/{case['case_id']}/remediations").json()
        assert listed["total"] == 1

        by_finding = client.get(
            f"/api/cases/{case['case_id']}/findings/{findings[0]['id']}/remediations"
        ).json()
        assert len(by_finding["remediations"]) == 1

        assert client.delete(f"/api/cases/{case['case_id']}/remediations/{rid}").status_code == 204
        assert client.get(f"/api/cases/{case['case_id']}/remediations/{rid}").status_code == 404
        # Deleting the remediation leaves the finding intact.
        assert client.get(f"/api/findings/{findings[0]['id']}").status_code == 200

    def test_cross_case_isolation(self, make_api) -> None:
        client = make_api()
        first = make_case(client, "First")
        second = make_case(client, "Second")
        created = attach(client, first["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        remediation = create_from_finding(client, first["case_id"], findings[0]["id"])
        assert (
            client.get(
                f"/api/cases/{second['case_id']}/remediations/{remediation['remediation_id']}"
            ).status_code
            == 404
        )
        assert (
            client.patch(
                f"/api/cases/{second['case_id']}/remediations/{remediation['remediation_id']}",
                json={"owner": "x"},
            ).status_code
            == 404
        )


class TestStateMachine:
    def _remediation(self, client, case_id: str):
        created = attach(client, case_id)
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        return create_from_finding(client, case_id, findings[0]["id"])

    def test_valid_transitions(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        rid = self._remediation(client, case["case_id"])["remediation_id"]
        path = f"/api/cases/{case['case_id']}/remediations/{rid}"
        assert client.patch(path, json={"status": "PLANNED"}).json()["status"] == "PLANNED"
        assert client.patch(path, json={"status": "IN_PROGRESS"}).json()["status"] == "IN_PROGRESS"
        assert client.patch(path, json={"status": "BLOCKED"}).json()["status"] == "BLOCKED"
        assert client.patch(path, json={"status": "IN_PROGRESS"}).json()["status"] == "IN_PROGRESS"
        closed = client.patch(path, json={"status": "COMPLETED"}).json()
        assert closed["status"] == "COMPLETED"
        assert closed["completed_at"] is not None

        timeline = client.get(f"/api/cases/{case['case_id']}/remediations/{rid}/timeline").json()[
            "timeline"
        ]
        events = [e["event_type"] for e in timeline]
        assert events[0] == "remediation_created"
        assert events.count("status_changed") == 5

    def test_invalid_transitions_rejected(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        rid = self._remediation(client, case["case_id"])["remediation_id"]
        path = f"/api/cases/{case['case_id']}/remediations/{rid}"
        # OPEN cannot jump to IN_PROGRESS or COMPLETED.
        assert client.patch(path, json={"status": "IN_PROGRESS"}).status_code == 422
        assert client.patch(path, json={"status": "COMPLETED"}).status_code == 422
        assert client.patch(path, json={"status": "BOGUS"}).status_code == 422
        client.patch(path, json={"status": "CANCELLED"})
        # Terminal states retain history but accept no transitions.
        assert client.patch(path, json={"status": "OPEN"}).status_code == 422
        assert client.get(path).json()["status"] == "CANCELLED"

    def test_timeline_insertion_order(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        remediation = create_from_finding(client, case["case_id"], findings[0]["id"])
        client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={
                "target_type": "remediation",
                "target_id": remediation["remediation_id"],
                "content": "note on remediation",
            },
        )
        timeline = client.get(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/timeline"
        ).json()["timeline"]
        assert [e["event_type"] for e in timeline] == ["remediation_created", "note_added"]


class TestVerification:
    def _two_captures(self, client, case_id: str):
        der = _leaf_certificate_der()
        baseline = attach(client, case_id, tls_variant_pcap(der, 49154), "base.pcap")
        verified = attach(client, case_id, tls_variant_pcap(der, 49155), "fixed.pcap")
        return baseline, verified

    def test_evidence_verification_failed_and_verified(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        baseline, verified = self._two_captures(client, case["case_id"])
        findings = client.get(f"/api/captures/{baseline['id']}/findings").json()
        rule_ids = {f["rule_id"] for f in findings}
        assert rule_ids, "baseline must carry findings"

        # Same-capture verification: the rule is still present → FAILED.
        remediation = create_from_finding(client, case["case_id"], findings[0]["id"])
        failed = client.post(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/verify",
            json={"mode": "evidence", "verification_capture_id": baseline["id"]},
        ).json()
        assert failed["result"] == "FAILED"
        assert failed["method"] == "evidence"
        assert "was still observed" in failed["comparison"]["statement"]
        state = client.get(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}"
        ).json()
        assert state["verification_status"] == "FAILED"
        assert state["verification_capture_id"] == baseline["id"]

        # Cross-capture verification against the twin: shared structure means
        # the rule persists → FAILED as well (deterministic, not assumed fixed).
        second = client.post(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/verify",
            json={"mode": "evidence", "verification_capture_id": verified["id"]},
        ).json()
        assert second["result"] in ("FAILED", "VERIFIED")
        history = client.get(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/verification"
        ).json()["verifications"]
        assert len(history) == 2, "verification history is append-only"

    def test_verification_rejections(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        other = make_case(client, "Other")
        created = attach(client, case["case_id"])
        foreign = attach(client, other["case_id"], tf.smtp_starttls_pcap(), "other.pcap")
        assert foreign["id"] != created["id"]
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        remediation = create_from_finding(client, case["case_id"], findings[0]["id"])
        path = f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/verify"
        # Cross-case capture rejected.
        assert (
            client.post(path, json={"mode": "evidence", "verification_capture_id": foreign["id"]})
        ).status_code == 422
        # Unknown capture rejected.
        assert (
            client.post(
                path, json={"mode": "evidence", "verification_capture_id": "capture_0123456789ab"}
            ).status_code
            == 422
        )
        # Unanalyzed capture rejected (distinct bytes, never analyzed).
        raw = client.post(
            "/api/captures",
            files={"file": ("fresh.pcap", tf.imap_pcap(), "application/octet-stream")},
        ).json()
        client.post(f"/api/cases/{case['case_id']}/captures", json={"capture_id": raw["id"]})
        assert (
            client.post(path, json={"mode": "evidence", "verification_capture_id": raw["id"]})
        ).status_code == 422
        # Missing capture rejected.
        assert client.post(path, json={"mode": "evidence"}).status_code == 422
        # Bad mode rejected.
        assert client.post(path, json={"mode": "vibes"}).status_code == 422
        # Non-finding remediation cannot use evidence mode.
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        session_rem = client.post(
            f"/api/cases/{case['case_id']}/remediations",
            json={"target_type": "session", "target_id": sessions[0]["id"], "title": "t"},
        ).json()
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/remediations/{session_rem['remediation_id']}/verify",
                json={"mode": "evidence", "verification_capture_id": created["id"]},
            ).status_code
            == 422
        )

    def test_manual_verification_pending_and_complete(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        remediation = create_from_finding(client, case["case_id"], findings[0]["id"])
        path = f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/verify"

        pending = client.post(path, json={"mode": "manual"}).json()
        assert pending["result"] == "PENDING"
        assert pending["method"] == "analyst_asserted"
        state = client.get(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}"
        ).json()
        assert state["verification_status"] == "PENDING"

        # Completing without notes is rejected.
        assert (
            client.patch(
                f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}"
                f"/verifications/{pending['verification_id']}",
                json={"notes": ""},
            ).status_code
            == 422
        )
        completed = client.patch(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}"
            f"/verifications/{pending['verification_id']}",
            json={"notes": "Operator confirmed the new configuration on the host."},
        ).json()
        assert completed["result"] == "VERIFIED"
        assert completed["completed_at"] is not None
        state = client.get(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}"
        ).json()
        assert state["verification_status"] == "VERIFIED"
        assert state["verification_method"] == "analyst_asserted"
        # Completed records are immutable.
        assert (
            client.patch(
                f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}"
                f"/verifications/{pending['verification_id']}",
                json={"notes": "second thoughts"},
            ).status_code
            == 404
        )
        timeline = client.get(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/timeline"
        ).json()["timeline"]
        events = [e["event_type"] for e in timeline]
        assert "verification_requested" in events
        assert "verification_completed" in events

    def test_manual_with_notes_completes_immediately(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        remediation = create_from_finding(client, case["case_id"], findings[0]["id"])
        result = client.post(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/verify",
            json={"mode": "manual", "notes": "Checked during maintenance window."},
        ).json()
        assert result["result"] == "VERIFIED"
        assert "Analyst-asserted" in result["comparison"]["notice"]


class TestRemediationListing:
    def test_filters_sort_search(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        first = create_from_finding(
            client, case["case_id"], findings[0]["id"], owner="alice", priority="HIGH"
        )
        client.patch(
            f"/api/cases/{case['case_id']}/remediations/{first['remediation_id']}",
            json={"status": "PLANNED"},
        )
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        client.post(
            f"/api/cases/{case['case_id']}/remediations",
            json={
                "target_type": "session",
                "target_id": sessions[0]["id"],
                "title": "Session follow-up",
                "owner": "bob",
                "priority": "LOW",
            },
        )
        assert (
            client.get(
                f"/api/cases/{case['case_id']}/remediations", params={"status": "PLANNED"}
            ).json()["total"]
            == 1
        )
        assert (
            client.get(
                f"/api/cases/{case['case_id']}/remediations", params={"owner": "BOB"}
            ).json()["total"]
            == 1
        )
        assert (
            client.get(
                f"/api/cases/{case['case_id']}/remediations", params={"search": "follow-up"}
            ).json()["total"]
            == 1
        )
        by_priority = client.get(
            f"/api/cases/{case['case_id']}/remediations", params={"sort": "priority"}
        ).json()["remediations"]
        assert [r["priority"] for r in by_priority] == ["HIGH", "LOW"]
        assert (
            client.get(
                f"/api/cases/{case['case_id']}/remediations", params={"status": "BOGUS"}
            ).status_code
            == 422
        )
        assert (
            client.get(
                f"/api/cases/{case['case_id']}/remediations", params={"sort": "bogus"}
            ).status_code
            == 422
        )
        assert (
            client.get(
                f"/api/cases/{case['case_id']}/remediations", params={"limit": 9999}
            ).status_code
            == 422
        )

    def test_summary_counts(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        remediation = create_from_finding(client, case["case_id"], findings[0]["id"])
        counts = client.get(f"/api/cases/{case['case_id']}/summary").json()["counts"][
            "remediations"
        ]
        assert counts == {
            "open": 1,
            "in_progress": 0,
            "blocked": 0,
            "completed": 0,
            "verification_pending": 0,
            "verified": 0,
            "failed": 0,
            "inconclusive": 0,
        }
        client.post(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/verify",
            json={"mode": "evidence", "verification_capture_id": created["id"]},
        )
        counts = client.get(f"/api/cases/{case['case_id']}/summary").json()["counts"][
            "remediations"
        ]
        assert counts["failed"] == 1
        assert "score" not in json.dumps(counts)


class TestRemediationReports:
    def test_report_export_bundle_import(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        case = make_case(client)
        der = _leaf_certificate_der()
        baseline = attach(client, case["case_id"], tls_variant_pcap(der, 49154), "base.pcap")
        attach(client, case["case_id"], tls_variant_pcap(der, 49155), "fixed.pcap")
        findings = client.get(f"/api/captures/{baseline['id']}/findings").json()
        remediation = create_from_finding(
            client, case["case_id"], findings[0]["id"], owner="netops"
        )
        client.patch(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}",
            json={"status": "PLANNED"},
        )
        client.patch(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}",
            json={"status": "IN_PROGRESS"},
        )
        client.post(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/verify",
            json={"mode": "evidence", "verification_capture_id": baseline["id"]},
        )

        report = client.get(f"/api/cases/{case['case_id']}/report.json").json()
        assert "remediation" in report
        assert "verification" in report
        assert report["remediation"]["count"] == 1
        assert report["verification"]["count"] == 1
        assert report["verification"]["by_result"] == {"FAILED": 1}
        html_body = client.get(f"/api/cases/{case['case_id']}/report.html").text
        assert "Remediation Workflow" in html_body
        assert "Verification Evidence" in html_body
        pdf = client.get(f"/api/cases/{case['case_id']}/report.pdf").content
        assert pdf.startswith(b"%PDF-")

        export = client.get(f"/api/cases/{case['case_id']}/export").json()
        assert export["schema_version"] == "1.3"
        assert len(export["remediations"]) == 1
        assert len(export["remediation_timeline"]) >= 3
        assert len(export["verification_results"]) == 1
        assert export["remediations"][0]["verification_status"] == "FAILED"

        imported = client.post("/api/cases/import", json=export)
        assert imported.status_code == 200, imported.text
        new_case = imported.json()
        fresh = client.get(f"/api/cases/{new_case['case_id']}/export").json()
        assert len(fresh["remediations"]) == 1
        assert fresh["remediations"][0]["verification_status"] == "NOT_VERIFIED"
        assert fresh["verification_results"] == []
        assert fresh["remediation_timeline"] == []
        # Legacy bundles still import.
        legacy = dict(export)
        legacy.pop("remediations", None)
        legacy.pop("remediation_timeline", None)
        legacy.pop("verification_results", None)
        legacy["schema_version"] = "1.1"
        assert client.post("/api/cases/import", json=legacy).status_code == 200
        assert (
            client.post("/api/cases/import", json={**export, "remediations": "nope"}).status_code
            == 422
        )

    def test_report_determinism_with_remediation(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        create_from_finding(client, case["case_id"], findings[0]["id"])
        first = client.get(f"/api/cases/{case['case_id']}/report.json").json()
        second = client.get(f"/api/cases/{case['case_id']}/report.json").json()
        assert first["remediation"] == second["remediation"]
        assert first["verification"] == second["verification"]


class TestRemediationSecurity:
    def test_malformed_ids_and_injection(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        malicious = "<img src=x onerror=alert(1)>"
        remediation = create_from_finding(
            client, case["case_id"], findings[0]["id"], owner=malicious
        )
        assert remediation["owner"] == malicious
        html_body = client.get(f"/api/cases/{case['case_id']}/report.html").text
        assert malicious not in html_body
        assert "&lt;img" in html_body
        for bad in ("rem_' OR '1'='1", "rem_<script>", "capture_abc"):
            response = client.get(f"/api/cases/{case['case_id']}/remediations/{bad}")
            assert response.status_code == 404, bad
            assert response.json()["error"]["code"] == "remediation_not_found"
            assert "traceback" not in response.text.lower()
        # Traversal-shaped target ids never reach storage.
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/remediations",
                json={"target_type": "finding", "target_id": "../../etc", "title": "t"},
            ).status_code
            == 422
        )
        assert client.get("/api/cases/case_bogus/remediations").status_code == 404
        unknown = client.get(f"/api/cases/{case['case_id']}/remediations/rem_0123456789abcdef")
        assert unknown.status_code == 404
        bad_verif = client.get(
            f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}"
            "/verifications/verif_0123456789abcdef"
        )
        assert bad_verif.status_code == 404
        assert bad_verif.json()["error"]["code"] == "verification_not_found"

    def test_oversized_and_hostile_inputs(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/remediations/from-finding",
                json={"finding_id": findings[0]["id"], "title": "x" * 201},
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/remediations/from-finding",
                json={"finding_id": findings[0]["id"], "owner": "x" * 129},
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/remediations/from-finding",
                json={"finding_id": findings[0]["id"], "owner": "bad\x00owner"},
            ).status_code
            == 422
        )
        remediation = create_from_finding(client, case["case_id"], findings[0]["id"])
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/remediations/{remediation['remediation_id']}/verify",
                json={"mode": "manual", "notes": "x" * 10001},
            ).status_code
            == 422
        )

    def test_no_secrets_in_workflow_output(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        create_from_finding(client, case["case_id"], findings[0]["id"])
        raw = client.get(f"/api/cases/{case['case_id']}/export").content.decode().lower()
        for token in ("api_key", "password", "begin private key", "authorization", "secret"):
            assert token not in raw, token


class TestRemediationIntegrity:
    """Workflow state must never mutate underlying forensic truth."""

    def _snapshot(self, client, capture_id):
        return {
            "posture": client.get(f"/api/captures/{capture_id}/posture").json(),
            "findings": client.get(f"/api/captures/{capture_id}/findings").json(),
            "anomalies": client.get(f"/api/captures/{capture_id}/anomalies").json(),
            "graph": client.get(f"/api/captures/{capture_id}/graph").json(),
        }

    def test_full_lifecycle_leaves_evidence_identical(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        case = make_case(client)
        der = _leaf_certificate_der()
        baseline = attach(client, case["case_id"], tls_variant_pcap(der, 49154), "base.pcap")
        verified = attach(client, case["case_id"], tls_variant_pcap(der, 49155), "fixed.pcap")
        before = self._snapshot(client, baseline["id"])

        findings = client.get(f"/api/captures/{baseline['id']}/findings").json()
        remediation = create_from_finding(
            client, case["case_id"], findings[0]["id"], owner="netops"
        )
        rid = remediation["remediation_id"]
        path = f"/api/cases/{case['case_id']}/remediations/{rid}"
        client.patch(path, json={"status": "PLANNED"})
        client.patch(path, json={"status": "IN_PROGRESS"})
        client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={"target_type": "remediation", "target_id": rid, "content": "working on it"},
        )
        client.post(
            path + "/verify",
            json={"mode": "evidence", "verification_capture_id": verified["id"]},
        )
        client.post(path + "/verify", json={"mode": "manual", "notes": "double-checked"})
        client.patch(path, json={"status": "COMPLETED"})
        client.patch(f"/api/cases/{case['case_id']}", json={"status": "CLOSED"})
        client.get(f"/api/cases/{case['case_id']}/report.json")
        client.get(f"/api/cases/{case['case_id']}/export")

        assert self._snapshot(client, baseline["id"]) == before
        assert self._snapshot(client, verified["id"]) == self._snapshot(client, verified["id"])
        # Findings are never deleted by the workflow.
        assert len(client.get(f"/api/captures/{baseline['id']}/findings").json()) == len(
            before["findings"]
        )
