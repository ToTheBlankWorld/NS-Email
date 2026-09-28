"""Stage 12 tests: deterministic multi-capture correlation.

Covers normalization, the index-based engine (deterministic ids,
cross-capture only, strength categories), the correlation API
(list/summary/detail/context/related/graph with filters), report and
export integration (current schema, 1.0 import compatibility), AI query
boundaries, security validation, evidence integrity, and an index-scale
performance regression.
"""

import time
from datetime import UTC, datetime

from engine.core.certificate import CertificateEvidence
from engine.core.findings import FindingCategory, FindingSeverity, SecurityFinding
from engine.core.session import EmailProtocol, Session
from engine.core.tls import KeyExchange, TLSHandshake, TLSVersion
from engine.correlation import (
    CaptureCorrelationInput,
    CorrelationType,
    correlate_case,
    correlation_id,
    normalize_evidence_key,
    normalize_fingerprint,
    normalize_hostname,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_subject,
    normalize_token,
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

_FP_A = "aa" * 32
_FP_B = "bb" * 32


def _session(
    index: int,
    capture_id: str,
    server_ip: str = "198.51.100.20",
    server_port: int = 25,
    protocol: EmailProtocol | None = EmailProtocol.SMTP,
    fingerprint: str | None = _FP_A,
    subject: str = "mail.example.org",
) -> Session:
    handshake = TLSHandshake(
        session_id=f"session_{index:016x}",
        tls_version=TLSVersion.TLS_1_2,
        cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange=KeyExchange.ECDHE,
        handshake_complete=True,
    )
    certificates = []
    if fingerprint is not None:
        certificates.append(
            CertificateEvidence(
                session_id=f"session_{index:016x}",
                subject=subject,
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
        started_at=datetime(2024, 9, 27, 9, 0, index % 60, tzinfo=UTC),
    )


def _finding(index: int, capture_id: str, rule_id: str = "PLAINTEXT-001") -> SecurityFinding:
    # Fixed detected_at: the default is wall-clock time, which would make
    # determinism assertions meaningless on coarse host clocks.
    return SecurityFinding(
        id=f"finding_{index:016x}",
        capture_id=capture_id,
        session_id=f"session_{index:016x}",
        title="Plaintext session",
        description="Session without TLS.",
        severity=FindingSeverity.MEDIUM,
        category=FindingCategory.HANDSHAKE,
        rule_id=rule_id,
        detected_at=datetime(2024, 9, 27, 9, 0, 0, tzinfo=UTC),
    )


class TestNormalization:
    def test_ip_canonicalization(self) -> None:
        assert normalize_ip("198.51.100.20") == "198.51.100.20"
        assert normalize_ip("::1") == "::1"
        assert normalize_ip("2001:DB8::1") == "2001:db8::1"
        assert normalize_ip("not-an-ip") is None
        assert normalize_ip("") is None
        assert normalize_ip(None) is None
        assert normalize_ip("1.2.3.4\nINJECTED") is None
        assert normalize_ip("x" * 65) is None

    def test_hostname_conservative(self) -> None:
        assert normalize_hostname("Mail.Example.ORG") == "mail.example.org"
        assert normalize_hostname("mail.example.org.") == "mail.example.org"
        assert normalize_hostname("") is None
        assert normalize_hostname("has space.example") is None
        assert normalize_hostname("bad\x01host") is None
        assert normalize_hostname("x" * 254) is None
        assert normalize_hostname(".") is None

    def test_fingerprint_subject_token(self) -> None:
        assert normalize_fingerprint("AA:BB:cc") == "aabbcc"
        assert normalize_fingerprint("zz") is None
        assert normalize_subject("  Mail.Example.ORG  ") == "mail.example.org"
        assert normalize_subject("") is None
        assert normalize_token("TLS 1.2") == "tls 1.2"
        assert normalize_token(None) is None
        assert normalize_protocol("SMTP") == "smtp"
        assert normalize_protocol("gopher") is None
        assert normalize_port(25) == 25
        assert normalize_port(99999) is None
        assert normalize_port(None) is None

    def test_evidence_key_bounds(self) -> None:
        assert normalize_evidence_key("a|b") == "a|b"
        assert normalize_evidence_key("") is None
        assert normalize_evidence_key("x" * 513) is None
        assert normalize_evidence_key("bad\x00key") is None


class TestCorrelationEngine:
    def _two_capture_inputs(self):
        return [
            CaptureCorrelationInput(
                capture_id="capture_aaaaaaaaaaaa",
                sessions=[_session(1, "capture_aaaaaaaaaaaa")],
                findings=[_finding(1, "capture_aaaaaaaaaaaa")],
                anomalies=[],
            ),
            CaptureCorrelationInput(
                capture_id="capture_bbbbbbbbbbbb",
                sessions=[_session(2, "capture_bbbbbbbbbbbb")],
                findings=[_finding(2, "capture_bbbbbbbbbbbb")],
                anomalies=[],
            ),
        ]

    def test_shared_evidence_correlates(self) -> None:
        report = correlate_case("case_0123456789abcdef", self._two_capture_inputs())
        by_type = {c.correlation_type for c in report.correlations}
        assert CorrelationType.SHARED_ENDPOINT in by_type
        assert CorrelationType.SHARED_HOST in by_type
        assert CorrelationType.SHARED_CERTIFICATE in by_type
        assert CorrelationType.SHARED_CERTIFICATE_SUBJECT in by_type
        assert CorrelationType.SHARED_TLS_CONFIGURATION in by_type
        assert CorrelationType.SHARED_PROTOCOL in by_type
        assert CorrelationType.SHARED_FINDING in by_type
        assert CorrelationType.REPEATED_SESSION_PATTERN in by_type
        assert report.sessions_scanned == 2
        assert report.index_keys > 0
        for correlation in report.correlations:
            assert correlation.correlation_id.startswith("corr_")
            assert correlation.capture_count == 2
            assert correlation.source_capture_ids == (
                "capture_aaaaaaaaaaaa",
                "capture_bbbbbbbbbbbb",
            )

    def test_single_capture_yields_no_correlations(self) -> None:
        (single,) = self._two_capture_inputs()[:1]
        report = correlate_case("case_0123456789abcdef", [single])
        assert report.correlations == ()
        assert report.sessions_scanned == 1

    def test_ids_are_deterministic(self) -> None:
        first = correlate_case("case_0123456789abcdef", self._two_capture_inputs())
        second = correlate_case("case_0123456789abcdef", self._two_capture_inputs())
        assert [c.correlation_id for c in first.correlations] == [
            c.correlation_id for c in second.correlations
        ]
        assert [c.to_dict() for c in first.correlations] == [
            c.to_dict() for c in second.correlations
        ]
        # Spot-check the id formula against the public helper.
        target = next(
            c for c in first.correlations if c.correlation_type == CorrelationType.SHARED_HOST
        )
        assert target.correlation_id == correlation_id(
            "case_0123456789abcdef",
            "shared_host",
            target.evidence_key,
            [
                "capture_aaaaaaaaaaaa|session_0000000000000001",
                "capture_bbbbbbbbbbbb|session_0000000000000002",
            ],
        )

    def test_distinct_evidence_does_not_correlate(self) -> None:
        captures = [
            CaptureCorrelationInput(
                capture_id="capture_aaaaaaaaaaaa",
                sessions=[_session(1, "capture_aaaaaaaaaaaa", fingerprint=_FP_A)],
                findings=[],
                anomalies=[],
            ),
            CaptureCorrelationInput(
                capture_id="capture_bbbbbbbbbbbb",
                sessions=[
                    _session(
                        2,
                        "capture_bbbbbbbbbbbb",
                        server_ip="198.51.100.99",
                        server_port=587,
                        protocol=EmailProtocol.IMAP,
                        fingerprint=_FP_B,
                        subject="other.example.org",
                    )
                ],
                findings=[],
                anomalies=[],
            ),
        ]
        report = correlate_case("case_0123456789abcdef", captures)
        types = {c.correlation_type for c in report.correlations}
        assert CorrelationType.SHARED_CERTIFICATE not in types
        assert CorrelationType.SHARED_ENDPOINT not in types
        assert CorrelationType.SHARED_HOST not in types

    def test_strength_categories(self) -> None:
        report = correlate_case("case_0123456789abcdef", self._two_capture_inputs())
        strengths = {c.correlation_type: c.strength.value for c in report.correlations}
        assert strengths[CorrelationType.SHARED_ENDPOINT] == "direct"
        assert strengths[CorrelationType.SHARED_CERTIFICATE] == "direct"
        assert strengths[CorrelationType.SHARED_TLS_CONFIGURATION] == "direct"
        assert strengths[CorrelationType.SHARED_FINDING] == "direct"
        assert strengths[CorrelationType.SHARED_PROTOCOL] == "derived"
        assert strengths[CorrelationType.SHARED_CERTIFICATE_SUBJECT] == "derived"

    def test_flagged_anomaly_bands_only(self) -> None:
        captures = self._two_capture_inputs()
        captures[0].anomalies.append(
            {
                "anomaly_id": "anomaly_1",
                "session_id": "session_0000000000000001",
                "band": "unusual",
                "status": "unusual",
            }
        )
        captures[1].anomalies.append(
            {
                "anomaly_id": "anomaly_2",
                "session_id": "session_0000000000000002",
                "band": "unusual",
                "status": "unusual",
            }
        )
        report = correlate_case("case_0123456789abcdef", captures)
        bands = [
            c
            for c in report.correlations
            if c.correlation_type == CorrelationType.SHARED_ANOMALY_PATTERN
        ]
        assert len(bands) == 1
        assert bands[0].evidence_key == "anomaly-band|unusual"

        plain = self._two_capture_inputs()
        plain[0].anomalies.append(
            {
                "anomaly_id": "anomaly_1",
                "session_id": "session_0000000000000001",
                "band": None,
                "status": "insufficient_evidence",
            }
        )
        plain[1].anomalies.append(
            {
                "anomaly_id": "anomaly_2",
                "session_id": "session_0000000000000002",
                "band": None,
                "status": "insufficient_evidence",
            }
        )
        report = correlate_case("case_0123456789abcdef", plain)
        assert not [
            c
            for c in report.correlations
            if c.correlation_type == CorrelationType.SHARED_ANOMALY_PATTERN
        ]

    def test_neutral_evidence_language(self) -> None:
        report = correlate_case("case_0123456789abcdef", self._two_capture_inputs())
        blob = str(report.to_summary())
        for word in ("attacker", "malicious", "compromise", "threat", "malware"):
            assert word not in blob.lower()


def upload_and_analyze(client, name: str = "smtp.pcap", content: bytes | None = None):
    created = client.post(
        "/api/captures",
        files={"file": (name, content or tf.smtp_plain_pcap(), "application/octet-stream")},
    ).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
    return created, analysis


def make_case(client, title: str = "Correlation case"):
    response = client.post(
        "/api/cases",
        json={"title": title, "description": "Stage 12 test case", "priority": "HIGH"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def attach(client, case_id: str, content: bytes | None = None):
    created, analysis = upload_and_analyze(client, content=content)
    assert analysis["status"] == "completed"
    response = client.post(f"/api/cases/{case_id}/captures", json={"capture_id": created["id"]})
    assert response.status_code == 200, response.text
    return created


def plain_variant_pcap(client_port: int = 49153) -> bytes:
    """Same SMTP conversation as tf.smtp_plain_pcap, distinct client port.

    Different bytes (distinct capture id) with identical server endpoint,
    protocol, and session pattern — the controlled overlap Stage 12 needs.
    """
    b = FrameConversation(client=("10.10.0.23", client_port))
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
        .c(b"Subject: Hello\r\n\r\nBody must not appear in evidence.\r\n.\r\n")
        .s(b"250 2.0.0 Ok: queued\r\n")
        .c(b"QUIT\r\n")
        .s(b"221 2.0.0 Bye\r\n")
        .fin_c()
        .fin_s()
    )
    return b.to_pcap()


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


class TestCorrelationAPI:
    def test_empty_case_has_no_correlations(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        attach(client, case["case_id"])
        body = client.get(f"/api/cases/{case['case_id']}/correlations").json()
        assert body["total"] == 0
        assert body["correlations"] == []
        summary = client.get(f"/api/cases/{case['case_id']}/correlations/summary").json()
        assert summary["correlation_count"] == 0
        assert summary["capture_count"] == 1
        assert "risk" not in summary

    def test_shared_protocol_and_endpoint(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        attach(client, case["case_id"])
        attach(client, case["case_id"], plain_variant_pcap())
        body = client.get(f"/api/cases/{case['case_id']}/correlations").json()
        assert body["total"] >= 2
        types = {c["correlation_type"] for c in body["correlations"]}
        assert "shared_protocol" in types
        assert "shared_endpoint" in types
        for correlation in body["correlations"]:
            assert correlation["correlation_id"].startswith("corr_")
            assert correlation["capture_count"] >= 2
            assert correlation["strength"] in ("direct", "derived")
            assert "attacker" not in str(correlation).lower()

        summary = client.get(f"/api/cases/{case['case_id']}/correlations/summary").json()
        assert summary["correlation_count"] == body["total"]
        assert summary["capture_count"] == 2
        assert summary["by_type"]["shared_protocol"] >= 1

    def test_tls_certificate_correlation(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        der = _leaf_certificate_der()
        attach(client, case["case_id"], tls_variant_pcap(der, 49154))
        attach(client, case["case_id"], tls_variant_pcap(der, 49155))
        body = client.get(
            f"/api/cases/{case['case_id']}/correlations",
            params={"type": "shared_certificate"},
        ).json()
        assert body["total"] >= 1
        assert all(c["correlation_type"] == "shared_certificate" for c in body["correlations"])

    def test_filters_search_sort_pagination(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        first = attach(client, case["case_id"])
        attach(client, case["case_id"], plain_variant_pcap())
        filtered = client.get(
            f"/api/cases/{case['case_id']}/correlations",
            params={"capture_id": first["id"]},
        ).json()
        assert filtered["total"] >= 1
        assert all(first["id"] in c["source_capture_ids"] for c in filtered["correlations"])

        searched = client.get(
            f"/api/cases/{case['case_id']}/correlations", params={"search": "smtp"}
        ).json()
        assert searched["total"] >= 1

        by_type = client.get(
            f"/api/cases/{case['case_id']}/correlations", params={"sort": "type"}
        ).json()
        ordered = [c["correlation_type"] for c in by_type["correlations"]]
        assert ordered == sorted(ordered)

        paged = client.get(
            f"/api/cases/{case['case_id']}/correlations", params={"limit": 1, "offset": 0}
        ).json()
        assert len(paged["correlations"]) == 1
        assert paged["total"] >= 1

        assert (
            client.get(
                f"/api/cases/{case['case_id']}/correlations", params={"type": "nope"}
            ).status_code
            == 422
        )
        assert (
            client.get(
                f"/api/cases/{case['case_id']}/correlations", params={"sort": "nope"}
            ).status_code
            == 422
        )
        assert (
            client.get(
                f"/api/cases/{case['case_id']}/correlations", params={"limit": 9999}
            ).status_code
            == 422
        )

    def test_detail_and_context(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        attach(client, case["case_id"])
        attach(client, case["case_id"], plain_variant_pcap())
        first = client.get(f"/api/cases/{case['case_id']}/correlations").json()["correlations"][0]
        detail = client.get(
            f"/api/cases/{case['case_id']}/correlations/{first['correlation_id']}"
        ).json()
        assert detail == first
        context = client.get(
            f"/api/cases/{case['case_id']}/correlations/{first['correlation_id']}/context"
        ).json()
        assert context["correlation"]["correlation_id"] == first["correlation_id"]
        assert "related_finding_ids" in context
        assert "related_anomaly_ids" in context
        assert context["graph_nodes"], "context must carry graph references"
        assert "timeline_refs" in context

        assert client.get(f"/api/cases/{case['case_id']}/correlations/corr_zzzz").status_code == 404
        unknown = client.get(f"/api/cases/{case['case_id']}/correlations/corr_0123456789abcdef")
        assert unknown.status_code == 404
        assert unknown.json()["error"]["code"] == "correlation_not_found"
        assert client.get("/api/cases/case_bogus/correlations").status_code == 404

    def test_session_related(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach(client, case["case_id"])
        attach(client, case["case_id"], plain_variant_pcap())
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        related = client.get(
            f"/api/cases/{case['case_id']}/sessions/{sessions[0]['id']}/related"
        ).json()
        assert related["session_id"] == sessions[0]["id"]
        assert len(related["related"]) >= 1
        entry = related["related"][0]
        assert entry["other_session_count"] >= 1
        assert entry["other_capture_ids"], "must name the other captures"

        missing = client.get(
            f"/api/cases/{case['case_id']}/sessions/session_0123456789abcdef/related"
        )
        assert missing.status_code == 404
        assert client.get(f"/api/cases/{case['case_id']}/sessions/bogus/related").status_code == 404

    def test_investigation_graph_layers(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        attach(client, case["case_id"])
        attach(client, case["case_id"], plain_variant_pcap())
        graph = client.get(f"/api/cases/{case['case_id']}/graph").json()
        assert graph["node_count"] >= 3
        assert graph["edge_count"] >= 2
        layers = {n["layer"] for n in graph["nodes"]}
        assert layers == {"forensic", "correlation"}
        edge_layers = {e["layer"] for e in graph["edges"]}
        assert edge_layers == {"forensic", "correlation"}
        node_types = {n["node_type"] for n in graph["nodes"]}
        assert "correlation" in node_types
        assert "case" in node_types
        # Stage 7 per-capture graphs are untouched: no layer field there.
        captures = client.get(f"/api/cases/{case['case_id']}/summary").json()["captures"]
        stage7 = client.get(f"/api/captures/{captures[0]['capture_id']}/graph").json()
        assert all("layer" not in node for node in stage7["nodes"])


class TestCorrelationReportExport:
    def _correlated_case(self, client):
        case = make_case(client)
        der = _leaf_certificate_der()
        attach(client, case["case_id"], tls_variant_pcap(der, 49154))
        attach(client, case["case_id"], tls_variant_pcap(der, 49155))
        return case

    def test_report_contains_correlation_section(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        case = self._correlated_case(client)
        report = client.get(f"/api/cases/{case['case_id']}/report.json").json()
        assert "correlation" in report
        assert report["correlation"]["summary"]["correlation_count"] >= 1
        assert "not attribution" in report["correlation"]["notice"]
        html_body = client.get(f"/api/cases/{case['case_id']}/report.html").text
        assert "Correlation" in html_body
        pdf = client.get(f"/api/cases/{case['case_id']}/report.pdf").content
        assert pdf.startswith(b"%PDF-")

    def test_export_schema_12_and_bundle(self, make_api) -> None:
        client = make_api()
        case = self._correlated_case(client)
        export = client.get(f"/api/cases/{case['case_id']}/export").json()
        assert export["schema_version"] == "1.3"
        assert "correlations" in export
        assert "correlation_summary" in export
        assert "remediations" in export
        assert "verification_results" in export
        assert export["correlation_summary"]["correlation_count"] >= 1
        raw = str(export).lower()
        assert "attacker" not in raw

    def test_import_10_still_works(self, make_api) -> None:
        client = make_api()
        case = self._correlated_case(client)
        export = client.get(f"/api/cases/{case['case_id']}/export").json()
        legacy = dict(export)
        legacy.pop("correlations", None)
        legacy.pop("correlation_summary", None)
        legacy["schema_version"] = "1.0"
        imported = client.post("/api/cases/import", json=legacy)
        assert imported.status_code == 200, imported.text
        new_case = imported.json()
        summary = client.get(f"/api/cases/{new_case['case_id']}/correlations/summary").json()
        assert summary["correlation_count"] >= 1, "correlations recompute from local evidence"

    def test_import_recomputes_correlations(self, make_api) -> None:
        client = make_api()
        case = self._correlated_case(client)
        export = client.get(f"/api/cases/{case['case_id']}/export").json()
        original = {(c["correlation_type"], c["evidence_key"]) for c in export["correlations"]}
        export["correlations"] = [
            {
                "correlation_id": "corr_ffff",
                "correlation_type": "shared_host",
                "evidence_key": "host|1.2.3.4",
            }
        ]
        imported = client.post("/api/cases/import", json=export).json()
        fresh = client.get(f"/api/cases/{imported['case_id']}/export").json()
        recomputed = {(c["correlation_type"], c["evidence_key"]) for c in fresh["correlations"]}
        assert recomputed == original
        assert not [c for c in fresh["correlations"] if c["evidence_key"] == "host|1.2.3.4"]
        assert (
            client.post("/api/cases/import", json={**export, "correlations": "nope"}).status_code
            == 422
        )


class TestCorrelationAI:
    def test_explicit_correlation_question(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        case = make_case(client)
        attach(client, case["case_id"])
        attach(client, case["case_id"], plain_variant_pcap())
        correlations = client.get(f"/api/cases/{case['case_id']}/correlations").json()[
            "correlations"
        ]
        target = correlations[0]
        response = client.post(
            "/api/ai/query-correlation",
            json={
                "question": "Explain the repeated observations in this case.",
                "case_id": case["case_id"],
                "correlation_id": target["correlation_id"],
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "completed"
        # Ephemeral: never persisted to capture AI history, never in reports.
        for capture_id in target["source_capture_ids"]:
            history = client.get(f"/api/ai/history/{capture_id}").json()
            assert all(target["correlation_id"] not in str(entry) for entry in history)
        report = client.get(f"/api/cases/{case['case_id']}/report.json").json()
        assert report["ai_interpretation"]["observations"] == []

    def test_ai_rejects_bad_input(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        assert (
            client.post(
                "/api/ai/query-correlation",
                json={"question": "x", "case_id": "bogus", "correlation_id": "corr_bogus"},
            ).status_code
            == 404
        )
        case = make_case(client)
        assert (
            client.post(
                "/api/ai/query-correlation",
                json={
                    "question": "x",
                    "case_id": case["case_id"],
                    "correlation_id": "corr_0123456789abcdef",
                },
            ).status_code
            == 404
        )
        assert (
            client.post(
                "/api/ai/query-correlation",
                json={
                    "question": "x" * 2001,
                    "case_id": case["case_id"],
                    "correlation_id": "corr_0123456789abcdef",
                },
            ).status_code
            == 422
        )

    def test_ai_unconfigured(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        attach(client, case["case_id"])
        attach(client, case["case_id"], plain_variant_pcap())
        target = client.get(f"/api/cases/{case['case_id']}/correlations").json()["correlations"][0]
        body = client.post(
            "/api/ai/query-correlation",
            json={
                "question": "Explain.",
                "case_id": case["case_id"],
                "correlation_id": target["correlation_id"],
            },
        ).json()
        assert body["status"] == "not_configured"


class TestCorrelationIntegrity:
    """Correlations must never mutate underlying forensic truth."""

    def _snapshot(self, client, capture_id):
        return {
            "posture": client.get(f"/api/captures/{capture_id}/posture").json(),
            "findings": client.get(f"/api/captures/{capture_id}/findings").json(),
            "anomalies": client.get(f"/api/captures/{capture_id}/anomalies").json(),
            "graph": client.get(f"/api/captures/{capture_id}/graph").json(),
        }

    def test_correlation_workflow_leaves_evidence_identical(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        case = make_case(client)
        der = _leaf_certificate_der()
        created = attach(client, case["case_id"], tls_variant_pcap(der, 49154))
        attach(client, case["case_id"], tls_variant_pcap(der, 49155))
        before = self._snapshot(client, created["id"])

        client.get(f"/api/cases/{case['case_id']}/correlations")
        client.get(f"/api/cases/{case['case_id']}/correlations/summary")
        first = client.get(f"/api/cases/{case['case_id']}/correlations").json()["correlations"][0]
        client.get(f"/api/cases/{case['case_id']}/correlations/{first['correlation_id']}")
        client.get(f"/api/cases/{case['case_id']}/correlations/{first['correlation_id']}/context")
        client.get(f"/api/cases/{case['case_id']}/graph")
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        client.get(f"/api/cases/{case['case_id']}/sessions/{sessions[0]['id']}/related")
        client.post(
            "/api/ai/query-correlation",
            json={
                "question": "Explain.",
                "case_id": case["case_id"],
                "correlation_id": first["correlation_id"],
            },
        )
        client.get(f"/api/cases/{case['case_id']}/report.json")
        client.get(f"/api/cases/{case['case_id']}/export")

        assert self._snapshot(client, created["id"]) == before


class TestCorrelationPerformance:
    """Index-based generation must scale linearly, not pairwise."""

    def test_index_scales_linearly(self) -> None:
        captures = []
        for capture_index in range(3):
            capture_id = f"capture_{capture_index:012x}"
            sessions = [_session(capture_index * 100 + i, capture_id) for i in range(100)]
            captures.append(CaptureCorrelationInput(capture_id=capture_id, sessions=sessions))
        started = time.monotonic()
        report = correlate_case("case_0123456789abcdef", captures)
        elapsed = time.monotonic() - started
        assert report.sessions_scanned == 300
        assert report.index_keys > 0
        assert report.index_keys < report.sessions_scanned * 12
        assert report.correlations, "identical sessions must correlate"
        assert elapsed < 5.0, f"300 sessions took {elapsed:.2f}s; indexing regressed?"
