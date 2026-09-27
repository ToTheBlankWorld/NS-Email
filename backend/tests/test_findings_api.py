"""Stage 4 API tests: findings generation, persistence, determinism."""

from tests import stage4_fixtures as s4
from tests import tcp_fixtures as tf
from tests import tls_fixtures as tlf


def upload_and_analyze(client, name: str, content: bytes):
    created = upload(client, name, content).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
    findings = client.get(f"/api/captures/{created['id']}/findings").json()
    return created, analysis, findings


def upload(client, name: str, content: bytes):
    return client.post(
        "/api/captures",
        files={"file": (name, content, "application/octet-stream")},
    )


class TestFindingsApi:
    def test_secure_tls_session_stays_clean(self, make_api) -> None:
        client = make_api()
        _, analysis, findings = upload_and_analyze(
            client, "secure.pcap", tlf.smtp_starttls_tls_pcap()
        )

        assert analysis["status"] == "completed"
        assert not [
            finding for finding in findings if finding["severity"] in ("critical", "high")
        ], "a secure session must not produce high-severity findings"

    def test_deprecated_tls_version_is_detected(self, make_api) -> None:
        client = make_api()
        _, _, findings = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())

        version_findings = [
            finding for finding in findings if finding["rule_id"] == "TLS-VERSION-001"
        ]
        assert len(version_findings) == 1
        assert version_findings[0]["severity"] == "high"
        assert version_findings[0]["observed_value"] == "TLS 1.0"
        assert version_findings[0]["evidence_refs"][0]["source"] == "ServerHello"
        assert version_findings[0]["evidence_refs"][0]["packet_numbers"]

    def test_expired_certificate_is_detected_against_capture_time(self, make_api) -> None:
        client = make_api()
        _, _, findings = upload_and_analyze(
            client, "expired.pcap", s4.smtp_expired_certificate_pcap()
        )

        validity = [finding for finding in findings if finding["rule_id"] == "CERT-VALIDITY-001"]
        assert len(validity) == 1
        assert validity[0]["severity"] == "high"
        assert "2024-09" in validity[0]["description"]  # capture timestamp, not today

    def test_starttls_requested_but_never_accepted(self, make_api) -> None:
        client = make_api()
        _, _, findings = upload_and_analyze(
            client, "no-tls.pcap", s4.smtp_starttls_never_accepted_pcap()
        )

        starttls = [finding for finding in findings if finding["rule_id"] == "STARTTLS-001"]
        assert len(starttls) == 1
        assert starttls[0]["observed_value"] == "STARTTLS requested; no acceptance observed"
        assert starttls[0]["severity"] == "medium"

    def test_plaintext_authentication_before_tls(self, make_api) -> None:
        client = make_api()
        _, _, findings = upload_and_analyze(client, "pop3.pcap", tf.pop3_pcap())

        auth = [finding for finding in findings if finding["rule_id"] == "AUTH-PLAINTEXT-001"]
        assert len(auth) == 1
        assert auth[0]["severity"] == "high"
        assert auth[0]["evidence_refs"][0]["packet_numbers"]
        # credential values were never stored
        dumped = repr(findings)
        assert "hunter2-secret" not in dumped and "dave" not in dumped


class TestFindingPersistence:
    def test_reanalysis_replaces_findings_atomically(self, make_api) -> None:
        client = make_api()
        created, _, first = upload_and_analyze(client, "smtp.pcap", tlf.smtp_starttls_tls_pcap())

        client.post(f"/api/captures/{created['id']}/analyze")
        second = client.get(f"/api/captures/{created['id']}/findings").json()

        assert len(first) == len(second)
        assert {f["id"] for f in second} == {f["id"] for f in first}

    def test_finding_detail_api(self, make_api) -> None:
        client = make_api()
        created, _, findings = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())

        version_finding = next(f for f in findings if f["rule_id"] == "TLS-VERSION-001")
        detail = client.get(f"/api/findings/{version_finding['id']}").json()

        assert detail["id"] == version_finding["id"]
        assert detail["capture_id"] == created["id"]
        assert detail["remediation"]["action"]
        assert detail["evidence_refs"][0]["source"] == "ServerHello"

    def test_unknown_finding_id_is_not_found(self, make_api) -> None:
        client = make_api()

        response = client.get("/api/findings/finding_000000000000")

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "finding_not_found"

    def test_malformed_finding_id_is_not_found(self, make_api) -> None:
        client = make_api()

        response = client.get("/api/findings/../etc/passwd")

        assert response.status_code == 404

    def test_session_findings_api(self, make_api) -> None:
        client = make_api()
        created, _, _ = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()

        response = client.get(f"/api/sessions/{sessions[0]['id']}/findings")

        assert response.status_code == 200
        assert all(f["session_id"] == sessions[0]["id"] for f in response.json())
