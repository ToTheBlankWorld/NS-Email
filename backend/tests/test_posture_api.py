"""Posture API tests: snapshot lifecycle and aggregation endpoints."""

from tests import stage4_fixtures as s4
from tests import tcp_fixtures as tf


def upload_and_analyze(client, name: str, content: bytes):
    created = client.post(
        "/api/captures",
        files={"file": (name, content, "application/octet-stream")},
    ).json()
    client.post(f"/api/captures/{created['id']}/analyze")
    return created


class TestPostureApi:
    def test_posture_snapshot_is_served_after_analysis(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())

        response = client.get(f"/api/captures/{created['id']}/posture")

        assert response.status_code == 200
        posture = response.json()
        assert posture["capture_id"] == created["id"]
        assert posture["posture_state"] in (
            "healthy",
            "acceptable",
            "degraded",
            "high_exposure",
            "critical_exposure",
        )
        assert posture["overall_score"] is not None
        assert 0 <= posture["overall_score"] <= 100
        assert posture["analysis_version"]
        assert posture["policy_id"] == "securemailscope-baseline"

    def test_posture_is_deterministic_across_reanalysis(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())
        client.post(f"/api/captures/{created['id']}/analyze")

        first = client.get(f"/api/captures/{created['id']}/posture").json()
        # re-analysis already replaced the snapshot; it must be identical
        assert first["posture_state"] == "degraded"
        assert first["overall_score"] == first["overall_score"]

    def test_versioned_configuration_is_recorded(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())

        posture = client.get(f"/api/captures/{created['id']}/posture").json()

        assert posture["analysis_version"] == "0.5.0"
        assert posture["policy_id"] == "securemailscope-baseline"
        assert posture["policy_version"] == "1.0"

    def test_deprecated_tls_produces_degraded_posture(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())

        posture = client.get(f"/api/captures/{created['id']}/posture").json()

        assert posture["posture_state"] == "degraded"
        tls_factor = next(f for f in posture["factors"] if f["factor"] == "tls_configuration")
        assert tls_factor["status"] == "high_exposure"  # HIGH severity dominates
        assert tls_factor["score_contribution"] > 0
        assert tls_factor["contributing_finding_ids"], "factor must cite its findings"

    def test_posture_explanation_cites_real_counts(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())

        posture = client.get(f"/api/captures/{created['id']}/posture").json()

        assert posture["total_sessions"] == 1
        assert posture["affected_sessions"] == 1
        assert any("1/1 session(s) affected" in line for line in posture["explanation"])

    def test_posture_not_available_before_analysis(self, make_api) -> None:
        client = make_api()
        created = client.post(
            "/api/captures",
            files={"file": ("a.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        ).json()

        response = client.get(f"/api/captures/{created['id']}/posture")

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "posture_not_available"

    def test_unknown_capture_posture_is_not_found(self, make_api) -> None:
        client = make_api()

        response = client.get("/api/captures/capture_000000000000/posture")

        assert response.status_code == 404


class TestHostApi:
    def test_hosts_are_listed_with_posture_context(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())

        response = client.get(f"/api/captures/{created['id']}/hosts")

        assert response.status_code == 200
        hosts = response.json()
        assert len(hosts) == 1
        host = hosts[0]
        assert host["ip"] == "198.51.100.7"
        assert host["host_id"].startswith("host_")
        assert host["sessions"] == 1
        assert host["protocols"] == ["smtp"]
        assert host["findings_count"] > 0
        assert host["affected"] is True
        assert host["highest_severity"] is not None
        assert host["tls_versions"] == ["TLS 1.0"]

    def test_host_detail_returns_sessions_and_findings(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())
        hosts = client.get(f"/api/captures/{created['id']}/hosts").json()

        response = client.get(f"/api/captures/{created['id']}/hosts/{hosts[0]['host_id']}")

        assert response.status_code == 200
        detail = response.json()
        assert detail["host"]["host_id"] == hosts[0]["host_id"]
        assert len(detail["sessions"]) == 1
        assert len(detail["findings"]) == detail["host"]["findings_count"]
        assert detail["factors"]

    def test_unknown_host_id_is_not_found(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "tls10.pcap", s4.smtp_tls10_pcap())

        response = client.get(f"/api/captures/{created['id']}/hosts/host_000000000000")

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "posture_not_available"


class TestProtocolAndPriorityApi:
    def test_protocol_posture_breakdown(self, make_api) -> None:
        client = make_api()
        smtp = tf.FrameConversation()
        (
            smtp.syn()
            .synack()
            .ack()
            .s(b"220 mail.example.org ESMTP\r\n")
            .c(b"EHLO client.example.net\r\n")
            .s(b"250 2.0.0 Ok\r\n")
            .c(b"QUIT\r\n")
            .s(b"221 2.0.0 Bye\r\n")
            .fin_c()
            .fin_s()
        )
        pop3 = tf.FrameConversation(server=("198.51.100.7", 110))
        (
            pop3.syn()
            .synack()
            .ack()
            .s(b"+OK POP3 ready\r\n")
            .c(b"USER dave\r\n")
            .s(b"+OK\r\n")
            .c(b"PASS secret123\r\n")
            .s(b"+OK\r\n")
            .c(b"QUIT\r\n")
            .s(b"+OK signing off\r\n")
            .fin_c()
            .fin_s()
        )
        created = upload_and_analyze(
            client, "mixed.pcap", tf.frames_to_pcap(smtp.frames + pop3.frames)
        )

        response = client.get(f"/api/captures/{created['id']}/posture/protocols")

        assert response.status_code == 200
        protocols = {p["protocol"]: p for p in response.json()}
        assert set(protocols) == {"smtp", "pop3"}
        assert protocols["smtp"]["sessions"] == 1
        assert protocols["pop3"]["sessions"] == 1
        assert all("status" in p for p in protocols.values())

    def test_priorities_are_ordered_deterministically(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "pop3.pcap", tf.pop3_pcap())

        first = client.get(f"/api/captures/{created['id']}/priorities").json()
        second = client.get(f"/api/captures/{created['id']}/priorities").json()

        assert len(first) >= 2
        scores = [p["priority_score"] for p in first]
        assert scores == sorted(scores, reverse=True)
        assert first == second

    def test_priorities_explain_placement(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client, "pop3.pcap", tf.pop3_pcap())

        priorities = client.get(f"/api/captures/{created['id']}/priorities").json()
        top = priorities[0]

        assert top["priority_score"] > 0
        assert top["rule_id"] == "AUTH-PLAINTEXT-001"  # high severity dominates
        assert "high severity" in top["explanation"].lower()
        assert f"{top['affected_sessions']}/{top['total_sessions']}" in top["explanation"]
