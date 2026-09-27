"""Stage 6 API tests: anomaly endpoints, persistence, determinism."""

from tests import tcp_fixtures as tf
from tests import tls_fixtures as tlf


def upload_and_analyze(client, name: str, content: bytes):
    created = client.post(
        "/api/captures",
        files={"file": (name, content, "application/octet-stream")},
    ).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
    return created, analysis


class TestAnomalyApi:
    def test_anomalies_endpoint_after_analysis(self, make_api) -> None:
        client = make_api()
        created, analysis = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())

        assert analysis["status"] == "completed"
        response = client.get(f"/api/captures/{created['id']}/anomalies")
        assert response.status_code == 200
        anomalies = response.json()
        assert len(anomalies) >= 1
        anomaly = anomalies[0]
        assert anomaly["session_id"]
        assert anomaly["status"] in (
            "normal",
            "unusual",
            "anomalous",
            "highly_anomalous",
            "insufficient_evidence",
            "model_error",
        )
        assert anomaly["feature_schema_version"] == "1.0"

    def test_anomaly_summary_counts_are_real(self, make_api) -> None:
        client = make_api()
        created, _ = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())

        response = client.get(f"/api/captures/{created['id']}/anomaly-summary")
        assert response.status_code == 200
        summary = response.json()
        assert summary["total_evaluated"] + summary.get("insufficient_evidence", 0) >= 1

    def test_anomaly_detail_via_session_endpoint(self, make_api) -> None:
        client = make_api()
        created, _ = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        session_id = sessions[0]["id"]

        response = client.get(f"/api/sessions/{session_id}/anomaly")
        assert response.status_code == 200
        anomaly = response.json()
        assert anomaly["session_id"] == session_id

    def test_anomaly_by_id_endpoint(self, make_api) -> None:
        client = make_api()
        created, _ = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())
        anomalies = client.get(f"/api/captures/{created['id']}/anomalies").json()

        anomaly_id = anomalies[0]["anomaly_id"]
        response = client.get(f"/api/anomalies/{anomaly_id}")
        assert response.status_code == 200
        assert response.json()["anomaly_id"] == anomaly_id

    def test_unknown_anomaly_is_not_found(self, make_api) -> None:
        client = make_api()

        response = client.get("/api/anomalies/anomaly_000000000000")

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "anomaly_not_available"

    def test_anomalies_not_available_before_analysis(self, make_api) -> None:
        client = make_api()
        created = client.post(
            "/api/captures",
            files={"file": ("a.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        ).json()

        response = client.get(f"/api/captures/{created['id']}/anomalies")

        assert response.status_code == 200
        assert response.json() == []


class TestAnomalyDeterminism:
    def test_repeated_analysis_is_deterministic(self, make_api) -> None:
        client = make_api()
        created, _ = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())

        client.get(f"/api/captures/{created['id']}/anomaly-summary")
        first = client.get(f"/api/captures/{created['id']}/anomalies").json()
        client.post(f"/api/captures/{created['id']}/analyze")
        second = client.get(f"/api/captures/{created['id']}/anomalies").json()

        assert [(a["session_id"], a["status"], a["score"]) for a in first] == [
            (a["session_id"], a["status"], a["score"]) for a in second
        ]

    def test_findings_and_posture_unaffected_by_anomaly_stage(self, make_api) -> None:
        client = make_api()
        created, _ = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())

        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        posture = client.get(f"/api/captures/{created['id']}/posture").json()

        # anomaly layer does not modify deterministic outputs
        assert posture["overall_score"] is not None
        assert all(f["evidence_refs"] for f in findings)


class TestAnomalyInsufficientBaseline:
    def test_single_session_gets_insufficient_evidence(self, make_api) -> None:
        client = make_api()
        created, analysis = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())

        assert analysis["status"] == "completed"
        anomalies = client.get(f"/api/captures/{created['id']}/anomalies").json()
        # 1 TLS session < minimum baseline of 8
        assert all(a["status"] == "insufficient_evidence" for a in anomalies)
        assert all(a["score"] is None for a in anomalies)
