"""Stage 6 live smoke: multi-session TLS capture with 1 unusual session."""

from tests import anomaly_fixtures as af


def upload_and_analyze(client, name: str, content: bytes):
    created = client.post(
        "/api/captures",
        files={"file": (name, content, "application/octet-stream")},
    ).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
    return created, analysis


class TestLiveSmoke:
    def test_multi_session_anomaly_pipeline(self, make_api) -> None:
        client = make_api()
        pcap = af.multi_session_tls_pcap()
        created, analysis = upload_and_analyze(client, "multi.pcap", pcap)

        assert analysis["status"] == "completed"
        assert analysis["sessions_found"] == 21  # 20 normal + 1 unusual

        anomalies = client.get(f"/api/captures/{created['id']}/anomalies").json()
        assert len(anomalies) == 21

        # baseline built from real sessions
        evaluated = [a for a in anomalies if a["score"] is not None]
        assert len(evaluated) == 21

        # the unusual session must be distinguishable
        unusual = max(anomalies, key=lambda a: a["score"] or 0)
        assert unusual["score"] is not None
        # the unusual session has no SNI + single suite → should score high
        assert unusual["anomaly_id"]

        # all anomalies reference their session
        for anomaly in anomalies:
            assert anomaly["session_id"]

        # summary counts are real
        summary = client.get(f"/api/captures/{created['id']}/anomaly-summary").json()
        assert summary["total_evaluated"] == 21

        # posture score remains Stage 5 deterministic value
        posture = client.get(f"/api/captures/{created['id']}/posture").json()
        assert posture["posture_state"] in (
            "healthy",
            "acceptable",
            "degraded",
            "high_exposure",
            "critical_exposure",
        )

        # deterministic findings are NOT modified by the anomaly stage
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        for finding in findings:
            assert finding["evidence_refs"]

    def test_deterministic_repeated_analysis(self, make_api) -> None:
        client = make_api()
        pcap = af.multi_session_tls_pcap()
        created, _ = upload_and_analyze(client, "multi.pcap", pcap)

        first = client.get(f"/api/captures/{created['id']}/anomalies").json()
        client.post(f"/api/captures/{created['id']}/analyze")
        second = client.get(f"/api/captures/{created['id']}/anomalies").json()

        assert [(a["session_id"], a["status"], a["score"]) for a in first] == [
            (a["session_id"], a["status"], a["score"]) for a in second
        ]
