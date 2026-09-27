"""Stage 7 API regression tests: evidence graph + investigation context."""

from tests import tcp_fixtures as tf


def upload_and_analyze(client):
    created = client.post(
        "/api/captures",
        files={"file": ("smtp.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
    ).json()
    client.post(f"/api/captures/{created['id']}/analyze")
    return created


class TestGraphApi:
    def test_graph_is_built_during_analysis(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client)

        response = client.get(f"/api/captures/{created['id']}/graph")

        assert response.status_code == 200
        graph = response.json()
        assert graph["nodes"], "analysis must persist the evidence graph"
        assert graph["edges"]
        node_types = {n["node_type"] for n in graph["nodes"]}
        assert "capture" in node_types
        assert "session" in node_types
        assert "finding" in node_types

    def test_graph_unknown_capture_is_error(self, make_api) -> None:
        client = make_api()

        response = client.get("/api/captures/capture_000000000000/graph")

        assert response.status_code == 404

    def test_graph_filter_by_node_type(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client)

        response = client.get(
            f"/api/captures/{created['id']}/graph", params={"node_type": "session"}
        )

        assert response.status_code == 200
        graph = response.json()
        assert graph["nodes"]
        assert all(n["node_type"] == "session" for n in graph["nodes"])


class TestSessionContext:
    def test_context_endpoint_returns_investigation_context(self, make_api) -> None:
        client = make_api()
        created = upload_and_analyze(client)
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        session_id = sessions[0]["id"]

        response = client.get(f"/api/sessions/{session_id}/context")

        assert response.status_code == 200
        context = response.json()
        assert context["session_id"] == session_id
        assert context["capture_id"] == created["id"]
        assert context["protocol"] == "smtp"
        assert isinstance(context["posture_factors"], list)
        assert isinstance(context["timeline_events"], list)
        assert isinstance(context["evidence_refs"], list)

    def test_context_unknown_session_is_error(self, make_api) -> None:
        client = make_api()

        response = client.get("/api/sessions/session_0000000000000000/context")

        assert response.status_code == 404
