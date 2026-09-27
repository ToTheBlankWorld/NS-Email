"""Stage 8 API tests: AI analyst endpoints, persistence, provider gating."""

from tests import tcp_fixtures as tf


def upload_and_analyze(client, name: str = "smtp.pcap"):
    created = client.post(
        "/api/captures",
        files={"file": (name, tf.smtp_plain_pcap(), "application/octet-stream")},
    ).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
    return created, analysis


class TestAIStatus:
    def test_status_configured_with_mock_provider(self, make_api) -> None:
        client = make_api(ai_provider="mock")

        response = client.get("/api/ai/status")

        assert response.status_code == 200
        status = response.json()
        assert status["configured"] is True
        assert status["provider"] == "mock"
        assert status["local"] is True
        # provider/model metadata only — never secrets or endpoints
        assert "api_key" not in response.text.lower().replace("api_key", "")

    def test_status_not_configured_by_default(self, make_api) -> None:
        client = make_api()

        response = client.get("/api/ai/status")

        assert response.status_code == 200
        assert response.json()["configured"] is False


class TestAIQuery:
    def test_query_returns_validated_grounded_response(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        session_id = sessions[0]["id"]

        response = client.post(
            "/api/ai/query",
            json={"session_id": session_id, "question": "Explain this session"},
        )

        assert response.status_code == 200
        result = response.json()
        assert result["status"] == "completed"
        assert result["validation_status"] == "validated"
        assert result["answer"]
        assert result["provider"] == "mock"
        cited_sessions = [c["session_id"] for c in result["citations"]]
        assert all(sid == session_id for sid in cited_sessions)
        # data minimization: no message bodies or credentials in AI output
        assert "Body must not appear" not in response.text

    def test_query_unknown_session_is_structured_not_found(self, make_api) -> None:
        client = make_api(ai_provider="mock")

        response = client.post(
            "/api/ai/query",
            json={"session_id": "session_0000000000000000", "question": "Explain"},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "not_found"

    def test_query_rejects_oversized_question(self, make_api) -> None:
        client = make_api(ai_provider="mock")

        response = client.post(
            "/api/ai/query",
            json={"session_id": "session_x", "question": "x" * 2001},
        )

        assert response.status_code == 422

    def test_query_persists_history(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        session_id = sessions[0]["id"]
        client.post(
            "/api/ai/query",
            json={"session_id": session_id, "question": "Explain this session"},
        )

        history = client.get(f"/api/ai/history/{created['id']}")

        assert history.status_code == 200
        entries = history.json()
        assert len(entries) == 1
        assert entries[0]["query"] == "Explain this session"
        assert entries[0]["validation_status"] == "validated"
        assert entries[0]["session_id"] == session_id


class TestAIHistory:
    def test_history_empty_before_any_query(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)

        history = client.get(f"/api/ai/history/{created['id']}")

        assert history.status_code == 200
        assert history.json() == []
