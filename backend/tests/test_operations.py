"""Stage 10 operational tests: readiness, configuration validation, limits."""

from pathlib import Path

import pytest

from app.config import DEFAULT_CORS_ORIGINS, Settings, validate_settings
from tests import tcp_fixtures as tf


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    defaults: dict[str, object] = {
        "service_name": "ns-email",
        "app_version": "0.0.0",
        "cors_origins": DEFAULT_CORS_ORIGINS,
        "capture_storage_dir": tmp_path / "captures",
    }
    defaults.update(overrides)
    return Settings(**defaults)  # type: ignore[arg-type]


class TestReadiness:
    def test_ready_reports_healthy_dependencies(self, make_api) -> None:
        client = make_api()

        response = client.get("/ready")

        assert response.status_code == 200
        body = response.json()
        assert body["ready"] is True
        assert body["checks"]["database"] is True
        assert body["checks"]["storage"] is True

    def test_ready_does_not_require_ai_configuration(self, make_api) -> None:
        # No AI provider configured — readiness must still be true.
        client = make_api()
        assert client.get("/ready").json()["ready"] is True

    def test_ready_degrades_when_database_is_corrupt(self, tmp_path: Path) -> None:
        from app.store import SQLiteSessionStore

        # A corrupt database file must make the readiness probe report
        # False instead of raising.
        db_path = tmp_path / "broken.sqlite"
        store = SQLiteSessionStore(db_path)
        db_path.write_bytes(b"this is not a sqlite database" * 100)
        assert store.ping() is False


class TestConfigurationValidation:
    def test_default_configuration_is_valid(self, tmp_path: Path) -> None:
        assert validate_settings(_settings(tmp_path)) == []

    def test_empty_ai_provider_is_valid(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, ai_provider="", ai_base_url="", ai_model="")
        assert validate_settings(settings) == []

    def test_unknown_ai_provider_is_rejected(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, ai_provider="gemini")
        problems = validate_settings(settings)
        assert len(problems) == 1
        assert "NS_EMAIL_AI_PROVIDER" in problems[0]

    def test_openai_requires_base_url_and_model(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, ai_provider="openai")
        problems = validate_settings(settings)
        assert any("NS_EMAIL_AI_BASE_URL" in p for p in problems)
        assert any("NS_EMAIL_AI_MODEL" in p for p in problems)

    def test_ollama_requires_base_url(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, ai_provider="ollama", ai_model="llama3")
        problems = validate_settings(settings)
        assert any("NS_EMAIL_AI_BASE_URL" in p for p in problems)

    def test_base_url_must_be_http(self, tmp_path: Path) -> None:
        settings = _settings(tmp_path, ai_provider="ollama", ai_base_url="ftp://localhost:11434")
        problems = validate_settings(settings)
        assert any("http" in p for p in problems)

    def test_api_key_values_are_never_echoed(self, tmp_path: Path) -> None:
        settings = _settings(
            tmp_path,
            ai_provider="openai",
            ai_base_url="https://api.example.com",
            ai_model="gpt-x",
            ai_api_key="sk-super-secret-value",
        )
        problems = validate_settings(settings)
        assert problems == []
        # even with problems, the key value must never appear
        settings_bad = _settings(tmp_path, ai_provider="openai")
        rendered = "\n".join(validate_settings(settings_bad))
        assert "sk-super-secret-value" not in rendered

    def test_invalid_provider_fails_fast_at_startup(self, tmp_path: Path) -> None:
        from app.main import create_app

        with pytest.raises(RuntimeError, match="invalid configuration"):
            create_app(_settings(tmp_path, ai_provider="bogus"))


class TestResourceLimits:
    def test_graph_node_limit_is_respected(self, make_api) -> None:
        """A capture whose graph exceeds the configured limit is still
        analyzed; only the graph is omitted, with an explicit warning."""
        client = make_api(max_graph_nodes=5)
        created = client.post(
            "/api/captures",
            files={"file": ("smtp.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        ).json()
        analysis = client.post(f"/api/captures/{created['id']}/analyze")
        assert analysis.status_code == 200
        record = client.get(f"/api/captures/{created['id']}").json()
        warnings = (record.get("analysis") or {}).get("warnings", [])
        assert any("graph omitted" in w for w in warnings)
        graph = client.get(f"/api/captures/{created['id']}/graph")
        assert graph.status_code == 404

    def test_default_graph_limit_admits_normal_captures(self, make_api) -> None:
        client = make_api()
        created = client.post(
            "/api/captures",
            files={"file": ("smtp.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        ).json()
        client.post(f"/api/captures/{created['id']}/analyze")
        graph = client.get(f"/api/captures/{created['id']}/graph")
        assert graph.status_code == 200
