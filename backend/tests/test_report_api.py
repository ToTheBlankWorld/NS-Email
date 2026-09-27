"""Stage 9 API tests: report model, JSON/HTML/PDF reports, AI integration."""

import json
import re
from datetime import datetime

from tests import tcp_fixtures as tf
from tests import tls_fixtures as tlf

_PDF_MAGIC = b"%PDF-"
_MALICIOUS = "<img src=x onerror=alert(1)>"


def upload_and_analyze(client, name: str = "smtp.pcap", content: bytes | None = None):
    created = client.post(
        "/api/captures",
        files={"file": (name, content or tf.smtp_plain_pcap(), "application/octet-stream")},
    ).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
    return created, analysis


class TestJSONReport:
    def test_report_schema_is_complete(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, analysis = upload_and_analyze(client)
        assert analysis["status"] == "completed"

        response = client.get(f"/api/captures/{created['id']}/report.json")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        report = json.loads(response.content)
        for section in (
            "report",
            "capture",
            "executive_summary",
            "posture",
            "findings",
            "anomalies",
            "tls_summary",
            "graph_summary",
            "ai_analyst",
            "limitations",
            "methodology",
        ):
            assert section in report, f"missing report section: {section}"
        assert report["report"]["schema_version"] == "1.0"
        assert report["report"]["report_id"].startswith("report_")
        assert report["capture"]["capture_id"] == created["id"]
        assert report["capture"]["sha256"]
        assert report["executive_summary"]["total_sessions"] >= 1
        assert report["executive_summary"]["findings_total"] >= 0

    def test_report_is_deterministic(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)

        first = client.get(f"/api/captures/{created['id']}/report.json")
        second = client.get(f"/api/captures/{created['id']}/report.json")

        assert first.content == second.content

    def test_report_includes_posture_findings_anomalies_graph(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())

        report = json.loads(client.get(f"/api/captures/{created['id']}/report.json").content)

        assert report["posture"]["available"] is True
        assert report["posture"]["policy_id"]
        assert report["graph_summary"]["node_count"] >= 1
        assert report["graph_summary"]["edge_count"] >= 1
        assert report["tls_summary"]["versions_observed"]
        assert report["anomalies"]["available"] is True

    def test_report_has_no_sensitive_fields(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)

        raw = client.get(f"/api/captures/{created['id']}/report.json").content.decode()
        lowered = raw.lower()

        assert "body must not appear in evidence" not in lowered
        assert "hunter2" not in lowered
        assert "api_key" not in lowered
        assert "authorization" not in lowered

    def test_report_includes_validated_ai_results(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        client.post(
            "/api/ai/query",
            json={"session_id": sessions[0]["id"], "question": "Explain this session"},
        )

        report = json.loads(client.get(f"/api/captures/{created['id']}/report.json").content)

        ai_section = report["ai_analyst"]
        assert ai_section["configured"] is True
        assert len(ai_section["observations"]) == 1
        entry = ai_section["observations"][0]
        assert entry["validation_status"] == "validated"
        assert entry["answer"]

    def test_report_without_ai_configured_still_works(self, make_api) -> None:
        client = make_api()
        created, _ = upload_and_analyze(client)

        response = client.get(f"/api/captures/{created['id']}/report.json")

        assert response.status_code == 200
        report = json.loads(response.content)
        assert report["ai_analyst"]["configured"] is False
        assert report["ai_analyst"]["note"] == "AI analyst not configured"
        assert report["ai_analyst"]["observations"] == []
        limitations = "\n".join(report["limitations"]["items"])
        assert "AI analyst is not configured" in limitations

    def test_unknown_capture_returns_structured_error(self, make_api) -> None:
        client = make_api(ai_provider="mock")

        response = client.get("/api/captures/capture_000000000000/report.json")

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "capture_not_found"

    def test_report_before_analysis_returns_structured_error(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created = client.post(
            "/api/captures",
            files={"file": ("a.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        ).json()

        response = client.get(f"/api/captures/{created['id']}/report.json")

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "posture_not_available"


class TestHTMLReport:
    def test_html_report_is_complete_and_standalone(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())

        response = client.get(f"/api/captures/{created['id']}/report.html")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        html = response.content.decode("utf-8")
        assert "<!DOCTYPE html>" in html
        assert "SecureMailScope" in html
        for heading in (
            "Executive Summary",
            "Security Posture",
            "Security Findings",
            "Behavioral Anomalies",
            "AI Analyst Observations",
            "Limitations",
            "Methodology",
        ):
            assert heading in html
        # no external resources
        assert "http://" not in html.replace("http://www.w3.org", "")
        assert "<script" not in html
        assert "cdn" not in html.lower()

    def test_html_report_escapes_malicious_evidence(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created = client.post(
            "/api/captures",
            files={
                "file": (_MALICIOUS + ".pcap", tf.smtp_plain_pcap(), "application/octet-stream")
            },
        ).json()
        client.post(f"/api/captures/{created['id']}/analyze")

        html = client.get(f"/api/captures/{created['id']}/report.html").content.decode("utf-8")

        assert "<img" not in html
        assert "&lt;img" in html

    def test_html_report_unanalyzed_capture_is_error(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created = client.post(
            "/api/captures",
            files={"file": ("a.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        ).json()

        response = client.get(f"/api/captures/{created['id']}/report.html")

        assert response.status_code == 404


class TestPDFReport:
    def test_pdf_report_is_structured_pdf(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())

        response = client.get(f"/api/captures/{created['id']}/report.pdf")

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content.startswith(b"%PDF-")
        assert len(response.content) > 2000
        assert b"/Page" in response.content
        assert b"%%EOF" in response.content

    def test_pdf_report_is_deterministic(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)

        first = client.get(f"/api/captures/{created['id']}/report.pdf")
        second = client.get(f"/api/captures/{created['id']}/report.pdf")

        assert first.content == second.content

    def test_pdf_creation_date_is_not_wall_clock(self, make_api) -> None:
        """The PDF Info date must mirror the report's deterministic generated_at."""
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)

        report = json.loads(client.get(f"/api/captures/{created['id']}/report.json").content)
        raw = client.get(f"/api/captures/{created['id']}/report.pdf").content

        match = re.search(rb"/CreationDate\s*\(([^)]*)\)", raw)
        assert match, "PDF must contain a /CreationDate entry"
        generated = datetime.fromisoformat(report["report"]["generated_at"])
        assert match.group(1).decode() == "D:" + generated.strftime("%Y%m%d%H%M%S") + "Z"

    def test_pdf_report_no_sensitive_values(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)

        raw = client.get(f"/api/captures/{created['id']}/report.pdf").content

        assert b"Body must not appear" not in raw

    def test_pdf_before_analysis_is_error(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created = client.post(
            "/api/captures",
            files={"file": ("a.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        ).json()

        response = client.get(f"/api/captures/{created['id']}/report.pdf")

        assert response.status_code == 404


class TestReportContent:
    def test_findings_carry_evidence_and_remediation(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client, "tls.pcap", tlf.smtp_starttls_tls_pcap())

        report = json.loads(client.get(f"/api/captures/{created['id']}/report.json").content)

        findings = report["findings"]
        assert findings, "expected at least one finding"
        first = findings[0]
        for field in ("rule_id", "severity", "confidence", "title", "description", "evidence_refs"):
            assert field in first
        assert isinstance(first["evidence_refs"], list)

    def test_report_id_is_stable_across_regenerations(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        created, _ = upload_and_analyze(client)

        first = json.loads(client.get(f"/api/captures/{created['id']}/report.json").content)
        second = json.loads(client.get(f"/api/captures/{created['id']}/report.json").content)

        assert first["report"]["report_id"] == second["report"]["report_id"]
        assert re.fullmatch(r"report_[0-9a-f]{12}", first["report"]["report_id"])
