"""Stage 9 live smoke test: analyst workstation + forensic reporting.

Runs against a real server on a temporary database with the mock AI
provider. Verifies the full analyst flow: upload -> analyze -> posture ->
findings -> anomalies -> graph -> session context -> AI query ->
JSON/HTML/PDF reports -> sensitive-data checks -> structured errors.
"""

import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

BASE = "http://127.0.0.1:8124"


def http(method: str, path: str, body: bytes | None = None, ctype: str | None = None,
         raw: bool = False):
    """Return (status, parsed-json-or-raw-bytes, content-type)."""
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            content_type = resp.headers.get("Content-Type", "")
            payload = resp.read()
            return resp.status, (payload if raw else _decode(payload, content_type)), content_type
    except urllib.error.HTTPError as e:
        return e.code, _decode(e.read(), "application/json"), ""


def _decode(raw: bytes, content_type: str):
    if "json" in content_type:
        return json.loads(raw.decode())
    return raw


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="nse_smoke9_")
    os.environ["NS_EMAIL_CAPTURE_STORAGE"] = os.path.join(tmp, "storage")
    os.environ["NS_EMAIL_AI_PROVIDER"] = "mock"

    from app.main import create_app  # noqa: E402

    import uvicorn  # noqa: E402

    app = create_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=8124, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "server failed to start"

    try:
        # -- 1-2. upload + analyze ----------------------------------------
        from tests.tls_fixtures import smtp_starttls_tls_pcap

        pcap = smtp_starttls_tls_pcap()
        boundary = "----smoke9"
        parts = [
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="starttls.pcap"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(),
            pcap,
            f"\r\n--{boundary}--\r\n".encode(),
        ]
        status, created, _ = http(
            "POST", "/api/captures", b"".join(parts),
            f"multipart/form-data; boundary={boundary}",
        )
        assert status == 201, (status, created)
        capture_id = created["id"]
        print(f"[1] uploaded capture: {capture_id}")

        status, analysis, _ = http("POST", f"/api/captures/{capture_id}/analyze")
        assert status == 200 and analysis["status"] == "completed", (status, analysis)
        print(f"[2] analyzed: {analysis['sessions_found']} session(s)")

        # -- 3-4. dashboard data: capture + posture ------------------------
        status, posture, _ = http("GET", f"/api/captures/{capture_id}/posture")
        assert status == 200 and posture["analysis_version"], (status, posture)
        print(
            f"[3] posture: state={posture['posture_state']} "
            f"score={posture['overall_score']}"
        )

        # -- 5-6. findings + anomalies --------------------------------------
        status, findings, _ = http("GET", f"/api/captures/{capture_id}/findings")
        assert status == 200 and isinstance(findings, list), (status, findings)
        print(f"[4] findings: {len(findings)}")

        status, anomalies, _ = http("GET", f"/api/captures/{capture_id}/anomalies")
        assert status == 200, (status, anomalies)
        print(f"[5] anomalies: {len(anomalies)}")

        # -- 7. evidence graph ------------------------------------------------
        status, graph, _ = http("GET", f"/api/captures/{capture_id}/graph")
        assert status == 200 and graph["nodes"], (status, graph)
        print(f"[6] graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")

        # -- 8. session context ------------------------------------------------
        status, sessions, _ = http("GET", f"/api/captures/{capture_id}/sessions")
        assert status == 200 and sessions, (status, sessions)
        session_id = sessions[0]["id"]
        status, context, _ = http("GET", f"/api/sessions/{session_id}/context")
        assert status == 200 and context["session_id"] == session_id, (status, context)
        print(f"[7] session context OK for {session_id}")

        # -- 9. AI query (mock provider) ------------------------------------
        status, ai_result, _ = http(
            "POST",
            "/api/ai/query",
            json.dumps({"session_id": session_id, "question": "Explain this session"}).encode(),
            "application/json",
        )
        assert status == 200 and ai_result["status"] == "completed", (status, ai_result)
        assert ai_result["validation_status"] == "validated", ai_result
        print(f"[8] AI query validated via {ai_result['provider']}/{ai_result['model']}")

        # -- 10-12. reports ------------------------------------------------------
        status, report_bytes, ctype = http(
            "GET", f"/api/captures/{capture_id}/report.json", raw=True
        )
        assert status == 200 and ctype.startswith("application/json"), (status, ctype)
        report = json.loads(report_bytes)
        for section in (
            "report", "capture", "executive_summary", "posture", "findings",
            "anomalies", "tls_summary", "graph_summary", "ai_analyst",
            "limitations", "methodology",
        ):
            assert section in report, f"missing section {section}"
        assert report["ai_analyst"]["configured"] is True
        assert len(report["ai_analyst"]["observations"]) == 1
        print(
            f"[9] JSON report OK: {report['graph_summary']['node_count']} graph nodes, "
            f"{report['executive_summary']['findings_total']} findings"
        )

        status, report2_bytes, _ = http(
            "GET", f"/api/captures/{capture_id}/report.json", raw=True
        )
        assert report_bytes == report2_bytes, "JSON report must be deterministic"
        print("[10] JSON report deterministic")

        status, html, ctype = http(
            "GET", f"/api/captures/{capture_id}/report.html", raw=True
        )
        assert status == 200 and ctype.startswith("text/html"), (status, ctype)
        html_text = html.decode("utf-8")
        assert "SecureMailScope" in html_text and "<script" not in html_text
        print("[11] HTML report OK (standalone, no inline scripts)")

        status, pdf, ctype = http(
            "GET", f"/api/captures/{capture_id}/report.pdf", raw=True
        )
        assert status == 200 and ctype == "application/pdf", (status, ctype)
        assert pdf.startswith(b"%PDF-"), "not a PDF"
        assert len(pdf) > 2000
        print(f"[12] PDF report OK ({len(pdf)} bytes)")

        # -- 13-14. sensitive-data exclusion ------------------------------------
        blob = json.dumps(report).lower() + html_text.lower()
        for forbidden in ("body must not appear", "hunter2", "api_key", "authorization"):
            assert forbidden not in blob, f"sensitive value leaked: {forbidden}"
        assert b"Body must not appear" not in pdf
        print("[13] no sensitive values in JSON/HTML/PDF reports")

        # -- 15. expected evidence present ----------------------------------------
        assert report["capture"]["capture_id"] == capture_id
        assert report["capture"]["sha256"]
        assert report["posture"]["available"] is True
        assert report["executive_summary"]["total_sessions"] >= 1
        assert report["tls_summary"]["versions_observed"]
        print("[14] report contains expected evidence")

        # -- 16. unknown capture structured error ---------------------------------
        status, error, _ = http("GET", "/api/captures/capture_000000000000/report.json")
        assert status == 404 and error["error"]["code"] == "capture_not_found", (status, error)
        status, error2, _ = http("GET", "/api/captures/capture_000000000000/report.pdf")
        assert status == 404, (status, error2)
        print("[15] unknown capture -> structured 404 for all report formats")

        print("SMOKE TEST PASSED")
        return 0
    finally:
        server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
