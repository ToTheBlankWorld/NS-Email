"""Stage 8 live smoke test: real server, real HTTP, mock AI provider.

Runs against a temporary database and storage directory. Verifies:
  1. /api/ai/status reports the mock provider as configured and local
  2. upload -> analyze -> AI query pipeline works end to end
  3. AI response is validated, grounded, and contains no credentials
"""

import json
import os
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

BASE = "http://127.0.0.1:8123"


def http(method: str, path: str, body: bytes | None = None, ctype: str | None = None):
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="nse_smoke_")
    os.environ["NS_EMAIL_CAPTURE_STORAGE"] = os.path.join(tmp, "storage")
    os.environ["NS_EMAIL_AI_PROVIDER"] = "mock"
    os.environ["NS_EMAIL_AI_MODEL"] = "mock-analyst"

    from app.main import create_app  # noqa: E402
    import uvicorn  # noqa: E402

    app = create_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=8123, log_level="warning")
    server = uvicorn.Server(config)

    import threading

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "server failed to start"

    try:
        # -- 1. AI status ------------------------------------------------
        status, body = http("GET", "/api/ai/status")
        assert status == 200, (status, body)
        assert body["configured"] is True, body
        assert body["provider"] == "mock", body
        assert body["local"] is True, body
        print(f"[1] AI status OK: {body}")

        # -- 2. upload + analyze -----------------------------------------
        from tests.tcp_fixtures import smtp_plain_pcap

        pcap = smtp_plain_pcap()
        boundary = "----smokeboundary"
        parts = [
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
            f'filename="smtp_plain.pcap"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(),
            pcap,
            f"\r\n--{boundary}--\r\n".encode(),
        ]
        upload_body = b"".join(parts)
        status, created = http(
            "POST", "/api/captures", upload_body, f"multipart/form-data; boundary={boundary}"
        )
        assert status == 201, (status, created)
        capture_id = created["id"]
        print(f"[2] uploaded capture: {capture_id}")

        status, analysis = http("POST", f"/api/captures/{capture_id}/analyze")
        assert status == 200 and analysis["status"] == "completed", (status, analysis)
        print(f"[2] analyzed: {analysis['sessions_found']} session(s)")

        status, sessions = http("GET", f"/api/captures/{capture_id}/sessions")
        assert status == 200 and len(sessions) >= 1, (status, sessions)
        session_id = sessions[0]["id"]
        print(f"[2] session: {session_id}")

        # -- 3. AI query ---------------------------------------------------
        status, result = http(
            "POST",
            "/api/ai/query",
            json.dumps(
                {"session_id": session_id, "question": "Explain this session in plain terms"}
            ).encode(),
            "application/json",
        )
        assert status == 200, (status, result)
        assert result["status"] == "completed", result
        assert result["answer"], result
        assert result["validation_status"] == "validated", result
        assert result["provider"] == "mock", result
        assert result["model"] == "mock-forensic-analyst", result
        assert result["citations"], result
        assert result["key_observations"], result
        cited = result["citations"][0]
        assert cited["session_id"] == session_id, cited
        print(f"[3] AI query OK (validation={result['validation_status']})")
        print(f"    answer: {result['answer'][:160]}")
        print(f"    observations: {len(result.get('key_observations', []))}")
        print(f"    interpretations: {len(result.get('interpretations', []))}")
        print(f"    uncertainties: {len(result.get('uncertainties', []))}")
        print(f"    citations: {len(result.get('citations', []))}")

        # data minimization: the message body must never reach AI output
        blob = json.dumps(result).lower()
        assert "body must not appear in evidence" not in blob, "message body leaked into AI output"
        assert "hunter2" not in blob and "password=" not in blob, "credential leaked"

        # -- 4. persistence + history --------------------------------------
        status, history = http("GET", f"/api/ai/history/{capture_id}")
        assert status == 200 and len(history) == 1, (status, history)
        assert history[0]["query"] == "Explain this session in plain terms", history
        assert history[0]["validation_status"] == "validated", history
        assert "api_key" not in json.dumps(history), "history must not contain secrets"
        print(f"[4] AI history persisted: {len(history)} entry")

        # -- 5. structured error for unknown session -----------------------
        status, result2 = http(
            "POST",
            "/api/ai/query",
            json.dumps({"session_id": "session_does_not_exist", "question": "Explain"}).encode(),
            "application/json",
        )
        assert status == 200 and result2["status"] == "not_found", (status, result2)
        print(f"[5] unknown session -> structured error: {result2['status']}")

        print("SMOKE TEST PASSED")
        return 0
    finally:
        server.should_exit = True
        thread.join(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
