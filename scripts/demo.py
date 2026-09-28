"""Deterministic demo workflow for SecureMailScope (Stage 10).

Loads the synthetic evaluation fixtures into an isolated demo storage,
runs the full pipeline, asks the mock AI provider, and generates
reports — entirely offline. Intended for reliable SIH demonstrations.

Usage:

    python -m scripts.demo                 # seed, verify, then serve
    python -m scripts.demo --run-once      # seed + verify + exit (CI-safe)
    python -m scripts.demo --port 8080     # custom port

The demo never requires internet, an external LLM, or real credentials,
and it never touches production storage (a temporary demo directory is
used unless --storage-dir is given).
"""

import argparse
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from scripts.fixtures import load_scenarios  # noqa: E402

DEMO_AI_PROVIDER = "mock"


def seed_demo(storage_dir: Path, port: int) -> dict[str, object]:
    """Seed an isolated demo backend and run the full workflow over HTTP."""
    import os

    os.environ["NS_EMAIL_CAPTURE_STORAGE"] = str(storage_dir)
    os.environ["NS_EMAIL_AI_PROVIDER"] = DEMO_AI_PROVIDER

    import uvicorn
    from fastapi.testclient import TestClient  # noqa: F401 - kept for parity

    from app.main import create_app

    app = create_app()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "demo server failed to start"

    try:
        import urllib.error
        import urllib.request

        def http(method: str, path: str, body: bytes | None = None, ctype: str | None = None):
            req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, method=method)
            if ctype:
                req.add_header("Content-Type", ctype)
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as e:  # pragma: no cover - demo path
                return e.code, e.read()

        summary: dict[str, object] = {"scenarios": [], "reports": []}
        boundary = "----nse-demo"
        seeded_captures: list[str] = []

        for scenario in load_scenarios():
            parts = [
                (
                    f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                    f'filename="{scenario.filename}"\r\n'
                    f"Content-Type: application/octet-stream\r\n\r\n"
                ).encode(),
                scenario.pcap,
                f"\r\n--{boundary}--\r\n".encode(),
            ]
            status, body = http(
                "POST",
                "/api/captures",
                b"".join(parts),
                f"multipart/form-data; boundary={boundary}",
            )
            # 201 = fresh upload, 200 = deterministic re-seed (duplicate)
            assert status in (200, 201), (status, body)
            capture_id = json.loads(body)["id"]

            status, body = http("POST", f"/api/captures/{capture_id}/analyze")
            assert status == 200, (status, body)
            analysis = json.loads(body)
            assert analysis["status"] == "completed", analysis

            sessions = json.loads(http("GET", f"/api/captures/{capture_id}/sessions")[1])
            if sessions:
                session_id = sessions[0]["id"]
                status, body = http(
                    "POST",
                    "/api/ai/query",
                    json.dumps(
                        {
                            "session_id": session_id,
                            "question": f"Explain the {scenario.scenario_id} scenario",
                        }
                    ).encode(),
                    "application/json",
                )
                assert status == 200 and json.loads(body)["status"] == "completed", body

            for fmt in ("json", "html", "pdf"):
                status, body = http("GET", f"/api/captures/{capture_id}/report.{fmt}")
                assert status == 200, (fmt, status, body[:200])
                summary["reports"].append(f"{capture_id}/report.{fmt}")  # type: ignore[union-attr]

            summary["scenarios"].append(  # type: ignore[union-attr]
                {
                    "scenario": scenario.scenario_id,
                    "capture_id": capture_id,
                    "sessions": analysis["sessions_found"],
                }
            )
            seeded_captures.append(capture_id)
            print(f"  seeded {scenario.scenario_id} -> {capture_id}")

        _seed_demo_case(http, seeded_captures, summary)

        return summary
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def _seed_demo_case(http, capture_ids: list[str], summary: dict[str, object]) -> None:
    """Demonstrate the Stage 11 case workflow over the seeded captures.

    Creates a case, attaches captures, reviews a finding, adds a
    bookmark/note/tag, generates the case report, and exports the case
    bundle — all offline over the real API.
    """
    import json as _json

    assert capture_ids, "demo requires at least one seeded capture"
    status, body = http(
        "POST",
        "/api/cases",
        _json.dumps(
            {
                "title": "Demo TLS investigation",
                "description": "Offline demonstration of case management.",
                "priority": "HIGH",
            }
        ).encode(),
        "application/json",
    )
    assert status == 200, (status, body)
    case_id = _json.loads(body)["case_id"]

    for capture_id in capture_ids[:2]:
        status, body = http(
            "POST",
            f"/api/cases/{case_id}/captures",
            _json.dumps({"capture_id": capture_id}).encode(),
            "application/json",
        )
        assert status == 200, (status, body)

    bookmarked = False
    for capture_id in capture_ids:
        _, findings_body = http("GET", f"/api/captures/{capture_id}/findings")
        for finding in _json.loads(findings_body):
            status, body = http(
                "POST",
                f"/api/cases/{case_id}/bookmarks",
                _json.dumps(
                    {
                        "target_type": "finding",
                        "target_id": finding["id"],
                        "label": "demo bookmark",
                    }
                ).encode(),
                "application/json",
            )
            assert status == 200, (status, body)
            bookmarked = True
            break
        if bookmarked:
            break
    assert bookmarked, "demo requires at least one finding to bookmark"

    status, body = http(
        "POST",
        f"/api/cases/{case_id}/notes",
        _json.dumps(
            {"target_type": "case", "target_id": case_id, "content": "Demo analyst note."}
        ).encode(),
        "application/json",
    )
    assert status == 200, (status, body)

    status, body = http(
        "POST",
        f"/api/cases/{case_id}/tags",
        _json.dumps({"tag": "demo"}).encode(),
        "application/json",
    )
    assert status == 200, (status, body)

    for path in ("report.json", "report.html", "report.pdf", "export", "bundle"):
        status, body = http("GET", f"/api/cases/{case_id}/{path}")
        assert status == 200, (path, status, body[:200])

    summary["case"] = {"case_id": case_id, "captures": len(capture_ids[:2])}
    print(f"  seeded demo case -> {case_id}")


def serve(storage_dir: Path, port: int) -> int:
    """Serve the seeded demo application until interrupted."""
    import os

    os.environ["NS_EMAIL_CAPTURE_STORAGE"] = str(storage_dir)
    os.environ["NS_EMAIL_AI_PROVIDER"] = DEMO_AI_PROVIDER

    import uvicorn

    from app.main import create_app

    app = create_app()
    print(f"\nDemo running: http://127.0.0.1:{port}  (Ctrl+C to stop)")
    print(f"Dashboard:    http://127.0.0.1:{port}/")
    print(f"Reports:      http://127.0.0.1:{port}/reports")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.demo",
        description="Deterministic offline demo: synthetic fixtures, mock AI, real APIs.",
    )
    parser.add_argument("--port", type=int, default=8900)
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Seed and verify the demo workflow, then exit (no serving)",
    )
    parser.add_argument(
        "--storage-dir",
        type=Path,
        default=None,
        help="Demo storage directory (default: a temporary directory)",
    )
    args = parser.parse_args(argv)

    storage = args.storage_dir or Path(__file__).parent.parent / ".demo"
    print(f"Seeding deterministic demo data into {storage}")
    summary = seed_demo(storage, args.port)
    print(
        f"Demo verified: {len(summary['scenarios'])} scenario(s), "
        f"{len(summary['reports'])} report(s), mock AI queried"
    )
    if args.run_once:
        return 0
    return serve(storage, args.port)


if __name__ == "__main__":
    sys.exit(main())
