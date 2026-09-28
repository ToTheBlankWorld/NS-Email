"""Deterministic demo workflow for SecureMailScope (Stages 10-14).

Loads the synthetic evaluation fixtures into an isolated demo storage,
runs the full pipeline, asks the mock AI provider, demonstrates the
case/correlation/remediation workflows, then demonstrates longitudinal
drift (baseline, verification, regression, posture trend) — entirely
offline. Intended for reliable SIH demonstrations.

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
        seeded_captures: dict[str, str] = {}

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
            seeded_captures[scenario.scenario_id] = capture_id
            print(f"  seeded {scenario.scenario_id} -> {capture_id}")

        _seed_demo_case(http, seeded_captures, summary)

        return summary
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def _seed_demo_case(http, capture_ids: dict[str, str], summary: dict[str, object]) -> None:
    """Demonstrate the Stage 11/12 case workflow over the seeded captures.

    Creates a case, attaches two SMTP captures sharing infrastructure,
    reviews a finding, adds a bookmark/note/tag, explores correlations,
    asks the mock AI about one correlation, then generates the case
    report and exports the case bundle — all offline over the real API.
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

    # Two SMTP captures sharing endpoint/host/protocol/SNI/issuer.
    case_captures = [capture_ids[s] for s in ("secure-tls12", "deprecated-tls10")]
    for capture_id in case_captures:
        status, body = http(
            "POST",
            f"/api/cases/{case_id}/captures",
            _json.dumps({"capture_id": capture_id}).encode(),
            "application/json",
        )
        assert status == 200, (status, body)

    bookmarked = False
    for capture_id in case_captures:
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

    _demo_correlations(http, case_id, case_captures)
    _demo_remediation(http, case_id, capture_ids)
    _demo_drift(http, summary)

    # Regenerate the report and export now that remediation workflow
    # state exists, so the bundle reflects the full demo.
    for path in ("report.json", "export", "bundle"):
        status, body = http("GET", f"/api/cases/{case_id}/{path}")
        assert status == 200, (path, status, body[:200])

    summary["case"] = {"case_id": case_id, "captures": len(case_captures)}
    print(f"  seeded demo case -> {case_id}")


def _demo_remediation(http, case_id: str, capture_ids: dict[str, str]) -> None:
    """Demonstrate the Stage 13 remediation workflow over the demo case.

    Baseline deprecated-tls10 carries TLS-VERSION-001; verification
    against secure-tls12 shows the rule absent (VERIFIED) with a quoted
    posture comparison. All offline over the real API.
    """
    import json as _json

    baseline_id = capture_ids["deprecated-tls10"]
    verification_id = capture_ids["secure-tls12"]

    _, findings_body = http("GET", f"/api/captures/{baseline_id}/findings")
    findings = _json.loads(findings_body)
    target = next(f for f in findings if f["rule_id"] == "TLS-VERSION-001")

    status, body = http(
        "POST",
        f"/api/cases/{case_id}/remediations/from-finding",
        _json.dumps({"finding_id": target["id"], "owner": "netops"}).encode(),
        "application/json",
    )
    assert status == 200, (status, body)
    remediation_id = _json.loads(body)["remediation_id"]

    for next_status in ("PLANNED", "IN_PROGRESS"):
        status, body = http(
            "PATCH",
            f"/api/cases/{case_id}/remediations/{remediation_id}",
            _json.dumps({"status": next_status}).encode(),
            "application/json",
        )
        assert status == 200, (status, body)

    status, body = http(
        "POST",
        f"/api/cases/{case_id}/remediations/{remediation_id}/verify",
        _json.dumps({"mode": "evidence", "verification_capture_id": verification_id}).encode(),
        "application/json",
    )
    assert status == 200, (status, body)
    result = _json.loads(body)
    assert result["result"] == "VERIFIED", body[:200]
    comparison = result["comparison"]
    print(f"  remediation {remediation_id} -> {result['result']}")
    print(f"  {comparison['statement']}")
    before = comparison["posture_before"]
    after = comparison["posture_after"]
    print(
        f"  posture: {before.get('posture_state')} ({before.get('overall_score')}) -> "
        f"{after.get('posture_state')} ({after.get('overall_score')})"
    )


def _demo_correlations(http, case_id: str, capture_ids: list[str]) -> None:
    """Demonstrate the Stage 12 correlation workflow over the demo case."""
    import json as _json

    status, body = http("GET", f"/api/cases/{case_id}/correlations/summary")
    assert status == 200, (status, body)
    corr_summary = _json.loads(body)
    assert corr_summary["correlation_count"] >= 1, corr_summary
    print(f"  correlations: {corr_summary['correlation_count']} across {len(capture_ids)} captures")

    status, body = http("GET", f"/api/cases/{case_id}/correlations?sort=type")
    assert status == 200, (status, body)
    correlations = _json.loads(body)["correlations"]
    first = correlations[0]
    print(f"  inspect {first['correlation_type']}: {first['evidence_key'][:72]}")

    status, body = http(
        "GET", f"/api/cases/{case_id}/correlations/{first['correlation_id']}/context"
    )
    assert status == 200, (status, body)
    assert _json.loads(body)["graph_nodes"], body[:200]

    status, body = http("GET", f"/api/cases/{case_id}/graph")
    assert status == 200, (status, body)
    assert _json.loads(body)["edge_count"] >= 1, body[:200]

    _, sessions_body = http("GET", f"/api/captures/{capture_ids[0]}/sessions")
    session_id = _json.loads(sessions_body)[0]["id"]
    status, body = http("GET", f"/api/cases/{case_id}/sessions/{session_id}/related")
    assert status == 200, (status, body)

    status, body = http(
        "POST",
        "/api/ai/query-correlation",
        _json.dumps(
            {
                "question": "Explain the repeated observations in this case.",
                "case_id": case_id,
                "correlation_id": first["correlation_id"],
            }
        ).encode(),
        "application/json",
    )
    assert status == 200 and _json.loads(body)["status"] == "completed", body
    print("  correlation summary displayed; shared evidence inspected; mock AI queried")


def _demo_drift(http, summary: dict[str, object]) -> None:
    """Demonstrate the Stage 14 longitudinal workflow over the demo case.

    Seeds three deterministic drift captures (A: TLS 1.0 findings,
    B: TLS 1.2 clean, C: TLS 1.0 findings return), selects A as the
    explicit baseline, verifies a remediation against B, then shows the
    posture trend, a resolved finding (A->B), a recurring finding
    (B->C), configuration drift, and the remediation regression — all
    offline over the real API.
    """
    import json as _json

    from scripts.drift_fixtures import load_drift_scenarios

    boundary = "----nse-demo-drift"
    scenarios = {s.scenario_id: s for s in load_drift_scenarios()}

    def upload(scenario_id: str) -> str:
        scenario = scenarios[scenario_id]
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
        assert status in (200, 201), (status, body)
        capture_id = _json.loads(body)["id"]
        status, body = http("POST", f"/api/captures/{capture_id}/analyze")
        assert status == 200, (status, body)
        assert _json.loads(body)["status"] == "completed", body
        return capture_id

    # 1-3. Seed baseline capture, analyze, create case, attach baseline.
    baseline_id = upload("drift-capture-a")
    print(f"  drift baseline seeded -> {baseline_id}")
    status, body = http(
        "POST",
        "/api/cases",
        _json.dumps(
            {
                "title": "Demo longitudinal investigation",
                "description": "Offline demonstration of security posture drift.",
                "priority": "HIGH",
            }
        ).encode(),
        "application/json",
    )
    assert status == 200, (status, body)
    case_id = _json.loads(body)["case_id"]
    status, body = http(
        "POST",
        f"/api/cases/{case_id}/captures",
        _json.dumps({"capture_id": baseline_id}).encode(),
        "application/json",
    )
    assert status == 200, (status, body)

    # 4-5. Explicit baseline selection + remediation from the TLS finding.
    status, body = http(
        "POST",
        f"/api/cases/{case_id}/observations/baseline",
        _json.dumps({"capture_id": baseline_id}).encode(),
        "application/json",
    )
    assert status == 200, (status, body)
    _, findings_body = http("GET", f"/api/captures/{baseline_id}/findings")
    target = next(f for f in _json.loads(findings_body) if f["rule_id"] == "TLS-VERSION-001")
    status, body = http(
        "POST",
        f"/api/cases/{case_id}/remediations/from-finding",
        _json.dumps({"finding_id": target["id"], "owner": "netops"}).encode(),
        "application/json",
    )
    assert status == 200, (status, body)
    remediation_id = _json.loads(body)["remediation_id"]
    for next_status in ("PLANNED", "IN_PROGRESS"):
        status, body = http(
            "PATCH",
            f"/api/cases/{case_id}/remediations/{remediation_id}",
            _json.dumps({"status": next_status}).encode(),
            "application/json",
        )
        assert status == 200, (status, body)

    # 6-7. Seed verification capture, verify the remediation.
    verification_id = upload("drift-capture-b")
    status, body = http(
        "POST",
        f"/api/cases/{case_id}/captures",
        _json.dumps({"capture_id": verification_id}).encode(),
        "application/json",
    )
    assert status == 200, (status, body)
    status, body = http(
        "POST",
        f"/api/cases/{case_id}/remediations/{remediation_id}/verify",
        _json.dumps({"mode": "evidence", "verification_capture_id": verification_id}).encode(),
        "application/json",
    )
    assert status == 200, (status, body)
    assert _json.loads(body)["result"] == "VERIFIED", body[:200]
    print(f"  drift remediation {remediation_id} verified against {verification_id}")

    # 8-9. Seed regression capture, read longitudinal observations.
    regression_id = upload("drift-capture-c")
    status, body = http(
        "POST",
        f"/api/cases/{case_id}/captures",
        _json.dumps({"capture_id": regression_id}).encode(),
        "application/json",
    )
    assert status == 200, (status, body)
    status, body = http("GET", f"/api/cases/{case_id}/observations")
    assert status == 200, (status, body)
    observations = _json.loads(body)["observations"]
    assert len(observations) == 3, body[:200]

    # 10. Posture trend (quoted scores, no causal claims).
    trend = [(o["capture_id"], o["posture_state"], o["posture_score"]) for o in observations]
    print(
        f"  posture trend: {trend[0][1]} ({trend[0][2]}) -> {trend[1][1]} ({trend[1][2]})"
        f" -> {trend[2][1]} ({trend[2][2]})"
    )

    # 11-13. Resolved finding, recurring finding, configuration drift.
    status, body = http("GET", f"/api/cases/{case_id}/drift/summary")
    assert status == 200, (status, body)
    drift_summary = _json.loads(body)
    assert drift_summary["resolved_findings"] >= 1, body[:200]
    assert drift_summary["recurring_findings"] >= 1, body[:200]
    assert drift_summary["configuration_changes"] >= 1, body[:200]
    print(
        f"  resolved findings: {drift_summary['resolved_findings']}, "
        f"recurring findings: {drift_summary['recurring_findings']}, "
        f"configuration changes: {drift_summary['configuration_changes']}"
    )

    # 14. Remediation regression after previous verification.
    status, body = http("GET", f"/api/cases/{case_id}/drift?type=finding_recurred")
    assert status == 200, (status, body)
    recurred = _json.loads(body)["drift"]
    assert any(
        d["regression_after_verification"] and remediation_id in d["related_remediation_ids"]
        for d in recurred
    ), body[:200]
    print("  regression detected after previous verification; remediation may require review")

    # 15-16. Case report and bundle including longitudinal analysis.
    for path in ("report.json", "report.html", "report.pdf", "export", "bundle"):
        status, body = http("GET", f"/api/cases/{case_id}/{path}")
        assert status == 200, (path, status, body[:200])
    summary["drift_case"] = {"case_id": case_id, "observations": 3}
    print(f"  seeded drift case -> {case_id}")


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
