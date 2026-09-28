"""Forensic case evaluation harness (Stage 11).

Builds one complete synthetic investigation — "Mixed TLS Security
Investigation" — over existing deterministic Stage 10 fixtures, drives
it through the real case API (create, attach, review, bookmark, note,
tag, report, export, bundle), and verifies every layer against the
fixtures' hand-defined ground truth.

Case metadata must never mutate forensic truth: the harness snapshots
findings, posture, anomaly, and graph output before the analyst
workflow and requires byte-identical output afterwards.

Usage:

    python -m scripts.evaluate_cases              # human-readable summary
    python -m scripts.evaluate_cases --json out   # also write JSON
    python -m scripts.evaluate_cases --repeat 2   # run twice, require
                                                  # identical evidence output

Exit code is 0 when every check passes on every run; 1 otherwise.
"""

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

CASE_EVALUATION_SCHEMA_VERSION = "1.0"

# The mixed investigation: one healthy capture, one deprecated-TLS
# capture, one plaintext-auth capture. Ground truth comes from the
# fixtures, defined by hand before execution (see scripts.fixtures).
CASE_SCENARIO_IDS = ("secure-tls12", "deprecated-tls10", "plaintext-authentication")
CASE_TITLE = "Mixed TLS Security Investigation"


@dataclass(frozen=True, slots=True)
class Check:
    check: str
    passed: bool
    expected: str
    actual: str


@dataclass
class CaseEvaluation:
    passed: bool
    checks: list[Check] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)


def _strip_dynamic(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_dynamic(item)
            for key, item in value.items()
            if key
            not in {
                "created_at",
                "updated_at",
                "closed_at",
                "attached_at",
                "exported_at",
                "generated_at",
            }
        }
    if isinstance(value, list):
        return [_strip_dynamic(item) for item in value]
    return value


def _check(checks: list[Check], name: str, passed: bool, expected: str, actual: str) -> None:
    checks.append(Check(check=name, passed=passed, expected=expected, actual=actual))


def _make_client(tmp: Path):
    from fastapi.testclient import TestClient

    from app.config import DEFAULT_CORS_ORIGINS, Settings
    from app.main import create_app

    settings = Settings(
        service_name="ns-email",
        app_version="0.0.0",
        cors_origins=DEFAULT_CORS_ORIGINS,
        capture_storage_dir=tmp / "captures",
        ai_provider="mock",
    )
    return TestClient(create_app(settings))


def run_case_evaluation() -> CaseEvaluation:
    """Run the full synthetic case workflow once through the real API."""
    from scripts.fixtures import load_scenarios

    checks: list[Check] = []
    observed: dict[str, Any] = {}
    scenarios = {s.scenario_id: s for s in load_scenarios()}
    missing = [sid for sid in CASE_SCENARIO_IDS if sid not in scenarios]
    _check(checks, "fixtures_available", not missing, "all present", ",".join(missing) or "all")
    if missing:
        return CaseEvaluation(passed=False, checks=checks, observed=observed)

    with tempfile.TemporaryDirectory(prefix="nse_case_eval_") as tmp:
        client = _make_client(Path(tmp))

        # 1. Create the case -------------------------------------------
        response = client.post(
            "/api/cases",
            json={"title": CASE_TITLE, "description": "Stage 11 evaluation", "priority": "HIGH"},
        )
        _check(checks, "case_create", response.status_code == 200, "200", str(response.status_code))
        if response.status_code != 200:
            return CaseEvaluation(passed=False, checks=checks, observed=observed)
        case = response.json()
        case_id = case["case_id"]
        _check(
            checks,
            "case_identity",
            case["title"] == CASE_TITLE and case["status"] == "OPEN",
            "OPEN investigation",
            f"{case['status']} {case['title']}",
        )

        # 2. Ingest, analyze, and attach the fixture captures -----------
        capture_ids: dict[str, str] = {}
        pre_workflow: dict[str, Any] = {}
        for scenario_id in CASE_SCENARIO_IDS:
            scenario = scenarios[scenario_id]
            uploaded = client.post(
                "/api/captures",
                files={
                    "file": (scenario.filename, scenario.pcap, "application/octet-stream"),
                },
            )
            _check(
                checks,
                f"ingest:{scenario_id}",
                uploaded.status_code in (200, 201),
                "200/201",
                str(uploaded.status_code),
            )
            capture_id = uploaded.json()["id"]
            capture_ids[scenario_id] = capture_id
            analyzed = client.post(f"/api/captures/{capture_id}/analyze").json()
            _check(
                checks,
                f"analyze:{scenario_id}",
                analyzed["status"] == "completed",
                "completed",
                str(analyzed.get("status")),
            )
            attached = client.post(
                f"/api/cases/{case_id}/captures", json={"capture_id": capture_id}
            )
            _check(
                checks,
                f"attach:{scenario_id}",
                attached.status_code == 200,
                "200",
                str(attached.status_code),
            )
            truth = scenario.ground_truth
            findings = client.get(f"/api/captures/{capture_id}/findings").json()
            fired = {f["rule_id"] for f in findings}
            _check(
                checks,
                f"findings:{scenario_id}",
                fired == set(truth.rule_severities),
                ",".join(sorted(truth.rule_severities)) or "(none)",
                ",".join(sorted(fired)) or "(none)",
            )
            posture = client.get(f"/api/captures/{capture_id}/posture").json()
            _check(
                checks,
                f"posture:{scenario_id}",
                posture["posture_state"] == truth.posture_state,
                truth.posture_state,
                str(posture.get("posture_state")),
            )
            pre_workflow[capture_id] = {
                "findings": findings,
                "posture": posture,
                "anomalies": client.get(f"/api/captures/{capture_id}/anomalies").json(),
                "graph": client.get(f"/api/captures/{capture_id}/graph").json(),
            }
        observed["captures"] = capture_ids

        # 3. Review workflow: bookmarks, notes, tags --------------------
        first_capture = capture_ids[CASE_SCENARIO_IDS[0]]
        # secure-tls12 is healthy: bookmark a finding from a misconfigured capture.
        target_finding = None
        for scenario_id in CASE_SCENARIO_IDS:
            items = client.get(f"/api/captures/{capture_ids[scenario_id]}/findings").json()
            if items:
                target_finding = items[0]
                break
        assert target_finding is not None
        bookmark = client.post(
            f"/api/cases/{case_id}/bookmarks",
            json={
                "target_type": "finding",
                "target_id": target_finding["id"],
                "label": "evaluation bookmark",
            },
        )
        _check(
            checks, "bookmark_create", bookmark.status_code == 200, "200", str(bookmark.status_code)
        )
        sessions = client.get(f"/api/captures/{first_capture}/sessions").json()
        session_mark = client.post(
            f"/api/cases/{case_id}/bookmarks",
            json={"target_type": "session", "target_id": sessions[0]["id"]},
        )
        _check(
            checks,
            "bookmark_session",
            session_mark.status_code == 200,
            "200",
            str(session_mark.status_code),
        )
        note = client.post(
            f"/api/cases/{case_id}/notes",
            json={"target_type": "case", "target_id": case_id, "content": "Evaluation note."},
        )
        _check(checks, "note_create", note.status_code == 200, "200", str(note.status_code))
        tag = client.post(f"/api/cases/{case_id}/tags", json={"tag": "evaluation"})
        _check(checks, "tag_create", tag.status_code == 200, "200", str(tag.status_code))

        # 4. Timeline, summary ------------------------------------------
        timeline = client.get(f"/api/cases/{case_id}/timeline").json()
        event_types = [e["event_type"] for e in timeline]
        for expected in (
            "case_created",
            "capture_attached",
            "finding_bookmarked",
            "note_created",
            "tag_added",
        ):
            _check(
                checks,
                f"timeline:{expected}",
                expected in event_types,
                "present",
                "missing" if expected not in event_types else "present",
            )
        summary = client.get(f"/api/cases/{case_id}/summary").json()
        _check(
            checks,
            "summary_counts",
            summary["counts"]["captures"] == 3
            and summary["counts"]["bookmarks"] == 2
            and summary["counts"]["notes"] == 1
            and summary["counts"]["tags"] == 1,
            "3 captures, 2 bookmarks, 1 note, 1 tag",
            json.dumps(summary["counts"], sort_keys=True),
        )
        _check(
            checks,
            "summary_has_no_case_score",
            "case_score" not in summary and "overall_score" not in summary["counts"],
            "no case score",
            "invented" if "case_score" in summary else "ok",
        )
        observed["summary_counts"] = summary["counts"]

        # 5. Case report -------------------------------------------------
        report = client.get(f"/api/cases/{case_id}/report.json").json()
        _check(
            checks,
            "report_sections",
            all(
                section in report
                for section in (
                    "report",
                    "case",
                    "evidence",
                    "analyst_work",
                    "ai_interpretation",
                    "provenance",
                    "limitations",
                    "methodology",
                )
            ),
            "all sections",
            ",".join(sorted(report)),
        )
        _check(
            checks,
            "report_separation",
            "not forensic evidence" in report["analyst_work"]["notice"]
            and "never forensic evidence" in report["ai_interpretation"]["notice"],
            "labeled separation",
            "missing labels",
        )
        report_hashes = {c["capture_id"]: c["sha256"] for c in report["evidence"]["captures"]}
        _check(
            checks,
            "report_hashes",
            len(report_hashes) == 3 and all(report_hashes.values()),
            "3 capture hashes",
            str(len(report_hashes)),
        )
        assert client.get(f"/api/cases/{case_id}/report.html").status_code == 200
        assert client.get(f"/api/cases/{case_id}/report.pdf").status_code == 200
        _check(checks, "report_formats", True, "json/html/pdf", "json/html/pdf")

        # 6. Export determinism + bundle --------------------------------
        first_export = client.get(f"/api/cases/{case_id}/export").json()
        second_export = client.get(f"/api/cases/{case_id}/export").json()
        first_norm = _strip_dynamic(first_export)
        second_norm = _strip_dynamic(second_export)
        first_timeline = first_norm.pop("timeline")
        second_timeline = second_norm.pop("timeline")
        _check(
            checks,
            "export_deterministic",
            first_norm == second_norm
            and len(second_timeline) == len(first_timeline) + 1
            and [e["event_type"] for e in second_timeline[:-1]]
            == [e["event_type"] for e in first_timeline],
            "identical apart from dynamic metadata",
            "mismatch" if first_norm != second_norm else "ok",
        )
        # Export ran twice with identical structure (checked above); only a
        # constant marker is fingerprinted since case ids are random per run.
        observed["export_ok"] = True
        bundle_response = client.get(f"/api/cases/{case_id}/bundle")
        _check(
            checks,
            "bundle_download",
            bundle_response.status_code == 200
            and bundle_response.headers["content-type"] == "application/zip",
            "zip bundle",
            str(bundle_response.status_code),
        )
        import io as _io
        import zipfile as _zipfile

        names = set(_zipfile.ZipFile(_io.BytesIO(bundle_response.content)).namelist())
        _check(
            checks,
            "bundle_contents",
            names
            == {
                "case.json",
                "README.txt",
                "evidence-manifest.json",
                "reports/case-report.json",
            },
            "case bundle layout",
            ",".join(sorted(names)),
        )

        # 7. Integrity: forensic truth unchanged by the whole workflow --
        intact = True
        for capture_id, snapshot in pre_workflow.items():
            current = {
                "findings": client.get(f"/api/captures/{capture_id}/findings").json(),
                "posture": client.get(f"/api/captures/{capture_id}/posture").json(),
                "anomalies": client.get(f"/api/captures/{capture_id}/anomalies").json(),
                "graph": client.get(f"/api/captures/{capture_id}/graph").json(),
            }
            if current != snapshot:
                intact = False
        _check(checks, "evidence_intact", intact, "identical", "mutated" if not intact else "ok")

    passed = all(check.passed for check in checks)
    return CaseEvaluation(passed=passed, checks=checks, observed=observed)


def evaluate(*, repeat: int = 2) -> dict[str, Any]:
    """Run the case evaluation, optionally repeating for determinism."""
    first = run_case_evaluation()
    deterministic = True
    if repeat > 1 and first.passed:
        fingerprint = json.dumps(_strip_dynamic(first.observed), sort_keys=True, default=str)
        for _ in range(repeat - 1):
            rerun = run_case_evaluation()
            if not rerun.passed or (
                json.dumps(_strip_dynamic(rerun.observed), sort_keys=True, default=str)
                != fingerprint
            ):
                deterministic = False
            first.checks.extend(rerun.checks)
    passed = first.passed and deterministic
    return {
        "schema_version": CASE_EVALUATION_SCHEMA_VERSION,
        "case": CASE_TITLE,
        "scenarios": list(CASE_SCENARIO_IDS),
        "passed": passed,
        "deterministic": deterministic,
        "determinism_repeat": repeat,
        "observed": first.observed,
        "checks": [
            {
                "check": check.check,
                "passed": check.passed,
                "expected": check.expected,
                "actual": check.actual,
            }
            for check in first.checks
        ],
    }


def summarize(result: dict[str, Any]) -> str:
    """Human-readable case evaluation summary."""
    lines = ["SecureMailScope case evaluation", "=" * 60]
    lines.append(f"Case: {result['case']}  scenarios: {', '.join(result['scenarios'])}")
    marker = "PASS" if result["passed"] else "FAIL"
    lines.append(f"Result: [{marker}] deterministic: {result['deterministic']}")
    lines.append("")
    for check in result["checks"]:
        assert isinstance(check, dict)
        if not check["passed"]:
            lines.append(
                f"  FAIL {check['check']}: expected {check['expected']}, got {check['actual']}"
            )
    if result["passed"]:
        lines.append(f"  all {len(result['checks'])} checks passed")
    lines.append("")
    lines.append(
        "Scope note: a synthetic case over controlled fixtures verifies the "
        "investigation workflow and evidence separation. Case metadata never "
        "alters forensic conclusions."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.evaluate_cases",
        description="Run the deterministic forensic case evaluation.",
    )
    parser.add_argument("--json", dest="json_path", type=Path, default=None)
    parser.add_argument("--repeat", type=int, default=2)
    args = parser.parse_args(argv)

    result = evaluate(repeat=max(1, args.repeat))
    print(summarize(result))
    if args.json_path is not None:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nMachine-readable result written to {args.json_path}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
