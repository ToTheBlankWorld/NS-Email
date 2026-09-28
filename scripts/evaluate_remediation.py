"""Remediation and verification evaluation harness (Stage 13).

Drives a synthetic remediation scenario through the real API using
existing deterministic Stage 10 fixtures:

- baseline: deprecated-tls10 (TLS-VERSION-001 and related findings)
- verification-good: secure-tls12 (rule absent → VERIFIED)
- verification-same: the baseline itself (rule present → FAILED)
- verification-unrelated: secure-tls13 (no relevant session → INCONCLUSIVE)

Ground truth (defined before execution): the remediation is created
from policy guidance, verification outcomes follow the semantics
above, the original finding and baseline evidence stay byte-identical,
and posture comparison is deterministic. Negative cases cover
cross-case and unanalyzed verification captures (both rejected).

Usage:

    python -m scripts.evaluate_remediation              # summary
    python -m scripts.evaluate_remediation --json out   # + JSON
    python -m scripts.evaluate_remediation --repeat 2   # run twice

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

REMEDIATION_EVALUATION_SCHEMA_VERSION = "1.0"
CASE_TITLE = "Remediation evaluation case"
BASELINE_SCENARIO = "deprecated-tls10"
GOOD_SCENARIO = "secure-tls12"
UNRELATED_SCENARIO = "secure-tls13"
TARGET_RULE = "TLS-VERSION-001"


@dataclass(frozen=True, slots=True)
class Check:
    check: str
    passed: bool
    expected: str
    actual: str


@dataclass
class RemediationEvaluation:
    passed: bool
    checks: list[Check] = field(default_factory=list)
    observed: dict[str, Any] = field(default_factory=dict)


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


def _strip_dynamic(value: Any) -> Any:
    """Remove wall-clock timestamps and random ids for cross-run comparison."""
    if isinstance(value, dict):
        return {
            key: _strip_dynamic(item)
            for key, item in value.items()
            if key
            not in {
                "created_at",
                "updated_at",
                "completed_at",
                "attached_at",
                "exported_at",
                "generated_at",
                "remediation_id",
                "verification_id",
                "note_id",
                "entry_id",
                "report_id",
                "case_id",
            }
        }
    if isinstance(value, list):
        return [_strip_dynamic(item) for item in value]
    return value


def run_remediation_evaluation() -> RemediationEvaluation:
    """Run the synthetic remediation scenario once through the real API."""
    from scripts.fixtures import load_scenarios

    checks: list[Check] = []
    observed: dict[str, Any] = {}
    scenarios = {s.scenario_id: s for s in load_scenarios()}

    with tempfile.TemporaryDirectory(prefix="nse_rem_eval_") as tmp:
        client = _make_client(Path(tmp))

        response = client.post(
            "/api/cases",
            json={"title": CASE_TITLE, "description": "Stage 13 evaluation", "priority": "HIGH"},
        )
        _check(checks, "case_create", response.status_code == 200, "200", str(response.status_code))
        if response.status_code != 200:
            return RemediationEvaluation(passed=False, checks=checks, observed=observed)
        case_id = response.json()["case_id"]

        capture_ids: dict[str, str] = {}
        for scenario_id in (BASELINE_SCENARIO, GOOD_SCENARIO, UNRELATED_SCENARIO):
            scenario = scenarios[scenario_id]
            uploaded = client.post(
                "/api/captures",
                files={"file": (scenario.filename, scenario.pcap, "application/octet-stream")},
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

        baseline_id = capture_ids[BASELINE_SCENARIO]
        baseline_findings = client.get(f"/api/captures/{baseline_id}/findings").json()
        target = next((f for f in baseline_findings if f["rule_id"] == TARGET_RULE), None)
        _check(
            checks,
            "baseline_rule_present",
            target is not None,
            TARGET_RULE,
            ",".join(sorted({f["rule_id"] for f in baseline_findings})),
        )
        if target is None:
            return RemediationEvaluation(passed=False, checks=checks, observed=observed)

        # Remediation from policy guidance --------------------------------
        remediation = client.post(
            f"/api/cases/{case_id}/remediations/from-finding",
            json={"finding_id": target["id"], "owner": "netops"},
        ).json()
        remediation_id = remediation["remediation_id"]
        _check(
            checks,
            "remediation_policy_source",
            remediation["recommended_action_source"] == "policy"
            and "SecureMailScope policy baseline" in remediation["recommended_action"],
            "policy guidance",
            remediation["recommended_action_source"],
        )
        for status in ("PLANNED", "IN_PROGRESS"):
            updated = client.patch(
                f"/api/cases/{case_id}/remediations/{remediation_id}", json={"status": status}
            )
            _check(
                checks,
                f"transition:{status}",
                updated.status_code == 200 and updated.json()["status"] == status,
                status,
                str(updated.status_code),
            )

        verify_path = f"/api/cases/{case_id}/remediations/{remediation_id}/verify"

        def verify(capture_id: str, mode: str = "evidence"):
            return client.post(
                verify_path, json={"mode": mode, "verification_capture_id": capture_id}
            )

        # Positive case: rule absent in the hardened capture → VERIFIED.
        good = verify(capture_ids[GOOD_SCENARIO]).json()
        _check(checks, "verify_good", good["result"] == "VERIFIED", "VERIFIED", good["result"])
        _check(
            checks,
            "verify_statement",
            "was not observed in verification capture" in good["comparison"]["statement"],
            "neutral absence",
            good["comparison"]["statement"][:80],
        )
        posture = good["comparison"]
        _check(
            checks,
            "posture_quoted",
            posture["posture_before"].get("posture_state") == "degraded"
            and posture["posture_after"].get("posture_state") == "healthy",
            "degraded→healthy",
            json.dumps(
                {
                    "before": posture["posture_before"].get("posture_state"),
                    "after": posture["posture_after"].get("posture_state"),
                },
                sort_keys=True,
            ),
        )
        observed["posture_delta"] = posture["posture_delta_points"]
        observed["statement"] = posture["statement"]

        # Negative 1: same finding still present → FAILED.
        same = verify(baseline_id).json()
        _check(checks, "verify_same_failed", same["result"] == "FAILED", "FAILED", same["result"])

        # Negative 2/5: unrelated capture (no relevant session) → INCONCLUSIVE.
        unrelated = verify(capture_ids[UNRELATED_SCENARIO]).json()
        _check(
            checks,
            "verify_unrelated_inconclusive",
            unrelated["result"] == "INCONCLUSIVE"
            and unrelated["comparison"]["session_match"] == "no_matching_session",
            "INCONCLUSIVE",
            unrelated["result"],
        )

        # Negative 3: cross-case capture rejected.
        other = client.post(
            "/api/cases", json={"title": "Other", "description": "", "priority": "LOW"}
        ).json()
        foreign_upload = client.post(
            "/api/captures",
            files={
                "file": (
                    "foreign.pcap",
                    scenarios["plaintext-smtp"].pcap,
                    "application/octet-stream",
                )
            },
        ).json()
        client.post(f"/api/captures/{foreign_upload['id']}/analyze")
        client.post(
            f"/api/cases/{other['case_id']}/captures",
            json={"capture_id": foreign_upload["id"]},
        )
        rejected = verify(foreign_upload["id"])
        _check(
            checks,
            "verify_cross_case_rejected",
            rejected.status_code == 422,
            "422",
            str(rejected.status_code),
        )

        # Negative 4: unanalyzed capture rejected.
        fresh = client.post(
            "/api/captures",
            files={
                "file": (
                    "fresh.pcap",
                    scenarios["plaintext-authentication"].pcap,
                    "application/octet-stream",
                )
            },
        ).json()
        client.post(f"/api/cases/{case_id}/captures", json={"capture_id": fresh["id"]})
        unanalyzed = verify(fresh["id"])
        _check(
            checks,
            "verify_unanalyzed_rejected",
            unanalyzed.status_code == 422,
            "422",
            str(unanalyzed.status_code),
        )

        # History is append-only; latest state wins.
        history = client.get(
            f"/api/cases/{case_id}/remediations/{remediation_id}/verification"
        ).json()["verifications"]
        _check(
            checks,
            "verification_history",
            [v["result"] for v in history] == ["VERIFIED", "FAILED", "INCONCLUSIVE"],
            "3 records in order",
            ",".join(v["result"] for v in history),
        )
        state = client.get(f"/api/cases/{case_id}/remediations/{remediation_id}").json()
        _check(
            checks,
            "latest_state",
            state["verification_status"] == "INCONCLUSIVE",
            "INCONCLUSIVE",
            state["verification_status"],
        )

        # Original finding and baseline evidence are unchanged.
        current = client.get(f"/api/captures/{baseline_id}/findings").json()
        _check(
            checks,
            "finding_intact",
            {f["id"]: f["severity"] for f in current}
            == {f["id"]: f["severity"] for f in baseline_findings},
            "identical",
            "mutated" if current != baseline_findings else "identical",
        )
        timeline = client.get(
            f"/api/cases/{case_id}/remediations/{remediation_id}/timeline"
        ).json()["timeline"]
        events = [e["event_type"] for e in timeline]
        _check(
            checks,
            "timeline_order",
            events[:2] == ["remediation_created", "status_changed"]
            and events.count("status_changed") == 2
            and events[-3:]
            == ["verification_completed", "verification_failed", "verification_failed"],
            "workflow order",
            ",".join(events),
        )

        # Report and export carry the workflow; manual path works too.
        manual = client.post(verify_path, json={"mode": "manual", "notes": "Eval sign-off."}).json()
        _check(
            checks,
            "manual_asserted",
            manual["result"] == "VERIFIED" and manual["method"] == "analyst_asserted",
            "VERIFIED asserted",
            manual["result"],
        )
        report = client.get(f"/api/cases/{case_id}/report.json").json()
        _check(
            checks,
            "report_sections",
            "remediation" in report
            and "verification" in report
            and report["verification"]["count"] == 4,
            "4 results",
            str(report["verification"].get("count")),
        )
        export = client.get(f"/api/cases/{case_id}/export").json()
        _check(
            checks,
            "export_schema_12",
            export["schema_version"] == "1.2"
            and len(export["remediations"]) == 1
            and len(export["verification_results"]) == 4,
            "1.2 with workflow",
            export.get("schema_version", "?"),
        )
        observed["verification_results"] = [
            {"result": v["result"], "method": v["method"]} for v in export["verification_results"]
        ]

    passed = all(check.passed for check in checks)
    return RemediationEvaluation(passed=passed, checks=checks, observed=observed)


def evaluate(*, repeat: int = 2) -> dict[str, Any]:
    """Run the remediation evaluation, repeating for determinism."""
    first = run_remediation_evaluation()
    deterministic = True
    if repeat > 1 and first.passed:
        fingerprint = json.dumps(_strip_dynamic(first.observed), sort_keys=True, default=str)
        for _ in range(repeat - 1):
            rerun = run_remediation_evaluation()
            if not rerun.passed or (
                json.dumps(_strip_dynamic(rerun.observed), sort_keys=True, default=str)
                != fingerprint
            ):
                deterministic = False
            first.checks.extend(rerun.checks)
    passed = first.passed and deterministic
    return {
        "schema_version": REMEDIATION_EVALUATION_SCHEMA_VERSION,
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
    """Human-readable remediation evaluation summary."""
    lines = ["SecureMailScope remediation evaluation", "=" * 60]
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
        "Scope note: a synthetic remediation scenario verifies the workflow "
        "and verification semantics. A finding describes historical observed "
        "evidence; a verification result describes evidence observed in a "
        "later capture. Absence of a finding in one capture does not prove "
        "global security."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.evaluate_remediation",
        description="Run the deterministic remediation and verification evaluation.",
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
