"""Multi-capture correlation evaluation harness (Stage 12).

Builds the three deterministic correlation fixtures (captures A, B, C
with deliberate overlaps), drives them through the real case API, and
verifies the exact expected correlation set — types, evidence keys,
affected captures, deterministic ids, and ordering — against ground
truth defined BEFORE execution (see scripts.correlation_fixtures).

Usage:

    python -m scripts.evaluate_correlations              # summary
    python -m scripts.evaluate_correlations --json out   # + JSON
    python -m scripts.evaluate_correlations --repeat 2   # run twice

Exit code is 0 when every check passes on every run; 1 otherwise.
"""

import argparse
import hashlib
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

CORRELATION_EVALUATION_SCHEMA_VERSION = "1.0"
CASE_TITLE = "Correlation evaluation case"


@dataclass(frozen=True, slots=True)
class Check:
    check: str
    passed: bool
    expected: str
    actual: str


@dataclass
class CorrelationEvaluation:
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


def _expected_ground_truth() -> dict[tuple[str, str], set[str]]:
    """Exact expected (type, evidence key) -> scenario ids, by hand."""
    from engine.correlation import normalize_subject

    from scripts.correlation_fixtures import _cert_x_der

    fingerprint_x = hashlib.sha256(_cert_x_der()).hexdigest()
    subject_x = normalize_subject("CN=mail.example.org")
    assert subject_x is not None
    return {
        ("shared_endpoint", "endpoint|198.51.100.20|25"): {"a", "b"},
        ("shared_host", "host|198.51.100.20"): {"a", "b"},
        ("shared_certificate", f"certificate|{fingerprint_x}"): {"a", "b"},
        ("shared_certificate_subject", f"certificate-subject|{subject_x}"): {"a", "b"},
        ("shared_protocol", "protocol|smtp"): {"a", "b", "c"},
        ("shared_finding", "finding-rule|cert-chain-001"): {"b", "c"},
        ("shared_evidence", "sni|mail.example.org"): {"a", "b", "c"},
        ("shared_evidence", "certificate-issuer|cn=synthetic mail ca"): {"a", "b", "c"},
    }


def run_correlation_evaluation() -> CorrelationEvaluation:
    """Run the A/B/C case workflow once through the real API."""
    from scripts.correlation_fixtures import load_correlation_scenarios

    checks: list[Check] = []
    observed: dict[str, Any] = {}

    with tempfile.TemporaryDirectory(prefix="nse_corr_eval_") as tmp:
        client = _make_client(Path(tmp))
        scenarios = load_correlation_scenarios()
        letters = ("a", "b", "c")

        response = client.post(
            "/api/cases",
            json={"title": CASE_TITLE, "description": "Stage 12 evaluation", "priority": "HIGH"},
        )
        _check(checks, "case_create", response.status_code == 200, "200", str(response.status_code))
        if response.status_code != 200:
            return CorrelationEvaluation(passed=False, checks=checks, observed=observed)
        case_id = response.json()["case_id"]

        capture_ids: dict[str, str] = {}
        for scenario, letter in zip(scenarios, letters, strict=True):
            uploaded = client.post(
                "/api/captures",
                files={"file": (scenario.filename, scenario.pcap, "application/octet-stream")},
            )
            _check(
                checks,
                f"ingest:{letter}",
                uploaded.status_code in (200, 201),
                "200/201",
                str(uploaded.status_code),
            )
            capture_id = uploaded.json()["id"]
            capture_ids[letter] = capture_id
            analyzed = client.post(f"/api/captures/{capture_id}/analyze").json()
            _check(
                checks,
                f"analyze:{letter}",
                analyzed["status"] == "completed",
                "completed",
                str(analyzed.get("status")),
            )
            attached = client.post(
                f"/api/cases/{case_id}/captures", json={"capture_id": capture_id}
            )
            _check(
                checks,
                f"attach:{letter}",
                attached.status_code == 200,
                "200",
                str(attached.status_code),
            )

        body = client.get(f"/api/cases/{case_id}/correlations", params={"sort": "type"}).json()
        correlations = body["correlations"]
        observed["correlation_count"] = len(correlations)
        # Fingerprinted across runs: types, keys, and capture sets only.
        # Correlation ids bind to the (random) case id by design, so they
        # are verified for shape within a run, not equality across runs.
        observed["correlations"] = [
            {
                "type": c["correlation_type"],
                "key": c["evidence_key"],
                "captures": sorted(c["source_capture_ids"]),
            }
            for c in correlations
        ]

        # Exact ground-truth comparison (modulo the TLS-config key, whose
        # fingerprint is asserted structurally below).
        truth = _expected_ground_truth()
        actual: dict[tuple[str, str], set[str]] = {}
        for correlation in correlations:
            key = (correlation["correlation_type"], correlation["evidence_key"])
            letters_for = {
                letter
                for letter, capture_id in capture_ids.items()
                if capture_id in correlation["source_capture_ids"]
            }
            actual[key] = letters_for

        tls_configs = [
            c for c in correlations if c["correlation_type"] == "shared_tls_configuration"
        ]
        _check(checks, "tls_config_single", len(tls_configs) == 1, "1", str(len(tls_configs)))
        if tls_configs:
            config = tls_configs[0]
            _check(
                checks,
                "tls_config_captures",
                {capture_ids["a"], capture_ids["c"]} == set(config["source_capture_ids"]),
                "A + C",
                str(sorted(config["source_capture_ids"])),
            )
            _check(
                checks,
                "tls_config_evidence",
                config["evidence"].get("tls_version") == "tls 1.2"
                and str(config["evidence"].get("config_fingerprint", "")).startswith("tlscfg_"),
                "tls 1.2 tlscfg_*",
                str(config["evidence"]),
            )
            actual.pop(("shared_tls_configuration", config["evidence_key"]), None)

        session_patterns = [
            c for c in correlations if c["correlation_type"] == "repeated_session_pattern"
        ]
        _check(
            checks,
            "session_pattern_single",
            len(session_patterns) == 1,
            "1",
            str(len(session_patterns)),
        )
        if session_patterns:
            pattern = session_patterns[0]
            _check(
                checks,
                "session_pattern_captures",
                set(pattern["source_capture_ids"]) == set(capture_ids.values()),
                "A + B + C",
                str(sorted(pattern["source_capture_ids"])),
            )
            actual.pop(("repeated_session_pattern", pattern["evidence_key"]), None)

        _check(
            checks,
            "exact_correlation_set",
            actual == truth,
            json.dumps({f"{k[0]}:{k[1]}": sorted(v) for k, v in sorted(truth.items())}),
            json.dumps({f"{k[0]}:{k[1]}": sorted(v) for k, v in sorted(actual.items())}),
        )
        _check(
            checks,
            "correlation_total",
            len(correlations) == 10,
            "10",
            str(len(correlations)),
        )

        # Single-capture rules must not correlate.
        lone_rules = set()
        for letter in letters:
            findings = client.get(f"/api/captures/{capture_ids[letter]}/findings").json()
            lone_rules.update(f["rule_id"] for f in findings)
        finding_keys = {
            c["evidence_key"] for c in correlations if c["correlation_type"] == "shared_finding"
        }
        _check(
            checks,
            "no_lone_rule_correlation",
            "finding-rule|cipher-selected-001" not in finding_keys
            and "finding-rule|keyex-001" not in finding_keys,
            "B-only rules uncorrelated",
            ",".join(sorted(finding_keys)),
        )

        # Strength categories and neutral language.
        strengths = {c["correlation_type"]: c["strength"] for c in correlations}
        _check(
            checks,
            "strength_direct",
            strengths.get("shared_endpoint") == "direct"
            and strengths.get("shared_certificate") == "direct",
            "direct",
            str({k: v for k, v in strengths.items() if v == "direct"}),
        )
        blob = json.dumps(correlations).lower()
        _check(
            checks,
            "neutral_language",
            not any(w in blob for w in ("attacker", "malicious", "compromise", "threat")),
            "neutral",
            "loaded" if any(w in blob for w in ("attacker",)) else "neutral",
        )

        # Deterministic ids and ordering.
        ids = [c["correlation_id"] for c in correlations]
        _check(
            checks,
            "id_shape",
            all(i.startswith("corr_") and len(i) == 21 for i in ids),
            "corr_<16hex>",
            ",".join(ids[:2]),
        )
        _check(
            checks,
            "deterministic_order",
            [(c["correlation_type"], c["evidence_key"]) for c in correlations]
            == sorted((c["correlation_type"], c["evidence_key"]) for c in correlations),
            "sorted",
            "ordered" if correlations else "empty",
        )

        # Summary, context, graph, and session-related endpoints.
        summary = client.get(f"/api/cases/{case_id}/correlations/summary").json()
        _check(
            checks,
            "summary_counts",
            summary["correlation_count"] == 10 and summary["capture_count"] == 3,
            "10 correlations, 3 captures",
            json.dumps(summary),
        )
        _check(
            checks,
            "summary_no_score",
            "risk" not in json.dumps(summary).lower()
            and "score" not in json.dumps(summary).lower(),
            "counts only",
            "clean",
        )
        first = correlations[0]
        detail = client.get(f"/api/cases/{case_id}/correlations/{first['correlation_id']}").json()
        _check(checks, "detail_round_trip", detail == first, "identical", "mismatch")
        context = client.get(
            f"/api/cases/{case_id}/correlations/{first['correlation_id']}/context"
        ).json()
        _check(
            checks,
            "context_graph_nodes",
            bool(context["graph_nodes"]),
            "non-empty",
            str(len(context["graph_nodes"])),
        )
        sessions = client.get(f"/api/captures/{capture_ids['a']}/sessions").json()
        related = client.get(f"/api/cases/{case_id}/sessions/{sessions[0]['id']}/related").json()
        _check(checks, "session_related", len(related["related"]) >= 1, ">=1", str(len(related)))
        graph = client.get(f"/api/cases/{case_id}/graph").json()
        _check(
            checks,
            "investigation_graph",
            {n["layer"] for n in graph["nodes"]} == {"forensic", "correlation"},
            "two layers",
            str({n["layer"] for n in graph["nodes"]}),
        )

        # Report/export carry correlations; evidence stays intact.
        pre = {
            capture_id: client.get(f"/api/captures/{capture_id}/findings").json()
            for capture_id in capture_ids.values()
        }
        report = client.get(f"/api/cases/{case_id}/report.json").json()
        _check(
            checks,
            "report_correlation",
            report["correlation"]["summary"]["correlation_count"] == 10,
            "10",
            str(report["correlation"]["summary"].get("correlation_count")),
        )
        export = client.get(f"/api/cases/{case_id}/export").json()
        _check(
            checks,
            "export_schema_13",
            export["schema_version"] == "1.3" and len(export["correlations"]) == 10,
            "1.3 with 10",
            f"{export.get('schema_version')} x{len(export.get('correlations', []))}",
        )
        intact = all(
            client.get(f"/api/captures/{capture_id}/findings").json() == findings
            for capture_id, findings in pre.items()
        )
        _check(checks, "evidence_intact", intact, "identical", "ok" if intact else "mutated")

    passed = all(check.passed for check in checks)
    return CorrelationEvaluation(passed=passed, checks=checks, observed=observed)


def evaluate(*, repeat: int = 2) -> dict[str, Any]:
    """Run the correlation evaluation, repeating for determinism."""
    first = run_correlation_evaluation()
    deterministic = True
    if repeat > 1 and first.passed:
        fingerprint = json.dumps(first.observed, sort_keys=True, default=str)
        for _ in range(repeat - 1):
            rerun = run_correlation_evaluation()
            if not rerun.passed or (
                json.dumps(rerun.observed, sort_keys=True, default=str) != fingerprint
            ):
                deterministic = False
            first.checks.extend(rerun.checks)
    passed = first.passed and deterministic
    return {
        "schema_version": CORRELATION_EVALUATION_SCHEMA_VERSION,
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
    """Human-readable correlation evaluation summary."""
    lines = ["SecureMailScope correlation evaluation", "=" * 60]
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
        "Scope note: deliberate overlaps across three synthetic captures verify "
        "the correlation workflow. Correlation is not attribution: repeated "
        "evidence does not establish intent, ownership, or compromise."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.evaluate_correlations",
        description="Run the deterministic multi-capture correlation evaluation.",
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
