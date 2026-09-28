"""End-to-end forensic evaluation harness (Stage 10).

Discovers the deterministic scenarios in ``scripts.fixtures``, runs each
through the full analysis pipeline, compares outputs against the
hand-defined ground truth, and reports results.

Usage:

    python -m scripts.evaluate              # human-readable summary
    python -m scripts.evaluate --json out   # also write machine-readable JSON
    python -m scripts.evaluate --repeat 3   # verify determinism across runs

Exit code is 0 when every scenario matches its ground truth and every
repeat run is identical; 1 otherwise.
"""

import argparse
import json
import sys
from pathlib import Path

from scripts.fixtures import load_scenarios
from scripts.runner import run_and_compare

EVALUATION_SCHEMA_VERSION = "1.0"


def evaluate(*, repeat: int = 1) -> dict[str, object]:
    """Run all scenarios; return the machine-readable evaluation result."""
    scenarios = load_scenarios()
    results: list[dict[str, object]] = []
    passed = 0
    failed = 0

    for scenario in scenarios:
        output, checks = run_and_compare(scenario)
        scenario_passed = all(check.passed for check in checks)

        # Determinism: a second run of the same scenario must produce
        # byte-identical findings and posture (intentionally dynamic
        # metadata is not part of this comparison).
        deterministic = True
        if repeat > 1:
            first_fingerprint = _fingerprint(output)
            for _ in range(repeat - 1):
                rerun_output, rerun_checks = run_and_compare(scenario)
                if _fingerprint(rerun_output) != first_fingerprint or not all(
                    check.passed for check in rerun_checks
                ):
                    deterministic = False
                    scenario_passed = False

        if scenario_passed:
            passed += 1
        else:
            failed += 1

        results.append(
            {
                "scenario_id": scenario.scenario_id,
                "title": scenario.title,
                "description": scenario.description,
                "capture_id": output.capture_id,
                "passed": scenario_passed,
                "deterministic": deterministic,
                "checks": [
                    {
                        "check": check.check,
                        "passed": check.passed,
                        "expected": check.expected,
                        "actual": check.actual,
                    }
                    for check in checks
                ],
                "observed": {
                    "protocol": output.protocol,
                    "sessions": output.session_count,
                    "tls_version": output.tls_version,
                    "cipher_suite": output.cipher_suite,
                    "key_exchange": output.key_exchange,
                    "posture_state": output.posture_state,
                    "posture_score": output.posture_score,
                    "affected_sessions": output.affected_sessions,
                    "graph_nodes": output.graph_node_count,
                    "graph_edges": output.graph_edge_count,
                    "rules_fired": sorted(output.rule_severities),
                },
            }
        )

    return {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "total_scenarios": len(scenarios),
        "passed": passed,
        "failed": failed,
        "determinism_repeat": repeat,
        "results": results,
    }


def _fingerprint(output: object) -> str:
    import dataclasses

    return json.dumps(dataclasses.asdict(output), sort_keys=True, default=str)  # type: ignore[arg-type]


def summarize(result: dict[str, object]) -> str:
    """Human-readable evaluation summary."""
    lines: list[str] = []
    lines.append("SecureMailScope forensic evaluation")
    lines.append("=" * 60)
    lines.append(
        f"Scenarios: {result['total_scenarios']}  "
        f"passed: {result['passed']}  failed: {result['failed']}  "
        f"(determinism runs: {result['determinism_repeat']})"
    )
    lines.append("")
    for entry in result["results"]:
        assert isinstance(entry, dict)
        marker = "PASS" if entry["passed"] else "FAIL"
        observed = entry["observed"]
        assert isinstance(observed, dict)
        lines.append(
            f"[{marker}] {entry['scenario_id']}: "
            f"{observed['protocol']} / {observed['tls_version']} / "
            f"posture {observed['posture_state']} ({observed['posture_score']})"
        )
        for check in entry["checks"]:
            assert isinstance(check, dict)
            if not check["passed"]:
                lines.append(
                    f"       {check['check']}: expected {check['expected']}, got {check['actual']}"
                )
    lines.append("")
    lines.append(
        "Scope note: controlled synthetic scenarios verify expected system "
        "behavior and guard regressions. They do not measure real-world "
        "attack-detection accuracy."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.evaluate",
        description="Run the deterministic forensic evaluation suite.",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        default=None,
        help="Write the machine-readable evaluation result to this path",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Run each scenario N times and require identical results",
    )
    args = parser.parse_args(argv)

    result = evaluate(repeat=max(1, args.repeat))
    print(summarize(result))
    if args.json_path is not None:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nMachine-readable result written to {args.json_path}")
    return 0 if result["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
