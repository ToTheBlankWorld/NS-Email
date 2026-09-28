"""Performance baseline harness (Stage 10).

Measures what the pipeline actually does on the deterministic fixtures:
ingestion/analysis/report durations, packet/session/finding/anomaly
counts, and graph sizes. Results are machine-readable and limited to
this machine and these synthetic scenarios — they are NOT production
throughput or real-world performance claims.

Usage:

    python -m scripts.benchmark                 # human-readable table
    python -m scripts.benchmark --json out.json # machine-readable output
"""

import argparse
import json
import struct
import sys
import time
from pathlib import Path

from scripts.evaluate import EVALUATION_SCHEMA_VERSION
from scripts.fixtures import load_scenarios
from scripts.runner import run_scenario


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


def benchmark_drift(*, repeat: int = 3) -> dict[str, object]:
    """Controlled longitudinal regression: three observations, one case.

    Measures observation count, comparison count, findings compared,
    drift records generated, and wall-clock durations over the real API
    using the deterministic drift fixtures. The consecutive-pair chain
    is linear in observations (indexed lookups, never pairwise across
    unrelated evidence). Timings are a regression baseline for this
    machine only — not throughput or capacity claims.
    """
    import tempfile

    from fastapi.testclient import TestClient

    from app.config import DEFAULT_CORS_ORIGINS, Settings
    from app.main import create_app
    from scripts.drift_fixtures import load_drift_scenarios

    scenarios = {s.scenario_id: s for s in load_drift_scenarios()}
    order = ("drift-capture-a", "drift-capture-b", "drift-capture-c")
    durations: list[float] = []
    result: dict[str, object] = {}
    for _ in range(max(1, repeat)):
        with tempfile.TemporaryDirectory(prefix="nse_drift_bench_") as tmp:
            settings = Settings(
                service_name="ns-email",
                app_version="0.0.0",
                cors_origins=DEFAULT_CORS_ORIGINS,
                capture_storage_dir=Path(tmp) / "captures",
                ai_provider="mock",
            )
            client = TestClient(create_app(settings))
            started = time.perf_counter()
            case_id = client.post(
                "/api/cases",
                json={"title": "Benchmark", "description": "", "priority": "LOW"},
            ).json()["case_id"]
            capture_ids = []
            for scenario_id in order:
                scenario = scenarios[scenario_id]
                capture_id = client.post(
                    "/api/captures",
                    files={
                        "file": (
                            scenario.filename,
                            scenario.pcap,
                            "application/octet-stream",
                        )
                    },
                ).json()["id"]
                client.post(f"/api/captures/{capture_id}/analyze")
                client.post(f"/api/cases/{case_id}/captures", json={"capture_id": capture_id})
                capture_ids.append(capture_id)
            client.post(
                f"/api/cases/{case_id}/observations/baseline",
                json={"capture_id": capture_ids[0]},
            )
            observations = client.get(f"/api/cases/{case_id}/observations").json()["observations"]
            comparisons = client.get(f"/api/cases/{case_id}/comparisons").json()["comparisons"]
            drift = client.get(f"/api/cases/{case_id}/drift").json()
            summary = client.get(f"/api/cases/{case_id}/drift/summary").json()
            durations.append((time.perf_counter() - started) * 1000)
            result = {
                "observations": len(observations),
                "comparisons": len(comparisons),
                "findings_compared": sum(len(o.get("finding_rules", [])) for o in observations),
                "drift_records": drift["total"],
                "summary": {
                    key: summary.get(key)
                    for key in (
                        "posture_changes",
                        "new_findings",
                        "resolved_findings",
                        "recurring_findings",
                        "configuration_changes",
                        "anomaly_changes",
                    )
                },
            }
    result["longitudinal_total_ms"] = round(_median(durations), 1)
    result["runs"] = repeat
    return result


def benchmark(*, repeat: int = 3) -> dict[str, object]:
    """Run each scenario `repeat` times; report median wall-clock timings."""
    scenarios = load_scenarios()
    entries: list[dict[str, object]] = []

    for scenario in scenarios:
        timings: list[dict[str, float]] = []
        output = None
        for _ in range(max(1, repeat)):
            started = time.perf_counter()
            output = run_scenario(scenario)
            total_ms = (time.perf_counter() - started) * 1000
            timings.append({"total_ms": round(total_ms, 1)})

        def median(values: list[float]) -> float:
            ordered = sorted(values)
            return ordered[len(ordered) // 2]

        assert output is not None
        packets = _packet_count(scenario.pcap)
        entries.append(
            {
                "scenario": scenario.scenario_id,
                "packets": packets,
                "sessions": output.session_count,
                "findings": len(output.rule_severities) and sum(1 for _ in output.rule_severities),
                "graph_nodes": output.graph_node_count,
                "graph_edges": output.graph_edge_count,
                "analysis_total_ms": median([t["total_ms"] for t in timings]),
                "runs": repeat,
            }
        )

    return {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "machine": sys.platform,
        "python": sys.version.split()[0],
        "scenarios": entries,
        "drift": benchmark_drift(repeat=repeat),
        "note": (
            "Wall-clock timings on the development machine running the "
            "deterministic synthetic scenarios. These numbers are a "
            "regression baseline only — not throughput, capacity, or "
            "real-world performance claims."
        ),
    }


def _packet_count(pcap: bytes) -> int:
    """Count pcap packet records from the 16-byte record headers."""
    count = 0
    offset = 24  # global header
    while offset + 16 <= len(pcap):
        _ts, _us, incl, _orig = struct.unpack("<IIII", pcap[offset : offset + 16])
        offset += 16 + incl
        count += 1
    return count


def summarize(result: dict[str, object]) -> str:
    lines = [
        "SecureMailScope performance baseline",
        "=" * 72,
        f"python {result['python']} on {result['machine']}",
        f"{'scenario':32s} {'pkts':>6s} {'sess':>5s} {'nodes':>6s} {'edges':>6s} {'total_ms':>10s}",
    ]
    for entry in result["scenarios"]:
        assert isinstance(entry, dict)
        lines.append(
            f"{entry['scenario']!s:32s} {entry['packets']:6d} "
            f"{entry['sessions']:5d} {entry['graph_nodes']:6d} "
            f"{entry['graph_edges']:6d} {entry['analysis_total_ms']:10.1f}"
        )
    drift = result.get("drift")
    if isinstance(drift, dict):
        lines.append("")
        lines.append(
            f"drift: {drift.get('observations')} observations, "
            f"{drift.get('comparisons')} comparisons, "
            f"{drift.get('findings_compared')} findings compared, "
            f"{drift.get('drift_records')} drift records, "
            f"{drift.get('longitudinal_total_ms')}ms longitudinal"
        )
    lines.append("")
    lines.append(str(result["note"]))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.benchmark",
        description="Measure pipeline timings over the deterministic fixtures.",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        default=None,
        help="Write machine-readable benchmark output to this path",
    )
    parser.add_argument("--repeat", type=int, default=3, help="Runs per scenario (median reported)")
    args = parser.parse_args(argv)

    result = benchmark(repeat=max(1, args.repeat))
    print(summarize(result))
    if args.json_path is not None:
        args.json_path.parent.mkdir(parents=True, exist_ok=True)
        args.json_path.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nMachine-readable result written to {args.json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
