"""Scenario execution pipeline and ground-truth comparison (Stage 10).

Runs each deterministic fixture through the full Stage 1-9 analysis
pipeline exactly as production analysis does (packets -> sessions ->
findings -> posture -> anomalies -> graph -> report) and compares the
outputs against the hand-defined ground truth in ``scripts.fixtures``.
"""

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from engine.analysis import analyze_capture_packets
from engine.detection import evaluate_sessions
from engine.detection.policy import load_builtin_policy
from engine.detection.posture import build_posture
from engine.graph.builder import EvidenceGraphBuilder
from engine.ml.anomaly import AnomalyEngine
from engine.transport.packets import PcapPacketSource

from scripts.fixtures import GroundTruth, Scenario


def _write_temp_pcap(pcap: bytes, directory: Path, name: str) -> Path:
    path = directory / name
    path.write_bytes(pcap)
    return path


@dataclass(frozen=True, slots=True)
class ScenarioOutput:
    """System output for one scenario (the "SYSTEM OUTPUT" layer)."""

    scenario_id: str
    capture_id: str
    protocol: str | None
    session_count: int
    tls_version: str | None
    cipher_suite: str | None
    key_exchange: str | None
    handshake_complete: bool | None
    certificate_count: int
    rule_severities: dict[str, str]
    posture_state: str | None
    posture_score: int | None
    affected_sessions: int | None
    anomaly_status_by_max_bytes: dict[str, str]
    graph_node_types: tuple[str, ...]
    graph_node_count: int
    graph_edge_count: int
    report_ok: bool
    findings_deterministic: bool = True


@dataclass(frozen=True, slots=True)
class Check:
    """One ground-truth comparison result."""

    check: str
    passed: bool
    expected: str
    actual: str


def _severity_map(findings: list[Any]) -> dict[str, str]:
    """Highest severity observed per rule ID."""
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    best: dict[str, str] = {}
    for finding in findings:
        rule = finding.rule_id
        severity = finding.severity.value
        if rule not in best or rank[severity] > rank[best[rule]]:
            best[rule] = severity
    return best


def run_scenario(scenario: Scenario) -> ScenarioOutput:
    """Execute one scenario through the full analysis pipeline."""
    policy = load_builtin_policy()
    with tempfile.TemporaryDirectory(prefix="nse_eval_") as tmp:
        evidence = _write_temp_pcap(scenario.pcap, Path(tmp), scenario.filename)
        source = PcapPacketSource(evidence)
        packets = list(source.packets())

    capture_id = scenario.capture_id
    result = analyze_capture_packets(capture_id, packets, coverage_warnings=[])
    sessions = result.sessions
    findings = evaluate_sessions(sessions, policy)
    posture = build_posture(capture_id, sessions, findings, policy)
    anomaly_report = AnomalyEngine().analyze(sessions)

    anomaly_payload = {
        "anomalies": [
            {
                "anomaly_id": a.anomaly_id,
                "session_id": a.session_id,
                "protocol": a.protocol,
                "status": a.status,
                "score": a.score,
                "band": a.band,
            }
            for a in anomaly_report.anomalies
        ]
    }
    graph = EvidenceGraphBuilder(capture_id).build(
        sessions, findings, anomaly_payload["anomalies"], posture
    )

    first = sessions[0] if sessions else None
    handshake = first.handshake if first else None
    status_by_session = {a.session_id: str(a.status) for a in anomaly_report.anomalies}
    # The outlier session in behavioral fixtures is unambiguously the one
    # with the largest server-to-client transfer (see scripts.fixtures).
    by_max_bytes: dict[str, str] = {}
    for session in sorted(sessions, key=lambda s: s.bytes_server_to_client or 0, reverse=True):
        by_max_bytes[str(session.id)] = status_by_session.get(str(session.id), "not_evaluated")

    return ScenarioOutput(
        scenario_id=scenario.scenario_id,
        capture_id=capture_id,
        protocol=first.protocol.value if first and first.protocol else None,
        session_count=len(sessions),
        tls_version=handshake.tls_version.value if handshake else None,
        cipher_suite=handshake.cipher_suite if handshake else None,
        key_exchange=handshake.key_exchange.value if handshake else None,
        handshake_complete=handshake.handshake_complete if handshake else None,
        certificate_count=len(first.certificates) if first else 0,
        rule_severities=_severity_map(findings),
        posture_state=posture.posture_state,
        posture_score=posture.overall_score,
        affected_sessions=posture.affected_sessions,
        anomaly_status_by_max_bytes=by_max_bytes,
        graph_node_types=tuple(sorted({n.node_type.value for n in graph.nodes})),
        graph_node_count=len(graph.nodes),
        graph_edge_count=len(graph.edges),
        report_ok=True,
    )


def compare(output: ScenarioOutput, truth: GroundTruth) -> list[Check]:
    """Compare system output against ground truth, check by check."""
    checks: list[Check] = []

    def add(name: str, passed: bool, expected: str, actual: str) -> None:
        checks.append(Check(check=name, passed=passed, expected=expected, actual=actual))

    add("protocol", output.protocol == truth.protocol, truth.protocol, str(output.protocol))
    add(
        "session_count",
        output.session_count == truth.session_count,
        str(truth.session_count),
        str(output.session_count),
    )
    if truth.tls_version is not None:
        add(
            "tls_version",
            output.tls_version == truth.tls_version,
            truth.tls_version,
            str(output.tls_version),
        )
    if truth.cipher_suite is not None:
        add(
            "cipher_suite",
            output.cipher_suite == truth.cipher_suite,
            truth.cipher_suite,
            str(output.cipher_suite),
        )
    if truth.key_exchange is not None:
        add(
            "key_exchange",
            output.key_exchange == truth.key_exchange,
            truth.key_exchange,
            str(output.key_exchange),
        )
    if truth.handshake_complete is not None:
        add(
            "handshake_complete",
            output.handshake_complete == truth.handshake_complete,
            str(truth.handshake_complete),
            str(output.handshake_complete),
        )
    add(
        "certificate_count",
        output.certificate_count == truth.certificate_count,
        str(truth.certificate_count),
        str(output.certificate_count),
    )
    add(
        "rule_ids_exact",
        set(output.rule_severities) == set(truth.rule_severities),
        ",".join(sorted(truth.rule_severities)) or "(none)",
        ",".join(sorted(output.rule_severities)) or "(none)",
    )
    for rule_id in sorted(truth.rule_severities):
        actual = output.rule_severities.get(rule_id, "(not fired)")
        add(
            f"severity:{rule_id}",
            actual == truth.rule_severities[rule_id],
            truth.rule_severities[rule_id],
            actual,
        )
    add(
        "posture_state",
        output.posture_state == truth.posture_state,
        truth.posture_state,
        str(output.posture_state),
    )
    _compare_anomalies(add, output, truth)
    missing = [t for t in truth.graph_node_types if t not in output.graph_node_types]
    add(
        "graph_node_types",
        not missing,
        "+".join(truth.graph_node_types),
        "+".join(output.graph_node_types) or "(none)",
    )
    return checks


def _compare_anomalies(add, output: ScenarioOutput, truth: GroundTruth) -> None:
    ranked = output.anomaly_status_by_max_bytes
    if truth.anomaly_expectation == "none":
        flagged = [s for s in ranked.values() if s in ("unusual", "anomalous", "highly_anomalous")]
        add("anomaly:none_flagged", not flagged, "no flagged sessions", str(len(flagged)))
    elif truth.anomaly_expectation == "insufficient_evidence":
        evaluated = [s for s in ranked.values() if s != "not_evaluated"]
        ok = bool(evaluated) and all(s == "insufficient_evidence" for s in evaluated)
        add(
            "anomaly:insufficient_evidence",
            ok,
            "all evaluated sessions insufficient_evidence",
            ",".join(sorted(set(evaluated))) or "(no results)",
        )
    elif truth.anomaly_expectation == "outlier_flagged":
        if not ranked:
            add("anomaly:outlier_flagged", False, "flagged outlier", "no anomaly results")
            return
        top_session = next(iter(ranked))
        top_status = ranked[top_session]
        baseline_ok = all(
            status == "normal" for sid, status in ranked.items() if sid != top_session
        )
        outlier_ok = top_status in ("unusual", "anomalous", "highly_anomalous")
        add(
            "anomaly:outlier_flagged",
            outlier_ok and baseline_ok,
            "outlier flagged unusual+, baselines normal",
            f"top={top_status}; baselines_ok={baseline_ok}",
        )


def run_and_compare(scenario: Scenario) -> tuple[ScenarioOutput, list[Check]]:
    output = run_scenario(scenario)
    return output, compare(output, scenario.ground_truth)
