"""Golden evidence tests over the deterministic evaluation fixtures (Stage 10).

Each scenario asserts protocol detection, session reconstruction, TLS
facts, certificate extraction, policy findings, posture, anomaly
behavior, and graph relationships against ground truth that was defined
by hand from the documented policy semantics BEFORE running the system.
These tests are regression detectors: a code change must not silently
alter established behavior.
"""

import pytest
from scripts.fixtures import load_scenarios
from scripts.runner import run_and_compare, run_scenario

SCENARIOS = load_scenarios()
SCENARIOS_BY_ID = {s.scenario_id: s for s in SCENARIOS}


def test_fixture_inventory_is_complete() -> None:
    expected = {
        "secure-tls13",
        "secure-tls12",
        "deprecated-tls10",
        "weak-cipher-3des",
        "expired-certificate",
        "sha1-certificate",
        "weak-certificate-key",
        "san-mismatch",
        "self-signed-certificate",
        "starttls-requested-not-accepted",
        "plaintext-smtp",
        "plaintext-authentication",
        "incomplete-tls-handshake",
        "tls-anomaly-outlier",
        "mixed-posture",
    }
    assert set(SCENARIOS_BY_ID) == expected


def test_fixtures_are_byte_deterministic() -> None:
    for scenario in SCENARIOS:
        assert load_scenarios()[SCENARIOS.index(scenario)].pcap == scenario.pcap


def test_fixture_capture_ids_are_stable() -> None:
    # capture id = capture_<sha256(pcap)[:12]> — content-addressed identity
    for scenario in SCENARIOS:
        rebuilt = load_scenarios()[SCENARIOS.index(scenario)]
        assert scenario.capture_id == rebuilt.capture_id


@pytest.mark.parametrize(
    "scenario_id", [s.scenario_id for s in SCENARIOS], ids=[s.scenario_id for s in SCENARIOS]
)
def test_scenario_matches_ground_truth(scenario_id: str) -> None:
    scenario = SCENARIOS_BY_ID[scenario_id]
    _, checks = run_and_compare(scenario)
    failures = [check for check in checks if not check.passed]
    assert not failures, "; ".join(
        f"{c.check}: expected {c.expected}, got {c.actual}" for c in failures
    )


def test_secure_scenarios_produce_zero_findings() -> None:
    for scenario_id in ("secure-tls13", "secure-tls12"):
        output = run_scenario(SCENARIOS_BY_ID[scenario_id])
        assert output.rule_severities == {}
        assert output.posture_score == 100


def test_weak_scenarios_flag_the_expected_rules() -> None:
    output = run_scenario(SCENARIOS_BY_ID["deprecated-tls10"])
    assert output.rule_severities == {
        "TLS-VERSION-001": "high",
        "CIPHER-SELECTED-001": "low",
        "CERT-CHAIN-001": "info",
    }


def test_expired_certificate_is_judged_against_capture_time() -> None:
    # The expired fixture uses a fixed 2024-09-27 capture instant; validity
    # must be judged against THAT, not the analysis host's clock.
    output = run_scenario(SCENARIOS_BY_ID["expired-certificate"])
    assert output.rule_severities.get("CERT-VALIDITY-001") == "high"


def test_anomaly_outlier_is_strictly_highest() -> None:
    output = run_scenario(SCENARIOS_BY_ID["tls-anomaly-outlier"])
    statuses = list(output.anomaly_status_by_max_bytes.values())
    top = statuses[0]
    assert top in ("unusual", "anomalous", "highly_anomalous")
    assert all(status == "normal" for status in statuses[1:])


def test_mixed_posture_counts_affected_sessions() -> None:
    output = run_scenario(SCENARIOS_BY_ID["mixed-posture"])
    assert output.affected_sessions == 3  # tls10, plaintext, plaintext-auth
    assert output.posture_state == "high_exposure"


def test_repeat_runs_are_deterministic() -> None:
    """Same fixture -> same findings, posture, anomaly result, graph topology."""
    for scenario_id in ("deprecated-tls10", "mixed-posture", "tls-anomaly-outlier"):
        first = run_scenario(SCENARIOS_BY_ID[scenario_id])
        second = run_scenario(SCENARIOS_BY_ID[scenario_id])
        assert first.rule_severities == second.rule_severities
        assert first.posture_score == second.posture_score
        assert first.posture_state == second.posture_state
        assert first.anomaly_status_by_max_bytes == second.anomaly_status_by_max_bytes
        assert first.graph_node_types == second.graph_node_types
        assert first.graph_node_count == second.graph_node_count
        assert first.graph_edge_count == second.graph_edge_count
