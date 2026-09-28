"""Longitudinal drift evaluation harness (Stage 14).

Drives a synthetic three-capture longitudinal case through the real
API using deterministic drift fixtures:

- A: TLS 1.0 + CBC + leafV only (valid) -> TLS-VERSION-001 and
  related findings, posture degraded.
- B: TLS 1.2 + AEAD + full chain -> no findings, posture healthy.
- C: TLS 1.0 + CBC + leafV only (SAME fingerprint, expired at
  C-time) -> original rules return plus CERT-VALIDITY-001, posture
  high_exposure.

Ground truth (defined before execution): the exact drift sets below,
lifecycle states, posture relations, remediation regression linkage,
negative cases, and determinism across runs.

Expected A -> B (11 records): posture_change x1, finding_resolved x3
(TLS-VERSION-001, CIPHER-SELECTED-001, CERT-CHAIN-001),
tls_configuration_changed x2, certificate_changed x3,
correlation_pattern_changed x2.

Expected B -> C (12 records): posture_change x1, finding_recurred x3,
finding_introduced x1 (CERT-VALIDITY-001), tls_configuration_changed
x2, certificate_changed x3, correlation_pattern_changed x2.

No protocol/anomaly/validity drift in chain pairs. POST A-vs-C
carries exactly one certificate_validity_changed record.

Usage:

    python -m scripts.evaluate_drift              # summary
    python -m scripts.evaluate_drift --json out   # + JSON
    python -m scripts.evaluate_drift --repeat 2   # run twice

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

DRIFT_EVALUATION_SCHEMA_VERSION = "1.0"
CASE_TITLE = "Drift evaluation case"
TARGET_RULE = "TLS-VERSION-001"


@dataclass(frozen=True, slots=True)
class Check:
    check: str
    passed: bool
    expected: str
    actual: str


@dataclass
class DriftEvaluation:
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
    """Remove wall-clock timestamps and random ids for cross-run comparison.

    Capture ids are content hashes and therefore stable; drift and
    observation ids embed the random case id and are verified
    exactly within a run instead.
    """
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
                "analyzed_at",
                "remediation_id",
                "verification_id",
                "note_id",
                "entry_id",
                "report_id",
                "case_id",
                "drift_id",
                "observation_id",
            }
        }
    if isinstance(value, list):
        return [_strip_dynamic(item) for item in value]
    return value


def _expected_drift_id(
    case_id: str, base_id: str, cmp_id: str, drift_type: str, evidence_key: str
) -> str:
    """Independently recompute a drift id from the specified canonical form."""
    canonical = "|".join([case_id, base_id, cmp_id, drift_type, evidence_key])
    return "drift_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def run_drift_evaluation() -> DriftEvaluation:
    """Run the synthetic longitudinal scenario once through the real API."""
    from engine.graph.model import tls_config_fingerprint

    from scripts.drift_fixtures import load_drift_scenarios
    from scripts.fixtures import load_scenarios as load_stage10_scenarios

    checks: list[Check] = []
    observed: dict[str, Any] = {}
    scenarios = {s.scenario_id: s for s in load_drift_scenarios()}
    stage10 = {s.scenario_id: s for s in load_stage10_scenarios()}

    with tempfile.TemporaryDirectory(prefix="nse_drift_eval_") as tmp:
        client = _make_client(Path(tmp))

        response = client.post(
            "/api/cases",
            json={"title": CASE_TITLE, "description": "Stage 14 evaluation", "priority": "HIGH"},
        )
        _check(checks, "case_create", response.status_code == 200, "200", str(response.status_code))
        if response.status_code != 200:
            return DriftEvaluation(passed=False, checks=checks, observed=observed)
        case_id = response.json()["case_id"]

        capture_ids: dict[str, str] = {}
        for scenario_id in ("drift-capture-a", "drift-capture-b", "drift-capture-c"):
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
        aid, bid, cid = (
            capture_ids[s] for s in ("drift-capture-a", "drift-capture-b", "drift-capture-c")
        )

        # Baseline rule present in A ------------------------------------
        baseline_findings = client.get(f"/api/captures/{aid}/findings").json()
        target = next((f for f in baseline_findings if f["rule_id"] == TARGET_RULE), None)
        _check(
            checks,
            "baseline_rule_present",
            target is not None,
            TARGET_RULE,
            ",".join(sorted({f["rule_id"] for f in baseline_findings})),
        )
        if target is None:
            return DriftEvaluation(passed=False, checks=checks, observed=observed)

        # Observations ----------------------------------------------------
        observations = client.get(f"/api/cases/{case_id}/observations").json()["observations"]
        _check(
            checks,
            "observation_order",
            [o["capture_id"] for o in observations] == [aid, bid, cid],
            "attachment order",
            ",".join(o["capture_id"] for o in observations),
        )
        _check(
            checks,
            "observations_analyzed",
            all(o["analyzed"] for o in observations) and len(observations) == 3,
            "3 analyzed",
            str(len(observations)),
        )
        observed_rules = {
            o["capture_id"]: sorted(r["rule_id"] for r in o["finding_rules"]) for o in observations
        }
        _check(
            checks,
            "observation_rules",
            observed_rules[aid] == ["CERT-CHAIN-001", "CIPHER-SELECTED-001", "TLS-VERSION-001"]
            and observed_rules[bid] == []
            and observed_rules[cid]
            == ["CERT-CHAIN-001", "CERT-VALIDITY-001", "CIPHER-SELECTED-001", "TLS-VERSION-001"],
            "A:3 B:0 C:4",
            json.dumps(observed_rules, sort_keys=True),
        )

        # Baseline selection ----------------------------------------------
        set_baseline = client.post(
            f"/api/cases/{case_id}/observations/baseline", json={"capture_id": aid}
        )
        _check(
            checks,
            "baseline_set",
            set_baseline.status_code == 200,
            "200",
            str(set_baseline.status_code),
        )
        baseline = client.get(f"/api/cases/{case_id}/observations/baseline").json()
        _check(
            checks,
            "baseline_read",
            baseline["baseline_capture_id"] == aid,
            aid,
            str(baseline["baseline_capture_id"]),
        )
        foreign = client.post(
            f"/api/cases/{case_id}/observations/baseline",
            json={"capture_id": "capture_0123456789ab"},
        )
        _check(
            checks,
            "baseline_unknown_rejected",
            foreign.status_code == 404,
            "404",
            str(foreign.status_code),
        )

        # Independent primitives for exact key assertions -------------------
        session_a = client.get(f"/api/sessions/{target['session_id']}").json()
        handshake = session_a["handshake"]
        fp_v = session_a["certificates"][0]["fingerprint_sha256"]
        tls_fp_v = tls_config_fingerprint(
            handshake["tls_version"], handshake["cipher_suite"], handshake["key_exchange"]
        )
        session_b = client.get(f"/api/captures/{bid}/sessions").json()
        session_b = client.get(f"/api/sessions/{session_b[0]['id']}").json()
        handshake_b = session_b["handshake"]
        tls_fp_b = tls_config_fingerprint(
            handshake_b["tls_version"], handshake_b["cipher_suite"], handshake_b["key_exchange"]
        )
        fp_b = session_b["certificates"][0]["fingerprint_sha256"]
        fp_ca = session_b["certificates"][1]["fingerprint_sha256"]
        correlations = client.get(f"/api/cases/{case_id}/correlations").json()["correlations"]
        corr_keys = {
            (c["correlation_type"], c["evidence_key"]): set(c["source_capture_ids"])
            for c in correlations
        }
        # Asymmetric correlations (not spanning all three captures) must
        # produce pattern-change records in both chain pairs.
        asymmetric = sorted((t, k) for (t, k), caps in corr_keys.items() if caps != {aid, bid, cid})
        postures = {
            capture_id: client.get(f"/api/captures/{capture_id}/posture").json()
            for capture_id in (aid, bid, cid)
        }

        def expected_pair(base_id: str, cmp_id: str) -> set[tuple[str, str, str, str]]:
            """Exact expected (type, key, base, cmp) set for a chain pair."""
            before, after = postures[base_id], postures[cmp_id]
            posture_key = (
                f"posture|{before['posture_state']}:{before['overall_score']}"
                f"->{after['posture_state']}:{after['overall_score']}"
            )
            pair_keys = {
                (f"correlation|{t}|{k}")
                for (t, k) in asymmetric
                if (base_id in corr_keys[(t, k)]) != (cmp_id in corr_keys[(t, k)])
            }
            types_keys = {
                ("posture_change", posture_key),
                *[("correlation_pattern_changed", k) for k in pair_keys],
            }
            if (base_id, cmp_id) == (aid, bid):
                types_keys |= {
                    ("finding_resolved", "finding-rule|tls-version-001"),
                    ("finding_resolved", "finding-rule|cipher-selected-001"),
                    ("finding_resolved", "finding-rule|cert-chain-001"),
                    ("tls_configuration_changed", f"tls-config|{tls_fp_v}"),
                    ("tls_configuration_changed", f"tls-config|{tls_fp_b}"),
                    ("certificate_changed", f"certificate|{fp_v}"),
                    ("certificate_changed", f"certificate|{fp_b}"),
                    ("certificate_changed", f"certificate|{fp_ca}"),
                }
            else:
                types_keys |= {
                    ("finding_recurred", "finding-rule|tls-version-001"),
                    ("finding_recurred", "finding-rule|cipher-selected-001"),
                    ("finding_recurred", "finding-rule|cert-chain-001"),
                    ("finding_introduced", "finding-rule|cert-validity-001"),
                    ("tls_configuration_changed", f"tls-config|{tls_fp_b}"),
                    ("tls_configuration_changed", f"tls-config|{tls_fp_v}"),
                    ("certificate_changed", f"certificate|{fp_b}"),
                    ("certificate_changed", f"certificate|{fp_ca}"),
                    ("certificate_changed", f"certificate|{fp_v}"),
                }
            return {(t, k, aid, cmp_id) for (t, k) in types_keys}

        # Drift list: exact sets -------------------------------------------
        drift = client.get(f"/api/cases/{case_id}/drift").json()["drift"]
        actual = {
            (
                d["drift_type"],
                d["evidence_key"],
                d["baseline_capture_id"],
                d["comparison_capture_id"],
            )
            for d in drift
        }
        expected = expected_pair(aid, bid) | expected_pair(bid, cid)
        _check(
            checks,
            "exact_drift_set",
            actual == expected,
            f"{len(expected)} records",
            f"{len(actual)} records: "
            + ",".join(
                sorted(f"{t}:{k.split('|')[-1][:12]}" for (t, k, _, _) in actual - expected)
                or ["-"]
            )
            + " / missing: "
            + ",".join(
                sorted(f"{t}:{k.split('|')[-1][:12]}" for (t, k, _, _) in expected - actual)
                or ["-"]
            ),
        )
        observed["drift"] = sorted(
            ({"type": d["drift_type"], "key": d["evidence_key"]} for d in drift),
            key=lambda item: (item["type"], item["key"]),
        )

        # Exact id recomputation (within-run): ids are canonical on the
        # lifecycle anchor (here the case baseline A), not the pair start.
        sample = next(
            d
            for d in drift
            if d["drift_type"] == "finding_recurred"
            and d["evidence_key"] == "finding-rule|tls-version-001"
        )
        _check(
            checks,
            "drift_id_exact",
            sample["drift_id"]
            == _expected_drift_id(case_id, aid, cid, sample["drift_type"], sample["evidence_key"]),
            "canonical hash",
            sample["drift_id"],
        )

        # Summary counts -------------------------------------------------------
        summary = client.get(f"/api/cases/{case_id}/drift/summary").json()
        _check(
            checks,
            "summary_counts",
            summary["observations"] == 3
            and summary["baseline_capture_id"] == aid
            and summary["posture_changes"] == 2
            and summary["new_findings"] == 1
            and summary["resolved_findings"] == 3
            and summary["recurring_findings"] == 3
            and summary["configuration_changes"] == 10
            and summary["anomaly_changes"] == 0,
            "3/2/1/3/3/10/0",
            json.dumps(
                {
                    k: summary.get(k)
                    for k in (
                        "observations",
                        "posture_changes",
                        "new_findings",
                        "resolved_findings",
                        "recurring_findings",
                        "configuration_changes",
                        "anomaly_changes",
                    )
                },
                sort_keys=True,
            ),
        )
        _check(
            checks,
            "summary_shape",
            set(summary)
            == {
                "case_id",
                "observations",
                "baseline_capture_id",
                "drift_count",
                "posture_changes",
                "new_findings",
                "resolved_findings",
                "recurring_findings",
                "configuration_changes",
                "anomaly_changes",
                "by_type",
            },
            "counts only, no scores",
            ",".join(sorted(set(summary))),
        )

        # Comparisons + lifecycle ----------------------------------------------
        comparisons = client.get(f"/api/cases/{case_id}/comparisons").json()["comparisons"]
        _check(
            checks,
            "comparison_chain",
            [(c["previous_capture_id"], c["comparison_capture_id"]) for c in comparisons]
            == [(aid, bid), (bid, cid)],
            "A->B, B->C",
            str([(c["previous_capture_id"], c["comparison_capture_id"]) for c in comparisons]),
        )
        lifecycle_bc = {
            row["rule_id"]: row["lifecycle"]
            for row in next(c for c in comparisons if c["comparison_capture_id"] == cid)[
                "finding_lifecycle"
            ]
        }
        _check(
            checks,
            "lifecycle_bc",
            lifecycle_bc
            == {
                "TLS-VERSION-001": "recurred",
                "CIPHER-SELECTED-001": "recurred",
                "CERT-CHAIN-001": "recurred",
                "CERT-VALIDITY-001": "new",
            },
            "3 recurred + 1 new",
            json.dumps(lifecycle_bc, sort_keys=True),
        )

        # POST A-vs-C carries the validity record -------------------------------
        posted = client.post(
            f"/api/cases/{case_id}/comparisons",
            json={"baseline_capture_id": aid, "comparison_capture_id": cid},
        ).json()
        validity = [d for d in posted["drift"] if d["drift_type"] == "certificate_validity_changed"]
        _check(
            checks,
            "validity_post_pair",
            len(validity) == 1 and validity[0]["evidence_key"] == f"certificate-validity|{fp_v}",
            "1 validity record",
            str(len(validity)),
        )
        fallback = client.post(
            f"/api/cases/{case_id}/comparisons", json={"comparison_capture_id": cid}
        )
        _check(
            checks,
            "post_fallback_baseline",
            fallback.status_code == 200,
            "200",
            str(fallback.status_code),
        )

        # Posture relations ------------------------------------------------------
        postures = {o["capture_id"]: (o["posture_state"], o["posture_score"]) for o in observations}
        _check(
            checks,
            "posture_states",
            postures[aid][0] == "degraded"
            and postures[bid][0] == "healthy"
            and postures[cid][0] == "high_exposure",
            "degraded/healthy/high_exposure",
            json.dumps(postures, sort_keys=True, default=str),
        )
        score_a, score_b, score_c = postures[aid][1], postures[bid][1], postures[cid][1]
        _check(
            checks,
            "posture_relations",
            all(isinstance(s, int) for s in (score_a, score_b, score_c))
            and score_c < score_a < score_b,
            "C < A < B",
            f"{score_c} < {score_a} < {score_b}",
        )
        observed["posture_scores"] = {"a": score_a, "b": score_b, "c": score_c}

        # Remediation regression --------------------------------------------------
        remediation = client.post(
            f"/api/cases/{case_id}/remediations/from-finding",
            json={"finding_id": target["id"], "owner": "netops"},
        ).json()
        remediation_id = remediation["remediation_id"]
        for status in ("PLANNED", "IN_PROGRESS"):
            client.patch(
                f"/api/cases/{case_id}/remediations/{remediation_id}", json={"status": status}
            )
        verified = client.post(
            f"/api/cases/{case_id}/remediations/{remediation_id}/verify",
            json={"mode": "evidence", "verification_capture_id": bid},
        ).json()
        _check(
            checks,
            "regression_verify",
            verified["result"] == "VERIFIED",
            "VERIFIED",
            verified["result"],
        )
        # Re-fetch: links are computed at read time, so records fetched
        # before the remediation existed carry no links.
        drift = client.get(f"/api/cases/{case_id}/drift").json()["drift"]
        recurred = next(
            d
            for d in drift
            if d["drift_type"] == "finding_recurred"
            and d["evidence_key"] == "finding-rule|tls-version-001"
        )
        _check(
            checks,
            "regression_linked",
            remediation_id in recurred["related_remediation_ids"]
            and recurred["regression_after_verification"] is True
            and "may require review" in recurred["statement"],
            "linked + review",
            ",".join(recurred["related_remediation_ids"]),
        )
        reg_view = client.get(f"/api/cases/{case_id}/remediations/{remediation_id}/drift").json()
        _check(
            checks,
            "remediation_drift_view",
            reg_view["regression_detected"] is True
            and reg_view["current_lifecycle"] == "recurred"
            and reg_view["baseline_capture_id"] == aid,
            "recurred",
            json.dumps(
                {
                    "regression": reg_view["regression_detected"],
                    "lifecycle": reg_view["current_lifecycle"],
                },
                sort_keys=True,
            ),
        )

        # Negative cases -----------------------------------------------------------
        other = client.post(
            "/api/cases", json={"title": "Other", "description": "", "priority": "LOW"}
        ).json()
        foreign_upload = client.post(
            "/api/captures",
            files={
                "file": (
                    "foreign.pcap",
                    stage10["plaintext-smtp"].pcap,
                    "application/octet-stream",
                )
            },
        ).json()
        client.post(f"/api/captures/{foreign_upload['id']}/analyze")
        client.post(
            f"/api/cases/{other['case_id']}/captures", json={"capture_id": foreign_upload["id"]}
        )
        cross = client.post(
            f"/api/cases/{case_id}/comparisons",
            json={"baseline_capture_id": aid, "comparison_capture_id": foreign_upload["id"]},
        )
        _check(
            checks, "cross_case_rejected", cross.status_code == 422, "422", str(cross.status_code)
        )
        foreign_baseline = client.post(
            f"/api/cases/{case_id}/observations/baseline",
            json={"capture_id": foreign_upload["id"]},
        )
        _check(
            checks,
            "baseline_unattached_rejected",
            foreign_baseline.status_code == 422,
            "422",
            str(foreign_baseline.status_code),
        )
        # Unanalyzed capture: distinct Stage 10 bytes (different from the
        # foreign capture above), attached, never analyzed.
        plain = stage10["plaintext-authentication"]
        fresh = client.post(
            "/api/captures",
            files={"file": ("fresh.pcap", plain.pcap, "application/octet-stream")},
        ).json()
        assert fresh["id"] not in capture_ids.values()
        client.post(f"/api/cases/{case_id}/captures", json={"capture_id": fresh["id"]})
        unanalyzed = client.post(
            f"/api/cases/{case_id}/comparisons",
            json={"baseline_capture_id": aid, "comparison_capture_id": fresh["id"]},
        )
        _check(
            checks,
            "unanalyzed_rejected",
            unanalyzed.status_code == 422,
            "422",
            str(unanalyzed.status_code),
        )
        # Detach the unanalyzed capture so later export assertions see
        # exactly the three analyzed observations.
        detached = client.delete(f"/api/cases/{case_id}/captures/{fresh['id']}")
        _check(
            checks, "detach_cleanup", detached.status_code == 204, "204", str(detached.status_code)
        )
        bad_drift = client.get(f"/api/cases/{case_id}/drift/drift_zzzz")
        _check(
            checks,
            "malformed_drift_id",
            bad_drift.status_code == 404,
            "404",
            str(bad_drift.status_code),
        )
        unknown_drift = client.get(f"/api/cases/{case_id}/drift/drift_0123456789abcdef")
        _check(
            checks,
            "unknown_drift_id",
            unknown_drift.status_code == 404,
            "404",
            str(unknown_drift.status_code),
        )
        bad_type = client.get(f"/api/cases/{case_id}/drift", params={"type": "nope"})
        _check(
            checks, "bad_type_filter", bad_type.status_code == 422, "422", str(bad_type.status_code)
        )
        bad_limit = client.get(f"/api/cases/{case_id}/drift", params={"limit": 9999})
        _check(checks, "bad_limit", bad_limit.status_code == 422, "422", str(bad_limit.status_code))
        same_pair = client.post(
            f"/api/cases/{case_id}/comparisons",
            json={"baseline_capture_id": aid, "comparison_capture_id": aid},
        )
        _check(
            checks,
            "same_pair_rejected",
            same_pair.status_code == 422,
            "422",
            str(same_pair.status_code),
        )

        # Evidence untouched ---------------------------------------------------------
        for scenario_id, wanted_rules in (
            ("drift-capture-a", ["CERT-CHAIN-001", "CIPHER-SELECTED-001", "TLS-VERSION-001"]),
            ("drift-capture-b", []),
            (
                "drift-capture-c",
                ["CERT-CHAIN-001", "CERT-VALIDITY-001", "CIPHER-SELECTED-001", "TLS-VERSION-001"],
            ),
        ):
            current = client.get(f"/api/captures/{capture_ids[scenario_id]}/findings").json()
            _check(
                checks,
                f"findings_intact:{scenario_id}",
                sorted(f["rule_id"] for f in current) == wanted_rules,
                ",".join(wanted_rules),
                ",".join(sorted(f["rule_id"] for f in current)),
            )

        # Report / export / bundle / import --------------------------------------------
        report = client.get(f"/api/cases/{case_id}/report.json").json()
        _check(
            checks,
            "report_longitudinal",
            "longitudinal" in report
            and report["longitudinal"]["drift_summary"]["recurring_findings"] == 3
            and len(report["longitudinal"]["drift"]) == 33,
            "33 records",
            str(len(report["longitudinal"].get("drift", []))),
        )
        for fmt in ("report.html", "report.pdf"):
            response = client.get(f"/api/cases/{case_id}/{fmt}")
            _check(
                checks,
                f"report_{fmt}",
                response.status_code == 200,
                "200",
                str(response.status_code),
            )
        export = client.get(f"/api/cases/{case_id}/export").json()
        _check(
            checks,
            "export_schema_13",
            export["schema_version"] == "1.3"
            and set(export) >= {"observations", "baseline", "comparisons", "drift", "drift_summary"}
            and export["baseline"]["baseline_capture_id"] == aid
            and len(export["drift"]) == 33,
            "1.3 with drift",
            export.get("schema_version", "?"),
        )
        import io as _io
        import zipfile as _zipfile

        bundle = client.get(f"/api/cases/{case_id}/bundle").content
        names = set(_zipfile.ZipFile(_io.BytesIO(bundle)).namelist())
        _check(
            checks,
            "bundle_layout",
            names
            == {"case.json", "README.txt", "evidence-manifest.json", "reports/case-report.json"},
            "stable layout",
            ",".join(sorted(names)),
        )
        imported = client.post("/api/cases/import", json=export)
        _check(checks, "import_ok", imported.status_code == 200, "200", str(imported.status_code))
        new_case = imported.json()
        fresh_export = client.get(f"/api/cases/{new_case['case_id']}/export").json()
        _check(
            checks,
            "import_baseline_restored",
            fresh_export["baseline"]["baseline_capture_id"] == aid,
            aid,
            str(fresh_export["baseline"].get("baseline_capture_id")),
        )
        old_struct = _strip_dynamic(
            {k: v for k, v in export.items() if k in ("drift", "comparisons")}
        )
        new_struct = _strip_dynamic(
            {k: v for k, v in fresh_export.items() if k in ("drift", "comparisons")}
        )
        # Remediation/verification ids are fresh random values in the
        # imported case, and verification history does not transfer, so
        # links cannot: normalize link fields before structural comparison.
        import re as _re

        def _scrub_ids(value: Any) -> Any:
            text = json.dumps(value, sort_keys=True, default=str)
            text = _re.sub(r"rem_[0-9a-f]{16}", "rem_ID", text)
            text = _re.sub(r"verif_[0-9a-f]{16}", "verif_ID", text)
            text = _re.sub(r"corr_[0-9a-f]{16}", "corr_ID", text)
            text = _re.sub(r"drift_[0-9a-f]{16}", "drift_ID", text)
            scrubbed = json.loads(text)
            # Drop link fields everywhere (including nested comparison drift).
            stack = [scrubbed]
            while stack:
                node = stack.pop()
                if isinstance(node, dict):
                    node.pop("related_remediation_ids", None)
                    node.pop("related_verification_ids", None)
                    if "regression_after_verification" in node:
                        node["regression_after_verification"] = False
                    statement = node.get("statement")
                    if isinstance(statement, str) and " Existing remediation " in statement:
                        node["statement"] = statement.split(" Existing remediation ")[0]
                    stack.extend(node.values())
                elif isinstance(node, list):
                    stack.extend(node)
            return scrubbed

        _check(
            checks,
            "import_drift_recomputed",
            _scrub_ids(old_struct) == _scrub_ids(new_struct),
            "identical structure",
            "diverged" if _scrub_ids(old_struct) != _scrub_ids(new_struct) else "identical",
        )
        _check(
            checks,
            "import_links_reset",
            all(not d.get("related_remediation_ids") for d in fresh_export["drift"]),
            "no transferred links",
            "links transferred"
            if any(d.get("related_remediation_ids") for d in fresh_export["drift"])
            else "none",
        )
        observed["drift"] = sorted(
            ({"type": d["drift_type"], "key": d["evidence_key"]} for d in drift),
            key=lambda item: (item["type"], item["key"]),
        )

    passed = all(check.passed for check in checks)
    return DriftEvaluation(passed=passed, checks=checks, observed=observed)


def evaluate(*, repeat: int = 2) -> dict[str, Any]:
    """Run the drift evaluation, repeating for determinism."""
    first = run_drift_evaluation()
    deterministic = True
    if repeat > 1 and first.passed:
        fingerprint = json.dumps(_strip_dynamic(first.observed), sort_keys=True, default=str)
        for _ in range(repeat - 1):
            rerun = run_drift_evaluation()
            if not rerun.passed or (
                json.dumps(_strip_dynamic(rerun.observed), sort_keys=True, default=str)
                != fingerprint
            ):
                deterministic = False
            first.checks.extend(rerun.checks)
    passed = first.passed and deterministic
    return {
        "schema_version": DRIFT_EVALUATION_SCHEMA_VERSION,
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
    """Human-readable drift evaluation summary."""
    lines = ["SecureMailScope drift evaluation", "=" * 60]
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
        "Scope note: a synthetic three-capture case verifies longitudinal "
        "drift semantics. Drift is derived from observed captures; it does "
        "not prove causality, and repeated findings do not prove malicious "
        "activity."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.evaluate_drift",
        description="Run the deterministic longitudinal drift evaluation.",
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
