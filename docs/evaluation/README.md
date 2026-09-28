# SecureMailScope — Forensic Evaluation Report (Stage 10)

- **Evaluation date:** 2026-09-28
- **System version:** Stage 9 (`d202b98`) plus Stage 10 hardening
- **Policy baseline:** `securemailscope-baseline v1.0`
- **Reproducibility:** `python -m scripts.evaluate --repeat 2 --json latest-results.json`

## 1. Evaluation scope

This report documents the controlled evaluation of the SecureMailScope
pipeline over **15 deterministic synthetic scenarios** covering secure and
misconfigured email/TLS behavior. Ground truth for every scenario was
defined by hand from the documented policy semantics *before* execution.

**Scope boundary (explicit):** controlled synthetic scenarios verify that
the system behaves as specified and guard against regressions. They do
**not** measure real-world attack-detection accuracy, and no real-world
detection rate is claimed anywhere in this repository.

## 2. Scenario inventory

| # | Scenario | Category | Ground-truth outcome |
| - | -------- | -------- | -------------------- |
| 1 | secure-tls13 | secure | no findings, posture healthy |
| 2 | secure-tls12 | secure | no findings, posture healthy |
| 3 | deprecated-tls10 | deprecated version | TLS-VERSION-001 (high), CIPHER-SELECTED-001 (low), CERT-CHAIN-001 (info) |
| 4 | weak-cipher-3des | weak cipher | CIPHER-SELECTED-001 (medium), KEYEX-001 (medium) |
| 5 | expired-certificate | certificate | CERT-VALIDITY-001 (high) |
| 6 | sha1-certificate | certificate | CERT-SIG-001 (high) |
| 7 | weak-certificate-key | certificate | CERT-KEY-001 (high) |
| 8 | san-mismatch | certificate identity | CERT-IDENTITY-001 (high) |
| 9 | self-signed-certificate | certificate | CERT-SELF-SIGNED-001 (low) |
| 10 | starttls-requested-not-accepted | STARTTLS | STARTTLS-001 (medium), PLAINTEXT-001 (medium) |
| 11 | plaintext-smtp | plaintext | PLAINTEXT-001 (medium) |
| 12 | plaintext-authentication | plaintext auth | AUTH-PLAINTEXT-001 (high), PLAINTEXT-001 (medium) |
| 13 | incomplete-tls-handshake | handshake | TLS-FAILURE-001 (info) |
| 14 | tls-anomaly-outlier | behavioral anomaly | outlier flagged unusual+, baselines normal |
| 15 | mixed-posture | multi-session | five rule outcomes across four sessions |

All scenarios are built from fixed synthetic key material, fixed serials,
fixed validity windows, and a fixed capture instant (2024-09-27), so every
PCAP is byte-identical across runs and every capture/finding/graph ID is
stable.

## 3. Detection results (ground truth vs. system output)

**15 of 15 controlled scenarios matched the expected rule outcomes.**

The comparison layer (``scripts/runner.py``) checks, per scenario: protocol
detection, session count, negotiated TLS version, cipher suite, key-exchange
family, handshake completeness, certificate count, the *exact* set of fired
rule IDs, the severity of each fired rule, the posture state, anomaly
expectations, and required evidence-graph node types.

## 4. Regression results

The golden suite (`backend/tests/test_golden_scenarios.py`, 24 tests)
asserts every scenario against its ground truth and asserts that repeated
runs of the same scenario produce identical findings, posture, anomaly
results, and graph topology (Phase 15 data-integrity requirement). The
evaluation harness additionally supports `--repeat N` for multi-run
fingerprint comparison.

## 5. Security tests

18 dedicated security regression tests (`backend/tests/test_security_regression.py`)
cover: path traversal (literal and percent-encoded), upload validation
(magic bytes, truncation, garbage), parser robustness (malformed packets,
truncated TLS records, corrupted extensions, garbage certificate DER),
report escaping, AI failure states (timeouts, malformed provider output,
foreign citations), and database safety (malformed IDs, duplicate evidence,
no SQL/traceback leakage). Earlier-stage security tests (ingestion
validation, AI grounding, redaction) remain in place and green.

## 6. Resource-limit tests

13 operational tests (`backend/tests/test_operations.py`) cover the
readiness endpoint, configuration validation (including fail-fast startup
on invalid AI configuration), and the configurable evidence-graph node
limit (`NS_EMAIL_MAX_GRAPH_NODES`): exceeding the limit keeps the analysis
intact, omits the graph, and surfaces an explicit warning — evidence is
never silently truncated.

## 7. Benchmark measurements

`python -m scripts.benchmark` produces the machine-readable baseline
(`latest-benchmark.json`): per-scenario packet/session/finding counts,
graph sizes, and median wall-clock durations over three runs. The
full-pipeline duration for the single-session scenarios is a few
milliseconds; the ten-session anomaly scenario (129 packets) is tens of
milliseconds. **These numbers are a regression baseline for this machine
and these synthetic fixtures only.** They are not throughput, capacity, or
production-scale claims.

## 8. Known limitations

- The evaluation is synthetic by design: controlled fixtures cannot speak
  to prevalence of misconfiguration in real traffic.
- Certificate-validity scenarios depend on the fixed capture instant;
  validity is always judged against capture time, never the host clock.
- The behavioral-anomaly expectation is statistical (IsolationForest with
  `random_state=42`); the fixture is constructed so the outlier is an
  extreme, unambiguous deviation, but bands are not attack labels.
- Report/PDF content is Latin-1 sanitized; exotic evidence strings are
  transliterated in PDFs.
- No frontend unit-test framework exists; frontend correctness is guarded
  by TypeScript, ESLint, the production build, and live smoke tests.

## 9. Reproducibility instructions

```bash
python -m pip install -e ".[dev]"
python -m pytest engine/tests backend/tests -q      # full test suite
python -m scripts.evaluate --repeat 2               # ground-truth evaluation
python -m scripts.evaluate_cases --repeat 2         # case workflow evaluation
python -m scripts.evaluate_correlations --repeat 2  # correlation evaluation
python -m scripts.benchmark --repeat 3              # performance baseline
python -m scripts.demo --run-once                   # offline demo verification
```

Machine-readable outputs land in `docs/evaluation/latest-*.json`.

## 10. Case evaluation (Stage 11)

`python -m scripts.evaluate_cases --repeat 2` builds one complete
synthetic investigation — **"Mixed TLS Security Investigation"** over
the `secure-tls12`, `deprecated-tls10`, and
`plaintext-authentication` fixtures — and drives it through the real
case API: case creation, capture attachment, ground-truth verification
of findings/posture per capture, finding/session bookmarks, analyst
notes, tags, timeline verification, case report generation
(JSON/HTML/PDF), export determinism (identical apart from explicitly
dynamic timestamps), bundle layout verification, and a final
findings/posture/anomaly/graph integrity check proving the analyst
workflow left forensic truth byte-identical.

Case ids and timeline timestamps are random/wall-clock per run by
design, so cross-run determinism compares evidence-derived output
(finding rule sets, posture states, export structure) rather than
identifiers. Like the capture evaluation, this verifies specified
behavior over controlled fixtures — it does not measure real-world
investigative efficacy, and case metadata never alters forensic
conclusions (asserted by both the harness and the backend regression
suite).

## 11. Correlation evaluation (Stage 12)

`python -m scripts.evaluate_correlations --repeat 2` builds three
deterministic captures with deliberate overlaps (A: endpoint X /
config X / cert X with chain; B: endpoint X / config Y / cert X leaf;
C: endpoint Z / config X / cert Y leaf) and asserts the exact expected
set of 10 correlations — types, evidence keys, affected captures,
deterministic ordering, DIRECT/DERIVED strengths, and neutral language
— plus summary counts, context, session-related observations, the
layered investigation graph, report/export integration (schema 1.1),
and findings integrity. Single-capture rules (B's 3DES findings) are
asserted to produce no correlation. Cross-run determinism compares
types, keys, and capture sets (capture ids are content hashes);
correlation ids additionally bind the random case id, so their shape —
not cross-run equality — is asserted. Correlation is not attribution,
and the harness scope note states that explicitly.
