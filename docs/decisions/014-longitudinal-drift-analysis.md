# ADR 014 — Longitudinal Security Drift Analysis

- **Status:** Accepted (Stage 14)
- **Date:** 2026-09-28
- **Scope:** observation model, explicit baseline selection,
  deterministic comparison, drift vocabulary, finding lifecycle,
  posture trend, regression detection, configuration drift, drift
  engine, deterministic ids, drift API, drift summary, workspace UI,
  remediation/correlation integration, report/export integration
  (schema 1.3), AI boundary, evaluation, demo

## Context

Stages 0–13 answer what was observed in one capture (or across
captures for shared evidence), what was done about a finding, and
whether a later capture shows the rule absent. Operators additionally
need to answer "how did the security posture change across multiple
observations?", "did a previously observed condition return?", and
"did a remediation remain effective in later captures?" — without
rewriting history, inventing scores, or claiming causality.

## Decisions

1. **Observations are derived, never persisted.** An observation
   snapshot (posture, finding rules, TLS versions/ciphers/exchanges,
   certificate footprints, protocols, anomaly bands) is a pure
   function of a case attachment plus immutable analysis output,
   assembled on demand with the analysis instant as its timestamp.
   No wall-clock time enters derived payloads, so derived data can
   never go stale and can never mutate forensic truth (Stage 12
   precedent).

2. **The baseline is an explicit analyst choice.** No automatic
   selection, no newest/first default. One baseline capture per case,
   stored as the only persisted longitudinal state (a metadata
   table), audited through the existing case timeline
   (`baseline_selected` / `baseline_cleared`). Detaching the
   referenced capture clears the selection.

3. **Finite drift vocabulary, evidence-gated emission.** Ten drift
   types (`posture_change`, `finding_introduced`,
   `finding_resolved`, `finding_recurred`,
   `tls_configuration_changed`, `certificate_changed`,
   `certificate_validity_changed`, `protocol_behavior_changed`,
   `anomaly_state_changed`, `correlation_pattern_changed`) plus five
   lifecycle states (`new`, `persistent`, `resolved`, `recurred`,
   `not_comparable`). A record fires only when its underlying
   structured evidence differs; unknown or missing evidence is
   silence, never speculation.

4. **Conservative lifecycle semantics.** Session-scoped rules reuse
   the Stage 13 relevance rule (same protocol + server endpoint);
   capture-level rules need completed analysis. An unrelated capture
   is never proof of resolution (`not_comparable`). Recurrence
   requires presence, then a comparable absence, then presence
   again. Lifecycle is anchored at the case baseline with
   intermediates strictly between anchor and target.

5. **Posture is quoted, never re-scored.** The Stage 5 formula is
   untouched. Trends show quoted scores/states with arithmetic
   deltas ("Posture score changed from 74 to 88."). No drift score,
   no risk/threat/compromise score, no causal claims ("improved
   because of remediation" is forbidden).

6. **Regression links, never transitions.** A `finding_recurred`
   record links remediations with a VERIFIED verification for the
   same rule and appends "Existing remediation … may require
   review." Remediation state is never auto-closed or reopened;
   the analyst acts explicitly. The remediation drift view
   (baseline, verification captures, later observations, current
   lifecycle, regression flag) is read-only.

7. **Reuse, don't duplicate.** TLS configuration identity reuses
   the Stage 7 fingerprints; certificate validity is judged at
   packet time; correlations feed pattern-change detection through
   the attached correlation service. Comparisons run along the
   canonical attachment order as consecutive pairs (linear, indexed
   lookups) plus explicit analyst-chosen pairs — never O(N²)
   across unrelated evidence.

8. **Deterministic ids.** `drift_<sha256(canonical)[:16]>` over
   case + baseline + comparison + type + evidence key; observation
   ids bind case + capture + evidence digest. Stable within a case
   and comparison pair; no random ids for derived records.

9. **Schema 1.3, compatible import.** Reports gain a
   `longitudinal` section (baseline, observations, posture trend,
   comparisons, drift, counts-only summary) in JSON/HTML/PDF with
   the standard content-class separation. Exports gain
   `observations`, `baseline`, `comparisons`, `drift`,
   `drift_summary`. Import accepts 1.0/1.1/1.2/1.3; imported drift
   is validated for shape and discarded with warnings —
   recomputed from local evidence, never trusted. Only the
   baseline choice transfers (when its capture attached locally);
   verification-linked regression flags reset because verification
   state does not transfer.

10. **AI stays interpretation-only.** AI may explain what changed
    and what uncertainties exist. It cannot create drift records,
    change drift types, alter remediation/verification state,
    modify findings/posture/anomalies, or declare compromise or
    attacker behavior (asserted by test: AI history leaves drift
    output byte-identical).

## Security considerations

- Case/capture/drift/remediation ids are regex-validated at the
  path layer; malformed ids (including traversal-shaped strings)
  return structured 404s with no internals.
- Baseline/comparison captures must belong to the case and be
  analyzed; cross-case, unattached, unanalyzed, and self-pair
  comparisons are rejected with structured errors.
- Filters and pagination are bounded; oversized inputs are
  rejected; drift output is scanned for secret/payload/SQL/
  path leakage by regression tests.
- Import shape-validation rejects malformed drift sections;
  bundles keep the stable layout with no raw evidence by default.

## Limitations

- Longitudinal drift is derived from observed captures. Drift
  does not prove causality. Finding absence in one capture does
  not prove global remediation. Repeated findings do not prove
  malicious activity. Posture changes do not prove that a
  particular action caused the change.
- Comparisons are pair-scoped: a certificate-validity change is
  visible only when the same fingerprint appears on both sides of
  one pair (documented in the fixture notes and asserted by the
  evaluation).
- Validity judgments use packet observation time; authoritative
  validity verdicts remain the Stage 4 findings.
- The posture trend handles missing scores as gaps, never as
  zeros; charts are avoided in favor of labeled tables so no
  causality is implied.
