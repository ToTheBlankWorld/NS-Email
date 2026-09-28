# ADR 012 — Multi-Capture Correlation and Investigation Intelligence

- **Status:** Accepted (Stage 12)
- **Date:** 2026-09-28
- **Scope:** correlation domain model, normalization, index-based
  engine, correlation API, investigation graph, session related
  observations, report/export integration (schema 1.1), AI correlation
  queries, correlation evaluation, demo, workspace UI

## Context

Stage 11 cases can hold multiple captures, but nothing answered "what
evidence is repeated across this case's captures?" Stage 12 adds that
derived intelligence layer. It is correlation — shared structured
observations — not attribution, threat intelligence, maliciousness
classification, or another ML system.

## Decisions

1. **Index-based engine, never pairwise.** `engine/correlation`
   files every session/certificate/finding/anomaly observation into
   keyed indexes in a single pass, then emits one relationship per
   key seen in two or more captures: O(N + relationships). Single-
   capture keys correctly yield nothing (within-capture pivots remain
   the Stage 7 graph's job). A performance regression test (300
   sessions, index stats, time bound) guards the complexity claim.

2. **Fixed ten-type vocabulary.** Shared endpoint/host/certificate/
   certificate-subject/TLS-configuration/protocol/finding, shared
   anomaly pattern (flagged bands only — normal/insufficient/model-
   error states are baseline noise, not patterns), repeated session
   pattern, and shared evidence (SNI hostname, certificate issuer
   subtypes). No free-text correlation keys; oversized or hostile
   values are rejected at normalization.

3. **Conservative offline normalization.** Canonical IPs via the
   standard library; hostnames lowercased with a single trailing-dot
   trim (no IDNA, no DNS, no WHOIS, no geolocation, no enrichment of
   any kind); TLS configuration reuses the Stage 7 fingerprint
   verbatim; certificate identity is the SHA-256 fingerprint.
   Un-normalizable values are skipped, never guessed.

4. **Deterministic ids bound to the case.** `corr_<sha256(case +
   type + key + sorted source ids)[:16]>`. Same evidence in the same
   case always yields the same id; different cases never collide.
   Strength is categorical (DIRECT = identity-level, DERIVED =
   normalized descriptive) — no probabilistic scores, no risk scores.

5. **Read-only and unpersisted.** Correlations are a pure function of
   case attachments plus evidence state, computed on demand. No
   storage, no invalidation, no staleness, and — by construction and
   by regression test — no mutation of findings, posture, anomalies,
   graphs, certificates, or sessions.

6. **Layered investigation graph.** The case graph view marks
   case/capture/session/evidence nodes as `layer: "forensic"` and
   correlation groupings as `layer: "correlation"`. Stage 7
   per-capture graphs are byte-identical (asserted: no `layer` field
   there). Sessions are bounded with explicit truncation reporting.

7. **Schema 1.1, backward-compatible import.** Exports and case
   reports gain `correlations`/`correlation_summary` and a
   `correlation` report section (between evidence and analyst work);
   the evidence digest covers correlations. Import accepts 1.0 and
   1.1; imported correlations are shape-validated and discarded —
   always recomputed from local evidence, with an explicit warning.

8. **Ephemeral, explicit AI questions only.** `POST
   /api/ai/query-correlation` resolves one correlation and forwards a
   minimized, bounded, sensitivity-stripped context. Responses carry
   no session id (citation validation stays vacuous-but-safe), are
   never written to capture AI history, and never appear in reports
   or exports. The AI cannot create or alter correlations.

9. **Session context is additive.** `GET
   /api/cases/{case_id}/sessions/{session_id}/related` lists related
   observations without touching existing session records or the
   existing session-context endpoint.

10. **Prerequisite persistence fix.** Cross-capture analysis exposed
    that `session_certificates.id` as a global primary key collapsed
    identical certificates observed in different sessions (last write
    won, silently dropping the earlier observation — including in
    session detail). The key is now `(id, session_id)` with a rebuild
    migration for legacy databases. No semantics change for
    single-capture flows; re-analysis stays idempotent.

## Security considerations

- Evidence-derived strings (hostnames, subjects, SNI, issuers) are
  untrusted data: length-capped at normalization, escaped in HTML
  reports, sanitized in PDFs, bounded in API output (occurrence and
  total caps, pagination limits).
- Correlation/finding/session path ids are regex-validated; malformed
  ids return structured 404s with no internals.
- Import caps and shape validation apply to correlation sections;
  hostile bundles are rejected or skipped with warnings.

## Limitations

- Correlation is not attribution. Repeated evidence does not
  establish malicious intent, common ownership, or attack activity;
  shared infrastructure is routinely benign (CDNs, shared mail
  providers, default certificates).
- Anomaly correlation covers flagged bands only; subtle behavioral
  relationships are out of scope by design.
- Certificate/TLS-identity correlations require the evidence to be
  present in stored sessions; captures that were never analyzed
  contribute no observations.
- Case evaluation is synthetic: deliberate A/B/C overlaps verify the
  workflow, not real-world investigative efficacy.
