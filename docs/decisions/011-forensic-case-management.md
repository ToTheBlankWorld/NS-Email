# ADR 011 — Forensic Case Management and Evidence Preservation

- **Status:** Accepted (Stage 11)
- **Date:** 2026-09-28
- **Scope:** case domain model, capture references, investigation timeline,
  analyst notes/tags/bookmarks, case API, case reporting/export/bundle/
  import, technical provenance, case workspace frontend, case evaluation

## Context

Stages 1-10 deliver analysis and reporting per capture. An investigation
typically spans several captures plus the analyst's working context:
which evidence was reviewed, what was bookmarked, what the analyst
concluded, and how the whole package can be reproduced later. Stage 11
adds that organizational and evidence-preservation layer without
touching any forensic semantics from Stages 1-10.

## Decisions

1. **Cases reference captures; they never copy them.** `case_captures`
   stores `(case_id, capture_id)` pairs only. A capture may belong to
   multiple cases: references cannot conflict because they mutate
   nothing on the capture side. Deleting a case deletes its metadata;
   evidence rows are untouched.

2. **Secure random case ids, derived display numbers.** Case, note,
   bookmark, timeline, and report-history ids are `prefix` +
   16 hex digits from `secrets.token_hex` — never sequential.
   `case_number` (`CASE-XXXXXXXX`) is derived deterministically from the
   id and is display metadata only. Malformed ids are reported as
   `case_not_found` (404), exactly like unknown ids, so ids can never
   address storage or leak existence information.

3. **Two timelines, never merged.** The forensic timeline (packet-derived
   session events, Stages 2-3) and the case timeline (analyst actions:
   created, attached, bookmarked, noted, reported, exported, status
   changes) are separate concepts, separate tables, and separate UI
   surfaces. The case timeline is append-only.

4. **Notes are untrusted analyst content.** Stored raw, escaped at every
   render boundary (`html.escape` in HTML reports, Latin-1 sanitization
   in PDFs). Finding/anomaly/session/capture/case references are
   verified at write time; certificate, TLS-handshake, graph-node, and
   timeline-event targets are lightweight references resolved at
   navigation time. Notes are never forwarded to the AI provider: the AI
   context builder is untouched, and reports quote only validated AI
   observations (`validation_status == "validated"`).

5. **Tags are open-vocabulary metadata.** Analyst-defined, normalized to
   lowercase, max 64 chars, URL-path safe, no control characters, max 50
   per case. Tags never alter severity, posture, anomaly scores, or
   findings — enforced by construction (no code path from tags to
   analysis) and by regression test.

6. **Bookmarks are references with deep links.** `(case_id,
   target_type, target_id)` is unique; re-bookmarking is idempotent.
   The workspace resolves each bookmark to its evidence view
   (finding/session/anomaly/capture detail, graph, or case timeline).

7. **No case score, ever.** Summaries and reports quote the authoritative
   per-capture Stage 5 snapshots verbatim and aggregate counts only.
   Any averaging of posture into a case metric was rejected as
   unjustified.

8. **Deterministic, side-effect-free builders.** Report, export, and
   bundle documents are pure functions of persisted state (report id and
   `generated_at` derive from case/capture ids and analysis timestamps,
   never wall-clock). Timeline/report-history writes happen AFTER
   serializing response bytes, so consecutive generations differ only in
   explicitly dynamic metadata (timestamps, history rows).

9. **Versioned export (`schema_version: "1.0"`).** `case.json` carries
   case metadata, capture metadata with SHA-256, findings, anomalies,
   bookmarks, notes, tags, timeline, report history, and provenance —
   and explicitly excludes raw email bodies, raw PCAP payloads,
   credentials, secrets, and unvalidated AI output. The zip bundle adds
   `README.txt`, `evidence-manifest.json`, and `reports/case-report.json`
   with fixed archive timestamps for byte-reproducibility. Raw evidence
   bytes ship only under an explicit `?include_evidence=true` opt-in.

10. **Import creates, never overwrites.** Import validates the schema
    version, re-validates every note/tag/bookmark (invalid entries are
    skipped with warnings), attaches only captures already registered
    locally with matching SHA-256, starts a fresh timeline with a single
    `case_imported` event (the imported trail is not replayed), and never
    imports AI observations. No filesystem paths exist in the format, so
    there is no traversal surface; target ids rejecting path components
    is defense in depth.

11. **Technical provenance, not legal custody.** Reports, exports, and
    bundles record capture hashes, ingestion/analysis timestamps,
    application version, attachment events, and export timestamps under
    an explicit "Technical provenance metadata" label with a "not a
    legal chain-of-custody certification" disclaimer in every renderer.

12. **CORS extended minimally.** `PATCH` and `DELETE` join the
    allow-list alongside `GET`/`POST` (required by the case API);
    origins remain allow-listed, headers unchanged.

13. **Frontend reuses, not duplicates.** The case workspace (`/cases`,
    `/cases/[caseId]`) orchestrates existing evidence views: capture
    detail, finding/anomaly detail, graph, and report downloads are
    linked, not reimplemented. No frontend test framework was introduced
    (Stage 9/10 decision respected); validation is typecheck/lint/build
    plus live API tests.

## Security considerations

- Analyst content (notes, labels, tags, titles, descriptions) is
  length-capped, control-character screened, and escaped in HTML/PDF;
  oversized, traversal-shaped, and injection-shaped inputs are covered
  by `test_cases_api.py` security tests.
- Case ids, note ids, and bookmark ids are regex-validated at the path
  layer; tag values are constrained to a routing-safe alphabet.
- Import caps (captures/notes/bookmarks) bound hostile bundle sizes;
  malformed bundles are rejected with structured 422s.
- Error responses keep the `{"error": {"code", "message"}}` shape; no
  tracebacks, SQL, paths, or secrets leak.

## Limitations

- Case evaluation is synthetic: one scripted investigation over three
  controlled fixtures verifies workflow and separation, not
  real-world investigative efficacy.
- Reference validation for certificate/TLS-handshake/graph-node targets
  is resolution-at-navigation, not verification-at-write.
- Import requires evidence to already exist locally with matching
  hashes; there is no evidence-upload-via-bundle path (raw bytes travel
  only via the explicit bundle opt-in and manual re-ingestion).
- Case metadata does not alter forensic evidence (by design and by
  regression test).
