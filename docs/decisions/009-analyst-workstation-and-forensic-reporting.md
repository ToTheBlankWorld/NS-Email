# ADR 009 — Analyst Workstation and Forensic Reporting

- **Status:** Accepted (Stage 9)
- **Date:** 2026-09-28
- **Scope:** frontend workstation, evidence graph frontend, report model, JSON/HTML/PDF report endpoints, report center

## Context

Stages 1-8 produce structured, persisted evidence: captures, sessions, TLS
and certificate evidence, deterministic findings, explainable posture,
behavioral anomalies, the forensic evidence graph, and validated AI
observations. Stage 9 turns these into a cohesive analyst workstation and
adds deterministic forensic reporting. It is an integration, frontend, and
reporting stage: no new ML, no new AI subsystem, and no changes to the
policy engine, posture formula, anomaly semantics, graph semantics, or AI
grounding semantics.

## Architecture

1. **Analyst shell** — the existing Next.js application shell (sidebar,
   top bar, backend health) now exposes the full navigation: Dashboard,
   Captures, Sessions, Findings, Anomalies, Evidence Graph, and Reports.
   Capture-scoped workspaces share a capture selector; selection is
   propagated via the `?capture=` query parameter so views are
   deep-linkable.

2. **Evidence graph frontend** — React Flow (`@xyflow/react`, the single
   graph library added) renders the Stage 7 graph from
   `GET /api/captures/{id}/graph`. A deterministic layered layout
   (BFS depth from the capture node, category- and id-sorted within
   layers) guarantees the same graph never jumps between renders.
   The full graph is downloaded once per page session and cached
   client-side; session workspaces render a client-side neighborhood
   extraction instead of re-downloading. Node/edge inspection, type
   filters, focus, fit, and reset are provided; node categories carry a
   legend and a stable color plus text label.

3. **Report model** — `report_builder.py` assembles a versioned
   (`report.schema_version = 1.0`) document exclusively from persisted
   evidence. Determinism: identical evidence produces byte-identical
   output; the report id is derived from the capture id and
   `generated_at` mirrors the analysis completion time, never wall clock.

4. **Report rendering** — three renderers consume the same document:
   JSON (stable, sorted keys), standalone HTML (self-contained CSS,
   print-friendly, every dynamic value escaped with `html.escape`),
   and structured PDF (fpdf2; real paginated sections, not a page
   screenshot; core fonts; Latin-1 sanitization; deterministic
   /CreationDate derived from the report's `generated_at`).

5. **AI/report boundary** — reports include only validated AI responses
   from `ai_history`, clearly labeled as interpretive assistance with
   citations and uncertainties preserved. AI output can never create
   findings, modify severity, posture, anomaly scores, or evidence.
   When AI is not configured the report states "AI analyst not
   configured" and still renders completely.

6. **Pipeline completion** — the Stage 7 graph builder is now invoked
   during capture analysis and persisted via the existing
   `replace_graph` store API; previously the graph was only built in
   engine tests. Two latent Stage 7 builder bugs found by live
   verification were fixed (a stale fingerprint variable in TLS
   configuration nodes, and posture factor nodes using the wrong node
   id function). No graph semantics changed.

## Security

- No API keys, credentials, authorization data, message bodies, or raw
  payloads enter reports; automated tests assert their absence.
- All HTML report content is escaped; evidence fields (filenames,
  hostnames, certificate subjects, AI output) are untrusted data.
- The PDF renderer strips control characters and non-representable
  glyphs; no markup interpretation exists in the PDF path.
- The frontend uses no `dangerouslySetInnerHTML`; graph labels and
  metadata render as React text nodes.
- Reports are generated on demand — no report blobs are stored.

## Limitations

- No frontend unit-test framework exists in this repository; frontend
  correctness is guarded by TypeScript, ESLint, the production build,
  and the live Stage 9 smoke test.
- The PDF uses core fonts with Latin-1 coverage; non-Latin evidence
  strings are transliterated/stripped rather than rendered with
  embedded Unicode fonts.
- Graph layout is layered and deterministic rather than force-directed;
  very wide captures fold into columns to stay readable.
