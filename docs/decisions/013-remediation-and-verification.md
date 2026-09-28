# ADR 013 — Remediation Workflow and Evidence-Based Verification

- **Status:** Accepted (Stage 13)
- **Date:** 2026-09-28
- **Scope:** remediation domain model, state machine, analyst
  ownership, remediation timeline, verification engine, before/after
  comparison, posture quoting, remediation API, finding/case
  integration, report/export integration (schema 1.2), remediation
  evaluation, demo, workspace UI

## Context

Stages 1-12 answer what was observed and what it means. Operators
additionally need to track what was DONE about a finding and whether
later evidence shows improvement — without rewriting history. Stage 13
adds that workflow layer around immutable findings.

## Decisions

1. **Three separate concepts.** Historical evidence (findings,
   sessions, posture — immutable), remediation state (analyst plans,
   statuses, owners — mutable workflow), verification evidence
   (comparisons quoting later captures — append-only). A finding's
   severity, confidence, rule, evidence, timestamp, and session are
   never touched by the workflow; verification creates new records.

2. **Policy guidance, never LLM invention.** Remediation records
   created from a finding preserve the Stage 4 recommendation
   verbatim, prefixed as "Recommended action from SecureMailScope
   policy baseline" with an explicit source flag (`policy` vs
   `analyst`). No language model generates security advice.

3. **Explicit state machine.** OPEN → PLANNED → IN_PROGRESS →
   COMPLETED, IN_PROGRESS ↔ BLOCKED, anything → CANCELLED;
   COMPLETED/CANCELLED are terminal with history retained.
   Nonsensical transitions are rejected with the allowed set.
   Ownership is free-form workflow text (no auth, no identity
   inference, length- and control-character validated).

4. **Own remediation timeline, insertion-ordered.** The Stage 11
   lesson (rowid ordering on coarse Windows clocks) is reused:
   remediation events read back in append order. Case notes can
   target remediations and feed the remediation timeline via a
   `note_added` hook.

5. **Two verification kinds, honestly labeled.** Evidence-based:
   deterministic engine comparison of the original rule against an
   explicitly selected, attached, analyzed verification capture.
   Manual: analyst notes only, recorded as `analyst_asserted` —
   either immediately (notes supplied) or via PENDING →
   notes-supplied completion. There is no "mark verified" click that
   bypasses evidence or notes.

6. **Conservative comparison semantics.** Session-scoped findings
   match candidate sessions by protocol + server endpoint; no
   candidate (or incomplete baseline evidence) → INCONCLUSIVE, never
   a false VERIFIED. Rule presence is scoped to matched sessions so
   unrelated sessions neither clear nor condemn. Capture-level
   findings compare rule presence directly. Statements name the rule
   and capture ("Rule X was not observed in verification capture C");
   "absent" is never equated with "globally secure".

7. **Posture is quoted, not recomputed.** Both snapshots come from
   the Stage 5 model; only the arithmetic difference is shown, with
   neutral wording ("produced a score N points higher") and an
   explicit no-causality note. No new formula, no remediation score.

8. **Schema 1.2, compatible import.** Reports gain `remediation` and
   `verification` sections; exports gain `remediations`,
   `remediation_timeline`, `verification_results`; digests cover the
   new state. Import accepts 1.0/1.1/1.2, revalidates remediation
   plans, resets verification state (results reference captures that
   may differ locally), and discards imported timelines/histories
   with warnings.

9. **AI stays out of verification.** No new AI surface: existing
   session questions already cover "explain this finding". AI output
   can never mark verified, change verification state, or appear as
   verification evidence (asserted by test: AI history carries no
   verification records).

10. **Prerequisite: none beyond prior stages.** Unlike Stage 12's
    store fix, no evidence-layer change was needed.

## Security considerations

- Remediation/workflow text (titles, owners, notes, actions) is
  length-capped, control-character screened, and escaped in HTML /
  sanitized in PDF; oversized, traversal-shaped, and injection-
  shaped inputs are covered by regression tests.
- Remediation/verification/case ids are regex-validated at the path
  layer; cross-case references never resolve; error responses keep
  the structured shape with no internals.
- Verification captures must be attached and analyzed; unanalyzed,
  foreign, and missing captures are rejected with structured errors.
- Import caps and shape validation apply to remediation sections;
  verification state never transfers between cases.

## Limitations

- Session matching is endpoint + protocol identity: NAT, load
  balancers, or re-addressed infrastructure can legitimately yield
  INCONCLUSIVE — that is the honest answer, not a failure.
- Certificate-validity comparison reads validity at session
  observation time; authoritative validity verdicts remain the
  Stage 4 findings.
- Verification compares one rule per remediation; multi-rule
  remediation plans verify rule by rule.
- A finding describes historical observed evidence; a remediation
  describes analyst workflow; a verification result describes
  evidence observed in a later capture. Technical verification is
  not a legal or compliance certification.
