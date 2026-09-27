# ADR 005 — Explainable Security Posture Model

- **Status:** Accepted (Stage 5)
- **Date:** 2026-09-27
- **Scope:** `engine/detection/posture.py`, posture APIs, frontend posture dashboard

## Context

Stage 4 produces deterministic findings. Stage 5 aggregates them into a capture-level
posture so an analyst can answer: *why is the posture at this level, which findings
contributed, which sessions and hosts are affected, and how much evidence supports the
conclusion?*

**The posture score is a SecureMailScope-defined analytical metric.** It is not an
industry-standard rating, not a CVSS score, and not an AI/ML output. Stage 5 is entirely
deterministic; ML/AI analysis arrives in later stages.

## Scoring formula (documented, deterministic, bounded 0–100)

```
finding deduction = severity_weight x confidence_multiplier x prevalence_multiplier
  severity weights:      critical 40, high 25, medium 12, low 5, info 0
  confidence multiplier: high 1.0, medium 0.75, low 0.5, unknown 0.25
  prevalence multiplier: 0.5 + 0.5 x (affected_sessions / total_sessions)

factor deduction = max finding deduction in the factor
                   + 0.25 x (sum of remaining deductions in the factor)

overall score = round(100 - sum of factor deductions), clamped to 0-100
```

### Rationale

- **Severity weights** span a 100-point budget so that a single critical finding with full
  prevalence and high confidence consumes 40 points (high_exposure) and two independent
  ones exhaust the budget (critical_exposure). They are analytical choices, not standards.
- **Confidence multiplier** discounts uncertain evidence rather than letting a low-confidence
  finding dominate: a LOW-confidence HIGH finding deducts half as much as a HIGH-confidence
  one. Severity and confidence are never merged into one field.
- **Prevalence multiplier** raises the cost of a condition from 0.5x (single session) to
  1.5x (all sessions) — sublinear by design: one finding affecting ten packets is not ten
  times the risk of the same finding affecting one packet.
- **Correlation / breadth**: findings are mapped to five posture factors (TLS configuration,
  certificates, STARTTLS usage, authentication, handshake reliability). Inside a factor,
  the dominant condition sets the deduction and each additional distinct condition adds
  only 25% of its own — TLS 1.0 + legacy cipher + no forward secrecy describe one broken
  TLS configuration, not three independent catastrophes. Original findings are never
  deleted; the factor cites their ids.

## Posture states (SecureMailScope bands, documented)

| Score | State |
| ----- | ----- |
| ≥ 90 | healthy |
| 75–89 | acceptable |
| 60–74 | degraded |
| 40–59 | high_exposure |
| < 40 | critical_exposure |
| no sessions | insufficient_evidence |

## Other model decisions

- **Determinism**: the same evidence + policy version + analysis version produces the same
  snapshot, byte-for-byte. `generated_at` is derived from the evidence itself (the latest
  finding/session instant), not the wall clock. `analysis_version` ("0.5.0") and
  `policy_id`/`policy_version` are embedded in every snapshot; scoring semantics never
  change silently.
- **Overall confidence** is the weakest confidence among the top-3 contributing findings —
  a posture dominated by low-confidence evidence is itself labeled low confidence.
- **Host aggregation** groups sessions by server endpoint IP (evidence-only; no external
  resolution). Host ids are deterministic hashes of the endpoint (`host_<hash[:12]>`) and
  are regex-validated at the API boundary so they can never become filesystem paths.
- **Priorities** rank rule groups by `severity_weight x confidence x prevalence`, with a
  documented explanation string per entry ("high severity affecting 2/2 session(s) (100%
  prevalence)..."). Not a bare severity sort.
- **Persistence**: one `posture_snapshots` row per capture holding the full snapshot as
  JSON (factors, hosts, protocols, priorities, explanation). Re-analysis replaces it
  atomically — stale posture never survives.
- **Insufficient evidence**: zero reconstructed sessions yield
  `state=insufficient_evidence, score=null` — no fabricated score.

## Limitations

- The weights and band boundaries are analytical defaults, tunable through future policy
  versions; they are not calibrated against industry incident data.
- Prevalence is measured per capture; a capture covering one hour says nothing about a year.
- Protocol-level scores derive from the same findings (no independent protocol analysis).
- Host posture uses the server IP as the host identity; TLS-level hostname (SNI) is
  reported separately per session but does not merge captures across IPs.
