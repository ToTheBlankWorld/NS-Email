# ADR 010 — Production Hardening and Forensic Evaluation

- **Status:** Accepted (Stage 10)
- **Date:** 2026-09-28
- **Scope:** evaluation fixtures/harness, security regression suite, resource
  limits, observability, readiness, configuration validation, CI gates,
  deployment reproducibility, demo mode

## Context

Stages 1-9 delivered the complete forensic platform. Stage 10 hardens it
and evaluates it objectively — without adding ML models, AI agents, or
redesigning existing stages.

## Decisions

1. **Ground truth before execution.** The 15 evaluation scenarios in
   `scripts/fixtures.py` carry hand-derived expectations (exact fired
   rule IDs, severities, TLS facts, posture states, anomaly bands)
   written from the documented policy and scoring semantics before any
   run. Where an initial ground-truth entry proved to be an arithmetic
   transcription error (three posture states), the correction was made by
   re-applying the documented formula — never by copying observed output.
   All scenarios build byte-deterministic PCAPs from embedded synthetic
   keys, fixed serials, fixed validity windows, and a fixed capture
   instant, so certificate fingerprints, finding IDs, and graph node IDs
   are stable across runs.

2. **Evaluation as a first-class command.** `python -m scripts.evaluate`
   runs every scenario through the production analysis pipeline, compares
   every layer (protocol, TLS facts, findings, posture, anomalies, graph,
   report), supports `--repeat N` determinism verification, emits
   machine-readable JSON, and exits non-zero on regression.

3. **Controlled resource limits.** Existing limits (capture size,
   analysis packet guard, AI context bound, report finding cap, question
   length) were inventoried and documented. The one unbounded surface —
   evidence-graph size — gained a configurable cap
   (`NS_EMAIL_MAX_GRAPH_NODES`, default 50 000). Exceeding it keeps the
   analysis, omits the graph, and records an explicit warning; evidence
   is never silently truncated.

4. **Observability without exposure.** Analysis, report generation, and
   AI requests log structured start/complete events with safe identifiers
   (capture/session IDs, format, byte counts, durations, statuses) —
   never credentials, payloads, prompts, or provider configuration.

5. **Readiness vs. liveness.** `GET /health` remains a process liveness
   signal. `GET /ready` verifies the database probe and the storage root.
   External AI availability is deliberately excluded from readiness: the
   platform must remain fully usable without an external LLM.

6. **Fail-fast configuration.** `validate_settings` produces actionable,
   secret-free problem lists (unknown provider, missing base URL/model,
   malformed URL); `create_app` refuses to start on invalid configuration.

7. **CI quality gates.** The GitHub Actions workflow runs the backend
   tests, ruff lint/format, strict mypy, the deterministic evaluation
   suite, the offline demo verification, and the frontend
   typecheck/lint/build. CI depends only on the mock AI provider.

8. **Deployment reproducibility.** Two-container Docker deployment
   (backend + frontend) with a persistent evidence volume and a readiness
   healthcheck. No Kubernetes, no microservices, no cloud services.

9. **Demo mode.** `python -m scripts.demo` seeds all 15 synthetic
   scenarios into isolated storage, runs analysis, mock-AI queries, and
   report generation over real HTTP, and (by default) serves the
   workstation. `--run-once` provides a CI-safe verification exit.
   Demo data is clearly synthetic and never touches production storage.

## Security considerations

- Fixture key material is synthetic and test-only; it guards nothing.
- Encoded-traversal uploads are rejected after multipart decoding; nested
  traversal payloads are rejected at validation.
- Unmatched routes now flow through the structured error shape; the
  generic handler logs server-side and returns a traceback-free 500.
- Reports remain fully escaped; hostile filenames/hostnames/certificate
  fields are covered by security regression tests.

## Limitations

- Controlled synthetic evaluation does not equal real-world
  attack-detection accuracy (see `docs/evaluation/README.md`).
- No frontend unit-test framework was introduced (Stage 9 decision
  respected); CI uses typecheck/lint/build plus live smoke tests instead.
- Benchmark numbers are a local regression baseline, not performance
  claims.
