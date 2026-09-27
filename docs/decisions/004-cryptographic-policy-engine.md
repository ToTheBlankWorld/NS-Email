# ADR 004 — Deterministic Cryptographic Policy Engine

- **Status:** Accepted (Stage 4)
- **Date:** 2026-09-27
- **Scope:** `engine/detection`, analysis pipeline integration, findings APIs, frontend

## Context

Stages 2–3 produce structured, evidence-backed facts about email sessions (protocol,
STARTTLS negotiation, TLS version, cipher suites, key exchange, certificates). Stage 4
turns those facts into deterministic security findings. The stage boundary is strict:
**every finding is the output of a versioned rule evaluating persisted evidence** — no ML,
no AI, no unexplained numeric scores, no attack attribution.

## Decisions

1. **Rules are pure functions of evidence + policy.**
   `SecurityRule.evaluate(context) → list[SecurityFinding]` with a `RuleContext` of one
   session's evidence plus the loaded policy. Rules live in `engine/detection/rules/` (one
   module per finding domain), are registered in a `RuleRegistry`, and never run inside
   routers. Evaluation is per-session: findings never merge unrelated hosts.

2. **Policy is versioned structured data.**
   The built-in baseline (`securemailscope-baseline` v1.0) ships as a JSON document parsed
   through typed pydantic models with `extra="forbid"` — a typo can never silently disable a
   control. An operator may point `NS_EMAIL_POLICY_FILE` at a custom JSON policy; it is
   parsed with the stdlib JSON parser under a hard size bound. No YAML, no code execution.

3. **Severity and confidence are separate axes.**
   Severity (INFO→CRITICAL) expresses how much the baseline disapproves of the observed
   condition; each rule documents its mapping (e.g. prohibited cipher families → critical,
   deprecated TLS 1.0/1.1 → high, static RSA key exchange → medium, self-signed → low,
   incomplete handshake → info). Confidence (unknown/low/medium/high) expresses how much we
   trust the underlying observation (full ServerHello → high; partial handshake → medium;
   no key-exchange evidence → low). They are never mixed.

4. **Unknown evidence never becomes a weakness.**
   Unknown cipher suites, unknown key-exchange mechanisms, unknown key algorithms, unknown
   signature algorithms, missing SNI/SAN, and undeterminable forward secrecy produce either
   no finding or an explicit INFO observation — never a "weak"/"critical" classification.

5. **Certificate rules evaluate against the CAPTURE timestamp.**
   Certificate validity is measured against the session's first observed packet time — not
   the analysis date. Hostname checks require both SNI and SAN evidence; otherwise nothing
   is claimed. A chain whose higher elements were not captured is recorded as an
   informational observation (passive captures rarely include roots) — never "invalid".

6. **Deterministic finding identity.**
   `finding_<sha256(rule|session|observed|condition)[:12]>` — re-analysis produces the same
   ids, duplicate findings collapse naturally, and replacement is atomic per capture.

7. **Evidence references are mandatory.**
   Findings cite structured evidence (source + packet numbers + detail): ServerHello for
   version/cipher/kx, Certificate(0) for certificate rules, SessionEvents for plaintext
   authentication. Credential values are redacted upstream and findings only reference
   redacted event shapes.

## Findings catalogue (Stage 4)

| Rule id | Trigger | Severity |
| ------- | ------- | -------- |
| `TLS-VERSION-001` | Negotiated version deprecated (SSL 2.0/3.0 → critical, TLS 1.0/1.1 → high) or below configured minimum | high/critical |
| `CIPHER-SELECTED-001` | Selected suite in a policy-unacceptable class (prohibited → critical, deprecated → medium, legacy → low) | critical/medium/low |
| `CIPHER-UNKNOWN-001` | Selected suite not in the registry | info |
| `KEYEX-001` | Prohibited key exchange (static RSA/DH/ECDH — no forward secrecy) | medium |
| `FS-001` | Forward secrecy undeterminable | info |
| `CERT-VALIDITY-001` | Certificate expired/not-yet-valid at capture time | high/medium |
| `CERT-KEY-001` | Public key below policy minimum (unknown algorithms → info) | high |
| `CERT-SIG-001` | MD5 signature → critical, SHA-1 signature → high | critical/high |
| `CERT-IDENTITY-001` | SNI/SAN mismatch with full evidence | high |
| `CERT-CHAIN-001` | Chain incomplete in capture (info) or structurally inconsistent (medium) | info/medium |
| `CERT-SELF-SIGNED-001` | Self-signed leaf per policy | low |
| `STARTTLS-001` | Advertised-not-requested / requested-not-accepted / accepted-but-no-handshake | medium |
| `AUTH-PLAINTEXT-001` | Authentication command observed outside TLS | high |
| `TLS-FAILURE-001` | TLS handshake terminated before completion | info |
| `PLAINTEXT-001` | Identified email session with no TLS at all | medium |

## Limitations (recorded honestly)

- Rule-based only: no anomaly detection, no ML, no AI-generated explanations (Stage 5+).
- No global risk score is produced in this stage.
- Trust-chain validation (root trust stores, revocation) is out of scope for passive
  capture analysis; chain findings distinguish captured-observation from validation.
- Weak-DH parameter detection is not attempted (parameters are not observable in the
  parsed evidence).
- The cipher registry covers commonly observed suites; unlisted codes classify as unknown.
