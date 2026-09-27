# ADR 006 — Behavioral Anomaly Detection

- **Status:** Accepted (Stage 6)
- **Date:** 2026-09-27
- **Scope:** `engine/ml`, analysis pipeline integration, anomaly APIs, frontend

## Context

Stages 2–5 produce deterministic, evidence-backed findings. Stage 6 adds a LOCAL,
unsupervised ML layer that identifies TLS sessions whose behavior differs significantly
from the capture-local baseline. This is behavioral anomaly detection — NOT attack
attribution, NOT a replacement for deterministic findings.

## Model choice: IsolationForest

- **Why**: unsupervised (no labeled attack data exists); isolates outliers with few
  axis splits so rare configurations score highly without attack labels; deterministic
  with fixed `random_state=42`; scikit-learn provides a mature dependency-light impl.
- **Assumptions**: features are representative; the capture-local baseline is the
  reference population; rare legitimate configurations can be flagged (false positives).
- **Limitations**: parameter-sensitive (contamination, tree count); no probabilistic
  semantics; does not generalize to captures with < minimum baseline sessions.
- **Training**: capture-local only — the model is trained on the current capture's
  sessions and discarded. No cross-capture contamination.
- **Inference**: scoring uses the same fitted model on the same feature vectors.

## Feature schema (v1.0)

19 typed features extracted from Session + TLS evidence (never from raw payloads):

| Feature | Type | Source |
|---------|------|--------|
| protocol | categorical | Session.protocol |
| server_port | numeric | Session.server_port |
| duration_seconds | numeric | Session start/end |
| packet_count | numeric | Session.packet_count |
| bytes_client_to_server | numeric | Session |
| bytes_server_to_client | numeric | Session |
| tcp_complete | categorical (0/1) | Session.complete |
| has_tls | categorical (0/1) | Session.handshake presence |
| tls_version | categorical | TLSHandshake.tls_version |
| cipher_class | categorical | cipher suite classification |
| offered_cipher_count | numeric | ClientHello |
| key_exchange | categorical | ServerHello derivation |
| extension_count | numeric | ClientHello |
| has_sni | categorical (0/1) | ClientHello SNI |
| alpn_count | numeric | ClientHello ALPN |
| certificate_count | numeric | Session.certificates |
| certificate_max_key_bits | numeric | max leaf/CA key size |
| certificate_min_validity_days | numeric | min days until expiry at capture time |
| has_implicit_tls | categorical (0/1) | Session.implicit_tls |

Categorical encoding uses fixed sorted vocabularies (persisted in the module).
Same evidence + schema version → identical feature vector.

## Protocol grouping

Sessions are grouped per protocol (SMTP/IMAP/POP3/unknown) so fundamentally different
behaviors don't dominate each other. Groups below the minimum baseline size
(default 8, configurable) report `insufficient_evidence` — no fabricated scores.

## Score normalization

`decision_function` is mapped through a logistic function (`1/(1+exp(df*20))`)
scaled to 0–100. This is monotonic and bounded: in-distribution sessions score low,
isolated sessions score high. No probabilistic semantics are claimed.

## Bands

normal (<50), unusual (≥50), anomalous (≥70), highly_anomalous (≥85).
SecureMailScope-defined descriptive labels, not industry-standard categories.

## Deviation explanations

For each feature, the observed value is compared against baseline statistics:
- numeric features: |observed − mean| / std (z-like distance)
- categorical features: 1 − (observed frequency in baseline)
Top 4 non-zero deviations are reported with actual observed values and
baseline distribution — defensible feature-distance explanations, no fake SHAP.

## Security

- Model artifacts are never loaded from API-supplied paths.
- No joblib deserialization of untrusted data (models are trained in-process and
  discarded; no model persistence to disk in Stage 6).
- Feature vectors are sanitized (NaN/Inf rejected, bounded) before training/scoring.
- Processing is fully local: no PCAP data, certificates, hostnames, or credentials
  are sent to external services.
- ML anomalies are kept separate from deterministic Stage 4 findings — they never
  merge, never influence the posture score, and never appear in the findings list.
