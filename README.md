# NS-Email — SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

NS-Email is a passive network forensic platform that reconstructs email traffic (SMTP, IMAP,
POP3) from PCAP / PCAPNG captures and assesses how well that traffic was actually protected —
TLS versions, cipher suites, key exchange, forward secrecy, STARTTLS usage, and X.509
certificate validity — producing evidence-backed, prioritized security findings and reports.

Built for **Smart India Hackathon 2026** as an original research project on enterprise email
cryptographic posture.

> **Status: Stage 10 — production hardening and forensic evaluation.**
> The platform now ships a complete analyst workstation: capture forensic
> dashboards, findings/anomaly workspaces, an interactive evidence graph,
> a session investigation view with the AI analyst, and deterministic
> JSON / HTML / PDF forensic reports. All Stage 1-8 semantics are unchanged.
> See [Development stages](#development-stages).

---

## The problem

Enterprises depend on email, but rarely have ground truth about how their email traffic is
protected on the wire. Misconfigurations are invisible until they are exploited:

- STARTTLS negotiated down, stripped, or offered but never enforced
- Obsolete protocol versions (SSLv3, TLS 1.0/1.1) still accepted
- Weak or non-forward-secret cipher suites
- Expired, self-signed, mismatched, or weak-key X.509 certificates
- Silent protocol downgrade behavior and anomalous TLS handshakes

Compliance scanners test *endpoints* on demand. NS-Email answers a different question:
**what actually happened to real email traffic**, reconstructed passively from captured
packets, with every conclusion tied to forensic evidence.

## Vision

A single analyst workstation that goes from raw capture to explainable report:

```
PCAP ingestion
      ↓
Protocol identification (SMTP / IMAP / POP3)
      ↓
TCP stream reconstruction
      ↓
Email session reconstruction
      ↓
STARTTLS detection
      ↓
TLS handshake reconstruction
      ↓
X.509 extraction
      ↓
Cryptographic analysis
      ↓
Rule-based findings  →  ML anomaly detection
      ↓
Risk prioritization
      ↓
Evidence graph
      ↓
AI-assisted explanation
      ↓
Dashboard  →  JSON / HTML / PDF forensic reports
```

The pipeline above is the **target architecture**. Only the foundation (highlighted below)
exists today.

## Architecture

NS-Email is a deliberate, small monorepo — one FastAPI backend, one analysis engine, one
Next.js frontend, SQLite persistence. No microservices, message queues, or distributed
workers: the system must stay easy to run locally and easy to demonstrate.

```
┌────────────────────────────┐
│ frontend/  (Next.js, TS)   │  forensic workstation UI
│  dashboard · empty states  │
└──────────┬─────────────────┘
           │ HTTPS (JSON)
┌──────────▼─────────────────┐
│ backend/app  (FastAPI)     │  REST API · ingestion surface · report surface
└──────────┬─────────────────┘
┌──────────▼─────────────────┐
│ engine/  (Python)          │  passive forensic analysis
│  core evidence models (now)│  ingestion · protocols · TLS · crypto (planned)
└──────────┬─────────────────┘
┌──────────▼─────────────────┐
│ SQLite evidence store      │  JSON-serializable forensic records
└────────────────────────────┘
```

See [docs/architecture/README.md](docs/architecture/README.md) for system boundaries and the
planned data flow, and [docs/development/SETUP.md](docs/development/SETUP.md) to run it locally.

## Technology stack

| Layer       | Now (Stage 0)                          | Planned                                        |
| ----------- | -------------------------------------- | ---------------------------------------------- |
| Backend     | Python 3.12, FastAPI, Pydantic v2, Uvicorn | —                                          |
| Engine      | Typed evidence models (Pydantic)       | tshark/PyShark/Scapy, `cryptography`, networkx |
| ML          | —                                      | numpy, pandas, scikit-learn (anomaly analysis) |
| Persistence | —                                      | SQLite (JSON-serializable evidence)            |
| Frontend    | Next.js, TypeScript, Tailwind, shadcn/ui, Lucide | Motion (purposeful, data-driven animation) |
| Tooling     | pytest, ruff, mypy                     | —                                              |

Dependencies are added only when a stage actually needs them.

## Development stages

| Stage | Scope                                                        | Status     |
| ----- | ------------------------------------------------------------ | ---------- |
| 0     | Repository foundation, backend `/health`, evidence models, frontend shell | done |
| 1     | Secure PCAP/PCAPNG evidence ingestion: validation, hashing, storage, registry, capture API | done |
| 2     | TCP flow reconstruction, stream reassembly, SMTP/IMAP/POP3 session forensics | done |
| 3     | TLS record/handshake parsing, version & cipher extraction, X.509 chain evidence | done |
| 4     | Deterministic policy engine: cryptographic security findings with evidence, severity, remediation | done |
| 5     | Explainable security posture: transparent scoring, factor/protocol/host aggregation, prioritization | done |
| 6     | TLS behavioral anomaly detection (IsolationForest over session features) | done |
| 7     | Forensic evidence graph and investigation intelligence | done |
| 8     | Evidence-grounded AI forensic analyst (LLM provider abstraction, context builder, citations) | done |
| 9     | Analyst workstation and forensic reporting (dashboards, graph frontend, JSON/HTML/PDF reports) | done |
| 10    | Production hardening: deterministic evaluation, security regressions, limits, readiness, CI, demo | **current** |
| 11+   | Future work | planned |

Each stage lands as its own reviewed, tested commit.

## Current foundation

- **Evidence ingestion (Stage 1)** — `POST /api/captures` accepts PCAP/PCAPNG uploads,
  validates them (extension allow-list + magic-byte sniffing + tshark structural check when
  available), streams a SHA-256 evidence hash, stores bytes under a deterministic
  content-derived id (`capture_<hash-prefix>`), and registers them in a SQLite registry.
  Duplicate evidence is detected by hash and deduplicated.
- **Session forensics (Stage 2)** — `POST /api/captures/{id}/analyze` reconstructs
  bidirectional TCP flows, reassembles streams (out-of-order, retransmissions, gaps, and
  termination are tracked honestly), identifies SMTP/IMAP/POP3 with explainable evidence and
  confidence, and records per-session timelines where every event cites the packets it was
  observed in. STARTTLS negotiation is detected as advertised/requested/accepted with the
  exact transition packet. Credential values are redacted before storage. Results are
  served via `GET /api/captures/{id}/sessions` and `GET /api/sessions/{id}`.
- **TLS evidence (Stage 3)** — where a session switches to TLS (STARTTLS boundary or
  implicit-TLS port), the engine parses the handshake: negotiated version, selected and
  offered cipher suites, key-exchange family, SNI and other hello extensions, and the
  visible X.509 chain (`cryptography`-backed, chain position, fingerprints). TLS 1.3
  encrypts certificates from the ServerHello onward — the evidence records that honestly
  instead of pretending otherwise.
- **Policy engine (Stage 4)** — 15 deterministic rules over the structured evidence:
  deprecated TLS versions, unacceptable cipher-suite classes, prohibited key exchange and
  missing forward secrecy, certificate validity (measured against the capture time), weak
  keys, MD5/SHA-1 signatures, hostname/SAN mismatch, chain observations, STARTTLS gaps,
  plaintext authentication, and incomplete handshakes. Each finding carries a deterministic
  id, structured evidence references with packet numbers, confidence separate from
  severity, remediation guidance, and documented standard references (e.g. RFC 8996,
  RFC 7525). Findings are served via
  `GET /api/captures/{id}/findings`, `GET /api/sessions/{id}/findings`, and
  `GET /api/findings/{id}`.
- **Security posture (Stage 5)** — every analysis produces an explainable posture
  snapshot: 0-100 score, descriptive state (healthy → critical_exposure), overall
  confidence, five correlated posture factors, per-protocol and per-host aggregation, and
  a deterministic priority ranking — each element citing the findings it derives from. The
  scoring formula (severity weights x confidence x prevalence, factor correlation) is
  documented in ADR 005 and surfaced in the UI under "How is this calculated?".
- **Behavioral anomalies (Stage 6)** — after deterministic analysis, an IsolationForest
  model trained on the capture's own sessions identifies behavioral outliers. Feature
  vectors are versioned, sanitized, and derived only from structured evidence — never
  from raw payloads. Sessions below the minimum baseline size report
  `insufficient_evidence`; model failures report `model_error`. Results are kept strictly
  separate from Stage 4 findings and the Stage 5 posture score. All processing is local.
- **AI forensic analyst (Stage 8)** — evidence-grounded AI assistant that consumes
  structured investigation context (never raw evidence) and produces explainable
  responses with observed/interpretation/uncertainty sections and evidence citations.
  Provider abstraction supports OpenAI-compatible APIs and local models (Ollama);
  a deterministic mock provider is used when no external provider is configured.
  Prompt injection defense, citation validation, and credential redaction are built in.
- **Analyst workstation and reporting (Stage 9)** — cohesive SOC-style workspace:
  capture forensic dashboards, findings and anomaly workspaces with
  filtering/sorting/deep links, an interactive evidence graph (React Flow,
  deterministic layered layout, type filters, inspection panel), a session
  investigation view (security summary, TLS, certificates, timeline, graph
  context, AI panel), a report center, and deterministic JSON / HTML / PDF
  forensic reports generated on demand from persisted evidence. Reports include
  only validated AI observations, clearly labeled, with citation and uncertainty
  preservation; every dynamic report value is escaped or sanitized.
- **Backend** — FastAPI: health, capture ingestion/retrieval, analysis APIs, structured
  error model, explicit CORS allow-list, pytest coverage.
- **Engine** — typed, immutable, JSON-serializable evidence models plus the analysis
  layers: packet source (pure-Python pcap/pcapng reader), flow grouping, stream reassembly,
  protocol detection, and per-protocol session reconstructors.
- **Frontend** — dark-first forensic workstation: capture upload, live backend status,
  one-click capture analysis with real session counts, sessions table, and a session detail
  view with a per-event timeline. No fake statistics, findings, or AI output.
- **Docs** — architecture overview, setup guide, and architecture decision records
  (`docs/decisions/001-…`, `002-…`).

## Security principles

NS-Email is a security tool, so it holds itself to the standard it assesses:

- **PCAP files are untrusted input.** Captures are parsed, never executed; extracted content
  is data, never code. No `eval`/`exec` on packet-derived data, ever.
- **Filenames and payloads are never trusted** — validated, size-limited, and processed in
  temporary directories with explicit filesystem boundaries.
- **No arbitrary filesystem access** through the API; no shell commands derived from user input.
- **Subprocess use (e.g., tshark) must be argument-array based** with explicit executables.
- **No secrets in source.** `.env` files, keys, credentials, and capture files are excluded
  from version control (see `.gitignore`).
- **Typed evidence, immutable once recorded** — forensic records reject unknown fields and
  mutation after creation.

## Local development

Prerequisites: Python 3.12+, Node.js 20+ (tshark is **not** required until the
packet-analysis stages).

```bash
# Backend
python -m venv .venv
.venv/bin/pip install -e ".[dev]"        # Windows: .venv\Scripts\pip ...
.venv/bin/uvicorn app.main:app --reload --port 8000   # → http://127.0.0.1:8000/health

# Frontend
cd frontend
npm install
npm run dev                              # → http://localhost:3000
```

Full instructions (including Windows notes): [docs/development/SETUP.md](docs/development/SETUP.md).

## License

[MIT](LICENSE) — original code, no third-party sources incorporated.
