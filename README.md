# NS-Email — SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

NS-Email is a passive network forensic platform that reconstructs email traffic (SMTP, IMAP,
POP3) from PCAP / PCAPNG captures and assesses how well that traffic was actually protected —
TLS versions, cipher suites, key exchange, forward secrecy, STARTTLS usage, and X.509
certificate validity — producing evidence-backed, prioritized security findings and reports.

Built for **Smart India Hackathon 2026** as an original research project on enterprise email
cryptographic posture.

> **Status: Stage 2 — TCP stream & email protocol forensics.**
> The platform ingests evidence, reconstructs TCP sessions, and identifies SMTP/IMAP/POP3
> conversations with timelines and evidence references. TLS handshake analysis, ML, and AI
> are still ahead. See [Development stages](#development-stages).

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
| 2     | TCP flow reconstruction, stream reassembly, SMTP/IMAP/POP3 session forensics | **current** |
| 3+    | STARTTLS enforcement analysis, TLS handshake reconstruction, X.509 extraction | planned |
| 4+    | Cryptographic analysis, rule-based findings                  | planned    |
| 5+    | Risk prioritization, ML anomaly analysis, evidence graph     | planned    |
| 6+    | AI-assisted explanation, reports (JSON / HTML / PDF), dashboard depth | planned |

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
