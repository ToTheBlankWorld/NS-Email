# Architecture

NS-Email (SecureMailScope) is a passive network forensic platform that assesses the
cryptographic security posture of email communications (SMTP, IMAP, POP3) from PCAP/PCAPNG
captures. This document describes the system boundaries, the current component
responsibilities, and the planned data flow.

## System boundaries

NS-Email is a single-process monorepo with three deployable surfaces and one storage layer:

```
┌──────────────────────────────────────────────────────────────┐
│                        Browser (analyst)                     │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTPS / JSON
┌───────────────────────────▼──────────────────────────────────┐
│ frontend/ — Next.js workstation UI                           │
│  • dashboard, navigation, empty states (Stage 0)             │
│  • visualization, evidence exploration, reports (planned)    │
└───────────────────────────┬──────────────────────────────────┘
                            │ REST (JSON) — CORS allow-listed
┌───────────────────────────▼──────────────────────────────────┐
│ backend/app — FastAPI service                                │
│  • health/system endpoints (Stage 0)                         │
│  • capture ingestion surface (planned)                       │
│  • analysis & report surface (planned)                       │
└───────────────────────────┬──────────────────────────────────┘
                            │ in-process imports (no network hop)
┌───────────────────────────▼──────────────────────────────────┐
│ engine/ — forensic analysis library (pure Python)            │
│  • core: typed evidence models (Stage 0)                     │
│  • ingestion, protocols, transport, crypto, detection,       │
│    intelligence (planned stages)                             │
└───────────────────────────┬──────────────────────────────────┘
┌───────────────────────────▼──────────────────────────────────┐
│ SQLite — evidence store (planned; JSON-serializable records) │
└──────────────────────────────────────────────────────────────┘
```

Deliberate constraints:

- **No microservices, message queues, or distributed workers.** The engine is an in-process
  library behind the API. This keeps the platform trivial to run locally and to demo; the
  module boundaries keep it extensible if scale ever demands more.
- **The engine never talks HTTP.** It is a pure analysis library the backend calls directly.
- **SQLite first.** PostgreSQL is deferred until a real requirement appears.

## Components

### `engine/` — forensic engine (Python)

The analysis core. Stage 0 establishes `engine/core`, the typed evidence model layer:

| Model                 | Purpose                                                            |
| --------------------- | ------------------------------------------------------------------ |
| `Capture`             | An ingested PCAP/PCAPNG file (metadata, SHA-256, size, format)      |
| `Session`             | A reconstructed TCP session carrying email traffic                  |
| `EmailProtocol`       | SMTP / IMAP / POP3 taxonomy with port heuristics                    |
| `TLSHandshake`        | Observed TLS parameters (version, cipher suite, key exchange, SNI)  |
| `CertificateEvidence` | X.509 facts observed on the wire (subject, validity, key, fingerprint) |
| `SecurityFinding`     | A rule- or analysis-derived observation with severity and category  |

Cross-cutting guarantees enforced by `engine/core/base.py`:

- **Immutable** — evidence is frozen once recorded.
- **Closed** — unknown fields are rejected, so malformed input cannot inject attributes.
- **JSON-serializable** — every model round-trips through JSON, the canonical persistence and
  exchange format.
- **Honest tri-state semantics** — reconstruction fields use `None` for "not yet determined",
  distinct from a definite `False`.

Verdicts (trust, expiry, weakness, anomaly) are never stored on evidence models; they are
produced by later analysis stages and recorded as `SecurityFinding` objects that reference
the evidence they derive from.

### `backend/app/` — API service (FastAPI)

Exposes the platform to the frontend. Stage 0 ships `GET /health` plus an explicit CORS
allow-list (default `http://localhost:3000`, overridable via `NS_EMAIL_CORS_ORIGINS`).
Ingestion and analysis endpoints arrive with their engine stages.

### `frontend/` — workstation UI (Next.js)

Dark-first, restrained forensic/SOC design language. Stage 0 ships the application shell
(sidebar, top bar with live backend status, system status area) and honest empty states
(capture upload, recent cases). No fake statistics, findings, or AI output — the shell
reflects exactly what the backend can do today.

## Planned data flow

Each arrow is a future stage; nothing below is implemented yet.

```
PCAP / PCAPNG
      ↓  ingestion + validation (magic bytes, size limits, temp dirs)
Capture
      ↓  protocol identification
      ↓  TCP stream reconstruction
      ↓  email session reconstruction
Session[]
      ↓  STARTTLS detection · TLS handshake reconstruction
TLSHandshake[] · CertificateEvidence[]
      ↓  cryptographic analysis · rule-based detection
SecurityFinding[]
      ↓  ML anomaly analysis · risk prioritization
      ↓  evidence graph (relationships between sessions, handshakes, findings)
      ↓  AI-assisted explanation (human-readable, evidence-cited)
      ↓  reports: JSON / HTML / PDF
Dashboard
```

## Security boundaries

- **Captures are untrusted input.** Parsing is read-only; extracted content is data, never
  code. No `eval`/`exec` on packet-derived data.
- **Filenames are display metadata only** — validated against path components and never used
  for filesystem access; size limits are enforced at the model layer (`MAX_CAPTURE_SIZE_BYTES`)
  and will be enforced at the ingestion boundary.
- **File processing will use temporary directories** with controlled cleanup; the API never
  exposes arbitrary filesystem access.
- **Subprocess use (tshark) must be argument-array based** with explicit executable paths —
  never shell strings built from user input.
- **CORS is allow-listed**, not wildcarded; only `GET` is exposed in Stage 0.
- **No secrets in source.** Configuration that varies per environment comes from environment
  variables (see `docs/development/SETUP.md`).

## Repository layout

```
NS-Email/
├── backend/
│   ├── app/            FastAPI service (routers, config)
│   └── tests/          API tests
├── engine/
│   ├── core/           evidence models (Stage 0)
│   ├── ingestion/      capture ingestion & validation (planned)
│   ├── protocols/      SMTP/IMAP/POP3 identification (planned)
│   ├── transport/      TCP stream reconstruction (planned)
│   ├── crypto/         TLS/X.509 reconstruction & analysis (planned)
│   ├── detection/      rule-based findings (planned)
│   ├── intelligence/   ML anomaly analysis (planned)
│   └── tests/          engine tests
├── frontend/           Next.js workstation UI
└── docs/
    ├── architecture/   this document
    ├── development/    setup and workflow guides
    └── decisions/      architecture decision records (planned)
```

Planned engine subpackages are not created until the stage that fills them — no empty
scaffolding.
