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

The analysis core. Stage 0 established `engine/core`, the typed evidence model layer;
Stage 1 adds `engine/ingestion`, the evidence-acquisition layer.

| Model / module         | Purpose                                                            |
| ---------------------- | ------------------------------------------------------------------ |
| `Capture`              | An ingested PCAP/PCAPNG file (metadata, SHA-256, size, format, packet metadata, status) |
| `CaptureFormat` / `CaptureStatus` | Container taxonomy and acquisition lifecycle (`registered` / `ready`) |
| `Session`              | A reconstructed TCP session carrying email traffic (Stage 2+)       |
| `EmailProtocol`        | SMTP / IMAP / POP3 taxonomy with port heuristics                    |
| `TLSHandshake`         | Observed TLS parameters (version, cipher suite, key exchange, SNI)  |
| `CertificateEvidence`  | X.509 facts observed on the wire (subject, validity, key, fingerprint) |
| `SecurityFinding`      | A rule- or analysis-derived observation with severity and category  |
| `engine.ingestion`     | Filename validation, magic-byte sniffing, streaming hashing, deterministic ids, capture inspection |

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

Exposes the platform to the frontend.

- `GET /health` — liveness payload (`Stage 0`).
- `POST /api/captures` — multipart capture ingestion: validate → stream-hash → store →
  inspect → register. Duplicates (same SHA-256) return the existing registration with
  `duplicate: true`.
- `GET /api/captures` — registered captures.
- `GET /api/captures/{capture_id}` — one capture; ids are hash-derived and regex-checked,
  so a capture id can never address the filesystem.

Errors are structured and stable: `{"error": {"code", "message"}}` with codes
`invalid_capture_type` (400), `capture_too_large` (413), `invalid_capture` (422),
`capture_not_found` (404), `capture_storage_error` / `internal_error` (500). Raw
tracebacks and internal paths never reach clients. CORS remains an explicit allow-list
(`NS_EMAIL_CORS_ORIGINS`).

### Capture ingestion flow (Stage 1)

```
upload (multipart)
  ↓  display-filename validation (extension allow-list, path components rejected)
staging file inside the storage root        ← single streaming pass:
  ↓                                            SHA-256 + size limit + magic sniff
deterministic id  capture_<sha256[:12]>
  ↓  duplicate check by SHA-256 → existing capture returned (duplicate: true)
atomic move to  <storage>/<id>/evidence.<format>   + metadata.json
  ↓  CaptureInspector (tshark when available)
SQLite registry (storage root/registry.sqlite3)
  ↓
API response: status ready | registered, packet metadata or explicit nulls
```

Storage layout:

```
<NS_EMAIL_CAPTURE_STORAGE>/
├── .staging/                transient uploads, cleaned after use
├── registry.sqlite3         capture registry (single-process SQLite)
└── <capture-id>/
    ├── evidence.pcap|pcapng
    └── metadata.json
```

### `frontend/` — workstation UI (Next.js)

Dark-first, restrained forensic/SOC design language. Stage 0 shipped the shell; Stage 1
adds real ingestion: the dashboard capture panel uploads with honest progress (bytes
transferred → "validating and registering evidence…"), shows the evidence SHA-256 and
inspection state, and `/captures` plus `/captures/<id>` provide the evidence list and
detail views. No fake statistics, findings, or AI output.

## Planned data flow

The first stage of the pipeline is implemented; the rest is future work, nothing below
the ingestion stage is built yet.

```
PCAP / PCAPNG
      ↓  ingestion + validation (magic bytes, size limits, temp dirs)   ← Stage 1 (implemented)
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
- **Filenames are display metadata only** — validated against path components and never
  used for filesystem access; evidence is stored under the hash-derived capture id as
  `<id>/evidence.<format>`.
- **Size limits are enforced twice**: during the streaming copy (configurable via
  `NS_EMAIL_MAX_CAPTURE_BYTES`, aborting early) and as an absolute ceiling in the
  `Capture` model (2 GiB).
- **Staged writes are atomic**: uploads land in `<storage>/.staging/` and move into place
  with `os.replace`; capture ids are regex-validated and re-checked against the storage
  root before any path join.
- **Subprocess use is argument-array only**: tshark is launched with fixed argv (path
  derived internally, `-n` disables name resolution, stdin closed, watchdog timeout) —
  never a shell string, never a user-controlled value.
- **CORS is allow-listed**, not wildcarded.
- **No secrets in source.** Configuration that varies per environment comes from environment
  variables (see `docs/development/SETUP.md`).

## Environment variables

| Variable                   | Default                 | Purpose                                        |
| -------------------------- | ----------------------- | ---------------------------------------------- |
| `NS_EMAIL_CORS_ORIGINS`    | `http://localhost:3000` | Comma-separated CORS allow-list                |
| `NS_EMAIL_CAPTURE_STORAGE` | `data/captures`         | Capture evidence + registry root               |
| `NS_EMAIL_MAX_CAPTURE_BYTES` | `2147483648` (2 GiB)  | Upload size limit (capped by the engine ceiling) |
| `NS_EMAIL_TSHARK_PATH`     | —                       | Explicit tshark binary path (else `PATH` lookup) |

## Repository layout

```
NS-Email/
├── backend/
│   ├── app/            FastAPI service (routers, services, storage, registry)
│   └── tests/          API, storage, registry, and security tests
├── engine/
│   ├── core/           typed evidence models (Stage 0)
│   ├── ingestion/      capture validation, hashing, storage ids, inspection (Stage 1)
│   ├── protocols/      SMTP/IMAP/POP3 identification (planned)
│   ├── transport/      TCP stream reconstruction (planned)
│   ├── crypto/         TLS/X.509 reconstruction & analysis (planned)
│   ├── detection/      rule-based findings (planned)
│   ├── intelligence/   ML anomaly analysis (planned)
│   └── tests/          engine tests
├── frontend/           Next.js workstation UI
└── docs/
    ├── architecture/   this document
    ├── decisions/      architecture decision records (001: capture ingestion)
    └── development/    setup and workflow guides
```

Planned engine subpackages are not created until the stage that fills them — no empty
scaffolding.
