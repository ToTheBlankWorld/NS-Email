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
Stage 1 added `engine/ingestion` (evidence acquisition); Stage 2 adds
`engine/transport` (packets, flows, reassembly) and `engine/protocols`
(detection + session reconstruction), orchestrated by `engine/analysis`.

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
| `SessionEvent` / `StarttlsObservation` | Timeline events with packet references; plaintext STARTTLS negotiation facts |
| `engine.transport`     | Packet source (pure-Python pcap/pcapng), flow grouping, stream reassembly, orientation |
| `engine.protocols`     | SMTP/IMAP/POP3 detection with evidence, session reconstruction, credential redaction |
| `engine.crypto`        | TLS record/handshake parsing, hello extensions, X.509 chain extraction (Stage 3) |
| `engine.detection`     | Versioned policy (securemailscope-baseline v1.0), 15 deterministic rules, findings evaluator, posture model (Stages 4-5) |
| `engine.ml`            | Behavioral anomaly detection: typed feature extraction, IsolationForest model (Stage 6) |
| `engine.graph`         | Forensic evidence graph: typed nodes/edges, certificate pivots, config fingerprints (Stage 7) |
| `engine.ai`            | Evidence-grounded AI analyst: provider abstraction, context builder, response validation (Stage 8) |
| `engine.analysis`      | Pipeline orchestration: packets → flows → sessions |

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

### Capture analysis flow (Stage 2)

```
registered capture
  ↓  PcapPacketSource (pure Python: pcap/pcapng, Ethernet/raw-IP, IPv4/TCP)
PacketRecord stream (skips counted per reason — coverage is explicit)
  ↓  FlowBuilder: canonical bidirectional 5-tuple
Flow[]   session_id = session_<sha256(capture_id + flow)[:16]>
  ↓  per-direction StreamAssembler (ISN-anchored reassembly)
stream bytes + gaps + retransmissions + duplicates + FIN/RST
  ↓  protocol detection (greetings + commands + ports → evidence, confidence)
  ↓  orientation (SYN → service ports → greeting; else "unknown")
  ↓  per-protocol reconstructors (SMTP/IMAP/POP3)
Session[] with event timelines (every event cites its packet numbers)
  ↓  STARTTLS boundary → TLS record parsing (Stage 3)
TLSHandshake (version · cipher suites · key exchange · extensions)
  ↓  X.509 chain extraction (cryptography-backed)
CertificateEvidence[] (chain position, fingerprints)
  ↓  policy evaluation (versioned baseline, 15 deterministic rules)  ← Stage 4 (implemented)
SecurityFinding[] (severity · confidence · evidence refs · remediation)
  ↓  SQLiteSessionStore (sessions · events · certificates · findings · analysis)
```

Security properties of this stage:

- Credential values (USER/PASS/AUTH/LOGIN/AUTHENTICATE arguments) are redacted to the
  literal `redacted` at the parser boundary — before evidence objects exist. Message body
  and multi-line data content is skipped, never stored.
- STARTTLS/STLS is recorded as advertised/requested/response-seen plus a `tls_transition`
  event; plaintext parsing stops at the boundary (the remainder is ciphertext).
- Unknown orientation, missing segments, and unparseable data are recorded as unknown or
  incomplete — never guessed.

### `frontend/` — workstation UI (Next.js)

Dark-first, restrained forensic/SOC design language. The shell (Stage 0) grew real
ingestion (Stage 1) and now analysis (Stage 2): the capture detail page offers one-click
analysis with the real session count and protocol breakdown, a sessions table, and a
session detail view with a per-event timeline and TLS-boundary section. No fake
statistics, findings, or AI output.

The first ten stages of the pipeline are implemented; the rest is future work.

```
PCAP / PCAPNG
      ↓  ingestion + validation (magic bytes, size limits, temp dirs)   ← Stage 1 (implemented)
Capture
      ↓  packet source → TCP flows → stream reassembly                  ← Stage 2 (implemented)
      ↓  protocol identification → email session reconstruction
Session[] with timelines + evidence references
      ↓  TLS record/handshake parsing → X.509 chain extraction          ← Stage 3 (implemented)
TLSHandshake[] · CertificateEvidence[]
      ↓  policy evaluation: 15 deterministic rules                      ← Stage 4 (implemented)
SecurityFinding[] with evidence refs and remediation
      ↓  cryptographic analysis · rule-based detection
SecurityFinding[]
      ↓  ML anomaly analysis · risk prioritization
      ↓  evidence graph (relationships between sessions, handshakes, findings)
      ↓  AI-assisted explanation (human-readable, evidence-cited)
      ↓  reports: JSON / HTML / PDF                                       ← Stage 9 (implemented)
Analyst workstation: dashboard · workspaces · evidence graph · report center
```

### Stage 9: analyst workstation and reporting

The frontend is a cohesive workstation: dashboard, captures, sessions,
findings, anomalies, evidence graph, and reports. The evidence graph
frontend renders the Stage 7 graph with React Flow using a deterministic
layered layout; the graph is downloaded once per session and reused.
Reports are assembled by `backend/app/services/report_builder.py` from
persisted evidence only (schema version 1.0, byte-identical per evidence
state) and rendered by three renderers into JSON, standalone HTML, and
structured PDF (fpdf2). AI observations appear only if validated and are
always labeled as interpretive assistance.

### Stage 11: forensic case management

Cases (`backend/app/case_store.py`, `backend/app/services/cases.py`,
`backend/app/routers/cases.py`) form an organizational layer above the
analysis store. The data flow is one-way: the case service READS
sessions, findings, posture snapshots, anomaly results, graph records,
and AI history, and WRITES only case metadata — case records, capture
references, analyst notes, tags, bookmarks, investigation-timeline
events, and report history. No code path runs from case metadata back
into analysis output.

```
CAPTURE → analysis (Stages 1-8, immutable) ─┐
                                            ├─→ case workspace
analyst notes/tags/bookmarks (Stage 11) ────┘        ↓
                                              reports · export · bundle
```

New tables live in the same SQLite file as the registry (`cases`,
`case_captures`, `case_notes`, `case_tags`, `case_bookmarks`,
`case_timeline`, `case_reports`); existing tables are untouched. The
frontend case workspace (`/cases`, `/cases/[caseId]`) links to existing
evidence views instead of reimplementing them. Full rationale and
boundaries: `docs/decisions/011-forensic-case-management.md`.

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
| `NS_EMAIL_CAPTURE_STORAGE` | `data/captures`         | Capture evidence, registry, and staging root   |
| `NS_EMAIL_MAX_CAPTURE_BYTES` | `2147483648` (2 GiB)  | Upload size limit (capped by the engine ceiling) |
| `NS_EMAIL_TSHARK_PATH`     | —                       | Explicit tshark binary path (else `PATH` lookup) |

CORS allows `GET`, `POST`, `PATCH`, and `DELETE` (Stage 11 case API);
origins remain an explicit allow-list.

## Repository layout

```
NS-Email/
├── backend/
│   ├── app/            FastAPI service (routers, services, storage, registry)
│   └── tests/          API, storage, registry, and security tests
├── engine/
│   ├── core/           typed evidence models (Stage 0)
│   ├── detection/      policy engine: rules, registry, evaluator, posture (Stage 4)
│   ├── ml/             behavioral anomaly detection (Stage 6)
│   ├── crypto/         TLS record/handshake parsing, X.509 extraction (Stage 3)
│   ├── ingestion/      capture validation, hashing, storage ids, inspection (Stage 1)
│   ├── transport/      packet source, flows, reassembly (Stage 2)
│   ├── protocols/      SMTP/IMAP/POP3 detection & session reconstruction (Stage 2)
│   ├── analysis.py     pipeline orchestration (Stage 2)
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
