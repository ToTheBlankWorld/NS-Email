# Local Development Setup

Prerequisites and commands for running, testing, and validating NS-Email locally.

## Prerequisites

| Tool             | Version     | Required for        | Notes                                            |
| ---------------- | ----------- | ------------------- | ------------------------------------------------ |
| Python           | 3.12+       | backend, engine     | https://www.python.org/downloads/                |
| Node.js          | 20+         | frontend            | npm 10+ ships with it                            |
| Git              | any recent  | everything          |                                                  |
| tshark (Wireshark) | 4.x       | packet metadata extraction | **Optional in Stage 1.** Without it, captures are still validated, hashed, and registered (status `registered`), but no packet metadata is extracted. Install Wireshark (includes tshark) or on Debian/Ubuntu: `sudo apt install tshark`. Set `NS_EMAIL_TSHARK_PATH` if tshark is not on `PATH`. |

`make` targets exist for POSIX environments (Linux, macOS, WSL). On Windows, run the plain
commands below directly.

## Backend (Python 3.12+)

From the repository root:

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate            # POSIX (Git Bash / WSL / macOS / Linux)
# .venv\Scripts\Activate.ps1         # Windows PowerShell
# .venv\Scripts\activate.bat         # Windows cmd

# 2. Install the backend + engine with development tools
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The editable install exposes the `app` (backend) and `engine` packages on `sys.path`.

### Run the API

```bash
uvicorn app.main:app --reload --port 8000
```

- Health check: http://127.0.0.1:8000/health
- Interactive API docs: http://127.0.0.1:8000/docs

### Environment variables

| Variable                     | Default                  | Purpose                                             |
| ---------------------------- | ------------------------ | --------------------------------------------------- |
| `NS_EMAIL_CORS_ORIGINS`      | `http://localhost:3000`  | Comma-separated CORS allow-list                     |
| `NS_EMAIL_CAPTURE_STORAGE`   | `data/captures`          | Capture evidence, registry, and staging root        |
| `NS_EMAIL_MAX_CAPTURE_BYTES` | `2147483648` (2 GiB)     | Upload size limit (capped by the engine ceiling)    |
| `NS_EMAIL_TSHARK_PATH`       | — (uses `PATH` lookup)   | Explicit tshark binary path for packet inspection   |

Copy `.env.example` for a template of supported variables. Stage 1 reads plain environment
variables only (no automatic `.env` loading); export them in your shell when overriding.

### Capture ingestion (Stage 1)

```bash
# Ingest a capture from the command line
curl -F "file=@sample.pcap" http://127.0.0.1:8000/api/captures

# List registered captures / fetch one
curl http://127.0.0.1:8000/api/captures
curl http://127.0.0.1:8000/api/captures/<capture_id>

# Analyze a capture and list reconstructed sessions (Stage 2)
curl -X POST http://127.0.0.1:8000/api/captures/<capture_id>/analyze
curl http://127.0.0.1:8000/api/captures/<capture_id>/sessions
curl http://127.0.0.1:8000/api/sessions/<session_id>
```

Session analysis runs on a pure-Python packet reader (Ethernet/raw-IP,
IPv4/TCP) and works without tshark. Captures with gaps, reordering, or
retransmissions report them honestly; credentials found in plaintext are
redacted before storage.

Stage 4 adds deterministic findings to every analysis run. Findings are
available per capture and per session:

```bash
curl http://127.0.0.1:8000/api/captures/<capture_id>/findings
curl http://127.0.0.1:8000/api/sessions/<session_id>/findings
curl http://127.0.0.1:8000/api/findings/<finding_id>
```

Findings are produced by the versioned built-in baseline
(`securemailscope-baseline` v1.0, shipped at
`engine/detection/data/`). To evaluate against a custom policy, point
`NS_EMAIL_POLICY_FILE` at a JSON document that validates against the
typed policy models in `engine/detection/policy.py` — policy files are
parsed as structured data only (no code execution).

Each analysis also produces an explainable security posture snapshot
(Stage 5):

```bash
curl http://127.0.0.1:8000/api/captures/<capture_id>/posture
curl http://127.0.0.1:8000/api/captures/<capture_id>/posture/protocols
curl http://127.0.0.1:8000/api/captures/<capture_id>/priorities
curl http://127.0.0.1:8000/api/captures/<capture_id>/hosts
curl http://127.0.0.1:8000/api/captures/<capture_id>/hosts/<host_id>
```

Behavioral anomaly results (Stage 6) are generated during each analysis run:

```bash
curl http://127.0.0.1:8000/api/captures/<capture_id>/anomalies
curl http://127.0.0.1:8000/api/sessions/<session_id>/anomaly
curl http://127.0.0.1:8000/api/captures/<capture_id>/anomaly-summary
```

Anomalies use an unsupervised IsolationForest trained on the capture's own sessions.
Processing is local — no data is sent to external services. Sessions below the minimum
baseline size report `insufficient_evidence`.

The posture score is a SecureMailScope-defined analytical metric: base
100 minus factor deductions (severity weight x confidence multiplier x
prevalence multiplier, correlated within five posture factors). The full
formula and rationale are documented in
`docs/decisions/005-security-posture-model.md` and exposed in the UI
under "How is this calculated?".

Evidence identity is the SHA-256 of the bytes: re-uploading the same capture returns the
existing registration (`duplicate: true`). Evidence files live under
`NS_EMAIL_CAPTURE_STORAGE/<capture_id>/evidence.<format>` — never under the upload
filename. Without tshark, captures register with `status: "registered"` and explicit
`null` packet metadata; with tshark they become `status: "ready"` with packet count,
capture time range, duration, and link type.

## Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev
```

The UI is served at http://localhost:3000. It detects the backend via
`NEXT_PUBLIC_API_BASE_URL` (default `http://localhost:8000`) and shows a live backend status
indicator.

## Testing

```bash
# Backend + engine tests (from the repo root, venv active)
python -m pytest

# A single test file
python -m pytest engine/tests/test_capture.py
```

`pytest` discovers both `backend/tests` and `engine/tests` via `pyproject.toml`.

## Linting, formatting, and type checking

```bash
python -m ruff check backend engine     # lint
python -m ruff format backend engine    # format
python -m ruff check --fix backend engine
python -m mypy                          # strict type check (backend/app + engine/core)
```

Ruff enforces a security-aware rule set (including flake8-bandit) configured in
`pyproject.toml`.

## Frontend validation

```bash
cd frontend
npm run lint        # ESLint
npm run typecheck   # tsc --noEmit
npm run build       # production build (includes type checking)
```

## Full validation sweep

POSIX (make):

```bash
make check    # test + lint + typecheck + frontend build
```

Windows (manual):

```bash
python -m pytest
python -m ruff check backend engine
python -m mypy
cd frontend && npm run build
```


## AI Analyst (Stage 8)

The AI forensic analyst consumes structured investigation context (never raw
evidence) and produces explainable responses with citations. Provider configuration:

| Variable | Default | Purpose |
| --- | --- | --- |
| `NS_EMAIL_AI_PROVIDER` | *(empty = disabled)* | `mock`, `openai`, or `ollama` |
| `NS_EMAIL_AI_MODEL` | *(empty)* | Model identifier |
| `NS_EMAIL_AI_BASE_URL` | *(empty)* | API base URL (e.g. `http://localhost:11434`) |
| `NS_EMAIL_AI_API_KEY` | *(empty)* | API key (never sent to the frontend) |

```bash
# Ask the AI analyst about a session
curl -X POST http://127.0.0.1:8000/api/ai/query   -H "Content-Type: application/json"   -d '{"question": "Explain this session", "session_id": "session_..."}'

# Check AI status
curl http://127.0.0.1:8000/api/ai/status
```

Without a provider configured, the AI status reports `not_configured` and queries
return a structured error. No data is sent to external services unless explicitly
configured. All AI responses are validated against the supplied evidence before
being returned.
