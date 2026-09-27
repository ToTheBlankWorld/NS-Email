# Local Development Setup

Prerequisites and commands for running, testing, and validating NS-Email locally.

## Prerequisites

| Tool             | Version     | Required for        | Notes                                            |
| ---------------- | ----------- | ------------------- | ------------------------------------------------ |
| Python           | 3.12+       | backend, engine     | https://www.python.org/downloads/                |
| Node.js          | 20+         | frontend            | npm 10+ ships with it                            |
| Git              | any recent  | everything          |                                                  |
| tshark (Wireshark) | 4.x       | packet-analysis stages only | **Not required for Stage 0.** Install with the packet-analysis stages (Wireshark installer includes it). On Debian/Ubuntu: `sudo apt install tshark`. |

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

| Variable                 | Default                  | Purpose                          |
| ------------------------ | ------------------------ | -------------------------------- |
| `NS_EMAIL_CORS_ORIGINS`  | `http://localhost:3000`  | Comma-separated CORS allow-list  |

Copy `.env.example` for a template of supported variables. Stage 0 reads plain environment
variables only (no automatic `.env` loading); export them in your shell when overriding.

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
