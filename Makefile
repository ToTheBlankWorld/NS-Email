# NS-Email — development tasks.
#
# GNU make is not bundled with Windows; these targets are aimed at POSIX
# environments (Linux, macOS, WSL). On Windows, run the equivalent commands
# documented in docs/development/SETUP.md.

PYTHON ?= python3
VENV ?= .venv
VENV_PY := $(VENV)/bin/python

.PHONY: help install setup-backend setup-frontend backend frontend test lint fmt typecheck build check

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-16s %s\n", $$1, $$2}'

install: setup-backend setup-frontend ## Install backend and frontend dependencies

setup-backend: ## Create venv and install backend with dev tools
	$(PYTHON) -m venv $(VENV)
	$(VENV_PY) -m pip install --upgrade pip
	$(VENV_PY) -m pip install -e ".[dev]"

setup-frontend: ## Install frontend dependencies
	cd frontend && npm install

backend: ## Run the backend API with auto-reload
	$(VENV_PY) -m uvicorn app.main:app --reload --port 8000

frontend: ## Run the frontend dev server
	cd frontend && npm run dev

test: ## Run backend and engine tests
	$(VENV_PY) -m pytest

lint: ## Lint Python sources
	$(VENV_PY) -m ruff check backend engine

fmt: ## Format Python sources
	$(VENV_PY) -m ruff format backend engine
	$(VENV_PY) -m ruff check --fix backend engine

typecheck: ## Type-check Python sources
	$(VENV_PY) -m mypy

build: ## Production build of the frontend
	cd frontend && npm run build

check: test lint typecheck build ## Run the full validation suite
