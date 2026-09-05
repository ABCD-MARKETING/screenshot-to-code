# Project Agent Instructions

Python environment:

- Always use the backend Poetry virtualenv (`backend-py3.10`) for Python commands.
- Preferred invocation: `cd backend && poetry run <command>`.
- If you need to activate directly, use Poetry to discover it in the current environment:
  - `cd backend && poetry env activate` (then run the `source .../bin/activate` command it prints)

Testing policy:

- Always run backend tests after every code change: `cd backend && poetry run pytest`.
- Always run type checking after every code change: `cd backend && poetry run pyright`.
- Type checking policy: no new warnings in changed files (`pyright`).

## Frontend

- Frontend: `cd frontend && pnpm lint`

If changes touch both, run both sets.

## Prompt formatting

- Prefer triple-quoted strings (`"""..."""`) for multi-line prompt text.
- For interpolated multi-line prompts, prefer a single triple-quoted f-string over concatenated string fragments.

# Hosted

The hosted version is on the `hosted` branch. The `hosted` branch connects to a saas backend, which is a seperate codebase at ../screenshot-to-code-saas

## Cursor Cloud specific instructions

Dependencies are refreshed automatically on startup (`poetry install` in `backend/`, `pnpm install` in `frontend/`); no manual install is needed.
Cursor Cloud environment setup should run `bash /agent/repos/screenshot-to-code/scripts/cursor-cloud-install.sh`; the script changes to the repo root before installing so it works regardless of the startup working directory.

Services (see `README.md` for the canonical commands):
- Backend (FastAPI + WebSocket): from `backend/`, `poetry run uvicorn main:app --reload --port 7001`.
- Frontend (Vite/React): from `frontend/`, `pnpm dev` → open `http://localhost:5173`. The Vite dev server binds to `localhost` only, so use `http://localhost:5173`, not `http://127.0.0.1:5173` (the latter refuses the connection).
- Frontend talks to the backend over a WebSocket (`VITE_WS_BACKEND_URL`, default `ws://127.0.0.1:7001`); generation streams over that socket, other routes are plain HTTP.

Non-obvious caveats:
- `poetry` is installed under `~/.local/bin` and is on PATH for interactive shells (`.bashrc`) but not necessarily for non-interactive scripts; use the full path `~/.local/bin/poetry` if `poetry` is not found.
- The Poetry virtualenv resolves to Python 3.12 (named like `backend-...-py3.12`), not 3.10 — `pyproject.toml` pins `^3.10`, which 3.12 satisfies. Just use `poetry run`.
- Core feature (screenshot → code) requires at least one LLM key: set `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GEMINI_API_KEY` in `backend/.env` (restart backend after editing) or in the in-app Settings dialog. Without a key, generation fails fast with a "No OpenAI, Anthropic, or Gemini API key" message. `REPLICATE_API_KEY` (image gen/edit) only works via `backend/.env`, not the UI.
- Playwright Chromium is pre-installed for the optional "Screenshot preview" tool; Settings shows it as "Available".
- `pnpm install` prints an "Ignored build scripts (esbuild, puppeteer)" warning — this is harmless; Vite build/dev and tests work without approving builds.
- `cd frontend && pnpm lint` currently reports pre-existing errors (e.g. `@typescript-eslint/no-explicit-any` in `generateCode.ts`) because lint runs with `--max-warnings 0`; these are baseline issues, not environment problems.

---

<!-- universal-completeness:begin (vendored from essman929/AI-MEMORY templates/universal-completeness-repo-kit — edit there, re-run install.py) -->
## Global rule: Universal Product Completeness & System Integration Protocol (2026-09-05)

**Applies to every development request in this repo, every session, every prompt.** A
request names one part of a larger system. Never change only the thing named.

Before any meaningful change run: **UNDERSTAND → LOCATE → SCAN → MAP → DESIGN →
IMPLEMENT → CONNECT → VERIFY → SEARCH AGAIN → AUDIT → REPORT.**

- **Four levels, never stop at 1:** User goal → full Workflow → System (pages, DB,
  APIs, automations, permissions, AI, notifications, reports) → Architecture.
- **Scan the whole repo first** (grep references, imports, schema, queries,
  endpoints, consumers, webhooks, jobs, prompts, agents, config, env, permissions,
  analytics, notifications, docs, tests, flags). Inspect DB schema and API
  contracts when available. Search again after building.
- **Change Impact Map** across frontend · backend · database · APIs · automations ·
  AI · business logic · analytics · security · tests.
- **Classify gaps P0 / P1 / P2.** Build P0 + safe P1. No speculative P2.
- **Connect every layer:** UI → API → backend → DB → result → UI; automations,
  AI prompts/agents, permissions (enforced on the backend), analytics, integrations.
- **Complete the entity:** CRUD + states (loading/empty/error/…) + forms +
  tables + permissions + cross-module links, sized to what the entity needs.
- **Single source of truth** over duplicated logic/config. Search before any
  rename/remove. Name architectural problems instead of building on them.
- **Done = user can operate the full workflow end to end**, verified with the
  repo's own checks and a real user-flow test. Visual ≠ functional.
- **Report:** changed · connected · dependencies found · extras · intentionally
  skipped · risks · P2 recs · workflow verified?

Operating copy: `.claude/skills/universal-completeness/SKILL.md`. Canonical text
(43 sections): `essman929/AI-MEMORY` → `memory/UNIVERSAL-COMPLETENESS-PROTOCOL.md`.
Per-prompt reminder: `.claude/hooks/universal-completeness.sh` (UserPromptSubmit).
Repo-specific rules above win on conventions (branch, deploy, DB access); this
protocol wins on completeness.
<!-- universal-completeness:end -->
