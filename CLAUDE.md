# PR Review Bot — project rules

## Git — HARD RULE
- NEVER run any git write command: no git add, git add ., git commit, git push, git pull,
  git merge, git rebase, git reset, git stash, git checkout, git switch, git restore,
  git rm, git mv, git tag, or anything else that changes repo state or history.
  Sam stages, commits and pushes everything herself.
- Read-only git (git status, git diff, git log) is fine.
- At the end of EVERY task, hand back:
  1. The list of files created / modified / deleted
  2. One commit message in Conventional Commits style. Plain message only —
     NO Co-Authored-By, Claude-Session or any other trailer.

## Secrets
- Never read, print or edit .env or any .pem file. Document variables in .env.example.
- Never hardcode or log secrets, tokens, keys or full diffs.

## Stack
- Python 3.12, FastAPI, uvicorn, httpx (async), PyJWT[crypto], pydantic-settings,
  SQLAlchemy 2.0 async (asyncpg for Postgres, aiosqlite for tests),
  pytest + pytest-asyncio + respx, ruff.
- Call the GitHub API and LLM API directly with httpx — no PyGithub, githubkit or LLM SDKs.
- No new dependencies without asking.
- Dev machine: Windows 11, PowerShell. Give all commands in PowerShell syntax. Venv is .venv.

## Conventions
- Tests never hit the network or a live DB: mock HTTP with respx, use SQLite for DB tests.
- Type hints everywhere, small focused modules.
- Before calling a task done: run `ruff check .` and `pytest` and report the results.

## Architecture (keep to this)
app/main.py          FastAPI app, /health, /webhook
app/config.py        settings
app/webhooks.py      signature verification, event filtering
app/github_client.py GitHub App auth + API calls
app/jobs.py          job table worker loop, retries, idempotency
app/db.py            engine, tables
app/comment.py       renders the PR comment
app/analysis/rules.py, secrets.py, summarizer.py
- The webhook handler ONLY verifies → filters → records a job → returns 202.
  All slow work (GitHub API, LLM) happens in the background worker.