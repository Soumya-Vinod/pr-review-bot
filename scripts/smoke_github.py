"""Dev-only smoke test for app.github_client against the real GitHub API.

Usage (PowerShell, from the repo root, with .env filled in):

    .venv\\Scripts\\python.exe scripts\\smoke_github.py <owner/repo> <pr_number>

What it does:
  1. Loads settings through app.config (GITHUB_APP_ID, private key, BOT_COMMENT_MARKER).
  2. Finds the App's installation on <owner/repo> (GET /repos/{owner}/{repo}/installation,
     authenticated with the App JWT).
  3. Fetches the PR and its files; prints the title, file count, and +/- per file.
  4. Creates or updates the bot's marked comment on the PR with a smoke-test line,
     then prints the comment id and whether it was created or updated.

It never prints tokens, keys or the webhook secret. Exit codes: 0 ok, 1 GitHub API error,
2 bad usage or configuration, 3 network error.

Note: step 4 WRITES a real comment on the PR. Use a playground repository.
"""

import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import ValidationError

# Allow `python scripts/smoke_github.py` from the repo root without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.github_client import GitHubAPIError, GitHubClient  # noqa: E402

USAGE = "usage: python scripts/smoke_github.py <owner/repo> <pr_number>"


def fail(message: str, code: int) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args(argv: list[str]) -> tuple[str, int]:
    if len(argv) != 2 or "/" not in argv[0] or not argv[1].isdigit():
        fail(USAGE, 2)
    return argv[0], int(argv[1])


async def run(repo: str, pr_number: int) -> None:
    try:
        settings = get_settings()
    except ValidationError as exc:
        # Only report which fields are wrong, never their values.
        names = ", ".join(str(err["loc"][0]).upper() for err in exc.errors() if err["loc"])
        fail(f"settings are invalid or missing: {names or exc.error_count()}", 2)

    try:
        private_key = settings.private_key_pem()
    except (OSError, ValueError) as exc:
        fail(f"could not load the GitHub App private key ({type(exc).__name__})", 2)

    async with GitHubClient(settings.github_app_id, private_key) as gh:
        installation_id = await gh.get_repo_installation(repo)
        print(f"Installation: {installation_id}")

        pr = await gh.get_pull_request(installation_id, repo, pr_number)
        files = await gh.list_pr_files(installation_id, repo, pr_number)
        print(f"PR #{pr_number}: {pr.get('title', '')}")
        print(f"Files changed: {len(files)}")
        for f in files:
            print(f"  {f.get('filename')}  +{f.get('additions', 0)} -{f.get('deletions', 0)}")

        stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        marker = settings.bot_comment_marker
        body = (
            f"{marker}\nSmoke test from pr-review-bot — {len(files)} files changed at {stamp}"
        )
        result = await gh.upsert_bot_comment(installation_id, repo, pr_number, body, marker)
        action = "created" if result.created else "updated"
        print(f"Comment {result.comment_id} {action}")


def main() -> None:
    repo, pr_number = parse_args(sys.argv[1:])
    try:
        asyncio.run(run(repo, pr_number))
    except GitHubAPIError as exc:
        fail(f"GitHub API {exc.method} {exc.path} returned {exc.status_code}: {exc.message}", 1)
    except ValueError as exc:
        fail(str(exc), 2)
    except httpx.TransportError as exc:
        fail(f"network error talking to GitHub ({type(exc).__name__})", 3)


if __name__ == "__main__":
    main()
