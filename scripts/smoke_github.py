"""Dev-only smoke test for app.github_client against the real GitHub API.

Usage (PowerShell, from the repo root, with .env filled in):

    .venv\\Scripts\\python.exe scripts\\smoke_github.py <owner/repo> <pr_number> [--analyze]

What it does:
  1. Loads settings through app.config (GITHUB_APP_ID, private key, BOT_COMMENT_MARKER).
  2. Finds the App's installation on <owner/repo> (GET /repos/{owner}/{repo}/installation,
     authenticated with the App JWT).
  3. Fetches the PR and its files; prints the title, file count, and +/- per file.
  4. Creates or updates the bot's marked comment on the PR, then prints the comment id
     and whether it was created or updated. The comment body is:
       - without --analyze: a one-line smoke-test message;
       - with --analyze: the real review comment. Files are converted with
         PRFile.from_api, run through run_rules() and the secret scan, and rendered by
         app.comment with no LLM summary ("Summary unavailable."). The overall risk
         level and every finding (rule_id, severity, files) are printed first; secret
         findings show masked values only.

It never prints tokens, keys, the webhook secret or a full detected secret.
Exit codes: 0 ok, 1 GitHub API error, 2 bad usage or configuration, 3 network error.

Note: step 4 WRITES a real comment on the PR. Use a playground repository.
"""

import asyncio
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError

# Allow `python scripts/smoke_github.py` from the repo root without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analysis.rules import Finding, PRFile, run_rules, sort_findings  # noqa: E402
from app.analysis.secrets import scan_files, to_findings  # noqa: E402
from app.comment import render_comment, risk_level  # noqa: E402
from app.config import get_settings  # noqa: E402
from app.github_client import GitHubAPIError, GitHubClient  # noqa: E402

USAGE = "usage: python scripts/smoke_github.py <owner/repo> <pr_number> [--analyze]"
ANALYZE_FLAG = "--analyze"
RISK_NAMES = {"high": "High", "warn": "Medium", "info": "Low", None: "Low"}


def fail(message: str, code: int) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args(argv: list[str]) -> tuple[str, int, bool]:
    analyze = ANALYZE_FLAG in argv
    positional = [arg for arg in argv if arg != ANALYZE_FLAG]
    if len(positional) != 2 or "/" not in positional[0] or not positional[1].isdigit():
        fail(USAGE, 2)
    if any(arg.startswith("-") for arg in positional):
        fail(USAGE, 2)
    return positional[0], int(positional[1]), analyze


def analyze_files(raw_files: list[dict[str, Any]]) -> tuple[list[PRFile], list[Finding]]:
    files = [PRFile.from_api(f) for f in raw_files]
    findings = sort_findings(run_rules(files) + to_findings(scan_files(files)))
    return files, findings


def print_findings(findings: list[Finding]) -> None:
    print(f"Risk level: {RISK_NAMES[risk_level(findings)]}")
    if not findings:
        print("Findings: none")
        return
    print(f"Findings: {len(findings)}")
    for finding in findings:
        print(f"  [{finding.severity}] {finding.rule_id}")
        # Secret findings: details hold "file line N: kind (masked)" — masked values only.
        for item in finding.details or finding.files:
            print(f"      {item}")


async def run(repo: str, pr_number: int, analyze: bool) -> None:
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
        raw_files = await gh.list_pr_files(installation_id, repo, pr_number)
        print(f"PR #{pr_number}: {pr.get('title', '')}")
        print(f"Files changed: {len(raw_files)}")
        for f in raw_files:
            print(f"  {f.get('filename')}  +{f.get('additions', 0)} -{f.get('deletions', 0)}")

        marker = settings.bot_comment_marker
        if analyze:
            files, findings = analyze_files(raw_files)
            print_findings(findings)
            body = render_comment(marker=marker, files=files, findings=findings, summary=None)
        else:
            stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
            body = (
                f"{marker}\nSmoke test from pr-review-bot — {len(raw_files)} files changed "
                f"at {stamp}"
            )
        result = await gh.upsert_bot_comment(installation_id, repo, pr_number, body, marker)
        action = "created" if result.created else "updated"
        print(f"Comment {result.comment_id} {action}")


def main() -> None:
    # PR titles and filenames may hold characters the Windows console code page lacks.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    repo, pr_number, analyze = parse_args(sys.argv[1:])
    try:
        asyncio.run(run(repo, pr_number, analyze))
    except GitHubAPIError as exc:
        fail(f"GitHub API {exc.method} {exc.path} returned {exc.status_code}: {exc.message}", 1)
    except ValueError as exc:
        fail(str(exc), 2)
    except httpx.TransportError as exc:
        fail(f"network error talking to GitHub ({type(exc).__name__})", 3)


if __name__ == "__main__":
    main()
