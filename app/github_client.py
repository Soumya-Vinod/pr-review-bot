"""GitHub API client over httpx: GitHub App JWT auth, installation access tokens,
fetching PR files/diffs, and creating or updating the bot's PR comment.
"""

import asyncio
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from types import TracebackType
from typing import Any, Self
from urllib.parse import urlsplit

import httpx
import jwt

GITHUB_API_URL = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "pr-review-bot"
DEFAULT_TIMEOUT = 10.0
JWT_BACKDATE_SECONDS = 60
JWT_LIFETIME_SECONDS = 9 * 60
TOKEN_REFRESH_MARGIN_SECONDS = 5 * 60
PER_PAGE = 100

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitHubAPIError(Exception):
    """A GitHub API request returned a non-2xx status."""

    def __init__(self, method: str, path: str, status_code: int, message: str) -> None:
        self.method = method
        self.path = path
        self.status_code = status_code
        self.message = message
        super().__init__(f"GitHub API {method} {path} failed with {status_code}: {message}")


@dataclass(frozen=True, slots=True)
class CommentUpsert:
    """Result of upsert_bot_comment."""

    comment_id: int
    created: bool


@dataclass(slots=True)
class _CachedToken:
    token: str
    expires_at: float  # unix timestamp


def _check_repo(repo: str) -> str:
    if not _REPO_RE.fullmatch(repo):
        raise ValueError(f"invalid repository name: {repo!r}")
    return repo


def _error_message(response: httpx.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return response.reason_phrase or "error"
    message = data.get("message") if isinstance(data, dict) else None
    return str(message)[:200] if message else (response.reason_phrase or "error")


class GitHubClient:
    """Async GitHub App client. One instance per process; safe to share across tasks."""

    def __init__(
        self,
        app_id: int,
        private_key_pem: str,
        *,
        base_url: str = GITHUB_API_URL,
        timeout: float = DEFAULT_TIMEOUT,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._app_id = app_id
        self._private_key = private_key_pem
        self._base_url = base_url.rstrip("/")
        self._host = urlsplit(self._base_url).netloc
        self._clock = clock
        self._owns_http = http is None
        self._http = http or httpx.AsyncClient(timeout=timeout)
        self._tokens: dict[int, _CachedToken] = {}
        self._token_lock = asyncio.Lock()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # --- auth -----------------------------------------------------------------

    def app_jwt(self) -> str:
        """Create a short-lived RS256 JWT that authenticates as the GitHub App."""
        now = int(self._clock())
        claims = {
            "iat": now - JWT_BACKDATE_SECONDS,
            "exp": now + JWT_LIFETIME_SECONDS,
            "iss": str(self._app_id),
        }
        return jwt.encode(claims, self._private_key, algorithm="RS256")

    async def installation_token(self, installation_id: int) -> str:
        """Return an installation token, cached until 5 minutes before it expires."""
        async with self._token_lock:
            cached = self._tokens.get(installation_id)
            if cached and self._clock() < cached.expires_at - TOKEN_REFRESH_MARGIN_SECONDS:
                return cached.token

            response = await self._send(
                "POST",
                f"/app/installations/{int(installation_id)}/access_tokens",
                auth=f"Bearer {self.app_jwt()}",
            )
            data = response.json()
            expires_at = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
            self._tokens[installation_id] = _CachedToken(data["token"], expires_at.timestamp())
            return data["token"]

    # --- low-level request ------------------------------------------------------

    def _headers(self, auth: str) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
            "Authorization": auth,
        }

    async def _send(
        self,
        method: str,
        path_or_url: str,
        *,
        auth: str,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        if path_or_url.startswith("http"):
            url = path_or_url
            if urlsplit(url).netloc != self._host:
                # Never send credentials to a host we did not configure.
                raise ValueError(f"refusing to follow link to another host: {url}")
        else:
            url = self._base_url + path_or_url
        response = await self._http.request(
            method, url, headers=self._headers(auth), json=json, params=params
        )
        if not response.is_success:
            path = urlsplit(url).path
            raise GitHubAPIError(method, path, response.status_code, _error_message(response))
        return response

    async def _installation_request(
        self,
        installation_id: int,
        method: str,
        path_or_url: str,
        *,
        json: Any = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        token = await self.installation_token(installation_id)
        return await self._send(
            method, path_or_url, auth=f"token {token}", json=json, params=params
        )

    async def _paginate(self, installation_id: int, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        url: str | None = path
        params: dict[str, Any] | None = {"per_page": PER_PAGE}
        while url:
            response = await self._installation_request(installation_id, "GET", url, params=params)
            page = response.json()
            if not isinstance(page, list):
                raise GitHubAPIError("GET", path, response.status_code, "expected a JSON list")
            items.extend(page)
            url = response.links.get("next", {}).get("url")
            params = None  # the next link already carries per_page and page
        return items

    # --- API calls --------------------------------------------------------------

    async def get_repo_installation(self, repo: str) -> int:
        """Return the id of this App's installation on a repository (authenticated as the App)."""
        response = await self._send(
            "GET", f"/repos/{_check_repo(repo)}/installation", auth=f"Bearer {self.app_jwt()}"
        )
        return int(response.json()["id"])

    async def get_pull_request(
        self, installation_id: int, repo: str, number: int
    ) -> dict[str, Any]:
        response = await self._installation_request(
            installation_id, "GET", f"/repos/{_check_repo(repo)}/pulls/{int(number)}"
        )
        return response.json()

    async def list_pr_files(
        self, installation_id: int, repo: str, number: int
    ) -> list[dict[str, Any]]:
        """All changed files of a PR. Entries may lack "patch" (binary or very large)."""
        return await self._paginate(
            installation_id, f"/repos/{_check_repo(repo)}/pulls/{int(number)}/files"
        )

    async def upsert_bot_comment(
        self, installation_id: int, repo: str, number: int, body: str, marker: str
    ) -> CommentUpsert:
        """Update the bot's marked comment on the PR, or create one."""
        repo = _check_repo(repo)
        comments = await self._paginate(
            installation_id, f"/repos/{repo}/issues/{int(number)}/comments"
        )
        for comment in comments:
            user = comment.get("user") or {}
            if marker in (comment.get("body") or "") and user.get("type") == "Bot":
                response = await self._installation_request(
                    installation_id,
                    "PATCH",
                    f"/repos/{repo}/issues/comments/{int(comment['id'])}",
                    json={"body": body},
                )
                return CommentUpsert(int(response.json()["id"]), created=False)

        response = await self._installation_request(
            installation_id,
            "POST",
            f"/repos/{repo}/issues/{int(number)}/comments",
            json={"body": body},
        )
        return CommentUpsert(int(response.json()["id"]), created=True)
