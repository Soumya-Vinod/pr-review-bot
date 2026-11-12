import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.github_client import API_VERSION, CommentUpsert, GitHubAPIError, GitHubClient

API = "https://api.github.com"
REPO = "octo-org/pr-bot-playground"
NOW = 1_700_000_000.0
INSTALL_TOKEN = "ghs_installation_token_for_tests"


class Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture(scope="module")
def rsa_keys() -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private, public


@pytest.fixture
def clock() -> Clock:
    return Clock(NOW)


@pytest.fixture
async def gh(rsa_keys: tuple[str, str], clock: Clock) -> AsyncIterator[GitHubClient]:
    async with GitHubClient(123, rsa_keys[0], clock=clock) as client:
        yield client


def token_response(expires_in: int = 3600) -> httpx.Response:
    expires = datetime.fromtimestamp(NOW + expires_in, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return httpx.Response(201, json={"token": INSTALL_TOKEN, "expires_at": expires})


def mock_token(router: respx.MockRouter, installation_id: int = 1) -> respx.Route:
    return router.post(f"{API}/app/installations/{installation_id}/access_tokens").mock(
        return_value=token_response()
    )


# --- auth -------------------------------------------------------------------


def test_app_jwt_claims(gh: GitHubClient, rsa_keys: tuple[str, str]) -> None:
    token = gh.app_jwt()

    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    claims = jwt.decode(
        token, rsa_keys[1], algorithms=["RS256"], options={"verify_exp": False, "verify_iat": False}
    )
    assert claims == {"iat": int(NOW) - 60, "exp": int(NOW) + 540, "iss": "123"}


@respx.mock
async def test_installation_token_is_cached(gh: GitHubClient) -> None:
    route = mock_token(respx.mock)

    assert await gh.installation_token(1) == INSTALL_TOKEN
    assert await gh.installation_token(1) == INSTALL_TOKEN

    assert route.call_count == 1
    assert route.calls[0].request.headers["Authorization"].startswith("Bearer ")


@respx.mock
async def test_installation_token_refreshes_five_minutes_before_expiry(
    gh: GitHubClient, clock: Clock
) -> None:
    route = mock_token(respx.mock)
    await gh.installation_token(1)

    clock.now = NOW + 3600 - 301  # still more than 5 min left
    await gh.installation_token(1)
    assert route.call_count == 1

    clock.now = NOW + 3600 - 299  # inside the 5 min margin
    await gh.installation_token(1)
    assert route.call_count == 2


@respx.mock
async def test_installation_tokens_are_cached_per_installation(gh: GitHubClient) -> None:
    first = mock_token(respx.mock, 1)
    second = mock_token(respx.mock, 2)

    await gh.installation_token(1)
    await gh.installation_token(2)
    await gh.installation_token(1)

    assert first.call_count == 1
    assert second.call_count == 1


# --- requests ---------------------------------------------------------------


@respx.mock
async def test_get_pull_request_sends_required_headers(gh: GitHubClient) -> None:
    mock_token(respx.mock)
    route = respx.get(f"{API}/repos/{REPO}/pulls/7").mock(
        return_value=httpx.Response(200, json={"number": 7, "title": "T"})
    )

    pr = await gh.get_pull_request(1, REPO, 7)

    assert pr["title"] == "T"
    for call in respx.calls:
        headers = call.request.headers
        assert headers["Accept"] == "application/vnd.github+json"
        assert headers["X-GitHub-Api-Version"] == API_VERSION
        assert headers["User-Agent"] == "pr-review-bot"
    assert route.calls[0].request.headers["Authorization"] == f"token {INSTALL_TOKEN}"


async def test_client_has_a_timeout(gh: GitHubClient) -> None:
    assert gh._http.timeout.read is not None


@respx.mock
async def test_list_pr_files_follows_link_header(gh: GitHubClient) -> None:
    mock_token(respx.mock)
    page2 = f"{API}/repositories/1001/pulls/7/files?per_page=100&page=2"
    first = respx.get(f"{API}/repos/{REPO}/pulls/7/files").mock(
        return_value=httpx.Response(
            200,
            json=[{"filename": "a.py", "patch": "@@ -0,0 +1 @@\n+x"}],
            headers={"Link": f'<{page2}>; rel="next", <{page2}>; rel="last"'},
        )
    )
    respx.get(page2).mock(return_value=httpx.Response(200, json=[{"filename": "logo.png"}]))

    files = await gh.list_pr_files(1, REPO, 7)

    assert [f["filename"] for f in files] == ["a.py", "logo.png"]
    assert "patch" not in files[1]
    assert first.calls[0].request.url.params["per_page"] == "100"


@respx.mock
async def test_pagination_refuses_links_to_other_hosts(gh: GitHubClient) -> None:
    mock_token(respx.mock)
    respx.get(f"{API}/repos/{REPO}/pulls/7/files").mock(
        return_value=httpx.Response(
            200, json=[], headers={"Link": '<https://evil.test/steal>; rel="next"'}
        )
    )

    with pytest.raises(ValueError, match="another host"):
        await gh.list_pr_files(1, REPO, 7)


@respx.mock
async def test_non_2xx_raises_typed_error_without_token(gh: GitHubClient) -> None:
    mock_token(respx.mock)
    respx.get(f"{API}/repos/{REPO}/pulls/7").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )

    with pytest.raises(GitHubAPIError) as excinfo:
        await gh.get_pull_request(1, REPO, 7)

    assert excinfo.value.status_code == 404
    assert excinfo.value.message == "Not Found"
    assert INSTALL_TOKEN not in str(excinfo.value)


@respx.mock
async def test_token_request_failure_raises_typed_error(gh: GitHubClient) -> None:
    respx.post(f"{API}/app/installations/1/access_tokens").mock(
        return_value=httpx.Response(401, text="bad")
    )

    with pytest.raises(GitHubAPIError) as excinfo:
        await gh.installation_token(1)
    assert excinfo.value.status_code == 401


@respx.mock
async def test_get_repo_installation_uses_app_jwt(gh: GitHubClient) -> None:
    route = respx.get(f"{API}/repos/{REPO}/installation").mock(
        return_value=httpx.Response(200, json={"id": 4242})
    )

    assert await gh.get_repo_installation(REPO) == 4242
    assert route.calls[0].request.headers["Authorization"].startswith("Bearer ")


async def test_invalid_repo_name_is_rejected(gh: GitHubClient) -> None:
    with pytest.raises(ValueError):
        await gh.get_pull_request(1, "../../admin", 1)


# --- upsert_bot_comment -----------------------------------------------------

MARKER = "<!-- pr-review-bot -->"


def comments_route(comments: list[dict]) -> respx.Route:
    return respx.get(f"{API}/repos/{REPO}/issues/7/comments").mock(
        return_value=httpx.Response(200, json=comments)
    )


@respx.mock
async def test_upsert_patches_existing_bot_comment(gh: GitHubClient) -> None:
    mock_token(respx.mock)
    comments_route(
        [
            {"id": 1, "body": "hello", "user": {"type": "User"}},
            {"id": 2, "body": f"{MARKER}\nold", "user": {"type": "Bot"}},
        ]
    )
    patch = respx.patch(f"{API}/repos/{REPO}/issues/comments/2").mock(
        return_value=httpx.Response(200, json={"id": 2})
    )
    post = respx.post(f"{API}/repos/{REPO}/issues/7/comments")

    result = await gh.upsert_bot_comment(1, REPO, 7, f"{MARKER}\nnew", MARKER)

    assert result == CommentUpsert(comment_id=2, created=False)
    assert json.loads(patch.calls[0].request.content) == {"body": f"{MARKER}\nnew"}
    assert not post.called


@respx.mock
async def test_upsert_ignores_marker_in_human_comment(gh: GitHubClient) -> None:
    mock_token(respx.mock)
    comments_route([{"id": 5, "body": f"quoting {MARKER}", "user": {"type": "User"}}])
    post = respx.post(f"{API}/repos/{REPO}/issues/7/comments").mock(
        return_value=httpx.Response(201, json={"id": 9})
    )

    assert await gh.upsert_bot_comment(1, REPO, 7, "body", MARKER) == CommentUpsert(9, True)
    assert post.called


@respx.mock
async def test_upsert_creates_comment_when_none_exist(gh: GitHubClient) -> None:
    mock_token(respx.mock)
    comments_route([])
    respx.post(f"{API}/repos/{REPO}/issues/7/comments").mock(
        return_value=httpx.Response(201, json={"id": 11})
    )

    assert await gh.upsert_bot_comment(1, REPO, 7, "body", MARKER) == CommentUpsert(11, True)
