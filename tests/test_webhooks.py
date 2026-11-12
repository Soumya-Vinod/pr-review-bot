import json
from typing import Any

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from app.config import Settings
from app.main import create_app
from app.webhooks import Ignored, PREvent, compute_signature, filter_event, verify_signature
from tests.conftest import WEBHOOK_SECRET, load_fixture

SECRET = WEBHOOK_SECRET.encode()


def post_event(
    client: TestClient,
    event: str,
    payload: dict[str, Any],
    *,
    signature: str | None = "valid",
    delivery: str = "delivery-1",
) -> Response:
    body = json.dumps(payload).encode()
    headers = {"X-GitHub-Event": event, "X-GitHub-Delivery": delivery,
               "Content-Type": "application/json"}
    if signature == "valid":
        headers["X-Hub-Signature-256"] = compute_signature(SECRET, body)
    elif signature is not None:
        headers["X-Hub-Signature-256"] = signature
    return client.post("/webhook", content=body, headers=headers)


# --- signature verification -------------------------------------------------


def test_verify_signature_accepts_correct_hmac() -> None:
    body = b'{"a": 1}'
    assert verify_signature(SECRET, body, compute_signature(SECRET, body))


@pytest.mark.parametrize(
    "header",
    [None, "", "sha256=", "sha1=abc", "sha256=" + "0" * 64, "sha256=ünïcode"],
)
def test_verify_signature_rejects_bad_headers(header: str | None) -> None:
    assert not verify_signature(SECRET, b"{}", header)


def test_signature_is_over_raw_bytes() -> None:
    signed = b'{"a": 1}'
    reserialized = b'{"a":1}'
    assert not verify_signature(SECRET, reserialized, compute_signature(SECRET, signed))


def test_missing_signature_returns_401(client: TestClient) -> None:
    response = post_event(client, "ping", load_fixture("ping.json"), signature=None)
    assert response.status_code == 401


def test_invalid_signature_returns_401(client: TestClient) -> None:
    response = post_event(client, "ping", load_fixture("ping.json"), signature="sha256=deadbeef")
    assert response.status_code == 401


def test_body_tampered_after_signing_returns_401(client: TestClient) -> None:
    body = json.dumps(load_fixture("ping.json")).encode()
    headers = {
        "X-GitHub-Event": "ping",
        "X-GitHub-Delivery": "d",
        "X-Hub-Signature-256": compute_signature(SECRET, body),
    }
    response = client.post("/webhook", content=body + b" ", headers=headers)
    assert response.status_code == 401


# --- event handling ---------------------------------------------------------


def test_ping_returns_200(client: TestClient) -> None:
    response = post_event(client, "ping", load_fixture("ping.json"))
    assert response.status_code == 200


@pytest.mark.parametrize("action", ["opened", "synchronize", "reopened", "ready_for_review"])
def test_reviewable_pull_request_actions_are_accepted(client: TestClient, action: str) -> None:
    payload = load_fixture("pull_request_opened.json")
    payload["action"] = action

    response = post_event(client, "pull_request", payload, delivery="abc-123")

    assert response.status_code == 202
    assert response.json() == {"queued": True, "delivery_id": "abc-123"}


def test_duplicate_delivery_returns_202_duplicate(client: TestClient) -> None:
    payload = load_fixture("pull_request_opened.json")

    first = post_event(client, "pull_request", payload, delivery="same-id")
    second = post_event(client, "pull_request", payload, delivery="same-id")

    assert first.json() == {"queued": True, "delivery_id": "same-id"}
    assert second.status_code == 202
    assert second.json() == {"duplicate": True}


def test_pull_request_without_database_returns_503(settings: Settings) -> None:
    no_db = settings.model_copy(update={"database_url": None})
    with TestClient(create_app(lambda: no_db, run_worker=False)) as client:
        ping = post_event(client, "ping", load_fixture("ping.json"))
        pr = post_event(client, "pull_request", load_fixture("pull_request_opened.json"))

    assert ping.status_code == 200
    assert pr.status_code == 503


def test_draft_pull_request_is_ignored(client: TestClient) -> None:
    response = post_event(client, "pull_request", load_fixture("pull_request_draft.json"))
    assert response.status_code == 202
    assert "draft" in response.json()["ignored"]


def test_closed_pull_request_is_ignored(client: TestClient) -> None:
    response = post_event(client, "pull_request", load_fixture("pull_request_closed.json"))
    assert response.status_code == 202
    assert "closed" in response.json()["ignored"]


def test_other_event_is_ignored(client: TestClient) -> None:
    response = post_event(client, "issues", load_fixture("issues_opened.json"))
    assert response.status_code == 202
    assert "issues" in response.json()["ignored"]


def test_invalid_json_with_valid_signature_returns_400(client: TestClient) -> None:
    body = b"not json"
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "d",
        "X-Hub-Signature-256": compute_signature(SECRET, body),
    }
    assert client.post("/webhook", content=body, headers=headers).status_code == 400


def test_missing_event_header_returns_400(client: TestClient) -> None:
    body = b"{}"
    headers = {"X-GitHub-Delivery": "d", "X-Hub-Signature-256": compute_signature(SECRET, body)}
    assert client.post("/webhook", content=body, headers=headers).status_code == 400


# --- filter_event -----------------------------------------------------------


def test_filter_event_builds_pr_event() -> None:
    result = filter_event("pull_request", "del-9", load_fixture("pull_request_opened.json"))

    assert result == PREvent(
        delivery_id="del-9",
        installation_id=4242,
        repo_full_name="octo-org/pr-bot-playground",
        pr_number=7,
        head_sha="a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
    )


def test_filter_event_ignores_missing_installation() -> None:
    payload = load_fixture("pull_request_opened.json")
    del payload["installation"]

    result = filter_event("pull_request", "d", payload)

    assert isinstance(result, Ignored)
    assert "installation" in result.reason


def test_filter_event_ignores_missing_head_sha() -> None:
    payload = load_fixture("pull_request_opened.json")
    del payload["pull_request"]["head"]

    assert isinstance(filter_event("pull_request", "d", payload), Ignored)
