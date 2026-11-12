"""Webhook intake: verify X-Hub-Signature-256 against GITHUB_WEBHOOK_SECRET and
decide which GitHub events (e.g. pull_request opened/synchronize) become review jobs.
"""

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

SIGNATURE_PREFIX = "sha256="
REVIEWABLE_ACTIONS = frozenset({"opened", "synchronize", "reopened", "ready_for_review"})


@dataclass(frozen=True, slots=True)
class PREvent:
    """A pull_request delivery that should be reviewed."""

    delivery_id: str
    installation_id: int
    repo_full_name: str
    pr_number: int
    head_sha: str


@dataclass(frozen=True, slots=True)
class Ignored:
    """A delivery that is valid but not reviewed, with the reason why."""

    reason: str


def compute_signature(secret: bytes, body: bytes) -> str:
    """Return the X-Hub-Signature-256 value GitHub would send for this raw body."""
    return SIGNATURE_PREFIX + hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_signature(secret: bytes, body: bytes, header: str | None) -> bool:
    """Check X-Hub-Signature-256 (HMAC-SHA256 over the raw body) in constant time."""
    if not header or not header.startswith(SIGNATURE_PREFIX):
        return False
    expected = compute_signature(secret, body).encode("ascii")
    # Encode as UTF-8 so a non-ASCII header fails the comparison instead of raising.
    return hmac.compare_digest(expected, header.encode("utf-8"))


def filter_event(event: str, delivery_id: str, payload: dict[str, Any]) -> PREvent | Ignored:
    """Turn a verified delivery into a PREvent, or explain why it is ignored."""
    if event != "pull_request":
        return Ignored(f"event '{event}' is not handled")

    action = payload.get("action")
    if action not in REVIEWABLE_ACTIONS:
        return Ignored(f"action '{action}' is not reviewed")

    pr = payload.get("pull_request")
    if not isinstance(pr, dict):
        return Ignored("payload has no pull_request")
    if pr.get("draft"):
        return Ignored("pull request is a draft")

    installation = payload.get("installation")
    if not isinstance(installation, dict) or not isinstance(installation.get("id"), int):
        return Ignored("payload has no installation id")

    try:
        return PREvent(
            delivery_id=delivery_id,
            installation_id=installation["id"],
            repo_full_name=str(payload["repository"]["full_name"]),
            pr_number=int(pr["number"]),
            head_sha=str(pr["head"]["sha"]),
        )
    except (KeyError, TypeError, ValueError):
        return Ignored("payload is missing pull request fields")
