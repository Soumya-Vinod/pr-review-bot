import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

import httpx
import respx
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings
from app.db import create_tables, jobs, make_engine, reviews
from app.github_client import GitHubAPIError, GitHubClient
from app.jobs import (
    Job,
    ReviewPipeline,
    Worker,
    WorkerConfig,
    backoff_delay,
    claim_next_job,
    enqueue_job,
    recover_stuck_jobs,
)
from app.main import create_app
from app.webhooks import PREvent, compute_signature
from tests.conftest import WEBHOOK_SECRET, load_fixture

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
FAST = WorkerConfig(backoff_base_seconds=0, poll_interval_seconds=0.01)
API = "https://api.github.com"
REPO = "octo-org/pr-bot-playground"
MARKER = "<!-- pr-review-bot -->"
T = TypeVar("T")


def event(delivery: str = "d1", pr_number: int = 7, sha: str = "abc") -> PREvent:
    return PREvent(delivery, 4242, REPO, pr_number, sha)


async def job_row(engine: AsyncEngine, delivery: str = "d1") -> dict[str, Any]:
    async with engine.connect() as conn:
        row = (await conn.execute(select(jobs).where(jobs.c.delivery_id == delivery))).mappings()
        return dict(row.one())


def as_utc(value: datetime) -> datetime:
    """SQLite returns naive datetimes; everything is stored in UTC."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class Recorder:
    def __init__(self, fail_with: BaseException | None = None) -> None:
        self.jobs: list[Job] = []
        self.fail_with = fail_with

    async def __call__(self, job: Job) -> None:
        self.jobs.append(job)
        if self.fail_with:
            raise self.fail_with


# --- enqueue / duplicate -----------------------------------------------------------


async def test_enqueue_duplicate_delivery_is_rejected(engine: AsyncEngine) -> None:
    assert await enqueue_job(engine, event("d1"))
    assert not await enqueue_job(engine, event("d1"))

    async with engine.connect() as conn:
        count = len((await conn.execute(select(jobs.c.id))).all())
    assert count == 1


# --- claim -------------------------------------------------------------------------


async def test_claim_marks_running_and_counts_attempt(engine: AsyncEngine) -> None:
    await enqueue_job(engine, event("d1"), now=NOW)

    job = await claim_next_job(engine, now=NOW)

    assert job is not None
    assert (job.delivery_id, job.status, job.attempts) == ("d1", "running", 1)
    assert await claim_next_job(engine, now=NOW) is None  # nothing left to claim


async def test_claim_takes_oldest_due_job_and_skips_future(engine: AsyncEngine) -> None:
    await enqueue_job(engine, event("later", pr_number=1), now=NOW + timedelta(minutes=5))
    await enqueue_job(engine, event("first", pr_number=2), now=NOW - timedelta(minutes=2))
    await enqueue_job(engine, event("second", pr_number=3), now=NOW - timedelta(minutes=1))

    claimed = [await claim_next_job(engine, now=NOW) for _ in range(3)]

    assert [j.delivery_id if j else None for j in claimed] == ["first", "second", None]


async def test_concurrent_claims_never_return_the_same_job(engine: AsyncEngine) -> None:
    for i in range(5):
        await enqueue_job(engine, event(f"d{i}", pr_number=i), now=NOW)

    results = await asyncio.gather(*(claim_next_job(engine, now=NOW) for _ in range(10)))

    ids = [j.id for j in results if j]
    assert len(ids) == len(set(ids)) == 5


# --- worker: success, retry, failure, superseded ---------------------------------


async def test_worker_processes_job_to_done(engine: AsyncEngine) -> None:
    await enqueue_job(engine, event("d1"))
    process = Recorder()

    await Worker(engine, process, FAST).run_once()

    assert [j.delivery_id for j in process.jobs] == ["d1"]
    row = await job_row(engine)
    assert (row["status"], row["attempts"], row["last_error"]) == ("done", 1, None)


async def test_failed_attempt_is_retried_with_backoff(engine: AsyncEngine) -> None:
    await enqueue_job(engine, event("d1"))
    worker = Worker(engine, Recorder(RuntimeError("boom")), WorkerConfig(backoff_base_seconds=30))

    before = datetime.now(UTC)
    await worker.run_once()

    row = await job_row(engine)
    assert row["status"] == "pending"
    assert row["attempts"] == 1
    assert row["last_error"] == "RuntimeError: boom"
    assert as_utc(row["run_after"]) >= before + timedelta(seconds=29)
    assert await worker.run_once() is None  # not due yet


def test_backoff_is_exponential_and_capped() -> None:
    config = WorkerConfig(backoff_base_seconds=30, backoff_max_seconds=300)
    delays = [backoff_delay(n, config).total_seconds() for n in range(1, 6)]
    assert delays == [30, 60, 120, 240, 300]


async def test_job_fails_after_max_attempts(engine: AsyncEngine) -> None:
    await enqueue_job(engine, event("d1"))
    process = Recorder(RuntimeError("still broken"))
    worker = Worker(engine, process, FAST)

    for _ in range(10):
        await worker.run_once()

    row = await job_row(engine)
    assert len(process.jobs) == 5
    assert (row["status"], row["attempts"]) == ("failed", 5)
    assert "still broken" in row["last_error"]


async def test_non_retryable_github_error_fails_immediately(engine: AsyncEngine) -> None:
    await enqueue_job(engine, event("d1"))
    error = GitHubAPIError("GET", "/repos/x/y/pulls/7", 404, "Not Found")

    await Worker(engine, Recorder(error), FAST).run_once()

    row = await job_row(engine)
    assert (row["status"], row["attempts"]) == ("failed", 1)


async def test_rate_limit_error_is_retried(engine: AsyncEngine) -> None:
    await enqueue_job(engine, event("d1"))
    error = GitHubAPIError("GET", "/repos/x/y/pulls/7", 429, "rate limited")

    await Worker(engine, Recorder(error), FAST).run_once()

    assert (await job_row(engine))["status"] == "pending"


async def test_older_job_for_same_pr_is_superseded(engine: AsyncEngine) -> None:
    await enqueue_job(engine, event("old", sha="sha1"), now=NOW)
    await enqueue_job(engine, event("new", sha="sha2"), now=NOW)
    await enqueue_job(engine, event("other-pr", pr_number=99), now=NOW)
    process = Recorder()
    worker = Worker(engine, process, FAST)

    while await worker.run_once():
        pass

    assert [j.delivery_id for j in process.jobs] == ["new", "other-pr"]
    old = await job_row(engine, "old")
    assert (old["status"], old["note"]) == ("done", "superseded")
    assert (await job_row(engine, "new"))["status"] == "done"


# --- stuck recovery ----------------------------------------------------------------


async def _force_running(engine: AsyncEngine, delivery: str, updated: datetime, attempts: int):
    async with engine.begin() as conn:
        await conn.execute(
            update(jobs)
            .where(jobs.c.delivery_id == delivery)
            .values(status="running", updated_at=updated, attempts=attempts)
        )


async def test_stuck_running_jobs_are_recovered(engine: AsyncEngine) -> None:
    await enqueue_job(engine, event("stuck", pr_number=1))
    await enqueue_job(engine, event("busy", pr_number=2))
    await enqueue_job(engine, event("hopeless", pr_number=3))
    await _force_running(engine, "stuck", NOW - timedelta(minutes=11), attempts=1)
    await _force_running(engine, "busy", NOW - timedelta(minutes=5), attempts=1)
    await _force_running(engine, "hopeless", NOW - timedelta(minutes=30), attempts=5)

    assert await recover_stuck_jobs(engine, now=NOW) == 2

    stuck = await job_row(engine, "stuck")
    assert (stuck["status"], stuck["note"]) == ("pending", "recovered after stuck")
    assert (await job_row(engine, "busy"))["status"] == "running"
    assert (await job_row(engine, "hopeless"))["status"] == "failed"


# --- worker task lifecycle -----------------------------------------------------------


async def _wait_for_status(engine: AsyncEngine, delivery: str, status: str) -> None:
    for _ in range(500):
        if (await job_row(engine, delivery))["status"] == status:
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"job {delivery} never reached {status}")


async def test_worker_task_starts_wakes_and_stops_cleanly(engine: AsyncEngine) -> None:
    process = Recorder()
    worker = Worker(engine, process, WorkerConfig(poll_interval_seconds=60))
    worker.start()
    assert worker.running

    await enqueue_job(engine, event("d1"))
    worker.notify()
    await _wait_for_status(engine, "d1", "done")

    await worker.stop()
    assert not worker.running


async def test_shutdown_timeout_releases_in_flight_job(engine: AsyncEngine) -> None:
    started = asyncio.Event()

    async def slow(job: Job) -> None:
        started.set()
        await asyncio.sleep(60)

    await enqueue_job(engine, event("d1"))
    worker = Worker(engine, slow, WorkerConfig(shutdown_timeout_seconds=0.05))
    worker.start()
    await asyncio.wait_for(started.wait(), timeout=5)

    await worker.stop()

    row = await job_row(engine)
    assert (row["status"], row["attempts"], row["note"]) == ("pending", 0, "released on shutdown")


# --- the review pipeline (GitHub mocked with respx) --------------------------------

AWS_KEY = "AKIA" + "Z" * 16


def mock_github(router: respx.MockRouter) -> dict[str, respx.Route]:
    expires = (datetime.now(UTC) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "token": router.post(f"{API}/app/installations/4242/access_tokens").mock(
            return_value=httpx.Response(201, json={"token": "t-test", "expires_at": expires})
        ),
        "pr": router.get(f"{API}/repos/{REPO}/pulls/7").mock(
            return_value=httpx.Response(200, json={"number": 7, "title": "Add config"})
        ),
        "files": router.get(f"{API}/repos/{REPO}/pulls/7/files").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "filename": "app/settings.py",
                        "status": "modified",
                        "additions": 1,
                        "deletions": 0,
                        "patch": f"@@ -1 +1,2 @@\n x = 1\n+aws = {AWS_KEY}",
                    },
                    {"filename": "logo.png", "status": "added", "additions": 0, "deletions": 0},
                ],
            )
        ),
        "comments": router.get(f"{API}/repos/{REPO}/issues/7/comments").mock(
            return_value=httpx.Response(200, json=[])
        ),
        "post": router.post(f"{API}/repos/{REPO}/issues/7/comments").mock(
            return_value=httpx.Response(201, json={"id": 555})
        ),
    }


@respx.mock
async def test_pipeline_posts_comment_and_saves_review(
    engine: AsyncEngine, rsa_keys: tuple[str, str]
) -> None:
    routes = mock_github(respx.mock)
    await enqueue_job(engine, event("d1", sha="headsha"))

    async with GitHubClient(123, rsa_keys[0]) as gh:
        await Worker(engine, ReviewPipeline(engine, gh, MARKER), FAST).run_once()

    assert (await job_row(engine))["status"] == "done"
    body = json.loads(routes["post"].calls[0].request.content)["body"]
    assert body.startswith(MARKER)
    assert "Summary unavailable" in body
    assert "AKIA****" in body
    assert AWS_KEY not in body

    async with engine.connect() as conn:
        review = (await conn.execute(select(reviews))).mappings().one()
    assert review["head_sha"] == "headsha"
    assert review["risk_level"] == "high"
    assert review["comment_id"] == 555
    assert review["llm_used"] is False
    rule_ids = {f["rule_id"] for f in json.loads(review["findings_json"])}
    assert {"secrets", "missing_tests", "unreviewable"} <= rule_ids
    assert AWS_KEY not in review["findings_json"]


# --- app lifespan: webhook -> job -> worker -> comment ---------------------------



def _db_call(settings: Settings, fn: Callable[[AsyncEngine], Awaitable[T]]) -> T:
    """Run an async DB helper from a sync test against the app's SQLite file."""

    async def runner() -> T:
        db = make_engine(settings.database_url.get_secret_value())  # type: ignore[union-attr]
        try:
            await create_tables(db)
            return await fn(db)
        finally:
            await db.dispose()

    return asyncio.run(runner())


def _wait_until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not met in time")
        time.sleep(0.01)


def test_app_lifespan_runs_worker_end_to_end(settings: Settings) -> None:
    payload = json.dumps(load_fixture("pull_request_opened.json")).encode()
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "e2e-1",
        "X-Hub-Signature-256": compute_signature(WEBHOOK_SECRET.encode(), payload),
    }
    app = create_app(lambda: settings, worker_config=FAST)

    with respx.mock(assert_all_called=False) as router:
        routes = mock_github(router)
        with TestClient(app) as client:
            response = client.post("/webhook", content=payload, headers=headers)
            assert response.status_code == 202
            _wait_until(lambda: routes["post"].called)
        # leaving the TestClient context ran the lifespan shutdown (worker stopped)

    assert _db_call(settings, lambda db: job_row(db, "e2e-1"))["status"] == "done"


def test_startup_recovers_and_processes_stuck_job(settings: Settings) -> None:
    async def make_stuck(db: AsyncEngine) -> None:
        await enqueue_job(db, event("crashed"))
        await _force_running(db, "crashed", datetime.now(UTC) - timedelta(minutes=15), 1)

    _db_call(settings, make_stuck)
    app = create_app(lambda: settings, worker_config=FAST)

    with respx.mock(assert_all_called=False) as router:
        routes = mock_github(router)
        with TestClient(app):
            _wait_until(lambda: routes["post"].called)

    row = _db_call(settings, lambda db: job_row(db, "crashed"))
    assert (row["status"], row["note"], row["attempts"]) == ("done", None, 2)


def test_no_fastapi_background_tasks() -> None:
    app_dir = Path(__file__).resolve().parent.parent / "app"
    for file in app_dir.rglob("*.py"):
        assert "BackgroundTasks" not in file.read_text(encoding="utf-8"), file
