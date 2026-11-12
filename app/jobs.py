"""Background job worker: polls the job table, runs reviews, retries failures with
backoff, and keeps processing idempotent per webhook delivery.

Lifecycle of a job row:
    pending --claim--> running --ok--> done
                          |  \\--newer job for same PR--> done (note "superseded")
                          |--error, attempts < max--> pending (run_after = now + backoff)
                          \\--error, attempts == max or not retryable--> failed
A job left in running by a crash is put back to pending on the next startup.
"""

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta

from sqlalchemy import and_, exists, insert, select, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from app.analysis.rules import Finding, PRFile, run_rules, sort_findings
from app.analysis.secrets import scan_files, to_findings
from app.comment import render_comment, risk_level
from app.db import jobs, reviews, utcnow
from app.github_client import GitHubAPIError, GitHubClient
from app.webhooks import PREvent

logger = logging.getLogger(__name__)

MAX_ATTEMPTS = 5
STUCK_AFTER = timedelta(minutes=10)
NON_RETRYABLE_STATUSES = frozenset({400, 404, 410, 422})
MAX_ERROR_CHARS = 500
RISK_NAMES = {"high": "high", "warn": "medium", "info": "low", None: "low"}


@dataclass(frozen=True, slots=True)
class Job:
    id: int
    delivery_id: str
    installation_id: int
    repo: str
    pr_number: int
    head_sha: str
    status: str
    attempts: int

    @classmethod
    def from_row(cls, row: RowMapping) -> "Job":
        return cls(**{f.name: row[f.name] for f in fields(cls)})


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    max_attempts: int = MAX_ATTEMPTS
    backoff_base_seconds: float = 30.0
    backoff_max_seconds: float = 30 * 60.0
    poll_interval_seconds: float = 5.0
    shutdown_timeout_seconds: float = 20.0


class PermanentJobError(Exception):
    """Raised by a processor when retrying cannot help."""


# --- queue operations --------------------------------------------------------------


async def enqueue_job(engine: AsyncEngine, event: PREvent, now: datetime | None = None) -> bool:
    """Insert a pending job. Returns False if this delivery_id was already recorded."""
    now = now or utcnow()
    try:
        async with engine.begin() as conn:
            await conn.execute(
                insert(jobs).values(
                    delivery_id=event.delivery_id,
                    installation_id=event.installation_id,
                    repo=event.repo_full_name,
                    pr_number=event.pr_number,
                    head_sha=event.head_sha,
                    status="pending",
                    attempts=0,
                    run_after=now,
                    created_at=now,
                    updated_at=now,
                )
            )
    except IntegrityError:
        return False
    return True


async def claim_next_job(engine: AsyncEngine, now: datetime | None = None) -> Job | None:
    """Atomically move the oldest due pending job to running and return it.

    A single UPDATE ... WHERE id = (SELECT ...) RETURNING, so two workers can never
    claim the same row. On Postgres the subquery also uses FOR UPDATE SKIP LOCKED;
    SQLite ignores that clause (and serialises writers anyway).
    """
    now = now or utcnow()
    next_id = (
        select(jobs.c.id)
        .where(jobs.c.status == "pending", jobs.c.run_after <= now)
        .order_by(jobs.c.run_after, jobs.c.id)
        .limit(1)
        .with_for_update(skip_locked=True)
        .scalar_subquery()
    )
    stmt = (
        update(jobs)
        .where(jobs.c.id == next_id, jobs.c.status == "pending")
        .values(status="running", attempts=jobs.c.attempts + 1, updated_at=now)
        .returning(*jobs.c)
    )
    async with engine.begin() as conn:
        row = (await conn.execute(stmt)).mappings().first()
    return Job.from_row(row) if row else None


async def has_newer_job(engine: AsyncEngine, job: Job) -> bool:
    stmt = select(
        exists().where(
            jobs.c.repo == job.repo, jobs.c.pr_number == job.pr_number, jobs.c.id > job.id
        )
    )
    async with engine.connect() as conn:
        return bool((await conn.execute(stmt)).scalar())


async def _set_job(engine: AsyncEngine, job_id: int, **values: object) -> None:
    async with engine.begin() as conn:
        await conn.execute(update(jobs).where(jobs.c.id == job_id).values(**values))


async def mark_done(
    engine: AsyncEngine, job: Job, note: str | None = None, now: datetime | None = None
) -> None:
    await _set_job(
        engine, job.id, status="done", note=note, last_error=None, updated_at=now or utcnow()
    )


def backoff_delay(attempts: int, config: WorkerConfig) -> timedelta:
    """Exponential backoff: base * 2^(attempts-1), capped."""
    seconds = config.backoff_base_seconds * (2 ** max(attempts - 1, 0))
    return timedelta(seconds=min(seconds, config.backoff_max_seconds))


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, PermanentJobError):
        return False
    if isinstance(exc, GitHubAPIError):
        return exc.status_code not in NON_RETRYABLE_STATUSES
    return True


def describe_error(exc: BaseException) -> str:
    """Short error text for the job row. Never includes request bodies or tokens."""
    return f"{type(exc).__name__}: {exc}"[:MAX_ERROR_CHARS]


async def mark_failed_attempt(
    engine: AsyncEngine,
    job: Job,
    exc: BaseException,
    config: WorkerConfig,
    now: datetime | None = None,
) -> str:
    """Schedule a retry or give up. Returns the new status."""
    now = now or utcnow()
    error = describe_error(exc)
    if job.attempts >= config.max_attempts or not _is_retryable(exc):
        await _set_job(engine, job.id, status="failed", last_error=error, updated_at=now)
        return "failed"
    await _set_job(
        engine,
        job.id,
        status="pending",
        last_error=error,
        run_after=now + backoff_delay(job.attempts, config),
        updated_at=now,
    )
    return "pending"


async def release_job(engine: AsyncEngine, job: Job, now: datetime | None = None) -> None:
    """Put a job interrupted by shutdown back to pending without using up an attempt."""
    now = now or utcnow()
    await _set_job(
        engine,
        job.id,
        status="pending",
        attempts=max(job.attempts - 1, 0),
        run_after=now,
        updated_at=now,
        note="released on shutdown",
    )


async def recover_stuck_jobs(
    engine: AsyncEngine, config: WorkerConfig | None = None, now: datetime | None = None
) -> int:
    """Reset jobs left in running for longer than 10 minutes (e.g. after a crash)."""
    config = config or WorkerConfig()
    now = now or utcnow()
    stuck = and_(jobs.c.status == "running", jobs.c.updated_at < now - STUCK_AFTER)
    async with engine.begin() as conn:
        failed = await conn.execute(
            update(jobs)
            .where(stuck, jobs.c.attempts >= config.max_attempts)
            .values(status="failed", last_error="stuck in running; out of attempts", updated_at=now)
        )
        reset = await conn.execute(
            update(jobs)
            .where(stuck)
            .values(status="pending", run_after=now, note="recovered after stuck", updated_at=now)
        )
    return int(failed.rowcount or 0) + int(reset.rowcount or 0)


# --- the review pipeline -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReviewResult:
    comment_id: int
    risk_level: str
    findings: list[Finding]
    llm_used: bool


class ReviewPipeline:
    """get PR -> files -> rules + secrets -> render -> upsert comment -> save review."""

    def __init__(self, engine: AsyncEngine, github: GitHubClient, marker: str) -> None:
        self._engine = engine
        self._github = github
        self._marker = marker

    async def __call__(self, job: Job) -> ReviewResult:
        gh = self._github
        await gh.get_pull_request(job.installation_id, job.repo, job.pr_number)
        raw_files = await gh.list_pr_files(job.installation_id, job.repo, job.pr_number)
        files = [PRFile.from_api(f) for f in raw_files]

        findings = sort_findings(run_rules(files) + to_findings(scan_files(files)))
        summary: str | None = None  # LLM summary arrives in phase 6
        body = render_comment(
            marker=self._marker, files=files, findings=findings, summary=summary
        )
        upsert = await gh.upsert_bot_comment(
            job.installation_id, job.repo, job.pr_number, body, self._marker
        )

        result = ReviewResult(
            comment_id=upsert.comment_id,
            risk_level=RISK_NAMES[risk_level(findings)],
            findings=findings,
            llm_used=summary is not None,
        )
        await save_review(self._engine, job, result)
        return result


async def save_review(engine: AsyncEngine, job: Job, result: ReviewResult) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            insert(reviews).values(
                repo=job.repo,
                pr_number=job.pr_number,
                head_sha=job.head_sha,
                risk_level=result.risk_level,
                findings_json=json.dumps([asdict(f) for f in result.findings]),
                llm_used=result.llm_used,
                comment_id=result.comment_id,
                created_at=utcnow(),
            )
        )


# --- the worker --------------------------------------------------------------------

Processor = Callable[[Job], Awaitable[object]]


class Worker:
    """A single asyncio task that claims and processes jobs one at a time."""

    def __init__(
        self, engine: AsyncEngine, process: Processor, config: WorkerConfig | None = None
    ) -> None:
        self._engine = engine
        self._process = process
        self._config = config or WorkerConfig()
        self._wake = asyncio.Event()
        self._stopping = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def notify(self) -> None:
        """Wake the worker early (called after a job is enqueued)."""
        self._wake.set()

    async def run_once(self) -> Job | None:
        """Claim and handle one due job. Returns the job, or None if nothing was due."""
        job = await claim_next_job(self._engine)
        if job is None:
            return None
        log = {"job_id": job.id, "delivery_id": job.delivery_id, "attempt": job.attempts}

        if await has_newer_job(self._engine, job):
            await mark_done(self._engine, job, note="superseded")
            logger.info("job superseded by a newer job for the same PR", extra=log)
            return job

        try:
            await self._process(job)
        except asyncio.CancelledError:
            await release_job(self._engine, job)
            raise
        except Exception as exc:
            status = await mark_failed_attempt(self._engine, job, exc, self._config)
            logger.warning(
                "job attempt failed (%s); now %s", type(exc).__name__, status, extra=log
            )
        else:
            await mark_done(self._engine, job)
            logger.info("job done", extra=log)
        return job

    async def run_forever(self) -> None:
        while not self._stopping.is_set():
            # Clear before claiming so a notify() that races with the claim is not lost.
            self._wake.clear()
            try:
                job = await self.run_once()
            except Exception:
                logger.exception("worker loop error; backing off")
                job = None
            if job is None and not self._stopping.is_set():
                try:
                    await asyncio.wait_for(
                        self._wake.wait(), timeout=self._config.poll_interval_seconds
                    )
                except TimeoutError:
                    pass

    def start(self) -> None:
        if not self.running:
            self._stopping.clear()
            self._task = asyncio.create_task(self.run_forever(), name="review-worker")

    async def stop(self) -> None:
        """Finish the current job (up to the shutdown timeout), then stop."""
        if self._task is None:
            return
        self._stopping.set()
        self._wake.set()
        try:
            await asyncio.wait_for(
                asyncio.shield(self._task), timeout=self._config.shutdown_timeout_seconds
            )
        except TimeoutError:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
