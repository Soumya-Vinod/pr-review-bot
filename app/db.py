"""Database layer: async SQLAlchemy engine factory, URL normalisation and table definitions.

Tables are SQLAlchemy Core so the job claim can be one portable UPDATE ... RETURNING that
works on both Postgres (asyncpg) and SQLite (aiosqlite, used in tests).
"""

from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    text,
)
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

metadata = MetaData()


def utcnow() -> datetime:
    return datetime.now(UTC)


jobs = Table(
    "jobs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("delivery_id", String(100), nullable=False, unique=True),
    Column("installation_id", BigInteger, nullable=False),
    Column("repo", String(200), nullable=False),
    Column("pr_number", Integer, nullable=False),
    Column("head_sha", String(64), nullable=False),
    # pending | running | done | failed
    Column("status", String(16), nullable=False, default="pending"),
    Column("attempts", Integer, nullable=False, default=0),
    Column("last_error", Text, nullable=True),
    Column("note", Text, nullable=True),
    Column("run_after", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Column("updated_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Index("ix_jobs_status_run_after", "status", "run_after"),
    Index("ix_jobs_repo_pr", "repo", "pr_number"),
)

reviews = Table(
    "reviews",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("repo", String(200), nullable=False),
    Column("pr_number", Integer, nullable=False),
    Column("head_sha", String(64), nullable=False),
    Column("risk_level", String(16), nullable=False),
    Column("findings_json", Text, nullable=False),
    Column("llm_used", Boolean, nullable=False, default=False),
    Column("comment_id", BigInteger, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, default=utcnow),
    Index("ix_reviews_repo_pr", "repo", "pr_number"),
)


def normalize_database_url(url: str) -> str:
    """Turn a provider URL into an async SQLAlchemy URL.

    - postgres:// and postgresql:// -> postgresql+asyncpg://
    - libpq's sslmode=... (e.g. Neon's sslmode=require) -> asyncpg's ssl=...
    - channel_binding=... is dropped (asyncpg does not accept it)
    - sqlite:// -> sqlite+aiosqlite://
    """
    parsed = make_url(url.strip())
    driver = parsed.drivername
    if driver in {"postgres", "postgresql"} or driver.startswith("postgresql+"):
        query = dict(parsed.query)
        query.pop("channel_binding", None)
        sslmode = query.pop("sslmode", None)
        if sslmode is not None and "ssl" not in query:
            query["ssl"] = sslmode
        parsed = parsed.set(drivername="postgresql+asyncpg", query=query)
    elif driver == "sqlite" or driver.startswith("sqlite+"):
        parsed = parsed.set(drivername="sqlite+aiosqlite")
    return parsed.render_as_string(hide_password=False)


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(normalize_database_url(url), pool_pre_ping=True)


async def create_tables(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)


async def ping(engine: AsyncEngine) -> int:
    """Run SELECT 1; used by health/setup checks."""
    async with engine.connect() as conn:
        return int((await conn.execute(text("SELECT 1"))).scalar_one())
