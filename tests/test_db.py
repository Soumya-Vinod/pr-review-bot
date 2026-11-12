import pytest
from sqlalchemy import inspect
from sqlalchemy.ext.asyncio import AsyncEngine

from app.db import normalize_database_url, ping


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("postgres://u:p@host:5432/db", "postgresql+asyncpg://u:p@host:5432/db"),
        ("postgresql://u:p@host/db", "postgresql+asyncpg://u:p@host/db"),
        ("postgresql+asyncpg://u:p@host/db", "postgresql+asyncpg://u:p@host/db"),
        (
            "postgresql://u:p@ep-x.neon.tech/neondb?sslmode=require&channel_binding=require",
            "postgresql+asyncpg://u:p@ep-x.neon.tech/neondb?ssl=require",
        ),
        ("sqlite:///./local.db", "sqlite+aiosqlite:///./local.db"),
        ("sqlite+aiosqlite:///:memory:", "sqlite+aiosqlite:///:memory:"),
    ],
)
def test_normalize_database_url(raw: str, expected: str) -> None:
    assert normalize_database_url(raw) == expected


def test_normalize_keeps_special_characters_in_password() -> None:
    url = normalize_database_url("postgres://user:p%40ss%2Fword@host/db")
    assert url == "postgresql+asyncpg://user:p%40ss%2Fword@host/db"


async def test_tables_are_created(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        tables = await conn.run_sync(lambda sync: set(inspect(sync).get_table_names()))
        job_columns = await conn.run_sync(
            lambda sync: {c["name"] for c in inspect(sync).get_columns("jobs")}
        )
    assert {"jobs", "reviews"} <= tables
    assert job_columns == {
        "id", "delivery_id", "installation_id", "repo", "pr_number", "head_sha", "status",
        "attempts", "last_error", "note", "run_after", "created_at", "updated_at",
    }


async def test_ping(engine: AsyncEngine) -> None:
    assert await ping(engine) == 1
