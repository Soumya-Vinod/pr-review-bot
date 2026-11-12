import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings
from app.db import create_tables, make_engine
from app.main import create_app

FIXTURES = Path(__file__).parent / "fixtures"
WEBHOOK_SECRET = "test-webhook-secret"


def load_fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def rsa_keys() -> tuple[str, str]:
    """A throwaway RSA key pair (private PEM, public PEM) generated per test session."""
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
def database_url(tmp_path: Path) -> str:
    return f"sqlite:///{(tmp_path / 'test.db').as_posix()}"


@pytest.fixture
def settings(database_url: str, rsa_keys: tuple[str, str]) -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None,
        github_app_id=123,
        github_webhook_secret=WEBHOOK_SECRET,
        github_private_key=rsa_keys[0],
        database_url=database_url,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    """App with a SQLite database but no background worker (no GitHub calls)."""
    app = create_app(lambda: settings, run_worker=False)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
async def engine(database_url: str) -> AsyncIterator[AsyncEngine]:
    db = make_engine(database_url)
    await create_tables(db)
    try:
        yield db
    finally:
        await db.dispose()
