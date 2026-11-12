from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings

BASE_ENV = {
    "GITHUB_APP_ID": "123",
    "GITHUB_WEBHOOK_SECRET": "webhook-secret",
    "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
    "LLM_BASE_URL": "https://llm.test/v1",
    "LLM_API_KEY": "llm-key",
    "LLM_MODEL": "test-model",
}


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in ("GITHUB_PRIVATE_KEY", "GITHUB_PRIVATE_KEY_PATH"):
        monkeypatch.delenv(name, raising=False)
    for name, value in BASE_ENV.items():
        monkeypatch.setenv(name, value)
    return monkeypatch


def load() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_inline_key_unescapes_literal_newlines(env: pytest.MonkeyPatch) -> None:
    # Literal backslash-n sequences, as written on one line in a .env file.
    env.setenv("GITHUB_PRIVATE_KEY", r"-----BEGIN KEY-----\nabc\n-----END KEY-----")

    settings = load()

    assert settings.private_key_pem() == "-----BEGIN KEY-----\nabc\n-----END KEY-----"
    assert settings.bot_comment_marker == "<!-- pr-review-bot -->"
    assert settings.log_level == "INFO"


def test_key_path_is_read(env: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key_file = tmp_path / "app.key"
    key_file.write_text("-----BEGIN KEY-----\nxyz\n-----END KEY-----\n", encoding="utf-8")
    env.setenv("GITHUB_PRIVATE_KEY_PATH", str(key_file))

    assert load().private_key_pem().startswith("-----BEGIN KEY-----\nxyz")


def test_missing_private_key_is_rejected(env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="GITHUB_PRIVATE_KEY"):
        load()


def test_empty_values_count_as_unset(env: pytest.MonkeyPatch) -> None:
    env.setenv("GITHUB_PRIVATE_KEY", "")
    env.setenv("GITHUB_PRIVATE_KEY_PATH", "")

    with pytest.raises(ValidationError):
        load()


def test_secrets_are_masked_in_repr(env: pytest.MonkeyPatch) -> None:
    env.setenv("GITHUB_PRIVATE_KEY", "super-private")

    text = repr(load())

    assert "super-private" not in text
    assert "llm-key" not in text


def test_database_and_llm_settings_are_optional(env: pytest.MonkeyPatch) -> None:
    for name in ("DATABASE_URL", "LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL"):
        env.delenv(name)
    env.setenv("GITHUB_PRIVATE_KEY", "key")

    settings = load()

    assert settings.database_url is None
    assert settings.llm_base_url is None
    assert settings.llm_configured is False


def test_llm_configured_when_all_llm_settings_present(env: pytest.MonkeyPatch) -> None:
    env.setenv("GITHUB_PRIVATE_KEY", "key")

    assert load().llm_configured is True


def test_log_level_is_case_insensitive(env: pytest.MonkeyPatch) -> None:
    env.setenv("GITHUB_PRIVATE_KEY", "key")
    env.setenv("LOG_LEVEL", "debug")

    assert load().log_level == "DEBUG"
