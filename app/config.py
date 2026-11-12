"""Application settings, loaded from environment variables and .env."""

from functools import lru_cache
from pathlib import Path
from typing import Literal, Self

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        extra="ignore",
    )

    github_app_id: int
    github_webhook_secret: SecretStr
    github_private_key_path: Path | None = None
    github_private_key: SecretStr | None = None

    # Optional at load time; checked by the code that needs them (app.db, summarizer).
    database_url: SecretStr | None = None

    llm_base_url: str | None = None
    llm_api_key: SecretStr | None = None
    llm_model: str | None = None

    bot_comment_marker: str = "<!-- pr-review-bot -->"
    log_level: LogLevel = "INFO"

    @field_validator("github_private_key", mode="before")
    @classmethod
    def _unescape_newlines(cls, value: object) -> object:
        # .env files often hold the PEM on one line with literal "\n" sequences.
        if isinstance(value, str):
            return value.replace("\\n", "\n")
        return value

    @field_validator("log_level", mode="before")
    @classmethod
    def _upper_log_level(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def _require_private_key(self) -> Self:
        if self.github_private_key is None and self.github_private_key_path is None:
            raise ValueError("Set either GITHUB_PRIVATE_KEY_PATH or GITHUB_PRIVATE_KEY")
        return self

    def private_key_pem(self) -> str:
        """Return the GitHub App private key as PEM text.

        Inline GITHUB_PRIVATE_KEY wins over GITHUB_PRIVATE_KEY_PATH when both are set.
        """
        if self.github_private_key is not None:
            return self.github_private_key.get_secret_value()
        if self.github_private_key_path is None:
            raise ValueError("Set either GITHUB_PRIVATE_KEY_PATH or GITHUB_PRIVATE_KEY")
        return self.github_private_key_path.read_text(encoding="utf-8")

    @property
    def llm_configured(self) -> bool:
        """True when all LLM_* settings are present."""
        return bool(self.llm_base_url and self.llm_api_key and self.llm_model)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings, loaded once on first use."""
    return Settings()  # type: ignore[call-arg]  # values come from the environment
