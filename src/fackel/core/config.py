from __future__ import annotations

from pydantic import BaseSettings


class Settings(BaseSettings):
    openai_api_key: str
    serpapi_api_key: str | None = None
    virustotal_api_key: str | None = None
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    langfuse_public_key: str | None = None
    langfuse_secret_key: str | None = None
    langfuse_host: str | None = None
    langfuse_user_id: str | None = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
