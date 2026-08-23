from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://netaudit:netaudit@localhost:5432/netaudit"
    redis_url: str = "redis://localhost:6379/0"
    app_env: str = "development"
    secret_key: str = "change-me"
    masscan_rate: int = 10000
    nmap_timing: int = 4
    root_path: str = ""

    # Cola Redis
    scan_queue_key: str = "netaudit:scans:queue"
    scan_progress_channel_prefix: str = "netaudit:scans:progress:"


@lru_cache
def get_settings() -> Settings:
    return Settings()
