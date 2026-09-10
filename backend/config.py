import os
from pathlib import Path
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Find .env in backend/ or root
current_dir = Path(__file__).resolve().parent
root_dir = current_dir.parent
env_path = current_dir / ".env" if (current_dir / ".env").exists() else root_dir / ".env"

class Settings(BaseSettings):
    """
    Application Settings configuration loaded from environment variables or .env file.
    """
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    SECRET_KEY: str = "strata_super_secret_jwt_key_2026_production"
    JWT_SECRET_KEY: str = "strata_super_secret_jwt_key_2026_production"
    JWT_ALGORITHM: str = "HS256"
    ALGORITHM: str = "HS256"
    RATE_LIMIT_REQUESTS: int = 10
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]

    model_config = SettingsConfigDict(
        env_file=str(env_path) if env_path.exists() else None,
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
# Sync SECRET_KEY and JWT_SECRET_KEY
if settings.SECRET_KEY != "strata_super_secret_jwt_key_2026_production" and settings.JWT_SECRET_KEY == "strata_super_secret_jwt_key_2026_production":
    settings.JWT_SECRET_KEY = settings.SECRET_KEY

