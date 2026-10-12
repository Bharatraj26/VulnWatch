"""
VulnWatch — Application Settings (Flask)
=========================================
All configuration is loaded from environment variables (with .env fallback).
No external APIs, cloud services, or external container runtimes required.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import ClassVar

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application configuration."""

    APP_ENV: str = os.getenv("APP_ENV", "development")
    DEBUG: bool = os.getenv("APP_DEBUG", "true").lower() in ("true", "1", "yes")
    HOST: str = os.getenv("APP_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("APP_PORT", "8000"))
    SECRET_KEY: str = os.getenv("SECRET_KEY", "vulnwatch-secret-key-educational-local")

    # CORS configuration
    cors_str = os.getenv(
        "CORS_ORIGINS",
        os.getenv("CORS_ORIGINS_STR", "http://localhost:5173,http://localhost:3000"),
    )
    CORS_ORIGINS: ClassVar[list[str]] = [
        origin.strip() for origin in cors_str.split(",") if origin.strip()
    ]

    # Database — SQLite (local file)
    DATABASE_PATH: str = os.getenv(
        "DATABASE_PATH", str(BASE_DIR / "vulnwatch.db")
    )

    # Allowed scan targets (loopback / local test applications only)
    allowed_targets_str = os.getenv("ALLOWED_TARGETS", "localhost,127.0.0.1,::1")
    ALLOWED_TARGETS: ClassVar[list[str]] = [
        t.strip().lower() for t in allowed_targets_str.split(",") if t.strip()
    ]


class TestConfig(Config):
    """Configuration for automated tests."""

    TESTING: bool = True
    DEBUG: bool = False
    DATABASE_PATH: str = ":memory:"
    ALLOWED_TARGETS: ClassVar[list[str]] = ["localhost", "127.0.0.1", "::1"]
