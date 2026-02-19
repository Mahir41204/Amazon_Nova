"""
Application settings loaded from environment variables.

All configurable values are centralized here — no hard-coded values elsewhere.
Uses pydantic-settings for type-safe .env loading.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from typing import Optional

from pydantic_settings import BaseSettings
from pydantic import Field


class Environment(str, Enum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Central configuration — loaded from .env / environment variables."""

    # ── General ──────────────────────────────────────────────────────────
    APP_NAME: str = "Nova Autonomous Cyber Defense Commander"
    ENVIRONMENT: Environment = Environment.DEVELOPMENT
    LOG_LEVEL: str = "INFO"
    ENABLE_TRACE_DASHBOARD: bool = True  # console pipeline trace
    DEBUG: bool = False
    DEMO_MODE: bool = True  # Default to demo mode for hackathon
    ENABLE_PRODUCTION_MODE: bool = False  # enforce real credentials when True

    # ── API Server ───────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # ── AWS Credentials ──────────────────────────────────────────────────
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_REGION: str = "us-east-1"

    # ── Nova / Bedrock ───────────────────────────────────────────────────
    NOVA_API_KEY: Optional[str] = None
    NOVA_MODEL_ID: str = "amazon.nova-pro-v1:0"
    NOVA_REGION: str = "us-east-1"
    NOVA_MAX_TOKENS: int = 4096
    NOVA_TEMPERATURE: float = 0.3

    # ── Nova Act ─────────────────────────────────────────────────────────
    NOVA_ACT_ENDPOINT: Optional[str] = None
    NOVA_ACT_API_KEY: Optional[str] = None

    # ── Security ─────────────────────────────────────────────────────────
    JWT_SECRET: str = "change-me-in-production-please"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_MINUTES: int = 60
    RATE_LIMIT_RPM: int = 60  # requests per minute

    # ── Confidence Threshold ─────────────────────────────────────────────
    CONFIDENCE_THRESHOLD: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Minimum confidence to execute automated defensive actions.",
    )

    # ── Memory / Vector Store ────────────────────────────────────────────
    VECTOR_STORE_PATH: str = "data/vector_store.json"
    INCIDENT_STORE_PATH: str = "data/incidents.json"
    VECTOR_DIMENSION: int = 256
    SIMILARITY_TOP_K: int = 5

    # ── Daemon / Realtime Engine ─────────────────────────────────────────
    RUN_MODE: str = "api"  # "api" | "daemon" | "hybrid"
    REALTIME_WINDOW_SECONDS: int = 60
    FAILED_ATTEMPT_THRESHOLD: int = 5
    BLOCK_DURATION_SECONDS: int = 600
    MAX_NOVA_CALLS_PER_MINUTE: int = 10
    EVENT_QUEUE_MAX_SIZE: int = 10000
    LOG_SOURCES: str = ""  # "path1:name1,path2:name2"

    # ── Telemetry Sensors ────────────────────────────────────────────────
    ENABLE_LOG_SENSOR: bool = True
    ENABLE_NETWORK_SENSOR: bool = True
    ENABLE_AUTH_SENSOR: bool = True
    ENABLE_PROCESS_SENSOR: bool = True

    # ── Correlation Engine ───────────────────────────────────────────────
    CORRELATION_WEIGHTS: dict = {"log": 0.30, "network": 0.25, "auth": 0.25, "process": 0.20}
    GLOBAL_SUSPICION_THRESHOLD: float = 0.85
    SUSPICION_WINDOW_SECONDS: int = 60

    # ── RBAC default credentials (demo only) ─────────────────────────────
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin"
    VIEWER_USERNAME: str = "viewer"
    VIEWER_PASSWORD: str = "viewer"

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()
