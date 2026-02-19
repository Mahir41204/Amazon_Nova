"""
Nova Autonomous Cyber Defense Commander — Application Entry Point.

Creates the FastAPI application, wires up all dependencies, and
mounts middleware (CORS, rate limiting, structured logging).

Supports three run modes (controlled by ``RUN_MODE`` setting):
  - ``api``    — REST API only (default, existing behaviour)
  - ``daemon`` — standalone event-driven daemon
  - ``hybrid`` — FastAPI + daemon background tasks
"""

from __future__ import annotations

import asyncio
import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router, set_orchestrator, set_daemon
from config.settings import get_settings
from core.orchestrator import Orchestrator
from core.state_manager import StateManager
from memory.vector_store import VectorStore
from memory.incident_repository import IncidentRepository
from security.rate_limiter import RateLimiter
from services.nova_client import NovaClient
from services.nova_act_client import NovaActClient
from services.embeddings_service import EmbeddingsService

# ── Logging setup ───────────────────────────────────────────────────────

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)

logger = logging.getLogger("nova")


# ── Application factory ────────────────────────────────────────────────

_daemon_instance = None  # module-level for hybrid mode


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan — initialize and tear down resources."""
    global _daemon_instance

    logger.info("═══ Starting Nova Autonomous Cyber Defense Commander ═══")
    logger.info(
        "Environment: %s | Demo Mode: %s | Run Mode: %s",
        settings.ENVIRONMENT,
        settings.DEMO_MODE,
        settings.RUN_MODE,
    )

    # Wire up dependencies
    nova_client = NovaClient()
    nova_act_client = NovaActClient()
    embeddings_service = EmbeddingsService()
    vector_store = VectorStore()
    incident_repo = IncidentRepository()
    state_manager = StateManager()

    orchestrator = Orchestrator(
        nova_client=nova_client,
        nova_act_client=nova_act_client,
        embeddings_service=embeddings_service,
        vector_store=vector_store,
        incident_repository=incident_repo,
        state_manager=state_manager,
    )

    # Inject into routes
    set_orchestrator(orchestrator)

    # ── Hybrid mode: start daemon alongside API ─────────────────────
    if settings.RUN_MODE == "hybrid":
        from daemon.realtime_daemon import RealtimeDaemon

        _daemon_instance = RealtimeDaemon()
        set_daemon(_daemon_instance)
        await _daemon_instance.start()
        logger.info("Hybrid mode: RealtimeDaemon started alongside API server")

    logger.info("All dependencies wired. System ready.")
    yield

    # ── Cleanup ──────────────────────────────────────────────────────
    if _daemon_instance is not None:
        await _daemon_instance.stop()
        _daemon_instance = None

    logger.info("═══ Shutting down Nova Cyber Defense Commander ═══")


app = FastAPI(
    title="Nova Autonomous Cyber Defense Commander",
    description=(
        "Multi-agent AI cybersecurity system that ingests logs, detects anomalies, "
        "classifies threats, simulates impact, executes defensive actions, and "
        "generates reports — powered by Amazon Nova."
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware ──────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(RateLimiter)

# ── Routes ──────────────────────────────────────────────────────────────

app.include_router(router)


# ── CLI entry point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    run_mode = settings.RUN_MODE.lower()

    if run_mode == "daemon":
        # Standalone daemon mode
        from daemon.daemon_service import _run_daemon

        simulate = "--simulate" in sys.argv
        asyncio.run(_run_daemon(simulate=simulate))

    else:
        # API or hybrid mode — let uvicorn handle it
        import uvicorn

        uvicorn.run(
            "main:app",
            host=settings.API_HOST,
            port=settings.API_PORT,
            reload=settings.DEBUG,
            log_level=settings.LOG_LEVEL.lower(),
        )

