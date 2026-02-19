"""
FastAPI routes for Nova Autonomous Cyber Defense Commander.

Endpoints:
  POST /auth/token      — Login and get JWT
  POST /analyze-log     — Submit logs for analysis (Admin)
  GET  /incident/{id}   — Retrieve incident details (Admin/Viewer)
  GET  /incidents       — List all incidents (Admin/Viewer)
  POST /simulate        — Run impact simulation (Admin)
  POST /demo            — Run full demo pipeline (Admin)
  GET  /health          — Health check (public)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status

from api.schemas import (
    DemoResponse,
    ErrorResponse,
    HealthResponse,
    IncidentResponse,
    IncidentSummary,
    LogInput,
    SimulationRequest,
    SimulationResponse,
    TokenRequest,
    TokenResponse,
)
from config.settings import get_settings
from core.exceptions import NovaBaseError, ValidationError as NovaValidationError
from core.orchestrator import Orchestrator
from security.auth import (
    Role,
    authenticate_user,
    create_token,
    get_current_user,
    require_role,
)
from security.validation import validate_log_input, validate_threat_type

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Module-level orchestrator reference (set by main.py) ────────────────

_orchestrator: Orchestrator | None = None


def set_orchestrator(orchestrator: Orchestrator) -> None:
    """Set the global orchestrator instance (called during app startup)."""
    global _orchestrator
    _orchestrator = orchestrator


def _get_orchestrator() -> Orchestrator:
    """Get the orchestrator or raise if not initialized."""
    if _orchestrator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Orchestrator not initialized",
        )
    return _orchestrator


# ── Daemon reference (set in hybrid mode) ────────────────────────────────

_daemon: Any = None


def set_daemon(daemon: Any) -> None:
    """Set the daemon instance for realtime status (hybrid mode only)."""
    global _daemon
    _daemon = daemon


# ── Public endpoints ────────────────────────────────────────────────────


@router.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Health check",
)
async def health_check() -> HealthResponse:
    """Return the service health status."""
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        demo_mode=settings.DEMO_MODE,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/realtime/status",
    tags=["System"],
    summary="Real-time daemon metrics",
)
async def realtime_status() -> dict[str, Any]:
    """Return real-time daemon metrics (available in daemon/hybrid modes)."""
    if _daemon is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Daemon not running. Start with RUN_MODE=daemon or RUN_MODE=hybrid",
        )
    return _daemon.get_status()


@router.get(
    "/realtime/telemetry",
    tags=["System"],
    summary="Telemetry sensor and correlation stats",
)
async def realtime_telemetry() -> dict[str, Any]:
    """Return per-sensor event counts, correlation stats, and enforcement status."""
    if _daemon is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Daemon not running. Start with RUN_MODE=daemon or RUN_MODE=hybrid",
        )

    result: dict[str, Any] = {"timestamp": datetime.now(timezone.utc).isoformat()}

    # Sensor stats
    if hasattr(_daemon, "_sensor_manager") and _daemon._sensor_manager:
        result["sensors"] = {}
        for sensor in _daemon._sensor_manager._sensors:
            result["sensors"][sensor.name] = sensor.stats

    # Correlation engine stats
    if hasattr(_daemon, "_correlation_engine") and _daemon._correlation_engine:
        ce = _daemon._correlation_engine
        tracked = ce.window_store.get_stats() if hasattr(ce, "window_store") else {}
        result["correlation"] = {
            "tracked_ips": tracked.get("tracked_ips", 0),
            "total_events": tracked.get("total_events", 0),
        }

    # Suspicion engine stats
    if hasattr(_daemon, "_suspicion_engine") and _daemon._suspicion_engine:
        se = _daemon._suspicion_engine
        tracked_ips = se.get_all_tracked_ips()
        result["suspicion"] = {
            "tracked_ips": len(tracked_ips),
            "escalated_ips": list(tracked_ips)[:20],
        }

    # Firewall stats
    if hasattr(_daemon, "_firewall") and _daemon._firewall:
        result["enforcement"] = _daemon._firewall.get_stats()

    return result


# ── Authentication ──────────────────────────────────────────────────────


@router.post(
    "/auth/token",
    response_model=TokenResponse,
    tags=["Authentication"],
    summary="Login and get JWT token",
)
async def login(request: TokenRequest) -> TokenResponse:
    """Authenticate and receive a JWT token."""
    from starlette.requests import Request

    # Placeholder IP for direct calls (middleware would inject real IP)
    client_ip = "127.0.0.1"

    try:
        user = authenticate_user(request.username, request.password)
    except Exception:
        # Feed failed login to AuthSensor for correlation
        try:
            from telemetry.auth_sensor import AuthSensor
            asyncio.ensure_future(
                AuthSensor.record_failed_login(client_ip, request.username)
            )
        except Exception:
            pass  # sensor not active — ignore
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    settings = get_settings()
    token = create_token(user["username"], user["role"])

    # Feed successful session to AuthSensor
    try:
        from telemetry.auth_sensor import AuthSensor
        asyncio.ensure_future(
            AuthSensor.record_session_creation(client_ip, user["username"])
        )
    except Exception:
        pass  # sensor not active — ignore

    return TokenResponse(
        access_token=token,
        expires_in_minutes=settings.JWT_EXPIRY_MINUTES,
        role=user["role"],
    )


# ── Analysis ────────────────────────────────────────────────────────────


@router.post(
    "/analyze-log",
    tags=["Analysis"],
    summary="Submit logs for full pipeline analysis",
    responses={403: {"model": ErrorResponse}},
)
async def analyze_log(
    request: LogInput,
    user: dict[str, Any] = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Run the full multi-agent analysis pipeline on submitted logs.

    Requires Admin role.
    """
    orchestrator = _get_orchestrator()

    try:
        validated_logs = validate_log_input(request.logs)
        result = await orchestrator.analyze_logs(validated_logs)
        logger.info(
            "Analysis completed for incident %s by user '%s'",
            result.get("incident_id"),
            user.get("username"),
        )
        return result
    except NovaValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message)
    except NovaBaseError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc.message)


# ── Incidents ───────────────────────────────────────────────────────────


@router.get(
    "/incident/{incident_id}",
    tags=["Incidents"],
    summary="Retrieve incident details",
)
async def get_incident(
    incident_id: str,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve a specific incident by ID. Available to Admin and Viewer."""
    orchestrator = _get_orchestrator()
    incident = orchestrator.get_incident(incident_id)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )
    return incident


@router.get(
    "/incidents",
    response_model=list[IncidentSummary],
    tags=["Incidents"],
    summary="List all incidents",
)
async def list_incidents(
    user: dict[str, Any] = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """List all stored incidents. Available to Admin and Viewer."""
    orchestrator = _get_orchestrator()
    return orchestrator.list_incidents()


# ── Simulation ──────────────────────────────────────────────────────────


@router.post(
    "/simulate",
    response_model=SimulationResponse,
    tags=["Simulation"],
    summary="Run impact simulation for a threat type",
)
async def simulate(
    request: SimulationRequest,
    user: dict[str, Any] = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Simulate the impact of a specific threat type.

    Requires Admin role.
    """
    orchestrator = _get_orchestrator()

    try:
        validated_type = validate_threat_type(request.threat_type)
        result = await orchestrator.simulate_threat(validated_type)
        return result
    except NovaValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=exc.message)
    except NovaBaseError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=exc.message)


# ── Demo mode ───────────────────────────────────────────────────────────


@router.post(
    "/demo",
    tags=["Demo"],
    summary="Run full demo pipeline with synthetic attack logs",
)
async def run_demo(
    user: dict[str, Any] = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Run a full demo of the pipeline using synthetic attack logs.

    Generates realistic brute-force attack logs, processes them through
    the entire pipeline, and returns the complete incident report.

    Requires Admin role.
    """
    from demo.synthetic_logs import generate_brute_force_logs

    orchestrator = _get_orchestrator()
    synthetic_logs = generate_brute_force_logs()

    logger.info("Demo mode triggered by user '%s'", user.get("username"))
    result = await orchestrator.analyze_logs(synthetic_logs)

    return {
        "message": "Demo pipeline completed successfully",
        "incident": result,
        "demo_logs_count": len(synthetic_logs),
    }
