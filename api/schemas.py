"""
Pydantic schemas for all API request / response payloads.

Provides strict type validation and auto-generated OpenAPI documentation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Request schemas ─────────────────────────────────────────────────────


class TokenRequest(BaseModel):
    """Login credentials."""

    username: str = Field(..., min_length=1, max_length=100, description="Username")
    password: str = Field(..., min_length=1, max_length=100, description="Password")


class LogInput(BaseModel):
    """Raw log submission for analysis."""

    logs: list[str] = Field(
        ...,
        min_length=1,
        max_length=10_000,
        description="List of raw log lines to analyze",
    )


class SimulationRequest(BaseModel):
    """Impact simulation request."""

    threat_type: str = Field(
        ...,
        description="Type of threat to simulate (e.g. brute_force, malware, phishing, data_exfiltration, privilege_escalation)",
    )


# ── Response schemas ────────────────────────────────────────────────────


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    role: str


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    service: str = "Nova Autonomous Cyber Defense Commander"
    version: str = "1.0.0"
    demo_mode: bool
    timestamp: str


class ErrorResponse(BaseModel):
    """Structured error response."""

    error: str
    detail: str
    status_code: int


class PatternDetail(BaseModel):
    """A detected suspicious pattern."""

    pattern_type: str
    description: str
    severity: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    target: Optional[str] = None
    count: Optional[int] = None


class ActionDetail(BaseModel):
    """A defensive action taken or deferred."""

    action_type: str
    target: str
    success: Optional[bool] = None
    simulated: Optional[bool] = None
    timestamp: Optional[str] = None
    reason: Optional[str] = None
    details: Optional[dict[str, Any]] = None
    execution_time_ms: Optional[float] = None


class ReportOutput(BaseModel):
    """Report output from the reporting agent."""

    executive_summary: str
    technical_report: str
    prevention_recommendations: list[str]


class IncidentSummary(BaseModel):
    """Lightweight incident summary for listing."""

    incident_id: str
    status: str
    created_at: str
    updated_at: str


class IncidentResponse(BaseModel):
    """Full incident response with all pipeline outputs."""

    incident_id: str
    status: str
    created_at: str
    updated_at: str
    stages: dict[str, Any] = Field(default_factory=dict)
    decision_log: list[dict[str, Any]] = Field(default_factory=list)


class SimulationResponse(BaseModel):
    """Impact simulation response."""

    affected_systems: list[str]
    risk_level: str
    estimated_downtime: str
    estimated_financial_impact: str
    blast_radius: str
    severity_score: float
    scenario_description: str


class DemoResponse(BaseModel):
    """Demo mode pipeline response."""

    message: str
    incident: IncidentResponse
    report: Optional[dict[str, Any]] = None
