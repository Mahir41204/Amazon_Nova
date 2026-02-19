"""
AuthenticationSensor — application-layer auth anomaly detection.

Integrates with the FastAPI middleware layer to track:
  - Failed login attempts (per IP)
  - Rapid token failures
  - Multiple users from same IP
  - Suspicious session churn

Design:
  - Non-blocking — uses a thread-safe event buffer
  - Async-safe — never blocks request processing
  - Receives events via ``record_*()`` class methods (called from middleware)
  - ``_collect_impl()`` drains the internal observation buffer
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from events.telemetry_event import TelemetryEvent
from telemetry.base_sensor import BaseSensor

logger = logging.getLogger(__name__)

# Thresholds
_FAILED_LOGIN_THRESHOLD = 3       # per IP within window
_RAPID_TOKEN_FAIL_THRESHOLD = 5   # per IP within window
_MULTI_USER_THRESHOLD = 3         # distinct users from same IP
_SESSION_CHURN_THRESHOLD = 10     # sessions created within window
_WINDOW_SECONDS = 60.0


class AuthSensor(BaseSensor):
    """Application-layer authentication anomaly sensor.

    Other components (middleware, auth handlers) call the class-level
    ``record_*()`` methods to push observations. The sensor's poll loop
    then analyses buffered observations and emits TelemetryEvents.
    """

    # Shared observation buffer (class-level so middleware can push without reference)
    _observations: list[dict[str, Any]] = []
    _obs_lock = asyncio.Lock()

    def __init__(self, poll_interval: float = 3.0) -> None:
        super().__init__(poll_interval=poll_interval)
        # Per-IP tracking within window
        self._ip_failures: dict[str, list[float]] = defaultdict(list)
        self._ip_token_failures: dict[str, list[float]] = defaultdict(list)
        self._ip_users: dict[str, set[str]] = defaultdict(set)
        self._ip_sessions: dict[str, list[float]] = defaultdict(list)

    @property
    def name(self) -> str:
        return "auth"

    # ── Class-level recording API (called from middleware) ──────────────

    @classmethod
    async def record_failed_login(cls, ip: str, username: str = "") -> None:
        """Record a failed login attempt."""
        async with cls._obs_lock:
            cls._observations.append({
                "type": "failed_login",
                "ip": ip,
                "user": username,
                "time": time.monotonic(),
            })

    @classmethod
    async def record_token_failure(cls, ip: str) -> None:
        """Record a JWT/token validation failure."""
        async with cls._obs_lock:
            cls._observations.append({
                "type": "token_failure",
                "ip": ip,
                "time": time.monotonic(),
            })

    @classmethod
    async def record_session_creation(cls, ip: str, username: str = "") -> None:
        """Record a new session/token creation."""
        async with cls._obs_lock:
            cls._observations.append({
                "type": "session_created",
                "ip": ip,
                "user": username,
                "time": time.monotonic(),
            })

    # ── Collection ──────────────────────────────────────────────────────

    async def _collect_impl(self) -> list[TelemetryEvent]:
        """Analyse buffered observations and emit anomaly events."""
        # Drain observations
        async with self._obs_lock:
            observations = self._observations.copy()
            self._observations.clear()

        now_mono = time.monotonic()
        now_utc = datetime.now(timezone.utc)
        cutoff = now_mono - _WINDOW_SECONDS
        events: list[TelemetryEvent] = []

        # Process observations
        for obs in observations:
            ip = obs.get("ip", "0.0.0.0")
            obs_time = obs["time"]

            if obs["type"] == "failed_login":
                self._ip_failures[ip].append(obs_time)
                user = obs.get("user", "")
                if user:
                    self._ip_users[ip].add(user)

            elif obs["type"] == "token_failure":
                self._ip_token_failures[ip].append(obs_time)

            elif obs["type"] == "session_created":
                self._ip_sessions[ip].append(obs_time)
                user = obs.get("user", "")
                if user:
                    self._ip_users[ip].add(user)

        # Expire old entries and compute anomalies
        for ip in set(
            list(self._ip_failures) + list(self._ip_token_failures) +
            list(self._ip_sessions)
        ):
            # Prune expired
            self._ip_failures[ip] = [t for t in self._ip_failures[ip] if t > cutoff]
            self._ip_token_failures[ip] = [t for t in self._ip_token_failures[ip] if t > cutoff]
            self._ip_sessions[ip] = [t for t in self._ip_sessions[ip] if t > cutoff]

            # Check failed logins
            fail_count = len(self._ip_failures[ip])
            if fail_count >= _FAILED_LOGIN_THRESHOLD:
                events.append(TelemetryEvent(
                    source="auth",
                    timestamp=now_utc,
                    event_type="login_brute_force",
                    severity_hint=min(0.5 + (fail_count / 20), 0.95),
                    ip=ip,
                    raw_payload={"failed_attempts": fail_count, "window_seconds": _WINDOW_SECONDS},
                ))

            # Check rapid token failures
            token_fails = len(self._ip_token_failures[ip])
            if token_fails >= _RAPID_TOKEN_FAIL_THRESHOLD:
                events.append(TelemetryEvent(
                    source="auth",
                    timestamp=now_utc,
                    event_type="rapid_token_failure",
                    severity_hint=min(0.6 + (token_fails / 25), 0.9),
                    ip=ip,
                    raw_payload={"token_failures": token_fails},
                ))

            # Check multi-user from same IP
            users = self._ip_users.get(ip, set())
            if len(users) >= _MULTI_USER_THRESHOLD:
                events.append(TelemetryEvent(
                    source="auth",
                    timestamp=now_utc,
                    event_type="multi_user_ip",
                    severity_hint=0.65,
                    ip=ip,
                    raw_payload={"distinct_users": len(users), "users": list(users)[:5]},
                ))

            # Check session churn
            session_count = len(self._ip_sessions[ip])
            if session_count >= _SESSION_CHURN_THRESHOLD:
                events.append(TelemetryEvent(
                    source="auth",
                    timestamp=now_utc,
                    event_type="session_churn",
                    severity_hint=0.55,
                    ip=ip,
                    raw_payload={"sessions_created": session_count},
                ))

        return events
