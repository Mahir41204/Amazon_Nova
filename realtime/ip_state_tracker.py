"""
IPStateTracker — per-IP state management and cooldown tracking.

Prevents duplicate Nova activations by tracking which IPs have
already triggered incidents and enforcing configurable cooldowns.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from config.settings import get_settings

logger = logging.getLogger(__name__)


@dataclass
class IPState:
    """State record for a single tracked IP address."""

    ip: str
    event_count: int = 0
    first_seen: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    triggered: bool = False
    trigger_time: datetime | None = None
    suspicion_level: float = 0.0


class IPStateTracker:
    """Tracks per-IP state and enforces Nova activation cooldowns.

    Prevents duplicate triggers: once an IP has triggered Nova,
    it enters cooldown and cannot trigger again until the cooldown
    expires (defaults to ``BLOCK_DURATION_SECONDS``).

    Usage::

        tracker = IPStateTracker()
        tracker.update("192.168.1.1", score=0.85)
        if not tracker.has_triggered("192.168.1.1"):
            tracker.mark_triggered("192.168.1.1")
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._states: dict[str, IPState] = {}

    # ── Public API ──────────────────────────────────────────────────────

    def update(self, ip: str, *, score: float = 0.0, events: int = 0) -> IPState:
        """Update state for an IP, creating if necessary."""
        now = datetime.now(timezone.utc)

        if ip not in self._states:
            self._states[ip] = IPState(
                ip=ip,
                event_count=events,
                first_seen=now,
                last_seen=now,
                suspicion_level=score,
            )
        else:
            state = self._states[ip]
            state.last_seen = now
            state.event_count = events
            state.suspicion_level = score

        return self._states[ip]

    def has_triggered(self, ip: str) -> bool:
        """Check if an IP has already triggered and is still in cooldown."""
        state = self._states.get(ip)
        if state is None or not state.triggered:
            return False

        # Check if cooldown has expired
        if state.trigger_time is not None:
            cooldown = timedelta(seconds=self._settings.BLOCK_DURATION_SECONDS)
            if datetime.now(timezone.utc) - state.trigger_time > cooldown:
                state.triggered = False
                state.trigger_time = None
                logger.info("IPStateTracker: cooldown expired for %s", ip)
                return False

        return True

    def mark_triggered(self, ip: str) -> None:
        """Mark an IP as having triggered Nova activation."""
        now = datetime.now(timezone.utc)
        if ip not in self._states:
            self._states[ip] = IPState(ip=ip, first_seen=now, last_seen=now)

        state = self._states[ip]
        state.triggered = True
        state.trigger_time = now
        logger.info("IPStateTracker: marked %s as triggered", ip)

    def reset(self, ip: str) -> None:
        """Reset an IP's trigger state (e.g. after unblock)."""
        if ip in self._states:
            self._states[ip].triggered = False
            self._states[ip].trigger_time = None

    def get_state(self, ip: str) -> IPState | None:
        """Get the current state for an IP."""
        return self._states.get(ip)

    def get_suspicious_ips(self, min_score: float = 0.3) -> list[IPState]:
        """Return all IPs with suspicion level above threshold."""
        return [
            s for s in self._states.values()
            if s.suspicion_level >= min_score
        ]

    def get_triggered_ips(self) -> list[IPState]:
        """Return all IPs currently in triggered/cooldown state."""
        return [s for s in self._states.values() if s.triggered]

    def cleanup_stale(self, max_age_seconds: int = 3600) -> int:
        """Remove IPs not seen recently. Returns count removed."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        stale = [
            ip for ip, s in self._states.items()
            if s.last_seen < cutoff and not s.triggered
        ]
        for ip in stale:
            del self._states[ip]
        return len(stale)

    def get_stats(self) -> dict[str, Any]:
        """Return tracker statistics."""
        return {
            "tracked_ips": len(self._states),
            "triggered_ips": sum(1 for s in self._states.values() if s.triggered),
            "suspicious_ips": sum(
                1 for s in self._states.values() if s.suspicion_level > 0.3
            ),
        }
