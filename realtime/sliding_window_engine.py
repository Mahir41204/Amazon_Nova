"""
SlidingWindowEngine — per-IP rolling time window for event analysis.

Maintains a ``deque`` per IP address with O(1) insertion and automatic
expiry of events older than the configured window duration.

Computes per-IP metrics:
  - Failed attempt count
  - Attempt rate (events/second)
  - Suspicion score (weighted combination)
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from config.settings import get_settings
from events.event_models import LogEvent

logger = logging.getLogger(__name__)


class SlidingWindowEngine:
    """Rolling time-window engine for per-IP event analysis.

    Thread-safe via asyncio.Lock. Designed for high-throughput
    event processing with O(1) insertion.

    Usage::

        engine = SlidingWindowEngine()
        engine.record(event)
        score = engine.get_suspicion_score("192.168.1.1")
        await engine.expire()  # call periodically to clean up
    """

    # Weights for suspicion score computation
    _WEIGHT_FAILED_COUNT = 0.4
    _WEIGHT_RATE = 0.3
    _WEIGHT_ESCALATION = 0.3

    def __init__(self) -> None:
        settings = get_settings()
        self._window_seconds = settings.REALTIME_WINDOW_SECONDS
        self._windows: dict[str, deque[LogEvent]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    # ── Public API ──────────────────────────────────────────────────────

    def record(self, event: LogEvent) -> None:
        """Record an event into the appropriate IP window. O(1)."""
        ip = event.source_ip
        self._windows[ip].append(event)

    def get_window(self, ip: str) -> list[LogEvent]:
        """Return all active events for an IP (after expiry)."""
        self._expire_ip(ip)
        return list(self._windows.get(ip, []))

    def get_event_count(self, ip: str) -> int:
        """Return the number of active events for an IP."""
        self._expire_ip(ip)
        return len(self._windows.get(ip, []))

    def get_failed_count(self, ip: str) -> int:
        """Count auth_failure events for an IP within the window."""
        self._expire_ip(ip)
        window = self._windows.get(ip, [])
        return sum(1 for e in window if e.event_type == "auth_failure")

    def get_attempt_rate(self, ip: str) -> float:
        """Compute events per second for an IP within the window."""
        self._expire_ip(ip)
        window = self._windows.get(ip, [])
        if len(window) < 2:
            return 0.0

        first = window[0].timestamp
        last = window[-1].timestamp
        span = (last - first).total_seconds()
        if span <= 0:
            return float(len(window))

        return len(window) / span

    def get_suspicion_score(self, ip: str) -> float:
        """Compute a normalized suspicion score (0.0–1.0) for an IP.

        Score components:
          - Failed count ratio vs threshold (40%)
          - Attempt rate normalization (30%)
          - Escalation signal presence (30%)
        """
        settings = get_settings()
        threshold = settings.FAILED_ATTEMPT_THRESHOLD

        self._expire_ip(ip)
        window = self._windows.get(ip, [])

        if not window:
            return 0.0

        # Component 1: Failed attempts relative to threshold
        failed = sum(1 for e in window if e.event_type == "auth_failure")
        failed_ratio = min(failed / max(threshold, 1), 1.0)

        # Component 2: Attempt rate (normalize to 1 event/sec = 1.0)
        rate = self.get_attempt_rate(ip)
        rate_score = min(rate / 1.0, 1.0)

        # Component 3: Escalation signals
        has_escalation = any(
            e.event_type == "privilege_escalation" for e in window
        )
        has_success_after_failure = self._detect_success_after_failures(window)
        escalation_score = 0.0
        if has_escalation:
            escalation_score = 1.0
        elif has_success_after_failure:
            escalation_score = 0.6

        score = (
            self._WEIGHT_FAILED_COUNT * failed_ratio
            + self._WEIGHT_RATE * rate_score
            + self._WEIGHT_ESCALATION * escalation_score
        )
        return min(score, 1.0)

    async def expire(self) -> int:
        """Expire old events across all IPs. Returns total events removed."""
        async with self._lock:
            total_removed = 0
            empty_ips: list[str] = []

            for ip in list(self._windows.keys()):
                removed = self._expire_ip(ip)
                total_removed += removed
                if not self._windows[ip]:
                    empty_ips.append(ip)

            for ip in empty_ips:
                del self._windows[ip]

            return total_removed

    def get_active_ips(self) -> list[str]:
        """Return all IPs with active events in their window."""
        return [ip for ip, w in self._windows.items() if w]

    def get_stats(self) -> dict[str, Any]:
        """Return engine statistics."""
        return {
            "active_ips": len(self._windows),
            "total_events": sum(len(w) for w in self._windows.values()),
            "window_seconds": self._window_seconds,
        }

    # ── Internal ────────────────────────────────────────────────────────

    def _expire_ip(self, ip: str) -> int:
        """Remove expired events from a single IP's window."""
        window = self._windows.get(ip)
        if not window:
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(
            seconds=self._window_seconds
        )
        removed = 0
        while window and window[0].timestamp < cutoff:
            window.popleft()
            removed += 1

        return removed

    @staticmethod
    def _detect_success_after_failures(window: deque[LogEvent]) -> bool:
        """Check if there's a success event after failures (breach indicator)."""
        seen_failure = False
        for event in window:
            if event.event_type == "auth_failure":
                seen_failure = True
            elif event.event_type == "auth_success" and seen_failure:
                return True
        return False
