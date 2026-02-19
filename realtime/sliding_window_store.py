"""
SlidingWindowStore — generic time-windowed storage for TelemetryEvents.

Maintains per-key (typically per-IP) deques of events with automatic
expiry of events older than the configured window duration.

Used by the CorrelationEngine for multi-source aggregation.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from events.telemetry_event import TelemetryEvent

logger = logging.getLogger(__name__)


class SlidingWindowStore:
    """Time-windowed event store keyed by IP address.

    Supports per-source sub-windows for correlation:
      - ``get_by_source(ip, "log")`` → events from log sensor only
      - ``get_all(ip)`` → all events for an IP

    Thread-safe via asyncio.Lock.

    Usage::

        store = SlidingWindowStore(window_seconds=60)
        store.record(event)
        log_events = store.get_by_source("10.0.0.1", "log")
        score = store.get_source_counts("10.0.0.1")
    """

    def __init__(self, window_seconds: int = 60) -> None:
        self._window_seconds = window_seconds
        # Primary store: IP → deque of events
        self._windows: dict[str, deque[TelemetryEvent]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    # ── Recording ───────────────────────────────────────────────────────

    def record(self, event: TelemetryEvent) -> None:
        """Record a telemetry event into the appropriate IP window."""
        key = event.ip or "__global__"
        self._windows[key].append(event)

    # ── Queries ─────────────────────────────────────────────────────────

    def get_all(self, ip: str) -> list[TelemetryEvent]:
        """Return all active events for an IP (after expiry)."""
        self._expire_key(ip)
        return list(self._windows.get(ip, []))

    def get_by_source(
        self, ip: str, source: str
    ) -> list[TelemetryEvent]:
        """Return events for an IP from a specific source."""
        self._expire_key(ip)
        return [
            e for e in self._windows.get(ip, [])
            if e.source == source
        ]

    def get_event_count(self, ip: str) -> int:
        """Total event count for an IP within the window."""
        self._expire_key(ip)
        return len(self._windows.get(ip, []))

    def get_source_counts(self, ip: str) -> dict[str, int]:
        """Return event counts per source for an IP."""
        self._expire_key(ip)
        counts: dict[str, int] = defaultdict(int)
        for event in self._windows.get(ip, []):
            counts[event.source] += 1
        return dict(counts)

    def get_max_severity(self, ip: str, source: str | None = None) -> float:
        """Return the maximum severity_hint for an IP, optionally per source."""
        self._expire_key(ip)
        events = self._windows.get(ip, [])
        if source:
            events = [e for e in events if e.source == source]
        if not events:
            return 0.0
        return max(e.severity_hint for e in events)

    def get_active_ips(self) -> list[str]:
        """Return all IPs with active events."""
        return [ip for ip, w in self._windows.items() if w and ip != "__global__"]

    def get_stats(self) -> dict[str, Any]:
        """Return store statistics."""
        return {
            "active_ips": len(self.get_active_ips()),
            "total_events": sum(len(w) for w in self._windows.values()),
            "window_seconds": self._window_seconds,
        }

    # ── Maintenance ─────────────────────────────────────────────────────

    async def expire_all(self) -> int:
        """Expire old events across all IPs. Returns total events removed."""
        async with self._lock:
            total_removed = 0
            empty_keys: list[str] = []

            for key in list(self._windows.keys()):
                removed = self._expire_key(key)
                total_removed += removed
                if not self._windows[key]:
                    empty_keys.append(key)

            for key in empty_keys:
                del self._windows[key]

            return total_removed

    # ── Internal ────────────────────────────────────────────────────────

    def _expire_key(self, key: str) -> int:
        """Remove expired events from a single key's window."""
        window = self._windows.get(key)
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
