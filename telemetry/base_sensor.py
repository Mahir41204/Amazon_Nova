"""
BaseSensor — abstract interface for all telemetry sensors.

Every sensor follows the same lifecycle:
  1. ``start()`` — begin background collection
  2. ``collect()`` — return buffered events since last call
  3. ``stop()`` — gracefully shut down

Sensors are:
  - Independent (run in their own async tasks)
  - Non-blocking (never pause the event loop)
  - Isolated (a crash in one sensor does not affect others)
  - Free of Nova logic (heuristics only — Nova decides downstream)
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any

from events.telemetry_event import TelemetryEvent

logger = logging.getLogger(__name__)


class BaseSensor(ABC):
    """Abstract base class for all telemetry sensors.

    Subclasses must implement:
      - ``_collect_impl()`` — the actual collection logic
      - ``name`` property — unique sensor identifier

    The base class provides:
      - Lifecycle management (start/stop)
      - Continuous polling loop with configurable interval
      - Error isolation (exceptions are logged, not propagated)
      - Event buffering (thread-safe via asyncio.Lock)
    """

    def __init__(self, poll_interval: float = 5.0) -> None:
        self._poll_interval = poll_interval
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._buffer: list[TelemetryEvent] = []
        self._lock = asyncio.Lock()

        # Stats
        self._total_events = 0
        self._total_errors = 0

    # ── Abstract interface ──────────────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this sensor (e.g. ``'log'``, ``'network'``)."""
        ...

    @abstractmethod
    async def _collect_impl(self) -> list[TelemetryEvent]:
        """Perform one collection cycle. Return new events."""
        ...

    # ── Lifecycle ───────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the sensor's background polling loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop(), name=f"sensor-{self.name}")
        logger.info("🛰️  Sensor [%s] started (poll=%.1fs)", self.name, self._poll_interval)

    async def stop(self) -> None:
        """Gracefully stop the sensor."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("🛰️  Sensor [%s] stopped (total_events=%d)", self.name, self._total_events)

    async def collect(self) -> list[TelemetryEvent]:
        """Drain the event buffer. Returns all events since last call."""
        async with self._lock:
            events = self._buffer.copy()
            self._buffer.clear()
        return events

    @property
    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> dict[str, Any]:
        """Return sensor statistics."""
        return {
            "name": self.name,
            "running": self._running,
            "total_events": self._total_events,
            "total_errors": self._total_errors,
            "buffer_size": len(self._buffer),
            "poll_interval": self._poll_interval,
        }

    # ── Internal ────────────────────────────────────────────────────────

    async def _poll_loop(self) -> None:
        """Continuous polling loop with error isolation."""
        while self._running:
            try:
                events = await self._collect_impl()
                if events:
                    async with self._lock:
                        self._buffer.extend(events)
                    self._total_events += len(events)
            except asyncio.CancelledError:
                break
            except Exception:
                self._total_errors += 1
                logger.exception("Sensor [%s] collection error", self.name)

            await asyncio.sleep(self._poll_interval)
