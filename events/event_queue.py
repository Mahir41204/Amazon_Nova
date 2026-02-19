"""
EventQueue — async event queue with backpressure and metrics.

Wraps ``asyncio.Queue`` to provide:
  - Configurable max size (backpressure)
  - Metrics tracking (enqueued, dropped, peak depth)
  - Non-blocking ``try_put`` for producers
  - Graceful ``drain`` for shutdown
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from config.settings import get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class QueueMetrics:
    """Snapshot of queue health metrics."""

    enqueued: int = 0
    dequeued: int = 0
    dropped: int = 0
    peak_depth: int = 0
    current_depth: int = 0


class EventQueue(Generic[T]):
    """Async event queue with backpressure control.

    When the queue is full, ``try_put`` drops the event and
    increments the ``dropped`` counter rather than blocking —
    ensuring producers never stall.

    Usage::

        queue = EventQueue[LogEvent]()
        await queue.put(event)        # blocks if full
        queue.try_put(event)          # drops if full
        event = await queue.get()     # blocks until available
    """

    def __init__(self, max_size: int | None = None) -> None:
        settings = get_settings()
        self._max_size = max_size or settings.EVENT_QUEUE_MAX_SIZE
        self._queue: asyncio.Queue[T] = asyncio.Queue(maxsize=self._max_size)
        self._enqueued = 0
        self._dequeued = 0
        self._dropped = 0
        self._peak_depth = 0

    # ── Producer API ────────────────────────────────────────────────────

    async def put(self, item: T) -> None:
        """Put an item, blocking if the queue is full."""
        await self._queue.put(item)
        self._enqueued += 1
        self._track_peak()

    def try_put(self, item: T) -> bool:
        """Non-blocking put — returns False and increments drop counter if full."""
        try:
            self._queue.put_nowait(item)
            self._enqueued += 1
            self._track_peak()
            return True
        except asyncio.QueueFull:
            self._dropped += 1
            if self._dropped % 100 == 1:
                logger.warning(
                    "Event queue full (max=%d). Total dropped: %d",
                    self._max_size,
                    self._dropped,
                )
            return False

    # ── Consumer API ────────────────────────────────────────────────────

    async def get(self) -> T:
        """Get the next item, blocking until available."""
        item = await self._queue.get()
        self._dequeued += 1
        return item

    def task_done(self) -> None:
        """Mark a dequeued item as processed."""
        self._queue.task_done()

    # ── Control ─────────────────────────────────────────────────────────

    async def drain(self, timeout: float = 5.0) -> int:
        """Drain remaining items during shutdown. Returns count drained."""
        drained = 0
        try:
            while not self._queue.empty():
                await asyncio.wait_for(self._queue.get(), timeout=timeout)
                drained += 1
        except (asyncio.TimeoutError, Exception):
            pass
        return drained

    # ── Properties ──────────────────────────────────────────────────────

    @property
    def depth(self) -> int:
        """Current queue depth."""
        return self._queue.qsize()

    @property
    def empty(self) -> bool:
        return self._queue.empty()

    @property
    def full(self) -> bool:
        return self._queue.full()

    def metrics(self) -> QueueMetrics:
        """Return a snapshot of queue metrics."""
        return QueueMetrics(
            enqueued=self._enqueued,
            dequeued=self._dequeued,
            dropped=self._dropped,
            peak_depth=self._peak_depth,
            current_depth=self.depth,
        )

    # ── Internal ────────────────────────────────────────────────────────

    def _track_peak(self) -> None:
        current = self.depth
        if current > self._peak_depth:
            self._peak_depth = current
