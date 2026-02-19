"""
WorkerPool — configurable async worker pool for event processing.

Provides supervised, bounded concurrency for event consumers
with backpressure support and task monitoring.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)


class WorkerPool:
    """Async worker pool with backpressure and supervision.

    Usage::

        pool = WorkerPool(size=4, name="event-processors")
        await pool.start()
        await pool.submit(process_event, event)
        await pool.stop()
    """

    def __init__(self, size: int = 4, name: str = "workers") -> None:
        self._size = size
        self._name = name
        self._queue: asyncio.Queue[tuple[Callable[..., Awaitable[Any]], tuple[Any, ...]]] = asyncio.Queue(
            maxsize=size * 10
        )
        self._workers: list[asyncio.Task[None]] = []
        self._running = False
        self._processed = 0
        self._errors = 0

    async def start(self) -> None:
        """Start all workers."""
        if self._running:
            return
        self._running = True
        for i in range(self._size):
            task = asyncio.create_task(
                self._worker_loop(i), name=f"{self._name}-{i}"
            )
            self._workers.append(task)
        logger.info("WorkerPool [%s] started with %d workers", self._name, self._size)

    async def stop(self) -> None:
        """Gracefully stop all workers."""
        self._running = False

        # Drain remaining items
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
            except asyncio.QueueEmpty:
                break

        # Cancel workers
        for worker in self._workers:
            worker.cancel()

        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        logger.info(
            "WorkerPool [%s] stopped (processed=%d, errors=%d)",
            self._name, self._processed, self._errors,
        )

    async def submit(self, func: Callable[..., Awaitable[Any]], *args: Any) -> bool:
        """Submit work to the pool. Returns False if pool is full (backpressure)."""
        try:
            self._queue.put_nowait((func, args))
            return True
        except asyncio.QueueFull:
            logger.warning("WorkerPool [%s]: backpressure — queue full", self._name)
            return False

    def get_stats(self) -> dict[str, Any]:
        """Return pool statistics."""
        return {
            "name": self._name,
            "size": self._size,
            "running": self._running,
            "queue_depth": self._queue.qsize(),
            "processed": self._processed,
            "errors": self._errors,
        }

    async def _worker_loop(self, worker_id: int) -> None:
        """Individual worker loop."""
        while self._running:
            try:
                func, args = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0
                )
                try:
                    await func(*args)
                    self._processed += 1
                except Exception:
                    self._errors += 1
                    logger.exception(
                        "WorkerPool [%s] worker-%d task error",
                        self._name, worker_id,
                    )
                finally:
                    self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
