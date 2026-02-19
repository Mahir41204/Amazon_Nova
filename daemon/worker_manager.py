"""
WorkerManager — manages background asyncio tasks for the daemon.

Tracks running workers, provides cancellation, automatic restart
on failure, and status reporting.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable, Coroutine

logger = logging.getLogger(__name__)


@dataclass
class WorkerInfo:
    """Metadata for a managed background worker."""

    name: str
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    restart_count: int = 0
    status: str = "running"
    last_error: str | None = None


class WorkerManager:
    """Manages background asyncio tasks with lifecycle control.

    Features:
      - Named worker registration
      - Automatic restart on failure (configurable)
      - Graceful shutdown of all workers
      - Status reporting

    Usage::

        manager = WorkerManager()
        await manager.start_worker("consumer", consumer_coro)
        await manager.stop_all()
    """

    def __init__(self, *, max_restarts: int = 3) -> None:
        self._max_restarts = max_restarts
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._workers: dict[str, WorkerInfo] = {}
        self._factories: dict[str, Callable[[], Coroutine[Any, Any, None]]] = {}
        self._running = False

    # ── Public API ──────────────────────────────────────────────────────

    async def start_worker(
        self,
        name: str,
        coro_factory: Callable[[], Coroutine[Any, Any, None]],
    ) -> None:
        """Start a named background worker.

        Args:
            name: Unique worker name.
            coro_factory: Callable that returns a coroutine (called on each start/restart).
        """
        self._running = True
        self._factories[name] = coro_factory
        self._workers[name] = WorkerInfo(name=name)

        task = asyncio.create_task(
            self._supervised(name, coro_factory),
            name=f"worker-{name}",
        )
        self._tasks[name] = task
        logger.info("WorkerManager: started worker '%s'", name)

    async def stop_worker(self, name: str) -> None:
        """Stop a specific worker by name."""
        task = self._tasks.pop(name, None)
        if task and not task.done():
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=5.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass

        if name in self._workers:
            self._workers[name].status = "stopped"

        logger.info("WorkerManager: stopped worker '%s'", name)

    async def stop_all(self) -> None:
        """Stop all running workers gracefully."""
        self._running = False
        names = list(self._tasks.keys())
        for name in names:
            await self.stop_worker(name)
        logger.info("WorkerManager: all workers stopped")

    def get_status(self) -> dict[str, Any]:
        """Return status of all workers."""
        return {
            name: {
                "status": info.status,
                "started_at": info.started_at.isoformat(),
                "restart_count": info.restart_count,
                "last_error": info.last_error,
            }
            for name, info in self._workers.items()
        }

    @property
    def running(self) -> bool:
        return self._running

    # ── Supervision ────────────────────────────────────────────────────

    async def _supervised(
        self,
        name: str,
        coro_factory: Callable[[], Coroutine[Any, Any, None]],
    ) -> None:
        """Run a worker with automatic restart on failure."""
        info = self._workers[name]

        while self._running and info.restart_count <= self._max_restarts:
            try:
                info.status = "running"
                await coro_factory()
                # If the coroutine returns normally, stop looping
                info.status = "completed"
                break
            except asyncio.CancelledError:
                info.status = "cancelled"
                break
            except Exception as exc:
                info.restart_count += 1
                info.last_error = str(exc)
                info.status = "restarting"
                logger.error(
                    "WorkerManager: worker '%s' failed (%d/%d): %s",
                    name,
                    info.restart_count,
                    self._max_restarts,
                    exc,
                )
                if info.restart_count > self._max_restarts:
                    info.status = "failed"
                    logger.error(
                        "WorkerManager: worker '%s' exceeded max restarts", name
                    )
                    break
                await asyncio.sleep(1.0)  # backoff before restart
