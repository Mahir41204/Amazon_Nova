"""
DaemonLifecycle — startup/shutdown management for Nova Sentinel.

Manages component initialization order, health checks,
and graceful shutdown sequences. Integrates with both
standalone daemon and FastAPI lifespan (hybrid) modes.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from daemon.daemon_service import NovaSentinelDaemon

logger = logging.getLogger(__name__)


class DaemonLifecycle:
    """Manages daemon startup and shutdown sequences.

    Handles:
      - Ordered component initialization
      - Health check validation
      - SIGINT/SIGTERM signal handling
      - Graceful shutdown with timeout

    Usage::

        lifecycle = DaemonLifecycle(daemon)
        await lifecycle.start()
        await lifecycle.wait_for_shutdown()
    """

    def __init__(
        self,
        daemon: NovaSentinelDaemon,
        *,
        shutdown_timeout: float = 10.0,
    ) -> None:
        self._daemon = daemon
        self._shutdown_timeout = shutdown_timeout
        self._shutdown_event = asyncio.Event()
        self._started = False

    # ── Public API ──────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialize all components and start the daemon."""
        logger.info("DaemonLifecycle: starting Nova Sentinel daemon...")
        self._install_signal_handlers()
        await self._daemon.start()
        self._started = True
        logger.info("DaemonLifecycle: daemon started successfully")

    async def wait_for_shutdown(self) -> None:
        """Block until a shutdown signal is received."""
        await self._shutdown_event.wait()
        await self.stop()

    async def stop(self) -> None:
        """Gracefully stop the daemon with timeout."""
        if not self._started:
            return

        logger.info("DaemonLifecycle: shutting down (timeout=%.1fs)...", self._shutdown_timeout)

        try:
            await asyncio.wait_for(
                self._daemon.stop(),
                timeout=self._shutdown_timeout,
            )
        except asyncio.TimeoutError:
            logger.warning("DaemonLifecycle: shutdown timed out, forcing exit")

        self._started = False
        logger.info("DaemonLifecycle: shutdown complete")

    def request_shutdown(self) -> None:
        """Request a graceful shutdown (can be called from signal handler)."""
        logger.info("DaemonLifecycle: shutdown requested")
        self._shutdown_event.set()

    def is_running(self) -> bool:
        return self._started

    def health_check(self) -> dict[str, Any]:
        """Return daemon health status."""
        return {
            "status": "healthy" if self._started else "stopped",
            "started": self._started,
        }

    # ── Signal handling ────────────────────────────────────────────────

    def _install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers for graceful shutdown."""
        loop = asyncio.get_running_loop()

        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, self.request_shutdown)
            logger.debug("DaemonLifecycle: signal handlers installed")
        except NotImplementedError:
            # Windows doesn't support add_signal_handler; fall back
            logger.debug("DaemonLifecycle: signal handlers not supported on this platform")
