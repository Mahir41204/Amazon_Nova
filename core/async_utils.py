"""
Async utility helpers for running coroutines from sync agent code.

NOTE: After the async refactor, agents should directly ``await`` async
calls instead of using ``run_async()``.  This module is kept for any
remaining edge-case callers.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from typing import Any, Coroutine

# Module-level singleton pool (lazy-init, max 4 threads)
_pool: concurrent.futures.ThreadPoolExecutor | None = None


def _get_pool() -> concurrent.futures.ThreadPoolExecutor:
    global _pool
    if _pool is None:
        _pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    return _pool


def run_async(coro: Coroutine) -> Any:
    """Run an async coroutine from synchronous code.

    Handles both cases:
    - No event loop running: uses asyncio.run()
    - Event loop already running: dispatches to a shared thread pool

    .. note::
       Prefer ``await`` directly where possible.  This helper exists
       only for sync call-sites that cannot be easily made async.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # Inside an async context — run in a background thread
        return _get_pool().submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


def shutdown_async_pool() -> None:
    """Shut down the shared thread pool (call at application exit)."""
    global _pool
    if _pool is not None:
        _pool.shutdown(wait=False)
        _pool = None
