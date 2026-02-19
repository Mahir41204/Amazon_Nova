"""
Async utility helpers for running coroutines from sync agent code.
"""

from __future__ import annotations

import asyncio
from typing import Any, Coroutine


def run_async(coro: Coroutine) -> Any:
    """Run an async coroutine from synchronous code.

    Handles both cases:
    - No event loop running: uses asyncio.run()
    - Event loop already running: creates a new thread with its own loop
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # We're inside an async context (e.g., FastAPI request)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        # No event loop — safe to use asyncio.run()
        return asyncio.run(coro)
