"""
LogStreamer — async log file tailer and event producer.

Watches configured log files asynchronously, parses new lines
into ``LogEvent`` objects, and pushes them into an ``EventQueue``.

Also supports programmatic ``feed()`` for daemon demo mode.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from config.settings import get_settings
from events.event_models import LogEvent
from events.event_queue import EventQueue

logger = logging.getLogger(__name__)


class LogStreamer:
    """Async log-file tailer that streams events into an EventQueue.

    Supports:
      - Multiple log sources (configured via ``LOG_SOURCES``)
      - Log rotation detection (inode tracking)
      - Graceful error recovery
      - Programmatic ``feed()`` for demo / test injection

    Usage::

        streamer = LogStreamer(queue)
        await streamer.start()       # starts tailing in background
        streamer.feed(line)          # inject a line programmatically
        await streamer.stop()        # graceful shutdown
    """

    def __init__(
        self,
        queue: EventQueue[LogEvent],
        *,
        poll_interval: float = 0.25,
    ) -> None:
        self._queue = queue
        self._settings = get_settings()
        self._poll_interval = poll_interval
        self._running = False
        self._tasks: list[asyncio.Task[None]] = []
        self._lines_read = 0

    # ── Public API ──────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start tailing all configured log sources."""
        self._running = True
        sources = self._parse_sources()

        if not sources:
            logger.info("LogStreamer: no log sources configured, feed-only mode")
            return

        for source_path, source_name in sources:
            task = asyncio.create_task(
                self._tail_file(source_path, source_name),
                name=f"log-tail-{source_name}",
            )
            self._tasks.append(task)
            logger.info("LogStreamer: tailing %s as '%s'", source_path, source_name)

    async def stop(self) -> None:
        """Stop all tailing tasks gracefully."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        logger.info("LogStreamer: stopped (%d lines read total)", self._lines_read)

    def feed(self, line: str, source: str = "injected") -> bool:
        """Programmatically inject a log line into the event stream.

        Used by daemon demo mode and tests.
        Returns True if the event was enqueued, False if dropped.
        """
        event = LogEvent.from_raw(line, source=source)
        return self._queue.try_put(event)

    def feed_event(self, event: LogEvent) -> bool:
        """Inject a pre-built LogEvent directly."""
        return self._queue.try_put(event)

    @property
    def lines_read(self) -> int:
        return self._lines_read

    @property
    def running(self) -> bool:
        return self._running

    # ── File tailing ────────────────────────────────────────────────────

    async def _tail_file(self, path: str, source_name: str) -> None:
        """Continuously tail a single log file."""
        last_inode: int | None = None
        last_pos: int = 0

        while self._running:
            try:
                if not os.path.exists(path):
                    await asyncio.sleep(self._poll_interval * 4)
                    continue

                # Detect rotation via inode change
                stat = os.stat(path)
                current_inode = stat.st_ino

                if last_inode is not None and current_inode != last_inode:
                    logger.info("LogStreamer: rotation detected for %s", source_name)
                    last_pos = 0

                last_inode = current_inode

                # Read new lines
                if stat.st_size > last_pos:
                    last_pos = await self._read_new_lines(
                        path, source_name, last_pos
                    )
                elif stat.st_size < last_pos:
                    # File was truncated
                    last_pos = 0

                await asyncio.sleep(self._poll_interval)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning(
                    "LogStreamer: error reading %s: %s (retrying)",
                    source_name,
                    exc,
                )
                await asyncio.sleep(self._poll_interval * 2)

    async def _read_new_lines(
        self, path: str, source_name: str, start_pos: int
    ) -> int:
        """Read new lines from a file starting at ``start_pos``.

        Returns the new file position after reading.
        Runs file I/O in an executor to avoid blocking the event loop.
        """
        loop = asyncio.get_running_loop()

        def _read() -> tuple[list[str], int]:
            with open(path, "r", errors="replace") as fh:
                fh.seek(start_pos)
                lines = fh.readlines()
                return lines, fh.tell()

        lines, new_pos = await loop.run_in_executor(None, _read)

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            event = LogEvent.from_raw(stripped, source=source_name)
            self._queue.try_put(event)
            self._lines_read += 1

        return new_pos

    # ── Config parsing ──────────────────────────────────────────────────

    def _parse_sources(self) -> list[tuple[str, str]]:
        """Parse LOG_SOURCES setting into (path, name) pairs.

        Format: ``path1:name1,path2:name2`` or just ``path1,path2``
        """
        raw = self._settings.LOG_SOURCES
        if not raw or not raw.strip():
            return []

        sources: list[tuple[str, str]] = []
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if ":" in entry:
                path, name = entry.rsplit(":", 1)
            else:
                path = entry
                name = Path(entry).stem
            sources.append((path.strip(), name.strip()))

        return sources
