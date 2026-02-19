"""
LogSensor — async log file tailing for security-relevant events.

Streams auth.log and application logs, parsing:
  - Failed SSH / login attempts
  - Successful login after failures
  - sudo / su usage
  - Privilege escalation signals

Handles log rotation and emits severity_hint values.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config.settings import get_settings
from events.telemetry_event import TelemetryEvent
from telemetry.base_sensor import BaseSensor

logger = logging.getLogger(__name__)

# ── Pattern definitions ─────────────────────────────────────────────────

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_USER_RE = re.compile(r"(?:user[= ])(\w+)", re.IGNORECASE)

_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    # (event_type, pattern, severity_hint)
    ("auth_failure", re.compile(
        r"(?i)(failed\s+password|authentication\s+fail|invalid\s+user|"
        r"access\s+denied|unauthorized|login\s+failed)"
    ), 0.6),
    ("auth_success", re.compile(
        r"(?i)(accepted\s+password|session\s+opened|authenticated\s+successfully|"
        r"login\s+success)"
    ), 0.1),
    ("privilege_escalation", re.compile(
        r"(?i)(sudo|su\s*:|root\s+shell|privilege|escalat|"
        r"setuid|capability\s+change)"
    ), 0.8),
    ("data_exfiltration", re.compile(
        r"(?i)(exfil|large\s+transfer|bulk\s+download|unusual\s+upload|"
        r"data\s+export)"
    ), 0.7),
    ("brute_force", re.compile(
        r"(?i)(too\s+many|rate\s+limit|repeated\s+fail|max\s+retries|"
        r"connection\s+refused\s+after)"
    ), 0.75),
    ("suspicious_command", re.compile(
        r"(?i)(/bin/bash|/bin/sh|cmd\.exe|powershell|wget\s+|curl\s+.*\|.*sh|"
        r"base64\s+-d|eval\s*\()"
    ), 0.85),
]


class LogSensor(BaseSensor):
    """Tails configured log files and emits TelemetryEvents.

    Configuration via ``LOG_SOURCES`` in settings:
        ``/path/to/log:name,/other/log:name2``
    """

    def __init__(self, poll_interval: float = 2.0) -> None:
        super().__init__(poll_interval=poll_interval)
        self._file_positions: dict[str, int] = {}
        self._file_inodes: dict[str, int] = {}

    @property
    def name(self) -> str:
        return "log"

    async def _collect_impl(self) -> list[TelemetryEvent]:
        """Read new lines from all configured log sources."""
        settings = get_settings()
        events: list[TelemetryEvent] = []

        # Parse LOG_SOURCES: "path:name,path:name"
        sources = self._parse_sources(settings.LOG_SOURCES)
        if not sources:
            return events

        for path_str, source_name in sources:
            path = Path(path_str)
            if not path.exists():
                continue

            try:
                new_lines = await self._read_new_lines(path)
                for line in new_lines:
                    event = self._parse_line(line.strip(), source_name)
                    if event is not None:
                        events.append(event)
            except Exception:
                logger.exception("LogSensor: error reading %s", path)

        return events

    # ── Parsing ─────────────────────────────────────────────────────────

    def _parse_line(self, line: str, source: str) -> TelemetryEvent | None:
        """Parse a single log line into a TelemetryEvent, or None if benign."""
        if not line:
            return None

        for event_type, pattern, severity in _PATTERNS:
            if pattern.search(line):
                ip_match = _IP_RE.search(line)
                user_match = _USER_RE.search(line)

                return TelemetryEvent(
                    source="log",
                    timestamp=datetime.now(timezone.utc),
                    event_type=event_type,
                    severity_hint=severity,
                    ip=ip_match.group(1) if ip_match else None,
                    user=user_match.group(1) if user_match else None,
                    raw_payload={"line": line, "log_source": source},
                )

        return None  # No match — benign line

    # ── File reading with rotation detection ────────────────────────────

    async def _read_new_lines(self, path: Path) -> list[str]:
        """Read lines added since last poll, detecting log rotation."""
        path_key = str(path)

        try:
            stat = path.stat()
            current_inode = stat.st_ino
        except OSError:
            return []

        # Detect rotation: inode changed or file shrunk
        prev_inode = self._file_inodes.get(path_key)
        prev_pos = self._file_positions.get(path_key, 0)

        if prev_inode is not None and current_inode != prev_inode:
            logger.info("LogSensor: rotation detected for %s", path)
            prev_pos = 0

        if stat.st_size < prev_pos:
            logger.info("LogSensor: file truncated %s", path)
            prev_pos = 0

        self._file_inodes[path_key] = current_inode

        # Read new content
        loop = asyncio.get_event_loop()
        lines = await loop.run_in_executor(
            None, self._read_from_position, path, prev_pos
        )

        # Update position
        self._file_positions[path_key] = prev_pos + sum(
            len(l.encode()) + 1 for l in lines  # +1 for newline
        )

        return lines

    @staticmethod
    def _read_from_position(path: Path, position: int) -> list[str]:
        """Synchronous file read from a byte position."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(position)
                return f.readlines()
        except Exception:
            return []

    @staticmethod
    def _parse_sources(log_sources: str) -> list[tuple[str, str]]:
        """Parse 'path:name,path:name' config string."""
        if not log_sources.strip():
            return []
        results = []
        for entry in log_sources.split(","):
            entry = entry.strip()
            if ":" in entry:
                path, name = entry.rsplit(":", 1)
                results.append((path.strip(), name.strip()))
        return results
