"""
ProcessSensor — system process monitoring for suspicious activity.

Uses ``psutil.process_iter()`` to detect:
  - Unexpected parent→child relationships (nginx → /bin/bash)
  - CPU spikes from suspicious processes
  - Shell spawned by web server
  - Known suspicious process names

Design:
  - Efficient — caches known PIDs, only scans deltas
  - Configurable poll interval
  - Avoids scanning entire process tree constantly
  - Falls back gracefully if psutil unavailable
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from events.telemetry_event import TelemetryEvent
from telemetry.base_sensor import BaseSensor

logger = logging.getLogger(__name__)

# Suspicious process name patterns
_SUSPICIOUS_NAMES = re.compile(
    r"(?i)(ncat|netcat|nc\.exe|socat|msfconsole|msfvenom|"
    r"mimikatz|lazagne|bloodhound|Empire|cobaltstrike|"
    r"reverse_tcp|bind_shell|webshell|c2_agent|"
    r"cryptominer|xmrig|minerd)"
)

# Suspicious parent→child relationships
_SUSPICIOUS_PARENT_CHILD: list[tuple[re.Pattern[str], re.Pattern[str]]] = [
    (re.compile(r"(?i)(nginx|apache|httpd|uwsgi|gunicorn)"), re.compile(r"(?i)(bash|sh|cmd|powershell|python|perl|ruby)")),
    (re.compile(r"(?i)(sshd)"), re.compile(r"(?i)(wget|curl|nc|ncat)")),
    (re.compile(r"(?i)(java|node|python)"), re.compile(r"(?i)(bash|sh|cmd|powershell)")),
]

# CPU threshold for flagging a process (fraction, e.g. 80%)
_CPU_THRESHOLD = 80.0


class ProcessSensor(BaseSensor):
    """Monitor running processes for suspicious activity.

    Maintains a set of known PIDs to detect *new* process creation
    efficiently — only new processes are fully inspected.
    """

    def __init__(self, poll_interval: float = 10.0) -> None:
        super().__init__(poll_interval=poll_interval)
        self._known_pids: set[int] = set()
        self._initialized = False

    @property
    def name(self) -> str:
        return "process"

    async def _collect_impl(self) -> list[TelemetryEvent]:
        """Scan for suspicious processes (delta-based)."""
        try:
            import psutil
        except ImportError:
            logger.debug("ProcessSensor: psutil not available, skipping")
            return []

        events: list[TelemetryEvent] = []
        now = datetime.now(timezone.utc)
        current_pids: set[int] = set()

        try:
            for proc in psutil.process_iter(
                attrs=["pid", "name", "ppid", "username", "cpu_percent", "cmdline"]
            ):
                try:
                    info = proc.info
                    pid = info["pid"]
                    current_pids.add(pid)

                    # Skip kernel/system PIDs
                    if pid <= 4:
                        continue

                    proc_name = info.get("name") or ""
                    username = info.get("username") or ""
                    cpu = info.get("cpu_percent") or 0.0
                    cmdline = info.get("cmdline") or []

                    # Only deeply inspect NEW processes (after first scan)
                    is_new = pid not in self._known_pids and self._initialized

                    # Check 1: Suspicious process names
                    if _SUSPICIOUS_NAMES.search(proc_name):
                        events.append(TelemetryEvent(
                            source="process",
                            timestamp=now,
                            event_type="suspicious_process",
                            severity_hint=0.9,
                            process_name=proc_name,
                            user=username,
                            raw_payload={
                                "pid": pid,
                                "cmdline": " ".join(cmdline[:5]),
                                "is_new": is_new,
                            },
                        ))

                    # Check 2: Suspicious parent→child (only for new processes)
                    if is_new:
                        parent = self._get_parent_name(info.get("ppid"), psutil)
                        if parent:
                            for parent_pat, child_pat in _SUSPICIOUS_PARENT_CHILD:
                                if parent_pat.search(parent) and child_pat.search(proc_name):
                                    events.append(TelemetryEvent(
                                        source="process",
                                        timestamp=now,
                                        event_type="shell_spawn",
                                        severity_hint=0.85,
                                        process_name=proc_name,
                                        user=username,
                                        raw_payload={
                                            "pid": pid,
                                            "parent": parent,
                                            "ppid": info.get("ppid"),
                                            "cmdline": " ".join(cmdline[:5]),
                                        },
                                    ))
                                    break

                    # Check 3: CPU spike + suspicious name (any process)
                    if cpu >= _CPU_THRESHOLD and _SUSPICIOUS_NAMES.search(proc_name):
                        events.append(TelemetryEvent(
                            source="process",
                            timestamp=now,
                            event_type="cpu_spike_suspicious",
                            severity_hint=min(0.7 + (cpu / 200), 0.95),
                            process_name=proc_name,
                            user=username,
                            raw_payload={
                                "pid": pid,
                                "cpu_percent": cpu,
                            },
                        ))

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception:
            logger.exception("ProcessSensor: error scanning processes")
            return events

        # Update known PIDs
        self._known_pids = current_pids
        self._initialized = True

        return events

    @staticmethod
    def _get_parent_name(ppid: int | None, psutil_mod: Any) -> str | None:
        """Get the name of a parent process by PID."""
        if ppid is None or ppid <= 0:
            return None
        try:
            parent = psutil_mod.Process(ppid)
            return parent.name()
        except (psutil_mod.NoSuchProcess, psutil_mod.AccessDenied):
            return None
