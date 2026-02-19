"""
Event models — typed data containers for the event-driven pipeline.

All events are immutable dataclasses with strict typing.
No business logic lives here — pure data carriers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventSeverity(str, Enum):
    """Severity classification for log events."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class LogEvent:
    """A single parsed log event from any source.

    Attributes:
        timestamp: When the event occurred (UTC).
        source_ip: The originating IP address.
        message: The raw log line or parsed message.
        source: Which log source produced this event (e.g. "sshd", "nginx").
        event_type: Classification hint (e.g. "auth_failure", "connection").
        metadata: Additional key-value pairs extracted from the log.
    """

    timestamp: datetime
    source_ip: str
    message: str
    source: str = "unknown"
    event_type: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, line: str, source: str = "unknown") -> LogEvent:
        """Parse a raw log line into a LogEvent.

        Extracts IP addresses and timestamps using simple heuristics.
        Falls back to current time and 'unknown' IP if parsing fails.
        """
        import re

        # Try to extract an IP address
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        source_ip = ip_match.group(1) if ip_match else "0.0.0.0"

        # Classify event type based on keywords
        lower = line.lower()
        if any(kw in lower for kw in ("failed", "denied", "invalid", "unauthorized")):
            event_type = "auth_failure"
        elif any(kw in lower for kw in ("accepted", "success", "authenticated")):
            event_type = "auth_success"
        elif any(kw in lower for kw in ("escalat", "sudo", "root", "privilege")):
            event_type = "privilege_escalation"
        elif any(kw in lower for kw in ("exfil", "transfer", "upload", "download")):
            event_type = "data_transfer"
        else:
            event_type = "general"

        return cls(
            timestamp=datetime.now(timezone.utc),
            source_ip=source_ip,
            message=line.strip(),
            source=source,
            event_type=event_type,
        )


@dataclass(frozen=True)
class IncidentTriggerEvent:
    """Emitted when the threshold engine decides Nova should be activated.

    Attributes:
        source_ip: The IP that triggered the incident.
        suspicion_score: The computed suspicion score at trigger time.
        event_count: Number of events in the current window.
        window_events: The events that make up the suspicious window.
        trigger_time: When the threshold was crossed (UTC).
        trigger_reason: Human-readable reason for the trigger.
    """

    source_ip: str
    suspicion_score: float
    event_count: int
    window_events: list[LogEvent]
    trigger_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    trigger_reason: str = "threshold_exceeded"
