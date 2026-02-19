"""
TelemetryEvent — unified event schema for all sensor sources.

All sensors emit this common model so the correlation engine can
process signals uniformly regardless of origin.

Immutable, JSON-serializable, lightweight validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Literal, Optional
import json


@dataclass(frozen=True)
class TelemetryEvent:
    """A single telemetry observation from any sensor.

    Attributes:
        source: Which sensor produced the event.
        timestamp: When the observation was made (UTC).
        ip: Source/target IP address (if applicable).
        user: Associated username (if applicable).
        process_name: Related process name (if applicable).
        event_type: Classification tag (e.g. ``auth_failure``,
            ``port_scan``, ``shell_spawn``).
        severity_hint: Sensor-provided severity estimate (0.0–1.0).
            This is a *hint* — the correlation engine computes the
            final score.
        raw_payload: Original sensor-specific data for audit/debug.
    """

    source: Literal["log", "network", "auth", "process"]
    timestamp: datetime
    event_type: str
    severity_hint: float = 0.0
    ip: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    raw_payload: dict[str, Any] = field(default_factory=dict)

    # ── Validation ──────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        # Clamp severity_hint to [0, 1]
        if not 0.0 <= self.severity_hint <= 1.0:
            object.__setattr__(
                self, "severity_hint", max(0.0, min(1.0, self.severity_hint))
            )

    # ── Serialization ───────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-friendly dictionary."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TelemetryEvent:
        """Reconstruct from a dictionary."""
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)
