"""
MetricsCollector — real-time observability counters for the daemon.

Tracks key performance indicators and exposes them via a ``snapshot()``
method for API consumption (``GET /realtime/status``).
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DaemonMetrics:
    """Snapshot of daemon health metrics."""

    # Throughput
    events_per_second: float = 0.0
    total_events_processed: int = 0

    # Detection
    active_suspicious_ips: int = 0
    blocked_ips: int = 0
    nova_activations: int = 0
    avg_detection_latency_ms: float = 0.0

    # Queue health
    queue_depth: int = 0
    queue_dropped: int = 0

    # Uptime
    uptime_seconds: float = 0.0
    started_at: str = ""

    # Component stats
    window_engine: dict[str, Any] = field(default_factory=dict)
    threshold_engine: dict[str, Any] = field(default_factory=dict)
    firewall: dict[str, Any] = field(default_factory=dict)
    ip_tracker: dict[str, Any] = field(default_factory=dict)


class MetricsCollector:
    """Centralized metrics collection for the Nova Sentinel daemon.

    Uses a sliding window of recent event timestamps to compute
    events/second in real time.

    Usage::

        metrics = MetricsCollector()
        metrics.record_event()
        metrics.record_nova_activation(latency_ms=45.2)
        snapshot = metrics.snapshot()
    """

    def __init__(self) -> None:
        self._start_time = time.monotonic()
        self._started_at = datetime.now(timezone.utc)

        # Event rate tracking (1-second sliding window of event timestamps)
        self._event_times: deque[float] = deque()
        self._total_events = 0

        # Nova activations
        self._nova_activations = 0
        self._detection_latencies: deque[float] = deque(maxlen=100)

        # Per-sensor metrics
        self._sensor_events: dict[str, int] = {
            "log": 0, "network": 0, "auth": 0, "process": 0,
        }

    # ── Recording ───────────────────────────────────────────────────────

    def record_event(self) -> None:
        """Record that an event was processed."""
        self._total_events += 1
        self._event_times.append(time.monotonic())

    def record_sensor_event(self, source: str) -> None:
        """Record an event from a specific sensor source."""
        self._sensor_events[source] = self._sensor_events.get(source, 0) + 1

    def record_nova_activation(self, latency_ms: float = 0.0) -> None:
        """Record a Nova activation with detection latency."""
        self._nova_activations += 1
        if latency_ms > 0:
            self._detection_latencies.append(latency_ms)

    # ── Queries ─────────────────────────────────────────────────────────

    def events_per_second(self) -> float:
        """Compute current events/second from recent timestamps."""
        now = time.monotonic()
        cutoff = now - 5.0  # 5-second window

        # Prune old timestamps
        while self._event_times and self._event_times[0] < cutoff:
            self._event_times.popleft()

        if not self._event_times:
            return 0.0

        span = now - self._event_times[0]
        if span <= 0:
            return float(len(self._event_times))

        return len(self._event_times) / span

    def avg_detection_latency(self) -> float:
        """Average detection latency in milliseconds (last 100 activations)."""
        if not self._detection_latencies:
            return 0.0
        return sum(self._detection_latencies) / len(self._detection_latencies)

    def uptime_seconds(self) -> float:
        """Daemon uptime in seconds."""
        return time.monotonic() - self._start_time

    def snapshot(
        self,
        *,
        queue_depth: int = 0,
        queue_dropped: int = 0,
        suspicious_ips: int = 0,
        blocked_ips: int = 0,
        window_stats: dict[str, Any] | None = None,
        threshold_stats: dict[str, Any] | None = None,
        firewall_stats: dict[str, Any] | None = None,
        tracker_stats: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a complete metrics snapshot for API consumption."""
        return {
            "events_per_second": round(self.events_per_second(), 2),
            "total_events_processed": self._total_events,
            "active_suspicious_ips": suspicious_ips,
            "blocked_ips": blocked_ips,
            "nova_activations": self._nova_activations,
            "avg_detection_latency_ms": round(self.avg_detection_latency(), 2),
            "queue_depth": queue_depth,
            "queue_dropped": queue_dropped,
            "uptime_seconds": round(self.uptime_seconds(), 1),
            "started_at": self._started_at.isoformat(),
            "sensor_events": dict(self._sensor_events),
            "components": {
                "window_engine": window_stats or {},
                "threshold_engine": threshold_stats or {},
                "firewall": firewall_stats or {},
                "ip_tracker": tracker_stats or {},
            },
        }
