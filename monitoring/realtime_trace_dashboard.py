"""
RealtimeTraceDashboard — console trace renderer for daemon activity.

Renders:
  - Sensor triggered events
  - Correlation score progression
  - Threshold crossings
  - Nova activations
  - Mitigation execution
  - Detection timing

Toggleable via ``ENABLE_TRACE_DASHBOARD`` config flag.
Purely visual — no business logic.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from config.settings import get_settings

logger = logging.getLogger(__name__)


class RealtimeTraceDashboard:
    """Console-based real-time trace renderer.

    Provides clean, formatted output of the detection pipeline
    for demo/debugging purposes. All methods are no-ops if
    ``ENABLE_TRACE_DASHBOARD`` is False in settings.
    """

    def __init__(self) -> None:
        settings = get_settings()
        self._enabled = getattr(settings, "ENABLE_TRACE_DASHBOARD", True)
        self._start_time = time.monotonic()

    def _timestamp(self) -> str:
        """Format current time for display."""
        return datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]

    def _elapsed(self) -> str:
        """Format elapsed time since dashboard start."""
        elapsed = time.monotonic() - self._start_time
        return f"+{elapsed:.1f}s"

    # ── Trace events ────────────────────────────────────────────────────

    def sensor_event(
        self, sensor_name: str, event_count: int, sample_types: list[str]
    ) -> None:
        """Trace a sensor producing events."""
        if not self._enabled:
            return
        types_str = ", ".join(sample_types[:3])
        print(
            f"  [{self._timestamp()}] [SENSOR] [{sensor_name:>8}] "
            f"-> {event_count} events ({types_str})"
        )

    def correlation_update(
        self, ip: str, score: float, source_scores: dict[str, float]
    ) -> None:
        """Trace a correlation score update."""
        if not self._enabled:
            return
        bar = self._score_bar(score)
        sources = " | ".join(
            f"{k}={v:.2f}" for k, v in source_scores.items() if v > 0
        )
        print(
            f"  [{self._timestamp()}] [LINK] {ip:>15} "
            f"score={score:.3f} {bar}  ({sources})"
        )

    def threshold_crossed(
        self, ip: str, score: float, threshold: float
    ) -> None:
        """Trace a threshold crossing."""
        if not self._enabled:
            return
        print(
            f"\n  [{self._timestamp()}] !!! THRESHOLD CROSSED !!!\n"
            f"  |  IP:        {ip}\n"
            f"  |  Score:     {score:.3f} >= {threshold:.3f}\n"
            f"  +- Activating Nova Multi-Agent Brain...\n"
        )

    def nova_activated(
        self, ip: str, latency_ms: float, result_summary: str = ""
    ) -> None:
        """Trace Nova activation and result."""
        if not self._enabled:
            return
        print(
            f"  [{self._timestamp()}] [NOVA] DECISION ({latency_ms:.0f}ms)\n"
            f"  |  IP:     {ip}\n"
            f"  |  Result: {result_summary[:80]}\n"
            f"  +- Passing to enforcement layer...\n"
        )

    def enforcement_action(
        self, action_type: str, target: str, success: bool
    ) -> None:
        """Trace an enforcement action."""
        if not self._enabled:
            return
        icon = "[OK]" if success else "[FAIL]"
        print(
            f"  [{self._timestamp()}] [ENFORCE] {icon} "
            f"{action_type} -> {target}"
        )

    def cooldown_applied(self, ip: str, duration: float) -> None:
        """Trace a cooldown being applied."""
        if not self._enabled:
            return
        print(
            f"  [{self._timestamp()}] [PAUSE] {ip} "
            f"({duration:.0f}s)"
        )

    def metrics_summary(self, metrics: dict[str, Any]) -> None:
        """Render a periodic metrics summary."""
        if not self._enabled:
            return
        print(
            f"\n  +-- METRICS {self._elapsed()} ----------------------\n"
            f"  |  Events/sec:   {metrics.get('events_per_second', 0):.1f}\n"
            f"  |  Active IPs:   {metrics.get('active_suspicious_ips', 0)}\n"
            f"  |  Blocked:      {metrics.get('blocked_ips', 0)}\n"
            f"  |  Nova calls:   {metrics.get('nova_activations', 0)}\n"
            f"  |  Latency:      {metrics.get('avg_detection_latency_ms', 0):.1f}ms\n"
            f"  +---------------------------------------\n"
        )

    def banner(self, sensor_names: list[str]) -> None:
        """Render the daemon startup banner."""
        if not self._enabled:
            return
        sensors = ", ".join(sensor_names) if sensor_names else "none"
        print(
            "\n"
            "  +-------------------------------------------------------+\n"
            "  |       NOVA SENTINEL -- Multi-Source EDR Daemon        |\n"
            "  +-------------------------------------------------------+\n"
            f"  |  Sensors:  {sensors:<42} |\n"
            "  |  Mode:     Event-Driven Autonomous Defense           |\n"
            "  |  Engine:   Multi-Source Correlation + Nova Brain      |\n"
            "  +-------------------------------------------------------+\n"
        )

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _score_bar(score: float, width: int = 20) -> str:
        """Render a simple text progress bar for a score."""
        filled = int(score * width)
        bar = "#" * filled + "-" * (width - filled)
        return f"[{bar}]"

