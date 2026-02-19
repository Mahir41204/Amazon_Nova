"""
SensorManager — lifecycle orchestrator for all telemetry sensors.

Responsibilities:
  - Start / stop all enabled sensors based on config
  - Periodically drain sensor buffers and push to EventQueue
  - Isolate sensor failures (one crash doesn't affect others)
  - Provide aggregated sensor statistics
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from config.settings import get_settings
from events.telemetry_event import TelemetryEvent
from telemetry.base_sensor import BaseSensor
from telemetry.log_sensor import LogSensor
from telemetry.network_sensor import NetworkSensor
from telemetry.auth_sensor import AuthSensor
from telemetry.process_sensor import ProcessSensor

logger = logging.getLogger(__name__)


class SensorManager:
    """Manages the lifecycle of all telemetry sensors.

    Usage::

        manager = SensorManager()
        await manager.start()

        # Periodically drain events
        events = await manager.collect_all()

        await manager.stop()
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._sensors: list[BaseSensor] = []
        self._running = False
        self._collection_task: asyncio.Task[None] | None = None
        self._event_buffer: list[TelemetryEvent] = []
        self._lock = asyncio.Lock()
        self._total_collected = 0

    async def start(self) -> None:
        """Initialize and start all enabled sensors."""
        if self._running:
            return

        self._sensors = self._create_sensors()
        if not self._sensors:
            logger.warning("SensorManager: no sensors enabled")
            return

        # Start each sensor independently
        for sensor in self._sensors:
            try:
                await sensor.start()
            except Exception:
                logger.exception("SensorManager: failed to start sensor %s", sensor.name)

        self._running = True
        logger.info(
            "🛰️  SensorManager started: %s",
            ", ".join(s.name for s in self._sensors),
        )

    async def stop(self) -> None:
        """Stop all sensors gracefully."""
        self._running = False

        for sensor in self._sensors:
            try:
                await sensor.stop()
            except Exception:
                logger.exception("SensorManager: error stopping sensor %s", sensor.name)

        logger.info("🛰️  SensorManager stopped (total_collected=%d)", self._total_collected)

    async def collect_all(self) -> list[TelemetryEvent]:
        """Drain events from all sensors. Returns combined event list."""
        all_events: list[TelemetryEvent] = []

        for sensor in self._sensors:
            try:
                events = await sensor.collect()
                all_events.extend(events)
            except Exception:
                logger.exception(
                    "SensorManager: error collecting from sensor %s",
                    sensor.name,
                )

        self._total_collected += len(all_events)
        return all_events

    def get_stats(self) -> dict[str, Any]:
        """Return aggregated sensor statistics."""
        return {
            "running": self._running,
            "total_collected": self._total_collected,
            "sensor_count": len(self._sensors),
            "sensors": {s.name: s.get_stats() for s in self._sensors},
        }

    @property
    def sensors(self) -> list[BaseSensor]:
        return self._sensors

    # ── Private ─────────────────────────────────────────────────────────

    def _create_sensors(self) -> list[BaseSensor]:
        """Create sensor instances based on configuration flags."""
        sensors: list[BaseSensor] = []

        if getattr(self._settings, "ENABLE_LOG_SENSOR", True):
            sensors.append(LogSensor(poll_interval=2.0))

        if getattr(self._settings, "ENABLE_NETWORK_SENSOR", True):
            sensors.append(NetworkSensor(poll_interval=5.0))

        if getattr(self._settings, "ENABLE_AUTH_SENSOR", True):
            sensors.append(AuthSensor(poll_interval=3.0))

        if getattr(self._settings, "ENABLE_PROCESS_SENSOR", True):
            sensors.append(ProcessSensor(poll_interval=10.0))

        return sensors
