"""
RealtimeDaemon — multi-source event-driven security daemon.

Wires together:
  SensorManager → EventQueue → CorrelationEngine → SuspicionEngine → Orchestrator

Architecture::

    ┌──────────────────────────────────────────────────────────┐
    │                  RealtimeDaemon                          │
    │                                                         │
    │  SensorManager   EventQueue   CorrelationEngine         │
    │   ├─LogSensor ──→  ┌────┐ ──→ weighted scoring          │
    │   ├─NetworkSensor  │buff│     + cross-source rules      │
    │   ├─AuthSensor ──→ │    │                 │              │
    │   └─ProcessSensor  └────┘                 ▼              │
    │                               SuspicionEngine            │
    │                               (cooldown + adaptive)      │
    │                                        │                 │
    │                                        ▼                 │
    │                               Orchestrator               │
    │                            (Nova Multi-Agent Brain)      │
    │                                        │                 │
    │                                        ▼                 │
    │                            SandboxFirewall               │
    │                            (enforce + audit)             │
    └──────────────────────────────────────────────────────────┘

Signal handling: SIGTERM / SIGINT → graceful shutdown.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
import time
from typing import Any

from config.settings import get_settings
from core.orchestrator import Orchestrator
from daemon.worker_pool import WorkerPool
from enforcement.sandbox_firewall import SandboxFirewall
from events.event_models import IncidentTriggerEvent
from events.event_queue import EventQueue
from events.telemetry_event import TelemetryEvent
from memory.incident_repository import IncidentRepository
from core.state_manager import StateManager
from memory.vector_store import VectorStore
from monitoring.metrics_collector import MetricsCollector
from monitoring.realtime_trace_dashboard import RealtimeTraceDashboard
from realtime.correlation_engine import CorrelationEngine
from realtime.suspicion_engine import SuspicionEngine
from services.embeddings_service import EmbeddingsService
from services.nova_client import NovaClient
from services.nova_act_client import NovaActClient
from telemetry.sensor_manager import SensorManager

logger = logging.getLogger(__name__)


class RealtimeDaemon:
    """Nova Sentinel — multi-source event-driven cyber defense daemon.

    Lifecycle:
      1. ``start()`` → initializes sensors, engines, workers
      2. Main loop: collect → correlate → gate → Nova → enforce
      3. ``stop()`` → graceful teardown

    Usage::

        daemon = RealtimeDaemon()
        await daemon.start()
        # ... runs until SIGTERM/SIGINT
        await daemon.stop()
    """

    def __init__(self) -> None:
        self._settings = get_settings()

        # Core components
        self._sensor_manager = SensorManager()
        self._event_queue: EventQueue[TelemetryEvent] = EventQueue()
        self._correlation_engine = CorrelationEngine(
            on_trigger=self._handle_trigger,
        )
        self._suspicion_engine = SuspicionEngine(
            base_threshold=getattr(self._settings, "GLOBAL_SUSPICION_THRESHOLD", 0.85),
        )
        self._firewall = SandboxFirewall()
        self._metrics = MetricsCollector()
        self._dashboard = RealtimeTraceDashboard()
        self._worker_pool = WorkerPool(size=4, name="event-processors")

        # Orchestrator (wired up on start)
        self._orchestrator: Orchestrator | None = None

        # State
        self._running = False
        self._tasks: list[asyncio.Task[None]] = []
        self._total_events = 0

    # ── Lifecycle ───────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start all daemon components and background workers."""
        if self._running:
            return

        self._running = True

        # Create orchestrator
        self._orchestrator = self._create_orchestrator()

        # Start components
        await self._sensor_manager.start()
        await self._worker_pool.start()

        # Print banner
        sensor_names = [s.name for s in self._sensor_manager.sensors]
        self._dashboard.banner(sensor_names)

        # Start background tasks
        self._tasks = [
            asyncio.create_task(self._sensor_poll_loop(), name="sensor-poll"),
            asyncio.create_task(self._correlation_loop(), name="correlation"),
            asyncio.create_task(self._expiry_loop(), name="expiry"),
            asyncio.create_task(self._metrics_loop(), name="metrics"),
        ]

        # Install signal handlers
        self._install_signal_handlers()

        logger.info("🛡️  RealtimeDaemon started (sensors=%d)", len(sensor_names))

    async def stop(self) -> None:
        """Gracefully stop all daemon components."""
        self._running = False

        # Cancel background tasks
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        # Stop components
        await self._sensor_manager.stop()
        await self._worker_pool.stop()

        logger.info(
            "🛡️  RealtimeDaemon stopped (total_events=%d)", self._total_events
        )

    @property
    def running(self) -> bool:
        return self._running

    def get_status(self) -> dict[str, Any]:
        """Build a complete status snapshot."""
        return {
            "running": self._running,
            "total_events": self._total_events,
            "sensors": self._sensor_manager.get_stats(),
            "correlation": self._correlation_engine.get_stats(),
            "suspicion": self._suspicion_engine.get_stats(),
            "firewall": self._firewall.get_stats(),
            "metrics": self._metrics.snapshot(
                suspicious_ips=len(self._suspicion_engine.get_all_tracked_ips()),
                blocked_ips=len(self._firewall.get_blocked_ips()),
                window_stats=self._correlation_engine.window_store.get_stats(),
            ),
            "worker_pool": self._worker_pool.get_stats(),
        }

    # ── Background loops ────────────────────────────────────────────────

    async def _sensor_poll_loop(self) -> None:
        """Collect events from all sensors and feed to correlation engine."""
        while self._running:
            try:
                events = await self._sensor_manager.collect_all()
                if events:
                    self._correlation_engine.ingest_batch(events)
                    self._total_events += len(events)

                    for event in events:
                        self._metrics.record_event()
                        if event.ip:
                            self._suspicion_engine.record_event(event.ip)

                    # Dashboard trace
                    source_types = list(set(e.event_type for e in events))
                    source_name = events[0].source if events else "unknown"
                    self._dashboard.sensor_event(
                        source_name, len(events), source_types
                    )

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("RealtimeDaemon: sensor poll error")

            await asyncio.sleep(1.0)  # Aggregate sensor outputs

    async def _correlation_loop(self) -> None:
        """Periodically evaluate all IPs for correlation threshold crossing."""
        while self._running:
            try:
                # Evaluate all active IPs
                active_ips = self._correlation_engine.window_store.get_active_ips()
                for ip in active_ips:
                    score_info = self._correlation_engine.get_ip_score(ip)
                    total_score = score_info["total_score"]

                    if total_score > 0:
                        self._dashboard.correlation_update(
                            ip, total_score, score_info["source_scores"]
                        )

                    # Check if suspicion engine allows triggering
                    if self._suspicion_engine.should_trigger(ip, total_score):
                        self._suspicion_engine.mark_triggered(ip)
                        self._dashboard.threshold_crossed(
                            ip, total_score,
                            self._suspicion_engine.get_adaptive_threshold(ip)
                        )
                        self._dashboard.cooldown_applied(
                            ip,
                            self._suspicion_engine.get_state(ip).get(
                                "cooldown_remaining", 0
                            ),
                        )

                        # Fire trigger via correlation engine
                        await self._correlation_engine._evaluate_ip(ip)

                # Expire old events
                await self._correlation_engine.window_store.expire_all()

            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("RealtimeDaemon: correlation loop error")

            await asyncio.sleep(2.0)

    async def _expiry_loop(self) -> None:
        """Periodically expire old firewall blocks."""
        while self._running:
            try:
                self._firewall.expire_blocks()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("RealtimeDaemon: expiry loop error")
            await asyncio.sleep(30.0)

    async def _metrics_loop(self) -> None:
        """Periodically log metrics."""
        while self._running:
            try:
                snapshot = self._metrics.snapshot(
                    suspicious_ips=len(
                        self._suspicion_engine.get_all_tracked_ips()
                    ),
                    blocked_ips=len(self._firewall.get_blocked_ips()),
                    window_stats=self._correlation_engine.window_store.get_stats(),
                )
                self._dashboard.metrics_summary(snapshot)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("RealtimeDaemon: metrics loop error")
            await asyncio.sleep(15.0)

    # ── Trigger handling ────────────────────────────────────────────────

    async def _handle_trigger(self, trigger: IncidentTriggerEvent) -> None:
        """Handle an incident trigger — run Nova pipeline and enforce."""
        if not self._orchestrator:
            logger.error("RealtimeDaemon: orchestrator not initialized")
            return

        start = time.perf_counter()

        try:
            result = await self._orchestrator.handle_realtime_incident(
                source_ip=trigger.source_ip,
                event_window=trigger.window_events,
                suspicion_score=trigger.suspicion_score,
            )

            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            self._metrics.record_nova_activation(latency_ms=elapsed_ms)

            # Dashboard trace
            threat_type = "unknown"
            if result and isinstance(result, dict):
                # Orchestrator returns stages nested under "stages" key
                stages = result.get("stages", {})
                threat_type = stages.get("threat_classification", {}).get(
                    "threat_type", "unknown"
                )
            self._dashboard.nova_activated(
                trigger.source_ip, elapsed_ms, f"threat={threat_type}"
            )

            # Enforce — block the IP
            blocked = self._firewall.block(
                trigger.source_ip,
                reason=f"correlated_threat:{trigger.suspicion_score:.2f}",
                incident_id=result.get("incident_id") if isinstance(result, dict) else None,
            )
            self._dashboard.enforcement_action(
                "block_ip", trigger.source_ip, blocked
            )

            logger.info(
                "⚡ RealtimeDaemon: incident handled for %s in %.0fms",
                trigger.source_ip,
                elapsed_ms,
            )

        except Exception:
            logger.exception(
                "RealtimeDaemon: error handling trigger for %s",
                trigger.source_ip,
            )

    # ── Setup helpers ───────────────────────────────────────────────────

    def _create_orchestrator(self) -> Orchestrator:
        """Wire up all orchestrator dependencies."""
        return Orchestrator(
            nova_client=NovaClient(),
            nova_act_client=NovaActClient(),
            embeddings_service=EmbeddingsService(),
            vector_store=VectorStore(),
            incident_repository=IncidentRepository(),
            state_manager=StateManager(),
        )

    def _install_signal_handlers(self) -> None:
        """Install SIGTERM/SIGINT handlers for graceful shutdown."""
        loop = asyncio.get_event_loop()

        def _signal_handler() -> None:
            logger.info("RealtimeDaemon: shutdown signal received")
            asyncio.create_task(self.stop())

        if sys.platform != "win32":
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, _signal_handler)

    # ── Simulation ──────────────────────────────────────────────────────

    async def simulate_multisource_attack(self) -> None:
        """Simulate a coordinated multi-source attack for demonstration.

        Emits events across all 4 sensor types to showcase the
        correlation engine's ability to detect compound threats.
        """
        from datetime import datetime, timezone

        print("\n  [SIM] Starting Multi-Source Attack Simulation...")
        print("  ----------------------------------------------\n")

        target_ip = "10.42.0.99"
        events: list[TelemetryEvent] = []

        # Phase 1: Auth failures (auth sensor)
        print("  Phase 1/4: Authentication Failures")
        for i in range(6):
            events.append(TelemetryEvent(
                source="auth",
                timestamp=datetime.now(timezone.utc),
                event_type="login_brute_force",
                severity_hint=0.5 + (i * 0.05),
                ip=target_ip,
                user=f"admin{i}",
                raw_payload={"attempt": i + 1},
            ))
        self._correlation_engine.ingest_batch(events[-6:])
        await asyncio.sleep(1.5)

        # Phase 2: Network spike (network sensor)
        print("  Phase 2/4: Network Connection Spike")
        for i in range(4):
            events.append(TelemetryEvent(
                source="network",
                timestamp=datetime.now(timezone.utc),
                event_type="connection_spike",
                severity_hint=0.6,
                ip=target_ip,
                raw_payload={"connection_count": 20 + (i * 5)},
            ))
        self._correlation_engine.ingest_batch(events[-4:])
        await asyncio.sleep(1.5)

        # Phase 3: Suspicious log entries (log sensor)
        print("  Phase 3/4: Suspicious Log Entries")
        for i in range(3):
            events.append(TelemetryEvent(
                source="log",
                timestamp=datetime.now(timezone.utc),
                event_type="privilege_escalation",
                severity_hint=0.8,
                ip=target_ip,
                raw_payload={"line": f"sudo: user admin{i} ran /bin/bash"},
            ))
        self._correlation_engine.ingest_batch(events[-3:])
        await asyncio.sleep(1.5)

        # Phase 4: Shell spawn (process sensor)
        print("  Phase 4/4: Shell Spawn Detection")
        events.append(TelemetryEvent(
            source="process",
            timestamp=datetime.now(timezone.utc),
            event_type="shell_spawn",
            severity_hint=0.85,
            ip=target_ip,
            process_name="/bin/bash",
            raw_payload={"parent": "nginx", "pid": 9999},
        ))
        self._correlation_engine.ingest_batch(events[-1:])

        # Score display
        score_info = self._correlation_engine.get_ip_score(target_ip)
        print(f"\n  [INFO] Correlation Score for {target_ip}:")
        for src, s in score_info["source_scores"].items():
            print(f"     {src:>8}: {s:.3f}")
        print(f"     {'boost':>8}: +{score_info['cross_source_boost']:.3f}")
        print(f"     {'TOTAL':>8}: {score_info['total_score']:.3f}")
        print(f"     threshold: {self._suspicion_engine.get_adaptive_threshold(target_ip):.3f}")

        # Trigger evaluation
        await asyncio.sleep(1.0)
        print("\n  [INFO] Evaluating correlation threshold...")
        triggers = await self._correlation_engine.evaluate_all()

        if triggers:
            print(f"\n  [TRIGGER] {len(triggers)} incident(s) triggered!")
            for t in triggers:
                print(f"     IP: {t.source_ip}, Score: {t.suspicion_score:.3f}")
                print(f"     Reason: {t.trigger_reason[:80]}")
        else:
            print("\n  [INFO] No triggers (score below threshold or in cooldown)")

        print("\n  [SIM] Simulation Complete")
        print("  ----------------------------------------------\n")


# ── CLI entry point ─────────────────────────────────────────────────────

async def _run_realtime_daemon(simulate: bool = False) -> None:
    """Run the realtime daemon (standalone mode)."""
    # Ensure UTF-8 on Windows
    if sys.platform == "win32":
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    daemon = RealtimeDaemon()

    try:
        await daemon.start()

        if simulate:
            await daemon.simulate_multisource_attack()
        else:
            # Run until interrupted
            while daemon.running:
                await asyncio.sleep(1.0)

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    finally:
        await daemon.stop()


if __name__ == "__main__":
    simulate = "--simulate" in sys.argv
    asyncio.run(_run_realtime_daemon(simulate=simulate))
