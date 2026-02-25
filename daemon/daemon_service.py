"""
NovaSentinelDaemon — the main event-driven cyber defense daemon.

Wires together all event-driven components and runs as a continuous
background service that:

  1. Streams log events from configured sources
  2. Feeds events through the sliding window engine
  3. Triggers Nova multi-agent pipeline when thresholds cross
  4. Enforces sandbox blocks on identified threats
  5. Tracks real-time metrics for observability

Can run standalone (``python -m daemon.daemon_service``),
or integrated into FastAPI via hybrid mode.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from datetime import datetime, timezone
from typing import Any

# Ensure project root is importable
sys.path.insert(0, ".")

from config.settings import get_settings
from core.orchestrator import Orchestrator
from core.state_manager import StateManager
from core.trace_dashboard import TraceRenderer
from daemon.worker_manager import WorkerManager
from enforcement.block_manager import BlockManager
from enforcement.sandbox_firewall import SandboxFirewall
from events.event_models import LogEvent, IncidentTriggerEvent
from events.event_queue import EventQueue
from events.log_streamer import LogStreamer
from memory.incident_repository import IncidentRepository
from memory.vector_store import VectorStore
from monitoring.metrics_collector import get_global_metrics
from realtime.ip_state_tracker import IPStateTracker
from realtime.sliding_window_engine import SlidingWindowEngine
from realtime.threshold_engine import ThresholdEngine
from services.embeddings_service import EmbeddingsService
from services.nova_client import NovaClient
from services.nova_act_client import NovaActClient

logger = logging.getLogger(__name__)


class NovaSentinelDaemon:
    """Nova Sentinel — continuous event-driven cyber defense daemon.

    Architecture::

        LogStreamer → EventQueue → Consumer Worker → SlidingWindow
                                                       ↓
                                              ThresholdEngine
                                                       ↓ (only when score crosses)
                                              Orchestrator (Nova Multi-Agent)
                                                       ↓
                                              BlockManager → SandboxFirewall
                                                       ↓
                                              MetricsCollector
    """

    def __init__(self) -> None:
        self._settings = get_settings()

        # ── Event infrastructure ────────────────────────────────────────
        self._event_queue: EventQueue[LogEvent] = EventQueue()
        self._log_streamer = LogStreamer(self._event_queue)

        # ── Realtime analysis ───────────────────────────────────────────
        self._window_engine = SlidingWindowEngine()
        self._ip_tracker = IPStateTracker()
        self._threshold_engine = ThresholdEngine(
            self._window_engine,
            self._ip_tracker,
            on_trigger=self._handle_trigger,
        )

        # ── Enforcement ─────────────────────────────────────────────────
        self._firewall = SandboxFirewall()

        # ── Nova pipeline ───────────────────────────────────────────────
        self._orchestrator = self._create_orchestrator()
        self._block_manager = BlockManager(self._firewall)

        # ── Monitoring ──────────────────────────────────────────────────
        self._metrics = get_global_metrics()
        self._trace = TraceRenderer()

        # ── Workers ─────────────────────────────────────────────────────
        self._worker_manager = WorkerManager()
        self._running = False

    # ── Public API ──────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start all daemon components and background workers."""
        self._running = True
        logger.info("═══ Nova Sentinel Daemon starting ═══")

        # Start log streamer
        await self._log_streamer.start()

        # Start background workers
        await self._worker_manager.start_worker(
            "event_consumer", self._event_consumer_loop
        )
        await self._worker_manager.start_worker(
            "expiry_cleaner", self._expiry_cleanup_loop
        )

        self._print_banner()
        logger.info("═══ Nova Sentinel Daemon running ═══")

    async def stop(self) -> None:
        """Gracefully stop all daemon components."""
        logger.info("═══ Nova Sentinel Daemon stopping ═══")
        self._running = False

        await self._log_streamer.stop()
        await self._worker_manager.stop_all()

        drained = await self._event_queue.drain()
        if drained:
            logger.info("Drained %d remaining events from queue", drained)

        logger.info("═══ Nova Sentinel Daemon stopped ═══")

    @property
    def running(self) -> bool:
        return self._running

    # Component accessors for API integration
    @property
    def metrics(self) -> MetricsCollector:
        return self._metrics

    @property
    def firewall(self) -> SandboxFirewall:
        return self._firewall

    @property
    def orchestrator(self) -> Orchestrator:
        return self._orchestrator

    def get_status(self) -> dict[str, Any]:
        """Build a complete status snapshot."""
        queue_metrics = self._event_queue.metrics()
        return self._metrics.snapshot(
            queue_depth=queue_metrics.current_depth,
            queue_dropped=queue_metrics.dropped,
            suspicious_ips=len(self._ip_tracker.get_suspicious_ips()),
            blocked_ips=len(self._firewall.get_blocked_ips()),
            window_stats=self._window_engine.get_stats(),
            threshold_stats=self._threshold_engine.get_stats(),
            firewall_stats=self._firewall.get_stats(),
            tracker_stats=self._ip_tracker.get_stats(),
        )

    # ── Background workers ──────────────────────────────────────────────

    async def _event_consumer_loop(self) -> None:
        """Main event processing loop — consumes from queue."""
        logger.info("Event consumer worker started")

        while self._running:
            try:
                event = await asyncio.wait_for(
                    self._event_queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue

            try:
                # Skip blocked IPs
                if self._firewall.is_blocked(event.source_ip):
                    logger.debug("Dropping event from blocked IP: %s", event.source_ip)
                    self._event_queue.task_done()
                    continue

                # Record metric
                self._metrics.record_event()

                # Evaluate against thresholds (may trigger Nova)
                await self._threshold_engine.evaluate(event)

                self._event_queue.task_done()

            except Exception as exc:
                logger.error("Error processing event: %s", exc)
                self._event_queue.task_done()

    async def _expiry_cleanup_loop(self) -> None:
        """Periodically expire old window entries and firewall blocks."""
        logger.info("Expiry cleanup worker started")

        while self._running:
            try:
                await asyncio.sleep(10.0)  # Run every 10 seconds
                expired_events = await self._window_engine.expire()
                expired_blocks = self._firewall.expire_blocks()
                stale_ips = self._ip_tracker.cleanup_stale()

                if expired_events or expired_blocks or stale_ips:
                    logger.debug(
                        "Cleanup: %d events expired, %d blocks expired, %d stale IPs removed",
                        expired_events,
                        expired_blocks,
                        stale_ips,
                    )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Cleanup error: %s", exc)

    # ── Nova trigger handler ────────────────────────────────────────────

    async def _handle_trigger(self, trigger: IncidentTriggerEvent) -> None:
        """Handle an incident trigger — run Nova pipeline and enforce."""
        detection_start = time.perf_counter()

        self._render_detection(trigger)

        # Convert window events to raw log lines for the orchestrator
        raw_logs = [e.message for e in trigger.window_events]

        try:
            result = await self._orchestrator.analyze_logs(raw_logs)
            detection_ms = (time.perf_counter() - detection_start) * 1000

            # Record metrics
            self._metrics.record_nova_activation(latency_ms=detection_ms)

            # Enforce
            enforcement = self._block_manager.process_pipeline_result(
                result, source_ip=trigger.source_ip
            )

            self._render_enforcement(trigger, enforcement, detection_ms)

            logger.info(
                "Incident %s — %d enforcement actions, latency=%.0fms",
                result.get("incident_id", "?"),
                len(enforcement),
                detection_ms,
            )

        except Exception as exc:
            logger.error(
                "Nova pipeline failed for %s: %s",
                trigger.source_ip,
                exc,
            )

    # ── Rendering ──────────────────────────────────────────────────────

    def _render_detection(self, trigger: IncidentTriggerEvent) -> None:
        """Render detection event to console."""
        if not self._trace.enabled:
            return
        print(
            f"\n{'═' * 60}\n"
            f"  ⚡ REALTIME DETECTION\n"
            f"{'═' * 60}\n"
            f"  IP          : {trigger.source_ip}\n"
            f"  Score       : {trigger.suspicion_score:.2f}\n"
            f"  Events      : {trigger.event_count}\n"
            f"  Time        : {trigger.trigger_time.strftime('%H:%M:%S.%f')[:-3]}\n"
            f"  Reason      : {trigger.trigger_reason}\n"
            f"{'─' * 60}\n"
            f"  🧠 Activating Nova multi-agent pipeline...\n"
            f"{'─' * 60}"
        )

    def _render_enforcement(
        self,
        trigger: IncidentTriggerEvent,
        enforcement: list[dict[str, Any]],
        latency_ms: float,
    ) -> None:
        """Render enforcement results to console."""
        if not self._trace.enabled:
            return

        lines = [
            f"\n{'─' * 60}",
            f"  🛡️  ENFORCEMENT RESULT",
            f"{'─' * 60}",
        ]

        for action in enforcement:
            status = "✅ BLOCKED" if action.get("success") else "⚠️ SKIPPED"
            lines.append(f"  {status} {action.get('target', '?')}")
            if action.get("reason"):
                lines.append(f"           reason: {action['reason']}")

        lines.extend([
            f"{'─' * 60}",
            f"  ⏱  Detection Latency : {latency_ms:.0f}ms",
            f"  🚫 Blocked IPs       : {len(self._firewall.get_blocked_ips())}",
            f"{'═' * 60}\n",
        ])

        print("\n".join(lines))

    def _print_banner(self) -> None:
        """Print daemon startup banner."""
        mode = self._settings.RUN_MODE
        demo = "DEMO" if self._settings.DEMO_MODE else "PRODUCTION"
        print(
            f"\n{'═' * 60}\n"
            f"  🛡️  NOVA SENTINEL — AUTONOMOUS CYBER DEFENSE DAEMON\n"
            f"{'═' * 60}\n"
            f"  Mode       : {mode.upper()}\n"
            f"  Engine     : {demo}\n"
            f"  Window     : {self._settings.REALTIME_WINDOW_SECONDS}s\n"
            f"  Threshold  : {self._settings.FAILED_ATTEMPT_THRESHOLD} failed attempts\n"
            f"  Block TTL  : {self._settings.BLOCK_DURATION_SECONDS}s\n"
            f"  Nova Limit : {self._settings.MAX_NOVA_CALLS_PER_MINUTE}/min\n"
            f"{'═' * 60}\n"
            f"  Watching for threats...\n"
            f"{'═' * 60}\n"
        )

    # ── DI ──────────────────────────────────────────────────────────────

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

    # ── Simulate attack (demo) ──────────────────────────────────────────

    async def simulate_live_attack(self) -> None:
        """Simulate a brute-force attack for demonstration.

        Gradually emits auth failure logs, showing:
          1. Sliding window rising
          2. Suspicion score climbing
          3. Threshold crossing → Nova activation
          4. Sandbox block applied
          5. Subsequent events rejected
        """
        print(
            f"\n{'═' * 60}\n"
            f"  🎯 LIVE ATTACK SIMULATION\n"
            f"{'═' * 60}\n"
            f"  Simulating SSH brute-force from 192.168.1.100\n"
            f"  Watch the sliding window fill up...\n"
            f"{'═' * 60}\n"
        )

        attacker_ip = "192.168.1.100"
        base_logs = [
            f"sshd: Failed password for admin from {attacker_ip} port 22 ssh2",
            f"sshd: Failed password for root from {attacker_ip} port 22 ssh2",
            f"sshd: Invalid user test from {attacker_ip} port 22 ssh2",
            f"sshd: Failed password for user from {attacker_ip} port 22 ssh2",
            f"sshd: Failed password for admin from {attacker_ip} port 22 ssh2",
            f"sshd: Failed password for root from {attacker_ip} port 22 ssh2",
            f"sshd: Failed password for oracle from {attacker_ip} port 22 ssh2",
            f"sshd: Accepted password for root from {attacker_ip} port 22 ssh2",
        ]

        for i, log_line in enumerate(base_logs, 1):
            # Feed event
            self._log_streamer.feed(log_line, source="sshd-sim")

            # Wait for processing
            await asyncio.sleep(0.5)

            # Print window state
            score = self._window_engine.get_suspicion_score(attacker_ip)
            count = self._window_engine.get_event_count(attacker_ip)
            failed = self._window_engine.get_failed_count(attacker_ip)
            blocked = self._firewall.is_blocked(attacker_ip)
            threshold = self._threshold_engine.get_threshold(attacker_ip)

            bar_len = int(score * 30)
            bar = "█" * bar_len + "░" * (30 - bar_len)

            status = "🚫 BLOCKED" if blocked else "👁️ WATCHING"

            print(
                f"  [{i:02d}] {status}  "
                f"events={count:2d}  failed={failed:2d}  "
                f"score=[{bar}] {score:.2f}/{threshold:.2f}"
            )

            # If blocked, show rejection
            if blocked:
                print(
                    f"\n  ✅ Attack halted — {attacker_ip} is now blocked!\n"
                    f"  All subsequent events from this IP will be rejected.\n"
                )
                # Feed a couple more to show rejection
                for j in range(2):
                    self._log_streamer.feed(
                        f"sshd: Failed password for admin from {attacker_ip} port 22 ssh2",
                        source="sshd-sim",
                    )
                    await asyncio.sleep(0.3)
                    print(f"  [{i + j + 1:02d}] 🚫 REJECTED  event from blocked IP {attacker_ip}")
                break

            await asyncio.sleep(0.3)

        # Wait for any remaining pipeline processing
        await asyncio.sleep(2.0)

        # Final summary
        status = self.get_status()
        print(
            f"\n{'═' * 60}\n"
            f"  📊 SIMULATION RESULTS\n"
            f"{'═' * 60}\n"
            f"  Events Processed   : {status['total_events_processed']}\n"
            f"  Nova Activations   : {status['nova_activations']}\n"
            f"  Blocked IPs        : {status['blocked_ips']}\n"
            f"  Avg Detection Time : {status['avg_detection_latency_ms']:.0f}ms\n"
            f"{'═' * 60}\n"
        )


# ── CLI entry point ─────────────────────────────────────────────────────

async def _run_daemon(simulate: bool = False) -> None:
    """Run the daemon (standalone mode)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)-35s | %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )

    daemon = NovaSentinelDaemon()
    await daemon.start()

    if simulate:
        await daemon.simulate_live_attack()
        await daemon.stop()
    else:
        # Run until interrupted
        from daemon.lifecycle import DaemonLifecycle
        lifecycle = DaemonLifecycle(daemon)
        try:
            print("\n  Press Ctrl+C to stop...\n")
            while daemon.running:
                await asyncio.sleep(1.0)
        except KeyboardInterrupt:
            pass
        finally:
            await daemon.stop()


if __name__ == "__main__":
    simulate = "--simulate" in sys.argv
    asyncio.run(_run_daemon(simulate=simulate))
