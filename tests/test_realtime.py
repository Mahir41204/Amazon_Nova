"""
Tests for the realtime event-driven daemon components.

Covers:
  - Event models and parsing
  - Event queue backpressure
  - Sliding window engine (insert, expiry, scoring)
  - IP state tracker (cooldown, trigger tracking)
  - Threshold engine (trigger, cooldown, rate limiting)
  - Sandbox firewall (block, unblock, whitelist, expiry)
  - Block manager (pipeline result processing)
  - Full daemon pipeline integration
  - Detection latency measurement
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import pytest
from datetime import datetime, timedelta, timezone

# Ensure project root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Force demo mode and low thresholds for testing
os.environ.setdefault("DEMO_MODE", "true")
os.environ["REALTIME_WINDOW_SECONDS"] = "10"
os.environ["FAILED_ATTEMPT_THRESHOLD"] = "3"
os.environ["BLOCK_DURATION_SECONDS"] = "5"
os.environ["MAX_NOVA_CALLS_PER_MINUTE"] = "20"
os.environ["EVENT_QUEUE_MAX_SIZE"] = "100"


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Clear settings cache so test env vars take effect."""
    from config.settings import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ═════════════════════════════════════════════════════════════════════════
# Event Models
# ═════════════════════════════════════════════════════════════════════════


class TestLogEvent:
    def test_from_raw_extracts_ip(self):
        from events.event_models import LogEvent

        event = LogEvent.from_raw(
            "sshd: Failed password for admin from 192.168.1.100 port 22 ssh2"
        )
        assert event.source_ip == "192.168.1.100"

    def test_from_raw_classifies_auth_failure(self):
        from events.event_models import LogEvent

        event = LogEvent.from_raw("sshd: Failed password for root from 10.0.0.1")
        assert event.event_type == "auth_failure"

    def test_from_raw_classifies_auth_success(self):
        from events.event_models import LogEvent

        event = LogEvent.from_raw("sshd: Accepted password for root from 10.0.0.1")
        assert event.event_type == "auth_success"

    def test_from_raw_classifies_privilege_escalation(self):
        from events.event_models import LogEvent

        event = LogEvent.from_raw("privilege escalation attempt detected from 10.0.0.1")
        assert event.event_type == "privilege_escalation"

    def test_from_raw_fallback_ip(self):
        from events.event_models import LogEvent

        event = LogEvent.from_raw("no ip address here")
        assert event.source_ip == "0.0.0.0"

    def test_from_raw_preserves_source(self):
        from events.event_models import LogEvent

        event = LogEvent.from_raw("test line", source="sshd")
        assert event.source == "sshd"


# ═════════════════════════════════════════════════════════════════════════
# Event Queue
# ═════════════════════════════════════════════════════════════════════════


class TestEventQueue:
    @pytest.mark.asyncio
    async def test_put_and_get(self):
        from events.event_queue import EventQueue

        queue: EventQueue[str] = EventQueue(max_size=10)
        await queue.put("hello")
        item = await queue.get()
        assert item == "hello"

    @pytest.mark.asyncio
    async def test_try_put_succeeds(self):
        from events.event_queue import EventQueue

        queue: EventQueue[str] = EventQueue(max_size=10)
        assert queue.try_put("hello") is True
        assert queue.depth == 1

    @pytest.mark.asyncio
    async def test_try_put_drops_when_full(self):
        from events.event_queue import EventQueue

        queue: EventQueue[str] = EventQueue(max_size=2)
        assert queue.try_put("a") is True
        assert queue.try_put("b") is True
        assert queue.try_put("c") is False  # dropped

        metrics = queue.metrics()
        assert metrics.dropped == 1
        assert metrics.enqueued == 2

    @pytest.mark.asyncio
    async def test_metrics_tracking(self):
        from events.event_queue import EventQueue

        queue: EventQueue[str] = EventQueue(max_size=10)
        await queue.put("a")
        await queue.put("b")
        await queue.get()

        metrics = queue.metrics()
        assert metrics.enqueued == 2
        assert metrics.dequeued == 1
        assert metrics.peak_depth == 2


# ═════════════════════════════════════════════════════════════════════════
# Sliding Window Engine
# ═════════════════════════════════════════════════════════════════════════


class TestSlidingWindowEngine:
    def _make_event(self, ip: str, event_type: str = "auth_failure", age_seconds: float = 0):
        from events.event_models import LogEvent

        ts = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
        return LogEvent(
            timestamp=ts,
            source_ip=ip,
            message="test",
            source="test",
            event_type=event_type,
        )

    def test_record_and_count(self):
        from realtime.sliding_window_engine import SlidingWindowEngine

        engine = SlidingWindowEngine()
        engine.record(self._make_event("10.0.0.1"))
        engine.record(self._make_event("10.0.0.1"))
        engine.record(self._make_event("10.0.0.2"))

        assert engine.get_event_count("10.0.0.1") == 2
        assert engine.get_event_count("10.0.0.2") == 1

    def test_failed_count(self):
        from realtime.sliding_window_engine import SlidingWindowEngine

        engine = SlidingWindowEngine()
        engine.record(self._make_event("10.0.0.1", "auth_failure"))
        engine.record(self._make_event("10.0.0.1", "auth_success"))
        engine.record(self._make_event("10.0.0.1", "auth_failure"))

        assert engine.get_failed_count("10.0.0.1") == 2

    def test_expiry_removes_old_events(self):
        from realtime.sliding_window_engine import SlidingWindowEngine

        engine = SlidingWindowEngine()
        # Add old event (beyond 10s window)
        engine.record(self._make_event("10.0.0.1", age_seconds=20))
        # Add recent event
        engine.record(self._make_event("10.0.0.1", age_seconds=0))

        assert engine.get_event_count("10.0.0.1") == 1  # old one expired

    def test_suspicion_score_rises_with_failures(self):
        from realtime.sliding_window_engine import SlidingWindowEngine

        engine = SlidingWindowEngine()

        # Add auth failures
        for _ in range(5):
            engine.record(self._make_event("10.0.0.1", "auth_failure"))

        score = engine.get_suspicion_score("10.0.0.1")
        assert score > 0.3  # Should be significantly suspicious

    def test_suspicion_score_zero_for_unknown_ip(self):
        from realtime.sliding_window_engine import SlidingWindowEngine

        engine = SlidingWindowEngine()
        assert engine.get_suspicion_score("10.0.0.99") == 0.0

    def test_escalation_boosts_score(self):
        from realtime.sliding_window_engine import SlidingWindowEngine

        engine = SlidingWindowEngine()
        engine.record(self._make_event("10.0.0.1", "auth_failure"))
        score_without = engine.get_suspicion_score("10.0.0.1")

        engine.record(self._make_event("10.0.0.1", "privilege_escalation"))
        score_with = engine.get_suspicion_score("10.0.0.1")

        assert score_with > score_without

    def test_active_ips(self):
        from realtime.sliding_window_engine import SlidingWindowEngine

        engine = SlidingWindowEngine()
        engine.record(self._make_event("10.0.0.1"))
        engine.record(self._make_event("10.0.0.2"))

        ips = engine.get_active_ips()
        assert set(ips) == {"10.0.0.1", "10.0.0.2"}

    @pytest.mark.asyncio
    async def test_expire_async(self):
        from realtime.sliding_window_engine import SlidingWindowEngine

        engine = SlidingWindowEngine()
        engine.record(self._make_event("10.0.0.1", age_seconds=20))
        engine.record(self._make_event("10.0.0.1", age_seconds=0))

        removed = await engine.expire()
        assert removed == 1


# ═════════════════════════════════════════════════════════════════════════
# IP State Tracker
# ═════════════════════════════════════════════════════════════════════════


class TestIPStateTracker:
    def test_update_creates_state(self):
        from realtime.ip_state_tracker import IPStateTracker

        tracker = IPStateTracker()
        state = tracker.update("10.0.0.1", score=0.5, events=3)
        assert state.ip == "10.0.0.1"
        assert state.suspicion_level == 0.5
        assert state.event_count == 3

    def test_has_triggered_false_by_default(self):
        from realtime.ip_state_tracker import IPStateTracker

        tracker = IPStateTracker()
        assert tracker.has_triggered("10.0.0.1") is False

    def test_mark_triggered_and_check(self):
        from realtime.ip_state_tracker import IPStateTracker

        tracker = IPStateTracker()
        tracker.mark_triggered("10.0.0.1")
        assert tracker.has_triggered("10.0.0.1") is True

    def test_reset_clears_trigger(self):
        from realtime.ip_state_tracker import IPStateTracker

        tracker = IPStateTracker()
        tracker.mark_triggered("10.0.0.1")
        tracker.reset("10.0.0.1")
        assert tracker.has_triggered("10.0.0.1") is False


# ═════════════════════════════════════════════════════════════════════════
# Threshold Engine
# ═════════════════════════════════════════════════════════════════════════


class TestThresholdEngine:
    def _make_event(self, ip: str, event_type: str = "auth_failure"):
        from events.event_models import LogEvent

        return LogEvent(
            timestamp=datetime.now(timezone.utc),
            source_ip=ip,
            message=f"sshd: Failed password from {ip}",
            source="test",
            event_type=event_type,
        )

    @pytest.mark.asyncio
    async def test_no_trigger_below_threshold(self):
        from realtime.sliding_window_engine import SlidingWindowEngine
        from realtime.ip_state_tracker import IPStateTracker
        from realtime.threshold_engine import ThresholdEngine

        engine = ThresholdEngine(SlidingWindowEngine(), IPStateTracker())

        result = await engine.evaluate(self._make_event("10.0.0.1"))
        assert result is None  # single event shouldn't trigger

    @pytest.mark.asyncio
    async def test_triggers_after_threshold(self):
        from realtime.sliding_window_engine import SlidingWindowEngine
        from realtime.ip_state_tracker import IPStateTracker
        from realtime.threshold_engine import ThresholdEngine

        triggered = []

        async def on_trigger(event):
            triggered.append(event)

        engine = ThresholdEngine(
            SlidingWindowEngine(),
            IPStateTracker(),
            on_trigger=on_trigger,
        )

        # Feed enough failures to cross threshold
        for _ in range(10):
            await engine.evaluate(self._make_event("10.0.0.1"))

        assert len(triggered) == 1
        assert triggered[0].source_ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_cooldown_prevents_duplicate(self):
        from realtime.sliding_window_engine import SlidingWindowEngine
        from realtime.ip_state_tracker import IPStateTracker
        from realtime.threshold_engine import ThresholdEngine

        triggered = []

        async def on_trigger(event):
            triggered.append(event)

        engine = ThresholdEngine(
            SlidingWindowEngine(),
            IPStateTracker(),
            on_trigger=on_trigger,
        )

        # Trigger once
        for _ in range(10):
            await engine.evaluate(self._make_event("10.0.0.1"))

        assert len(triggered) == 1

        # More events shouldn't trigger again (cooldown)
        for _ in range(5):
            await engine.evaluate(self._make_event("10.0.0.1"))

        assert len(triggered) == 1  # still just 1


# ═════════════════════════════════════════════════════════════════════════
# Sandbox Firewall
# ═════════════════════════════════════════════════════════════════════════


class TestSandboxFirewall:
    def test_block_and_check(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        fw.block("10.0.0.1", reason="test")
        assert fw.is_blocked("10.0.0.1") is True

    def test_unblock(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        fw.block("10.0.0.1", reason="test")
        fw.unblock("10.0.0.1")
        assert fw.is_blocked("10.0.0.1") is False

    def test_whitelist_prevents_block(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        fw.add_whitelist("10.0.0.1")
        result = fw.block("10.0.0.1", reason="test")
        assert result is False
        assert fw.is_blocked("10.0.0.1") is False

    def test_auto_expiry(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        # Block with very short duration
        fw.block("10.0.0.1", reason="test", duration_seconds=0)
        # Wait a tiny bit so wall-clock moves past expires_at
        import time
        time.sleep(0.05)
        # Trigger expiry explicitly
        expired = fw.expire_blocks()
        assert expired == 1
        assert fw.is_blocked("10.0.0.1") is False

    def test_audit_log(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        fw.block("10.0.0.1", reason="brute_force")
        fw.unblock("10.0.0.1")

        log = fw.get_audit_log()
        assert len(log) == 2
        assert log[0]["action"] == "blocked"
        assert log[1]["action"] == "unblocked"

    def test_stats(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        fw.block("10.0.0.1", reason="test")
        fw.block("10.0.0.2", reason="test")
        fw.unblock("10.0.0.1")

        stats = fw.get_stats()
        assert stats["currently_blocked"] == 1
        assert stats["total_blocks"] == 2
        assert stats["total_unblocks"] == 1


# ═════════════════════════════════════════════════════════════════════════
# Block Manager
# ═════════════════════════════════════════════════════════════════════════


class TestBlockManager:
    def test_processes_block_ip_action(self):
        from enforcement.sandbox_firewall import SandboxFirewall
        from enforcement.block_manager import BlockManager

        fw = SandboxFirewall()
        manager = BlockManager(fw)

        result = {
            "incident_id": "INC-001",
            "stages": {
                "response": {
                    "result": {
                        "actions_taken": [
                            {"action_type": "block_ip", "target": "10.0.0.1"}
                        ]
                    }
                },
                "threat_classification": {
                    "result": {"confidence_score": 0.5}
                },
            },
        }

        enforcement = manager.process_pipeline_result(result, source_ip="10.0.0.1")
        assert len(enforcement) >= 1
        assert fw.is_blocked("10.0.0.1") is True


# ═════════════════════════════════════════════════════════════════════════
# Metrics Collector
# ═════════════════════════════════════════════════════════════════════════


class TestMetricsCollector:
    def test_record_and_snapshot(self):
        from monitoring.metrics_collector import MetricsCollector

        metrics = MetricsCollector()
        metrics.record_event()
        metrics.record_event()
        metrics.record_nova_activation(latency_ms=45.0)

        snap = metrics.snapshot()
        assert snap["total_events_processed"] == 2
        assert snap["nova_activations"] == 1
        assert snap["avg_detection_latency_ms"] == 45.0

    def test_uptime(self):
        from monitoring.metrics_collector import MetricsCollector

        metrics = MetricsCollector()
        import time
        time.sleep(0.1)
        assert metrics.uptime_seconds() > 0.05


# ═════════════════════════════════════════════════════════════════════════
# Full Daemon Pipeline (Integration)
# ═════════════════════════════════════════════════════════════════════════


class TestDaemonIntegration:
    @pytest.mark.asyncio
    async def test_daemon_start_stop(self):
        """Daemon starts and stops cleanly."""
        from daemon.daemon_service import NovaSentinelDaemon

        daemon = NovaSentinelDaemon()
        await daemon.start()
        assert daemon.running is True

        status = daemon.get_status()
        assert "events_per_second" in status
        assert "nova_activations" in status

        await daemon.stop()
        assert daemon.running is False

    @pytest.mark.asyncio
    async def test_detection_latency_measurement(self):
        """Events fed through the daemon get processed with measurable latency."""
        from daemon.daemon_service import NovaSentinelDaemon

        daemon = NovaSentinelDaemon()
        await daemon.start()

        start = time.perf_counter()

        # Feed a few events
        for i in range(3):
            daemon._log_streamer.feed(
                f"sshd: Failed password for admin from 10.0.0.50 port 22",
                source="test",
            )

        # Give the consumer time to process
        await asyncio.sleep(1.0)

        elapsed = (time.perf_counter() - start) * 1000
        status = daemon.get_status()
        assert status["total_events_processed"] >= 1
        assert elapsed < 5000  # Should process within 5 seconds

        await daemon.stop()
