"""
Tests for the multi-source telemetry architecture.

Covers:
  - TelemetryEvent model
  - SlidingWindowStore
  - CorrelationEngine scoring + cross-source rules
  - SuspicionEngine adaptive thresholds + cooldowns
  - SensorManager lifecycle
  - SandboxFirewall extensions (flag_process, flag_user)
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

import pytest

# ── Test TelemetryEvent ─────────────────────────────────────────────────


class TestTelemetryEvent:
    """Unit tests for events.telemetry_event.TelemetryEvent."""

    def test_create_basic_event(self):
        from events.telemetry_event import TelemetryEvent

        event = TelemetryEvent(
            source="log",
            timestamp=datetime.now(timezone.utc),
            event_type="auth_failure",
            severity_hint=0.7,
            ip="10.0.0.1",
        )
        assert event.source == "log"
        assert event.event_type == "auth_failure"
        assert event.severity_hint == 0.7
        assert event.ip == "10.0.0.1"

    def test_severity_clamping(self):
        from events.telemetry_event import TelemetryEvent

        event = TelemetryEvent(
            source="network",
            timestamp=datetime.now(timezone.utc),
            event_type="spike",
            severity_hint=1.5,  # over max
        )
        assert event.severity_hint == 1.0

        event2 = TelemetryEvent(
            source="network",
            timestamp=datetime.now(timezone.utc),
            event_type="spike",
            severity_hint=-0.5,  # under min
        )
        assert event2.severity_hint == 0.0

    def test_serialization_roundtrip(self):
        from events.telemetry_event import TelemetryEvent

        now = datetime.now(timezone.utc)
        event = TelemetryEvent(
            source="auth",
            timestamp=now,
            event_type="login_brute_force",
            severity_hint=0.8,
            ip="192.168.1.1",
            user="admin",
            raw_payload={"attempts": 5},
        )
        d = event.to_dict()
        restored = TelemetryEvent.from_dict(d)
        assert restored.source == event.source
        assert restored.event_type == event.event_type
        assert restored.severity_hint == event.severity_hint
        assert restored.ip == event.ip
        assert restored.user == event.user

    def test_immutability(self):
        from events.telemetry_event import TelemetryEvent

        event = TelemetryEvent(
            source="process",
            timestamp=datetime.now(timezone.utc),
            event_type="shell_spawn",
        )
        with pytest.raises(AttributeError):
            event.source = "log"  # type: ignore[misc]


# ── Test SlidingWindowStore ─────────────────────────────────────────────


class TestSlidingWindowStore:
    """Unit tests for realtime.sliding_window_store.SlidingWindowStore."""

    def test_record_and_retrieve(self):
        from events.telemetry_event import TelemetryEvent
        from realtime.sliding_window_store import SlidingWindowStore

        store = SlidingWindowStore(window_seconds=60)
        event = TelemetryEvent(
            source="log",
            timestamp=datetime.now(timezone.utc),
            event_type="auth_failure",
            ip="10.0.0.1",
        )
        store.record(event)
        assert store.get_event_count("10.0.0.1") == 1
        assert len(store.get_all("10.0.0.1")) == 1

    def test_per_source_filtering(self):
        from events.telemetry_event import TelemetryEvent
        from realtime.sliding_window_store import SlidingWindowStore

        store = SlidingWindowStore(window_seconds=60)
        now = datetime.now(timezone.utc)

        store.record(TelemetryEvent(
            source="log", timestamp=now, event_type="auth_failure", ip="10.0.0.1",
        ))
        store.record(TelemetryEvent(
            source="network", timestamp=now, event_type="connection_spike", ip="10.0.0.1",
        ))

        log_events = store.get_by_source("10.0.0.1", "log")
        net_events = store.get_by_source("10.0.0.1", "network")
        assert len(log_events) == 1
        assert len(net_events) == 1
        assert store.get_event_count("10.0.0.1") == 2

    def test_source_counts(self):
        from events.telemetry_event import TelemetryEvent
        from realtime.sliding_window_store import SlidingWindowStore

        store = SlidingWindowStore(window_seconds=60)
        now = datetime.now(timezone.utc)

        for _ in range(3):
            store.record(TelemetryEvent(
                source="log", timestamp=now, event_type="auth_failure", ip="10.0.0.1",
            ))
        for _ in range(2):
            store.record(TelemetryEvent(
                source="auth", timestamp=now, event_type="brute_force", ip="10.0.0.1",
            ))

        counts = store.get_source_counts("10.0.0.1")
        assert counts["log"] == 3
        assert counts["auth"] == 2

    @pytest.mark.asyncio
    async def test_expiry(self):
        from events.telemetry_event import TelemetryEvent
        from realtime.sliding_window_store import SlidingWindowStore

        store = SlidingWindowStore(window_seconds=1)  # 1 second window
        past = datetime.now(timezone.utc) - timedelta(seconds=5)

        store.record(TelemetryEvent(
            source="log", timestamp=past, event_type="old_event", ip="10.0.0.1",
        ))

        removed = await store.expire_all()
        assert removed == 1
        assert store.get_event_count("10.0.0.1") == 0


# ── Test CorrelationEngine ──────────────────────────────────────────────


class TestCorrelationEngine:
    """Unit tests for realtime.correlation_engine.CorrelationEngine."""

    def test_ingest_and_score(self):
        from events.telemetry_event import TelemetryEvent
        from realtime.correlation_engine import CorrelationEngine

        engine = CorrelationEngine()
        now = datetime.now(timezone.utc)

        # Ingest events from multiple sources
        engine.ingest(TelemetryEvent(
            source="log", timestamp=now, event_type="auth_failure",
            severity_hint=0.7, ip="10.0.0.1",
        ))
        engine.ingest(TelemetryEvent(
            source="network", timestamp=now, event_type="connection_spike",
            severity_hint=0.6, ip="10.0.0.1",
        ))

        score_info = engine.get_ip_score("10.0.0.1")
        assert score_info["total_score"] > 0
        assert score_info["source_scores"]["log"] > 0
        assert score_info["source_scores"]["network"] > 0

    def test_cross_source_boost(self):
        from events.telemetry_event import TelemetryEvent
        from realtime.correlation_engine import CorrelationEngine

        engine = CorrelationEngine()
        now = datetime.now(timezone.utc)

        # Trigger cross-source rule: auth_failure + connection_spike
        engine.ingest(TelemetryEvent(
            source="log", timestamp=now, event_type="auth_failure",
            severity_hint=0.7, ip="10.0.0.1",
        ))
        engine.ingest(TelemetryEvent(
            source="network", timestamp=now, event_type="connection_spike",
            severity_hint=0.6, ip="10.0.0.1",
        ))

        score_info = engine.get_ip_score("10.0.0.1")
        assert score_info["cross_source_boost"] > 0  # Rule should match

    def test_no_boost_single_source(self):
        from events.telemetry_event import TelemetryEvent
        from realtime.correlation_engine import CorrelationEngine

        engine = CorrelationEngine()
        now = datetime.now(timezone.utc)

        engine.ingest(TelemetryEvent(
            source="log", timestamp=now, event_type="auth_failure",
            severity_hint=0.7, ip="10.0.0.1",
        ))

        score_info = engine.get_ip_score("10.0.0.1")
        assert score_info["cross_source_boost"] == 0

    def test_batch_ingest(self):
        from events.telemetry_event import TelemetryEvent
        from realtime.correlation_engine import CorrelationEngine

        engine = CorrelationEngine()
        now = datetime.now(timezone.utc)

        events = [
            TelemetryEvent(
                source="log", timestamp=now, event_type="auth_failure",
                severity_hint=0.7, ip="10.0.0.1",
            ),
            TelemetryEvent(
                source="auth", timestamp=now, event_type="login_brute_force",
                severity_hint=0.8, ip="10.0.0.1",
            ),
        ]
        engine.ingest_batch(events)

        stats = engine.get_stats()
        assert stats["total_ingested"] == 2
        assert stats["active_ips"] == 1


# ── Test SuspicionEngine ───────────────────────────────────────────────


class TestSuspicionEngine:
    """Unit tests for realtime.suspicion_engine.SuspicionEngine."""

    def test_should_trigger_above_threshold(self):
        from realtime.suspicion_engine import SuspicionEngine

        engine = SuspicionEngine(base_threshold=0.5)
        assert engine.should_trigger("10.0.0.1", 0.6) is True

    def test_should_not_trigger_below_threshold(self):
        from realtime.suspicion_engine import SuspicionEngine

        engine = SuspicionEngine(base_threshold=0.8)
        assert engine.should_trigger("10.0.0.1", 0.5) is False

    def test_cooldown_prevents_repeat_trigger(self):
        from realtime.suspicion_engine import SuspicionEngine

        engine = SuspicionEngine(base_threshold=0.5)
        assert engine.should_trigger("10.0.0.1", 0.7) is True
        engine.mark_triggered("10.0.0.1")

        # Should be in cooldown now
        assert engine.should_trigger("10.0.0.1", 0.9) is False

    def test_adaptive_threshold_lowers_for_repeat_offenders(self):
        from realtime.suspicion_engine import SuspicionEngine

        engine = SuspicionEngine(base_threshold=0.8)
        initial_threshold = engine.get_adaptive_threshold("10.0.0.1")

        # Simulate multiple triggers
        engine.mark_triggered("10.0.0.1")
        engine.mark_triggered("10.0.0.1")

        lower_threshold = engine.get_adaptive_threshold("10.0.0.1")
        assert lower_threshold < initial_threshold

    def test_escalation_after_3_triggers(self):
        from realtime.suspicion_engine import SuspicionEngine

        engine = SuspicionEngine(base_threshold=0.5)

        for _ in range(3):
            engine.mark_triggered("10.0.0.1")

        state = engine.get_state("10.0.0.1")
        assert state["is_escalated"] is True

    def test_reset_clears_state(self):
        from realtime.suspicion_engine import SuspicionEngine

        engine = SuspicionEngine(base_threshold=0.5)
        engine.mark_triggered("10.0.0.1")

        engine.reset("10.0.0.1")
        state = engine.get_state("10.0.0.1")
        assert state["tracking"] is False


# ── Test SandboxFirewall extensions ─────────────────────────────────────


class TestSandboxFirewallExtensions:
    """Tests for multi-source enforcement extensions."""

    def test_flag_process(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        result = fw.flag_process("ncat", reason="reverse_shell", ip="10.0.0.1")
        assert result is True

        flagged = fw.get_flagged_processes()
        assert "ncat" in flagged
        assert flagged["ncat"]["reason"] == "reverse_shell"

    def test_flag_process_duplicate(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        fw.flag_process("ncat")
        result = fw.flag_process("ncat")  # duplicate
        assert result is False

    def test_flag_user(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        result = fw.flag_user("admin", reason="brute_force", ip="10.0.0.1")
        assert result is True

        flagged = fw.get_flagged_users()
        assert "admin" in flagged

    def test_stats_include_flagged(self):
        from enforcement.sandbox_firewall import SandboxFirewall

        fw = SandboxFirewall()
        fw.flag_process("proc1")
        fw.flag_user("user1")

        stats = fw.get_stats()
        assert stats["flagged_processes"] == 1
        assert stats["flagged_users"] == 1


# ── Test MetricsCollector extensions ────────────────────────────────────


class TestMetricsCollectorExtensions:
    """Tests for per-sensor metrics."""

    def test_sensor_event_tracking(self):
        from monitoring.metrics_collector import MetricsCollector

        mc = MetricsCollector()
        mc.record_sensor_event("log")
        mc.record_sensor_event("log")
        mc.record_sensor_event("network")

        snapshot = mc.snapshot()
        assert snapshot["sensor_events"]["log"] == 2
        assert snapshot["sensor_events"]["network"] == 1


# ── Test LogSensor parsing ──────────────────────────────────────────────


class TestLogSensorParsing:
    """Tests for log line parsing in LogSensor."""

    def test_parse_auth_failure(self):
        from telemetry.log_sensor import LogSensor

        sensor = LogSensor()
        event = sensor._parse_line(
            "Failed password for admin from 192.168.1.100 port 22 ssh2",
            "sshd",
        )
        assert event is not None
        assert event.event_type == "auth_failure"
        assert event.ip == "192.168.1.100"
        assert event.severity_hint > 0

    def test_parse_privilege_escalation(self):
        from telemetry.log_sensor import LogSensor

        sensor = LogSensor()
        event = sensor._parse_line(
            "sudo: admin : COMMAND=/bin/bash",
            "syslog",
        )
        assert event is not None
        assert event.event_type == "privilege_escalation"
        assert event.severity_hint >= 0.8

    def test_parse_benign_line(self):
        from telemetry.log_sensor import LogSensor

        sensor = LogSensor()
        event = sensor._parse_line(
            "Starting daily cron job",
            "cron",
        )
        assert event is None  # Benign lines should not produce events

    def test_parse_empty_line(self):
        from telemetry.log_sensor import LogSensor

        sensor = LogSensor()
        event = sensor._parse_line("", "test")
        assert event is None


# ── Test WorkerPool ─────────────────────────────────────────────────────


class TestWorkerPool:
    """Tests for daemon.worker_pool.WorkerPool."""

    @pytest.mark.asyncio
    async def test_start_stop(self):
        from daemon.worker_pool import WorkerPool

        pool = WorkerPool(size=2, name="test")
        await pool.start()
        assert pool.get_stats()["running"] is True

        await pool.stop()
        assert pool.get_stats()["running"] is False

    @pytest.mark.asyncio
    async def test_process_task(self):
        from daemon.worker_pool import WorkerPool

        pool = WorkerPool(size=2, name="test")
        results = []

        async def work(x: int) -> None:
            results.append(x)

        await pool.start()
        await pool.submit(work, 42)
        await asyncio.sleep(0.2)  # let worker process it
        await pool.stop()

        assert 42 in results
