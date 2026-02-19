"""
CorrelationEngine — multi-source signal correlation for threat detection.

Consumes TelemetryEvents from all sensors, maintains per-IP suspicion
scores using weighted multi-source scoring, and emits IncidentTriggerEvents
when correlation thresholds are exceeded.

Design principles:
  - Weighted scoring: ``total = w_log*log + w_net*net + w_auth*auth + w_proc*proc``
  - Cross-source correlation rules amplify compound signals
  - Sliding time window with configurable duration
  - Avoids double-counting (deduplication within same poll cycle)
  - Nova only activates when correlation threshold is exceeded
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from config.settings import get_settings
from events.telemetry_event import TelemetryEvent
from events.event_models import IncidentTriggerEvent, LogEvent
from realtime.sliding_window_store import SlidingWindowStore

logger = logging.getLogger(__name__)

# Default correlation weights
_DEFAULT_WEIGHTS = {
    "log": 0.30,
    "network": 0.25,
    "auth": 0.25,
    "process": 0.20,
}

# Cross-source correlation rules: (source_a, source_b, score_boost)
# When signals from both sources exist, boost the total score
_CROSS_SOURCE_RULES: list[tuple[str, str, str, str, float]] = [
    # (source_a, event_type_a, source_b, event_type_b, boost)
    ("log", "auth_failure", "network", "connection_spike", 0.15),
    ("log", "auth_failure", "auth", "login_brute_force", 0.20),
    ("process", "shell_spawn", "network", "connection_spike", 0.25),
    ("process", "suspicious_process", "network", "suspicious_port", 0.20),
    ("auth", "login_brute_force", "network", "port_scan", 0.15),
    ("log", "privilege_escalation", "process", "shell_spawn", 0.30),
    ("auth", "rapid_token_failure", "log", "auth_failure", 0.10),
]


class CorrelationEngine:
    """Multi-source signal correlator with weighted scoring.

    Architecture::

        TelemetryEvents → SlidingWindowStore → Per-IP Score Computation
                                                      ↓
                                              Cross-Source Rules
                                                      ↓
                                              Total Score ≥ Threshold?
                                                      ↓ YES
                                              IncidentTriggerEvent → callback

    Usage::

        engine = CorrelationEngine(on_trigger=handle_trigger)
        engine.ingest(event)
        await engine.evaluate_all()
    """

    def __init__(
        self,
        *,
        on_trigger: Callable[[IncidentTriggerEvent], Awaitable[None]] | None = None,
    ) -> None:
        settings = get_settings()

        self._window_store = SlidingWindowStore(
            window_seconds=getattr(settings, "SUSPICION_WINDOW_SECONDS", 60)
        )
        self._on_trigger = on_trigger

        # Configurable weights
        self._weights = getattr(settings, "CORRELATION_WEIGHTS", _DEFAULT_WEIGHTS)
        self._threshold = getattr(settings, "GLOBAL_SUSPICION_THRESHOLD", 0.85)

        # Rate limiting for Nova calls
        self._nova_calls: list[float] = []
        self._max_nova_calls = settings.MAX_NOVA_CALLS_PER_MINUTE

        # Stats
        self._total_ingested = 0
        self._total_triggers = 0
        self._total_evaluations = 0

    # ── Public API ──────────────────────────────────────────────────────

    def ingest(self, event: TelemetryEvent) -> None:
        """Record a telemetry event into the correlation window."""
        self._window_store.record(event)
        self._total_ingested += 1

    def ingest_batch(self, events: list[TelemetryEvent]) -> None:
        """Record multiple events at once."""
        for event in events:
            self.ingest(event)

    async def evaluate_all(self) -> list[IncidentTriggerEvent]:
        """Evaluate all active IPs and trigger incidents as needed."""
        self._total_evaluations += 1
        triggers: list[IncidentTriggerEvent] = []

        for ip in self._window_store.get_active_ips():
            trigger = await self._evaluate_ip(ip)
            if trigger:
                triggers.append(trigger)

        return triggers

    def get_ip_score(self, ip: str) -> dict[str, Any]:
        """Compute and return the detailed score breakdown for an IP."""
        return self._compute_score(ip)

    @property
    def window_store(self) -> SlidingWindowStore:
        return self._window_store

    def get_stats(self) -> dict[str, Any]:
        """Return correlation engine statistics."""
        return {
            "total_ingested": self._total_ingested,
            "total_triggers": self._total_triggers,
            "total_evaluations": self._total_evaluations,
            "active_ips": len(self._window_store.get_active_ips()),
            "threshold": self._threshold,
            "weights": self._weights,
            "nova_calls_last_minute": self._count_recent_nova_calls(),
            "window_store": self._window_store.get_stats(),
        }

    # ── Internal scoring ────────────────────────────────────────────────

    async def _evaluate_ip(self, ip: str) -> IncidentTriggerEvent | None:
        """Evaluate a single IP's correlation score."""
        score_info = self._compute_score(ip)
        total_score = score_info["total_score"]

        if total_score < self._threshold:
            return None

        # Rate limit
        if not self._can_call_nova():
            logger.warning(
                "CorrelationEngine: Nova rate limit reached, deferring %s (score=%.2f)",
                ip, total_score,
            )
            return None

        # Build trigger
        all_events = self._window_store.get_all(ip)

        # Convert to LogEvent-compatible format for orchestrator
        window_log_events = [
            LogEvent(
                timestamp=e.timestamp,
                source_ip=e.ip or ip,
                message=f"[{e.source}:{e.event_type}] severity={e.severity_hint:.2f}",
                source=e.source,
                event_type=e.event_type,
                metadata=e.raw_payload,
            )
            for e in all_events
        ]

        trigger = IncidentTriggerEvent(
            source_ip=ip,
            suspicion_score=total_score,
            event_count=len(all_events),
            window_events=window_log_events,
            trigger_reason=(
                f"Correlated suspicion {total_score:.2f} ≥ threshold {self._threshold:.2f} "
                f"| sources: {score_info['source_scores']} "
                f"| cross-source boost: +{score_info['cross_source_boost']:.2f}"
            ),
        )

        self._nova_calls.append(time.monotonic())
        self._total_triggers += 1

        logger.info(
            "⚡ CorrelationEngine: TRIGGER for %s — total=%.2f, "
            "log=%.2f, net=%.2f, auth=%.2f, proc=%.2f, boost=+%.2f",
            ip, total_score,
            score_info["source_scores"].get("log", 0),
            score_info["source_scores"].get("network", 0),
            score_info["source_scores"].get("auth", 0),
            score_info["source_scores"].get("process", 0),
            score_info["cross_source_boost"],
        )

        if self._on_trigger:
            await self._on_trigger(trigger)

        return trigger

    def _compute_score(self, ip: str) -> dict[str, Any]:
        """Compute weighted multi-source score for an IP.

        Returns a dict with:
          - source_scores: per-source max severity
          - weighted_score: weighted combination
          - cross_source_boost: bonus from correlation rules
          - total_score: final clamped score
        """
        source_scores: dict[str, float] = {}

        for source in ("log", "network", "auth", "process"):
            events = self._window_store.get_by_source(ip, source)
            if events:
                # Use max severity as the source signal strength
                max_sev = max(e.severity_hint for e in events)
                # Factor in event count (more events = higher confidence)
                count_factor = min(len(events) / 5.0, 1.0)
                source_scores[source] = max_sev * 0.7 + count_factor * 0.3
            else:
                source_scores[source] = 0.0

        # Weighted combination
        weighted = sum(
            self._weights.get(src, 0.0) * score
            for src, score in source_scores.items()
        )

        # Cross-source correlation boost
        boost = self._compute_cross_source_boost(ip)

        total = min(weighted + boost, 1.0)

        return {
            "ip": ip,
            "source_scores": source_scores,
            "weighted_score": round(weighted, 4),
            "cross_source_boost": round(boost, 4),
            "total_score": round(total, 4),
            "event_counts": self._window_store.get_source_counts(ip),
        }

    def _compute_cross_source_boost(self, ip: str) -> float:
        """Compute score boost from cross-source correlation rules."""
        boost = 0.0
        events = self._window_store.get_all(ip)
        event_types_by_source: dict[str, set[str]] = defaultdict(set)

        for e in events:
            event_types_by_source[e.source].add(e.event_type)

        for src_a, type_a, src_b, type_b, rule_boost in _CROSS_SOURCE_RULES:
            if (
                type_a in event_types_by_source.get(src_a, set()) and
                type_b in event_types_by_source.get(src_b, set())
            ):
                boost += rule_boost
                logger.debug(
                    "CorrelationEngine: cross-source rule matched "
                    "%s:%s + %s:%s → +%.2f for %s",
                    src_a, type_a, src_b, type_b, rule_boost, ip,
                )

        return min(boost, 0.5)  # Cap boost at 0.5

    def _can_call_nova(self) -> bool:
        """Check if we're within the per-minute Nova call limit."""
        now = time.monotonic()
        cutoff = now - 60.0
        self._nova_calls = [t for t in self._nova_calls if t > cutoff]
        return len(self._nova_calls) < self._max_nova_calls

    def _count_recent_nova_calls(self) -> int:
        now = time.monotonic()
        cutoff = now - 60.0
        return sum(1 for t in self._nova_calls if t > cutoff)
