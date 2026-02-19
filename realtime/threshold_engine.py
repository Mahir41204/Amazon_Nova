"""
ThresholdEngine — evaluates suspicion scores and triggers Nova activation.

Sits between the SlidingWindowEngine and the Orchestrator.
Nova is NOT called for every event — only when the per-IP suspicion
score crosses the configured threshold.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Awaitable

from config.settings import get_settings
from events.event_models import LogEvent, IncidentTriggerEvent
from realtime.sliding_window_engine import SlidingWindowEngine
from realtime.ip_state_tracker import IPStateTracker

logger = logging.getLogger(__name__)


class ThresholdEngine:
    """Evaluates per-IP suspicion and activates Nova when thresholds cross.

    Design:
      - Heuristics trigger. Nova decides.
      - Each event updates the sliding window and suspicion score.
      - If score crosses threshold AND IP hasn't triggered recently → emit.
      - Rate-limits Nova calls via ``MAX_NOVA_CALLS_PER_MINUTE``.

    Usage::

        engine = ThresholdEngine(window_engine, ip_tracker, on_trigger=callback)
        await engine.evaluate(event)
    """

    def __init__(
        self,
        window_engine: SlidingWindowEngine,
        ip_tracker: IPStateTracker,
        *,
        on_trigger: Callable[[IncidentTriggerEvent], Awaitable[None]] | None = None,
    ) -> None:
        self._settings = get_settings()
        self._window = window_engine
        self._tracker = ip_tracker
        self._on_trigger = on_trigger

        # Rate limiting for Nova calls
        self._nova_calls: list[float] = []
        self._total_evaluations = 0
        self._total_triggers = 0

    # ── Public API ──────────────────────────────────────────────────────

    async def evaluate(self, event: LogEvent) -> IncidentTriggerEvent | None:
        """Evaluate a single event against thresholds.

        Returns an ``IncidentTriggerEvent`` if Nova should be activated,
        otherwise ``None``.
        """
        self._total_evaluations += 1

        # Record in sliding window
        self._window.record(event)

        # Compute suspicion score
        ip = event.source_ip
        score = self._window.get_suspicion_score(ip)
        event_count = self._window.get_event_count(ip)

        # Update IP state
        self._tracker.update(ip, score=score, events=event_count)

        # Check threshold
        threshold = self._compute_threshold(ip)

        if score < threshold:
            return None

        # Check cooldown
        if self._tracker.has_triggered(ip):
            logger.debug(
                "ThresholdEngine: %s score=%.2f exceeds threshold but in cooldown",
                ip,
                score,
            )
            return None

        # Check rate limit
        if not self._can_call_nova():
            logger.warning(
                "ThresholdEngine: Nova rate limit reached. "
                "Deferring trigger for %s (score=%.2f)",
                ip,
                score,
            )
            return None

        # TRIGGER — emit incident
        window_events = self._window.get_window(ip)
        trigger = IncidentTriggerEvent(
            source_ip=ip,
            suspicion_score=score,
            event_count=len(window_events),
            window_events=window_events,
            trigger_reason=(
                f"Suspicion score {score:.2f} crossed threshold {threshold:.2f} "
                f"({len(window_events)} events in window)"
            ),
        )

        self._tracker.mark_triggered(ip)
        self._nova_calls.append(time.monotonic())
        self._total_triggers += 1

        logger.info(
            "⚡ ThresholdEngine: TRIGGER for %s — score=%.2f, threshold=%.2f, events=%d",
            ip,
            score,
            threshold,
            len(window_events),
        )

        if self._on_trigger is not None:
            await self._on_trigger(trigger)

        return trigger

    def get_threshold(self, ip: str) -> float:
        """Get the effective threshold for an IP."""
        return self._compute_threshold(ip)

    def get_stats(self) -> dict[str, Any]:
        """Return engine statistics."""
        return {
            "total_evaluations": self._total_evaluations,
            "total_triggers": self._total_triggers,
            "nova_calls_last_minute": self._count_recent_calls(),
            "trigger_rate": (
                self._total_triggers / max(self._total_evaluations, 1) * 100
            ),
        }

    # ── Internal ────────────────────────────────────────────────────────

    def _compute_threshold(self, ip: str) -> float:
        """Compute the effective threshold for an IP.

        Base threshold from config, with adaptive adjustments:
          - Lower threshold for IPs with escalation patterns
          - Higher threshold for IPs with mostly benign traffic
        """
        base = self._settings.FAILED_ATTEMPT_THRESHOLD
        # Normalize to 0–1 scale: threshold = base_count / (base_count + 2)
        # e.g., threshold=5 → 0.71, threshold=10 → 0.83
        normalized = base / (base + 2.0)

        # Check for escalation signal — lower the threshold
        window = self._window.get_window(ip)
        has_escalation = any(
            e.event_type == "privilege_escalation" for e in window
        )
        if has_escalation:
            normalized *= 0.7  # 30% lower for escalation

        return normalized

    def _can_call_nova(self) -> bool:
        """Check if we're within the per-minute Nova call limit."""
        max_calls = self._settings.MAX_NOVA_CALLS_PER_MINUTE
        now = time.monotonic()
        cutoff = now - 60.0

        # Prune old entries
        self._nova_calls = [t for t in self._nova_calls if t > cutoff]

        return len(self._nova_calls) < max_calls

    def _count_recent_calls(self) -> int:
        """Count Nova calls in the last minute."""
        now = time.monotonic()
        cutoff = now - 60.0
        return sum(1 for t in self._nova_calls if t > cutoff)
