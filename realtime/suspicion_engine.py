"""
SuspicionEngine — adaptive thresholding and cooldown management.

Sits between the CorrelationEngine and Nova activation to:
  - Prevent repeated triggering for the same IP
  - Apply exponential backoff cooldowns
  - Adaptively lower thresholds for repeat offenders
  - Reduce false positives through intelligent gating

Separated from CorrelationEngine for single-responsibility design.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Base cooldown after a trigger (seconds)
_BASE_COOLDOWN = 120.0
# Maximum cooldown (seconds)
_MAX_COOLDOWN = 3600.0
# Backoff multiplier
_BACKOFF_MULTIPLIER = 2.0
# Threshold reduction per repeat offense
_THRESHOLD_REDUCTION_PER_OFFENSE = 0.05
# Minimum threshold (never go below this)
_MIN_THRESHOLD = 0.4


@dataclass
class IPSuspicionState:
    """Tracks suspicion state for a single IP."""

    trigger_count: int = 0
    last_trigger_time: float = 0.0
    current_cooldown: float = _BASE_COOLDOWN
    is_escalated: bool = False
    total_events: int = 0
    peak_score: float = 0.0


class SuspicionEngine:
    """Adaptive threshold and cooldown manager.

    Works with the CorrelationEngine to gate Nova activations:

    1. CorrelationEngine computes raw score
    2. SuspicionEngine checks:
       - Has this IP triggered recently? (cooldown)
       - Should the threshold be lower for repeat offenders? (adaptive)
       - Is the score high enough given the current adaptive threshold?

    Usage::

        engine = SuspicionEngine(base_threshold=0.85)

        # Before triggering Nova:
        if engine.should_trigger(ip, score):
            engine.mark_triggered(ip)
            # ... trigger Nova
    """

    def __init__(self, base_threshold: float = 0.85) -> None:
        self._base_threshold = base_threshold
        self._states: dict[str, IPSuspicionState] = {}

    # ── Public API ──────────────────────────────────────────────────────

    def should_trigger(self, ip: str, score: float) -> bool:
        """Determine if an IP should trigger Nova activation.

        Returns True if:
          - Score meets the adaptive threshold for this IP
          - The IP is not in cooldown
        """
        state = self._get_or_create(ip)

        # Update peak score
        if score > state.peak_score:
            state.peak_score = score

        # Check cooldown
        if self._in_cooldown(ip):
            logger.debug(
                "SuspicionEngine: %s in cooldown (%.0fs remaining)",
                ip,
                self._cooldown_remaining(ip),
            )
            return False

        # Compute adaptive threshold
        threshold = self.get_adaptive_threshold(ip)

        if score >= threshold:
            return True

        return False

    def mark_triggered(self, ip: str) -> None:
        """Record that Nova was activated for this IP."""
        state = self._get_or_create(ip)
        state.trigger_count += 1
        state.last_trigger_time = time.monotonic()

        # Exponential backoff on cooldown
        state.current_cooldown = min(
            _BASE_COOLDOWN * (_BACKOFF_MULTIPLIER ** (state.trigger_count - 1)),
            _MAX_COOLDOWN,
        )

        # Escalate after 3 triggers
        if state.trigger_count >= 3:
            state.is_escalated = True

        logger.info(
            "SuspicionEngine: marked %s triggered (count=%d, cooldown=%.0fs, escalated=%s)",
            ip,
            state.trigger_count,
            state.current_cooldown,
            state.is_escalated,
        )

    def get_adaptive_threshold(self, ip: str) -> float:
        """Get the effective threshold for an IP.

        Repeat offenders get a lower threshold (easier to trigger).
        """
        state = self._get_or_create(ip)

        reduction = state.trigger_count * _THRESHOLD_REDUCTION_PER_OFFENSE
        threshold = max(
            self._base_threshold - reduction,
            _MIN_THRESHOLD,
        )

        return threshold

    def record_event(self, ip: str) -> None:
        """Record that an event was seen for this IP."""
        state = self._get_or_create(ip)
        state.total_events += 1

    def reset(self, ip: str) -> None:
        """Reset suspicion state for an IP."""
        if ip in self._states:
            del self._states[ip]

    def get_state(self, ip: str) -> dict[str, Any]:
        """Get the suspicion state for an IP."""
        state = self._states.get(ip)
        if not state:
            return {"ip": ip, "tracking": False}

        return {
            "ip": ip,
            "tracking": True,
            "trigger_count": state.trigger_count,
            "is_escalated": state.is_escalated,
            "in_cooldown": self._in_cooldown(ip),
            "cooldown_remaining": round(self._cooldown_remaining(ip), 1),
            "adaptive_threshold": round(self.get_adaptive_threshold(ip), 3),
            "peak_score": round(state.peak_score, 3),
            "total_events": state.total_events,
        }

    def get_all_tracked_ips(self) -> list[str]:
        """Return all IPs currently being tracked."""
        return list(self._states.keys())

    def get_escalated_ips(self) -> list[str]:
        """Return all IPs that have been escalated."""
        return [ip for ip, s in self._states.items() if s.is_escalated]

    def get_stats(self) -> dict[str, Any]:
        """Return engine statistics."""
        return {
            "tracked_ips": len(self._states),
            "escalated_ips": len(self.get_escalated_ips()),
            "in_cooldown": sum(
                1 for ip in self._states if self._in_cooldown(ip)
            ),
            "base_threshold": self._base_threshold,
            "total_triggers": sum(s.trigger_count for s in self._states.values()),
        }

    # ── Internal ────────────────────────────────────────────────────────

    def _get_or_create(self, ip: str) -> IPSuspicionState:
        if ip not in self._states:
            self._states[ip] = IPSuspicionState()
        return self._states[ip]

    def _in_cooldown(self, ip: str) -> bool:
        state = self._states.get(ip)
        if not state or state.last_trigger_time == 0.0:
            return False
        elapsed = time.monotonic() - state.last_trigger_time
        return elapsed < state.current_cooldown

    def _cooldown_remaining(self, ip: str) -> float:
        state = self._states.get(ip)
        if not state or state.last_trigger_time == 0.0:
            return 0.0
        elapsed = time.monotonic() - state.last_trigger_time
        remaining = state.current_cooldown - elapsed
        return max(remaining, 0.0)
