"""
BaseAgent — abstract base class for all Nova agents.

Every agent must implement analyze(), reason(), and act().
The execute() template method chains them and adds logging / timing.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any

from core.exceptions import AgentError

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class that every Nova agent inherits from.

    Agents are **stateless** — they receive data, process it, and return
    structured JSON-serialisable dicts.  They never call other agents
    directly; all inter-agent communication flows through the Orchestrator.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self._logger = logging.getLogger(f"nova.agent.{name}")

    # ── Abstract methods that subclasses must implement ─────────────────

    @abstractmethod
    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Parse and extract relevant features from the raw input."""

    @abstractmethod
    def reason(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Apply domain logic / LLM reasoning on the analysed data."""

    @abstractmethod
    async def act(self, reasoning: dict[str, Any]) -> dict[str, Any]:
        """Produce the final structured output (action / report)."""

    # ── Template method ─────────────────────────────────────────────────

    async def execute(self, data: dict[str, Any]) -> dict[str, Any]:
        """Run the full agent pipeline: analyze → reason → act.

        Returns a structured dict with ``agent``, ``result``, and
        ``execution_time_ms`` keys.  Wraps any unexpected exceptions
        in an ``AgentError``.
        """
        self._logger.info("Starting execution for agent '%s'", self.name)
        start = time.perf_counter()

        try:
            analysis = self.analyze(data)
            self._logger.debug("[%s] Analysis complete: %s", self.name, list(analysis.keys()))

            reasoning = self.reason(analysis)
            self._logger.debug("[%s] Reasoning complete: %s", self.name, list(reasoning.keys()))

            result = await self.act(reasoning)
            self._logger.debug("[%s] Action complete: %s", self.name, list(result.keys()))

        except AgentError:
            raise  # already a well-formed error
        except Exception as exc:
            self._logger.exception("Unexpected error in agent '%s'", self.name)
            raise AgentError(self.name, str(exc)) from exc

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        self._logger.info(
            "Agent '%s' completed in %.2f ms", self.name, elapsed_ms
        )

        return {
            "agent": self.name,
            "result": result,
            "execution_time_ms": elapsed_ms,
        }
