"""
StateManager — thread-safe pipeline state for each incident.

Maintains a per-incident state dict that accumulates agent outputs
as the orchestrator progresses through the pipeline.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class StateManager:
    """Manages global pipeline state across agents for a single run.

    Each incident gets a UUID.  Agent outputs are stored under named
    stages.  Thread-safe via a re-entrant lock.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._incidents: dict[str, dict[str, Any]] = {}

    # ── Public API ──────────────────────────────────────────────────────

    def create_incident(self, raw_input: dict[str, Any]) -> str:
        """Create a new incident record and return its UUID."""
        incident_id = str(uuid.uuid4())
        with self._lock:
            self._incidents[incident_id] = {
                "incident_id": incident_id,
                "status": "in_progress",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "raw_input_summary": self._summarize_input(raw_input),
                "stages": {},
                "decision_log": [],
            }
        logger.info("Created incident %s", incident_id)
        return incident_id

    def update_stage(
        self,
        incident_id: str,
        stage_name: str,
        output: dict[str, Any],
    ) -> None:
        """Record the output of a pipeline stage."""
        with self._lock:
            incident = self._get(incident_id)
            incident["stages"][stage_name] = output
            incident["updated_at"] = datetime.now(timezone.utc).isoformat()
        logger.info("Incident %s — stage '%s' complete", incident_id, stage_name)

    def add_decision(self, incident_id: str, decision: str) -> None:
        """Append a decision / log entry to the audit trail."""
        with self._lock:
            incident = self._get(incident_id)
            incident["decision_log"].append(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "decision": decision,
                }
            )

    def get_state(self, incident_id: str) -> dict[str, Any]:
        """Return a *copy* of the current incident state."""
        with self._lock:
            return dict(self._get(incident_id))

    def get_stage(self, incident_id: str, stage_name: str) -> dict[str, Any]:
        """Return output of a specific stage, or empty dict."""
        with self._lock:
            return self._get(incident_id).get("stages", {}).get(stage_name, {})

    def finalize(self, incident_id: str, status: str = "completed") -> dict[str, Any]:
        """Mark the incident as finalized and return the full state."""
        with self._lock:
            incident = self._get(incident_id)
            incident["status"] = status
            incident["updated_at"] = datetime.now(timezone.utc).isoformat()
            logger.info("Incident %s finalized with status '%s'", incident_id, status)
            return dict(incident)

    def list_incidents(self) -> list[dict[str, Any]]:
        """Return lightweight summaries of all stored incidents."""
        with self._lock:
            return [
                {
                    "incident_id": v["incident_id"],
                    "status": v["status"],
                    "created_at": v["created_at"],
                    "updated_at": v["updated_at"],
                }
                for v in self._incidents.values()
            ]

    # ── Internal helpers ────────────────────────────────────────────────

    def _get(self, incident_id: str) -> dict[str, Any]:
        try:
            return self._incidents[incident_id]
        except KeyError:
            raise ValueError(f"Incident '{incident_id}' not found") from None

    @staticmethod
    def _summarize_input(raw_input: dict[str, Any]) -> str:
        logs = raw_input.get("logs", [])
        if isinstance(logs, list):
            return f"{len(logs)} log entries submitted"
        return "raw input submitted"
