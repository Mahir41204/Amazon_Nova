"""
IncidentRepository — persistent storage for complete incident records.

Stores every agent output, decision, and action for post-mortem analysis.
In-memory dict with JSON file persistence (swap for a DB in production).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from config.settings import get_settings

logger = logging.getLogger(__name__)


class IncidentRepository:
    """CRUD repository for incident records.

    Each incident record is the full state dict produced by the
    orchestrator, including all agent outputs and the decision log.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._store: dict[str, dict[str, Any]] = {}
        self._load()

    # ── CRUD ────────────────────────────────────────────────────────────

    def save(self, incident: dict[str, Any]) -> str:
        """Save or update an incident record."""
        incident_id = incident["incident_id"]
        self._store[incident_id] = incident
        self._persist()
        logger.info("Saved incident %s", incident_id)
        return incident_id

    def get(self, incident_id: str) -> dict[str, Any] | None:
        """Retrieve an incident by ID, or None if not found."""
        return self._store.get(incident_id)

    def list_all(self) -> list[dict[str, Any]]:
        """Return lightweight summaries of all incidents."""
        return [
            {
                "incident_id": v["incident_id"],
                "status": v.get("status", "unknown"),
                "created_at": v.get("created_at", ""),
                "updated_at": v.get("updated_at", ""),
            }
            for v in self._store.values()
        ]

    def delete(self, incident_id: str) -> bool:
        """Delete an incident record. Returns True if existed."""
        if incident_id in self._store:
            del self._store[incident_id]
            self._persist()
            logger.info("Deleted incident %s", incident_id)
            return True
        return False

    @property
    def count(self) -> int:
        """Number of stored incidents."""
        return len(self._store)

    # ── Persistence ─────────────────────────────────────────────────────

    def _persist(self) -> None:
        path = Path(self._settings.INCIDENT_STORE_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._store, indent=2, default=str))

    def _load(self) -> None:
        path = Path(self._settings.INCIDENT_STORE_PATH)
        if path.exists():
            try:
                self._store = json.loads(path.read_text())
                logger.info("Loaded %d incidents from %s", len(self._store), path)
            except Exception as exc:
                logger.warning("Failed to load incident store: %s", exc)
