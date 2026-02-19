"""
BlockManager — bridges Orchestrator pipeline results to SandboxFirewall.

After the orchestrator completes a realtime incident pipeline, the
BlockManager extracts enforcement actions and registers them in the
SandboxFirewall.
"""

from __future__ import annotations

import logging
from typing import Any

from enforcement.sandbox_firewall import SandboxFirewall

logger = logging.getLogger(__name__)


class BlockManager:
    """Coordinates enforcement between orchestrator output and firewall.

    Extracts ``block_ip`` actions from pipeline results and registers
    them in the ``SandboxFirewall``. Also handles unblock triggers.

    Usage::

        manager = BlockManager(firewall)
        manager.process_pipeline_result(result, source_ip="1.2.3.4")
    """

    def __init__(self, firewall: SandboxFirewall) -> None:
        self._firewall = firewall
        self._actions_processed = 0

    def process_pipeline_result(
        self,
        result: dict[str, Any],
        source_ip: str,
    ) -> list[dict[str, Any]]:
        """Extract enforcement actions from a pipeline result.

        Returns a list of enforcement action records.
        """
        enforcement_log: list[dict[str, Any]] = []
        incident_id = result.get("incident_id", "unknown")

        # Extract actions from the response stage
        stages = result.get("stages", {})
        response = stages.get("response", {}).get("result", {})
        actions_taken = response.get("actions_taken", [])

        for action in actions_taken:
            action_type = action.get("action_type", "")
            target = action.get("target", source_ip)

            if action_type == "block_ip":
                blocked = self._firewall.block(
                    target,
                    reason=f"pipeline_action_{incident_id}",
                    incident_id=incident_id,
                )
                enforcement_log.append({
                    "action": "block_ip",
                    "target": target,
                    "success": blocked,
                    "incident_id": incident_id,
                })
                self._actions_processed += 1

        # Also block the source IP if threat confidence is high enough
        threat = stages.get("threat_classification", {}).get("result", {})
        confidence = threat.get("confidence_score", 0)

        if confidence >= 0.85 and source_ip not in [
            a.get("target") for a in enforcement_log
        ]:
            blocked = self._firewall.block(
                source_ip,
                reason=f"high_confidence_threat_{incident_id}",
                incident_id=incident_id,
            )
            if blocked:
                enforcement_log.append({
                    "action": "block_ip",
                    "target": source_ip,
                    "success": True,
                    "incident_id": incident_id,
                    "reason": f"auto_block_confidence_{confidence:.2f}",
                })

        return enforcement_log

    def get_stats(self) -> dict[str, Any]:
        """Return block manager statistics."""
        return {
            "actions_processed": self._actions_processed,
            **self._firewall.get_stats(),
        }
