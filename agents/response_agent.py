"""
ResponseAgent — executes automated defensive actions via Nova Act.

Safety-critical: only executes when confidence exceeds the configured
threshold.  All actions are logged for audit compliance.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from config.settings import get_settings
from core.agent_base import BaseAgent
from core.exceptions import ConfidenceThresholdError
from services.nova_act_client import NovaActClient, ActionResult
from services.nova_client import NovaClient

logger = logging.getLogger(__name__)

# ── Action mappings ─────────────────────────────────────────────────────

_ACTION_PLANS: dict[str, list[dict[str, Any]]] = {
    "block_ip": [
        {"action": "block_ip", "priority": "immediate"},
    ],
    "disable_user": [
        {"action": "disable_user", "priority": "immediate"},
    ],
    "update_firewall": [
        {"action": "update_firewall", "priority": "high"},
    ],
    "quarantine_system": [
        {"action": "quarantine_system", "priority": "high"},
    ],
    "block_ip_and_disable": [
        {"action": "block_ip", "priority": "immediate"},
        {"action": "disable_user", "priority": "immediate"},
    ],
}


class ResponseAgent(BaseAgent):
    """Executes automated defensive actions with confidence gating."""

    def __init__(
        self,
        nova_client: NovaClient,
        nova_act_client: NovaActClient,
    ) -> None:
        super().__init__("Response")
        self._nova = nova_client
        self._act_client = nova_act_client
        self._settings = get_settings()

    # ── BaseAgent interface ─────────────────────────────────────────────

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Determine which actions are needed."""
        recommended = data.get("recommended_action", "flag_for_review")
        confidence = data.get("confidence_score", 0.0)
        threat_type = data.get("threat_type", "unknown")

        # Build action plan
        actions = _ACTION_PLANS.get(recommended, [])
        if not actions and threat_type in _ACTION_PLANS:
            actions = _ACTION_PLANS[threat_type]

        # For critical threats, add escalation actions
        if data.get("risk_level") == "critical" and recommended == "block_ip":
            actions = _ACTION_PLANS.get("block_ip_and_disable", actions)

        return {
            "confidence_score": confidence,
            "threshold": self._settings.CONFIDENCE_THRESHOLD,
            "above_threshold": confidence >= self._settings.CONFIDENCE_THRESHOLD,
            "planned_actions": actions,
            "threat_type": threat_type,
            "recommended_action": recommended,
            "source_data": data,
        }

    def reason(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Decide whether to execute or defer to human review."""
        above = analysis["above_threshold"]
        confidence = analysis["confidence_score"]
        threshold = analysis["threshold"]

        if above:
            logger.info(
                "Confidence %.2f >= threshold %.2f — AUTOMATED RESPONSE AUTHORIZED",
                confidence,
                threshold,
            )
            decision = "execute"
        else:
            logger.warning(
                "Confidence %.2f < threshold %.2f — DEFERRING TO HUMAN REVIEW",
                confidence,
                threshold,
            )
            decision = "defer"

        # Extract targets from source data
        patterns = analysis.get("source_data", {}).get("suspicious_patterns", [])
        targets = {}
        for p in patterns:
            if p.get("source_ip"):
                targets["ip"] = p["source_ip"]
            if p.get("user"):
                targets["user"] = p["user"]
            if p.get("target"):
                targets["system"] = p["target"]

        # Default targets for demo
        if not targets:
            targets = {"ip": "192.168.1.105", "user": "jdoe", "system": "ssh-gateway-01"}

        return {
            "decision": decision,
            "confidence_score": confidence,
            "threshold": threshold,
            "planned_actions": analysis["planned_actions"],
            "targets": targets,
            "threat_type": analysis["threat_type"],
        }

    def act(self, reasoning: dict[str, Any]) -> dict[str, Any]:
        """Execute or defer actions based on confidence decision."""
        from core.async_utils import run_async

        decision = reasoning["decision"]
        actions_taken: list[dict[str, Any]] = []
        actions_deferred: list[dict[str, Any]] = []

        if decision == "execute":
            for action_plan in reasoning["planned_actions"]:
                action_type = action_plan["action"]
                target = self._resolve_target(action_type, reasoning["targets"])

                try:
                    result = run_async(
                        self._act_client.execute_action(
                            action_type=action_type,
                            params={"target": target},
                            confidence=reasoning["confidence_score"],
                        )
                    )

                    actions_taken.append({
                        "action_type": result.action_type,
                        "target": result.target,
                        "success": result.success,
                        "simulated": result.simulated,
                        "timestamp": result.timestamp,
                        "details": result.details,
                        "execution_time_ms": result.execution_time_ms,
                    })

                except Exception as exc:
                    logger.exception("Action execution failed: %s", action_type)
                    actions_deferred.append({
                        "action_type": action_type,
                        "target": target,
                        "reason": f"Execution failed: {exc}",
                    })
        else:
            # Defer all actions
            for action_plan in reasoning["planned_actions"]:
                action_type = action_plan["action"]
                target = self._resolve_target(action_type, reasoning["targets"])
                actions_deferred.append({
                    "action_type": action_type,
                    "target": target,
                    "reason": (
                        f"Confidence {reasoning['confidence_score']:.2%} below "
                        f"threshold {reasoning['threshold']:.2%}"
                    ),
                })

        return {
            "decision": decision,
            "confidence_score": reasoning["confidence_score"],
            "threshold": reasoning["threshold"],
            "actions_taken": actions_taken,
            "actions_deferred": actions_deferred,
            "requires_human_review": decision == "defer",
            "audit_log": self._act_client.get_audit_log(),
        }

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _resolve_target(action_type: str, targets: dict[str, str]) -> str:
        """Map action type to the appropriate target."""
        mapping = {
            "block_ip": "ip",
            "disable_user": "user",
            "update_firewall": "system",
            "quarantine_system": "system",
        }
        key = mapping.get(action_type, "ip")
        return targets.get(key, "unknown")
