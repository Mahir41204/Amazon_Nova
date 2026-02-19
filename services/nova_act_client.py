"""
NovaActClient — client for Nova Act automation actions.

Simulates defensive actions (block IP, disable user, update firewall,
quarantine system).  In DEMO_MODE every action is simulated and logged.
In production, this would integrate with the Nova Act SDK.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from config.settings import get_settings
from core.exceptions import NovaActClientError

logger = logging.getLogger(__name__)


@dataclass
class ActionResult:
    """Result of a defensive action execution."""

    action_type: str
    target: str
    success: bool
    simulated: bool
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0


class NovaActClient:
    """Client for executing automated defensive actions.

    Every action is logged for audit compliance.  In demo mode,
    actions are simulated without real side-effects.
    """

    # ┌─────────────────────────────────────────────────────────────────┐
    # │  PRODUCTION INTEGRATION GUIDE                                  │
    # ├─────────────────────────────────────────────────────────────────┤
    # │                                                                │
    # │  To replace simulation with real Nova Act SDK:                 │
    # │                                                                │
    # │  1. Install the Nova Act SDK:                                  │
    # │     pip install nova-act                                       │
    # │                                                                │
    # │  2. Replace _execute_real() with:                              │
    # │     from nova_act import NovaAct                               │
    # │     with NovaAct(                                              │
    # │         starting_page=self._settings.NOVA_ACT_ENDPOINT,        │
    # │         nova_act_api_key=self._settings.NOVA_ACT_API_KEY,      │
    # │     ) as nova:                                                 │
    # │         result = nova.act(                                     │
    # │             f"{action_type} on {target}",                      │
    # │             timeout=30000,                                     │
    # │         )                                                      │
    # │         return ActionResult(                                   │
    # │             action_type=action_type,                           │
    # │             target=target,                                     │
    # │             success=result.response is not None,               │
    # │             simulated=False,                                   │
    # │             details=result.metadata,                           │
    # │         )                                                      │
    # │                                                                │
    # │  3. Set ENABLE_PRODUCTION_MODE=True and DEMO_MODE=False        │
    # │                                                                │
    # │  4. Set NOVA_ACT_API_KEY and NOVA_ACT_ENDPOINT env vars        │
    # │                                                                │
    # └─────────────────────────────────────────────────────────────────┘

    SUPPORTED_ACTIONS = {"block_ip", "disable_user", "update_firewall", "quarantine_system"}

    def __init__(self) -> None:
        self._settings = get_settings()
        self._audit_log: list[ActionResult] = []
        self._validate_production_config()

    def _validate_production_config(self) -> None:
        """Validate that production credentials exist when production mode is on."""
        if self._settings.ENABLE_PRODUCTION_MODE and not self._settings.DEMO_MODE:
            if not self._settings.NOVA_ACT_API_KEY:
                raise NovaActClientError(
                    "ENABLE_PRODUCTION_MODE is True but NOVA_ACT_API_KEY is not set. "
                    "Provide valid Nova Act SDK credentials or set DEMO_MODE=True."
                )
            logger.info("NovaActClient running in PRODUCTION mode")

    async def execute_action(
        self,
        action_type: str,
        params: dict[str, Any],
        *,
        confidence: float | None = None,
    ) -> ActionResult:
        """Execute a defensive action.

        Args:
            action_type: One of the SUPPORTED_ACTIONS.
            params: Action-specific parameters (e.g. ``{"ip": "1.2.3.4"}``).

        Returns:
            An ``ActionResult`` describing what happened.

        Raises:
            NovaActClientError: If the action type is unsupported or execution fails.
        """
        if action_type not in self.SUPPORTED_ACTIONS:
            raise NovaActClientError(
                f"Unsupported action type: '{action_type}'. "
                f"Supported: {self.SUPPORTED_ACTIONS}"
            )

        start = time.perf_counter()
        target = params.get("target", "unknown")

        if self._settings.DEMO_MODE:
            result = await self._simulate_action(action_type, target, params)
        else:
            result = await self._execute_real(action_type, target, params)

        result.execution_time_ms = round((time.perf_counter() - start) * 1000, 2)
        self._audit_log.append(result)

        logger.info(
            "ACTION AUDIT | type=%s | target=%s | success=%s | simulated=%s",
            action_type,
            target,
            result.success,
            result.simulated,
        )

        self._log_execution(result, confidence=confidence)

        return result

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Return all recorded actions for audit purposes."""
        return [
            {
                "action_type": r.action_type,
                "target": r.target,
                "success": r.success,
                "simulated": r.simulated,
                "timestamp": r.timestamp,
                "details": r.details,
                "execution_time_ms": r.execution_time_ms,
            }
            for r in self._audit_log
        ]

    # ── Simulated actions ───────────────────────────────────────────────

    async def _simulate_action(
        self, action_type: str, target: str, params: dict[str, Any]
    ) -> ActionResult:
        """Simulate a defensive action (demo mode)."""
        details = {
            "block_ip": {
                "rule_added": f"iptables -A INPUT -s {target} -j DROP",
                "firewall": "primary",
                "duration": "permanent",
            },
            "disable_user": {
                "command": f"usermod -L {target}",
                "sessions_terminated": 3,
                "tokens_revoked": True,
            },
            "update_firewall": {
                "rules_updated": 2,
                "new_rule": f"DENY inbound SSH from {target}",
                "applied_to": ["sg-primary", "sg-dmz"],
            },
            "quarantine_system": {
                "system": target,
                "network_isolated": True,
                "snapshot_created": True,
                "forensic_image": f"forensic-{target}-{int(time.time())}.img",
            },
        }

        return ActionResult(
            action_type=action_type,
            target=target,
            success=True,
            simulated=True,
            details=details.get(action_type, {}),
        )

    async def _execute_real(
        self, action_type: str, target: str, params: dict[str, Any]
    ) -> ActionResult:
        """Execute a real defensive action via Nova Act SDK.

        This is the production integration point.
        """
        try:
            # CMS-style dynamic import to avoid hard dependency on SDK
            # that might not be installed in all environments.
            from nova_act import NovaAct
            
            logger.info(
                f"Connecting to Nova Act execution environment: {self._settings.NOVA_ACT_ENDPOINT}"
            )
            
            # Using context manager as per SDK pattern
            with NovaAct(
                starting_page=self._settings.NOVA_ACT_ENDPOINT,
                nova_act_api_key=self._settings.NOVA_ACT_API_KEY,
            ) as nova:
                
                instruction = f"Perform {action_type} on {target}. Context: {params}"
                logger.info(f"Dispatching Nova Act instruction: {instruction}")
                
                # Execute the action
                result = nova.act(instruction)
                
                return ActionResult(
                    action_type=action_type,
                    target=target,
                    success=True,
                    simulated=False,
                    details={"output": str(result), "instruction": instruction},
                )

        except ImportError:
            logger.error(
                "Nova Act SDK not found. Install 'nova-act' or similar package."
            )
            return ActionResult(
                action_type=action_type,
                target=target,
                success=False,
                simulated=False,
                details={"error": "Nova Act SDK missing"},
            )
        except Exception as exc:
            logger.exception("Real action execution failed: %s", action_type)
            return ActionResult(
                action_type=action_type,
                target=target,
                success=False,
                simulated=False,
                details={"error": str(exc)},
            )

    def _log_execution(
        self,
        result: ActionResult,
        *,
        confidence: float | None = None,
    ) -> None:
        """Emit a structured [NOVA ACT EXECUTION] log block."""
        status = "SUCCESS" if result.success else "DEFERRED"
        confidence_str = f"{confidence:.2%}" if confidence is not None else "N/A"
        simulated_cmd = self._get_simulated_command(result)

        logger.info(
            "\n\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\n"
            "\u2551                  [NOVA ACT EXECUTION]                       \u2551\n"
            "\u2560\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563\n"
            "\u2551  Action      : %-44s\u2551\n"
            "\u2551  Target      : %-44s\u2551\n"
            "\u2551  Sim Command : %-44s\u2551\n"
            "\u2551  Status      : %-44s\u2551\n"
            "\u2551  Confidence  : %-44s\u2551\n"
            "\u2551  Timestamp   : %-44s\u2551\n"
            "\u2551  Exec Time   : %-44s\u2551\n"
            "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d",
            result.action_type,
            result.target,
            simulated_cmd,
            status,
            confidence_str,
            result.timestamp,
            f"{result.execution_time_ms} ms",
        )

    @staticmethod
    def _get_simulated_command(result: ActionResult) -> str:
        """Extract the simulated system command from action details."""
        if not result.simulated:
            return "N/A (live execution)"
        details = result.details
        cmd = (
            details.get("rule_added")
            or details.get("command")
            or details.get("new_rule")
            or f"isolate {details.get('system', result.target)}"
        )
        return cmd[:44] if isinstance(cmd, str) else "simulated"
