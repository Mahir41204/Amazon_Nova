"""
NovaClient — wrapper for Amazon Nova (Bedrock) reasoning API.

In DEMO_MODE, returns realistic mock LLM responses so the system
can be demonstrated without live API credentials.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from config.settings import get_settings
from core.exceptions import NovaClientError

logger = logging.getLogger(__name__)

# ── Demo / mock responses ───────────────────────────────────────────────

_DEMO_RESPONSES: dict[str, str] = {
    "log_analysis": json.dumps({
        "anomaly_score": 0.87,
        "suspicious_patterns": [
            {
                "pattern_type": "brute_force",
                "description": "47 failed SSH login attempts from 192.168.1.105 within 3 minutes",
                "severity": "high",
            },
            {
                "pattern_type": "privilege_escalation",
                "description": "User 'jdoe' escalated to root via sudo 12 seconds after first successful login",
                "severity": "critical",
            },
        ],
        "summary": "Detected a coordinated brute-force attack followed by immediate privilege escalation. The attack originated from IP 192.168.1.105, targeting the SSH service. After gaining access, the attacker escalated privileges to root within seconds, indicating automated post-exploitation tooling.",
        "events_analyzed": 128,
    }),
    "threat_classification": json.dumps({
        "threat_type": "brute_force",
        "confidence_score": 0.92,
        "explanation": "The pattern of 47 failed SSH login attempts in rapid succession from a single IP address, followed by a successful login and immediate privilege escalation, is a textbook brute-force attack combined with automated post-exploitation. The timing and volume are consistent with tools like Hydra or Medusa.",
        "recommended_action": "block_ip",
        "secondary_threat": "privilege_escalation",
    }),
    "impact_simulation": json.dumps({
        "affected_systems": [
            "ssh-gateway-01",
            "db-primary-01",
            "app-server-01",
            "app-server-02",
        ],
        "risk_level": "critical",
        "estimated_downtime": "2-4 hours",
        "estimated_financial_impact": "$45,000 - $120,000",
        "blast_radius": "high",
        "severity_score": 9.2,
        "scenario_description": "With root access, the attacker could exfiltrate the primary database, install persistent backdoors across application servers, and pivot to internal network segments. Estimated data at risk: 2.3M customer records.",
    }),
    "response_planning": json.dumps({
        "recommended_actions": [
            {"action": "block_ip", "target": "192.168.1.105", "priority": "immediate"},
            {"action": "disable_user", "target": "jdoe", "priority": "immediate"},
            {"action": "update_firewall", "target": "ssh-gateway-01", "priority": "high"},
            {"action": "quarantine_system", "target": "ssh-gateway-01", "priority": "high"},
        ],
        "rationale": "Immediate containment required to prevent lateral movement.",
    }),
    "report_generation": json.dumps({
        "executive_summary": "A coordinated cyber attack was detected and automatically mitigated. An attacker attempted to breach our SSH gateway using brute-force methods, briefly gaining elevated access before our automated defense system blocked the attack and isolated affected systems. No data loss occurred. Estimated prevented damage: $45,000-$120,000.",
        "technical_report": "## Incident Timeline\n\n- **22:14:03 UTC** — First failed SSH login from 192.168.1.105\n- **22:17:12 UTC** — 47th failed attempt; successful login with user 'jdoe'\n- **22:17:24 UTC** — Privilege escalation to root via sudo\n- **22:17:25 UTC** — Anomaly detected by Nova Log Intelligence\n- **22:17:26 UTC** — IP blocked, user disabled, firewall updated\n\n## Indicators of Compromise\n- Source IP: 192.168.1.105\n- Targeted service: SSH (port 22)\n- Compromised account: jdoe\n\n## Remediation\n- IP permanently blocked\n- Account disabled pending investigation\n- SSH gateway isolated for forensic analysis\n- Firewall rules updated to restrict SSH access\n\n## Prevention Recommendations\n- Implement SSH key-only authentication\n- Deploy fail2ban with stricter thresholds\n- Enable multi-factor authentication for privileged accounts\n- Review sudo policies and implement least-privilege access",
    }),
    "nova_reasoning_summary": json.dumps({
        "reasoning_summary": (
            "Nova's multi-agent analysis classified this incident as a brute-force "
            "attack with high confidence (92%). The classification was driven by the "
            "detection of 47 failed SSH login attempts from a single source IP within "
            "a 3-minute window — a pattern consistent with automated credential-stuffing "
            "tools. The anomaly score of 0.87 exceeded the baseline threshold by 3.2 "
            "standard deviations. Confidence was further reinforced by similarity to "
            "2 prior incidents in the vector memory store (avg similarity: 0.84), both "
            "confirmed brute-force attacks. The immediate privilege escalation to root "
            "12 seconds post-breach elevated the severity from 'high' to 'critical', "
            "triggering automated containment via Nova Act."
        ),
    }),
}


class NovaClient:
    """Client for Amazon Nova reasoning API (Bedrock).

    When ``DEMO_MODE`` is enabled, returns pre-built realistic responses
    instead of calling the live API, enabling offline demonstration.
    """

    # ┌─────────────────────────────────────────────────────────────────┐
    # │  PRODUCTION INTEGRATION GUIDE                                  │
    # ├─────────────────────────────────────────────────────────────────┤
    # │                                                                │
    # │  To replace demo mode with live AWS Bedrock:                   │
    # │                                                                │
    # │  1. Install boto3:                                             │
    # │     pip install boto3                                          │
    # │                                                                │
    # │  2. Replace _call_bedrock() with:                              │
    # │     import boto3                                               │
    # │     client = boto3.client(                                     │
    # │         "bedrock-runtime",                                     │
    # │         region_name=self._settings.NOVA_REGION,                │
    # │     )                                                          │
    # │     response = client.invoke_model(                            │
    # │         modelId=self._settings.NOVA_MODEL_ID,                  │
    # │         body=json.dumps({...}),                                │
    # │         contentType="application/json",                        │
    # │     )                                                          │
    # │     # SigV4 auth is handled automatically by boto3 via         │
    # │     # AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars        │
    # │     # or IAM role when deployed on ECS/Lambda.                 │
    # │                                                                │
    # │  3. Set ENABLE_PRODUCTION_MODE=True and DEMO_MODE=False        │
    # │                                                                │
    # │  4. Ensure AWS credentials are available (env vars / IAM role) │
    # │                                                                │
    # └─────────────────────────────────────────────────────────────────┘

    def __init__(self) -> None:
        self._settings = get_settings()
        self._validate_production_config()

    def _validate_production_config(self) -> None:
        """Validate that production credentials exist when production mode is on."""
        if self._settings.ENABLE_PRODUCTION_MODE and not self._settings.DEMO_MODE:
            if not self._settings.AWS_ACCESS_KEY_ID or not self._settings.AWS_SECRET_ACCESS_KEY:
                raise NovaClientError(
                    "ENABLE_PRODUCTION_MODE is True but AWS credentials are not set. "
                    "Provide AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or set DEMO_MODE=True."
                )
            logger.info("NovaClient running in PRODUCTION mode (model: %s)", self._settings.NOVA_MODEL_ID)

    async def invoke(
        self,
        prompt: str,
        system_prompt: str = "",
        context: str = "general",
    ) -> str:
        """Send a prompt to Nova and return the response text.

        Args:
            prompt: The user / agent prompt.
            system_prompt: Optional system-level instructions.
            context: A key used to select the appropriate demo response.

        Returns:
            The model's text response.
        """
        start = time.perf_counter()
        timestamp = datetime.now(timezone.utc).isoformat()

        if self._settings.DEMO_MODE:
            response = self._demo_response(context)
        else:
            response = await self._call_bedrock(prompt, system_prompt)

        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

        self._log_reasoning(
            context=context,
            prompt=prompt,
            response=response,
            timestamp=timestamp,
            elapsed_ms=elapsed_ms,
        )

        return response

    # ── Private helpers ─────────────────────────────────────────────────

    def _log_reasoning(
        self,
        *,
        context: str,
        prompt: str,
        response: str,
        timestamp: str,
        elapsed_ms: float,
    ) -> None:
        """Emit a structured [NOVA REASONING] log block."""
        mode = "DEMO" if self._settings.DEMO_MODE else "LIVE"
        prompt_summary = self._truncate(prompt, 200)
        response_summary = self._truncate(response, 200)

        logger.info(
            "\n╔══════════════════════════════════════════════════════════════╗\n"
            "║                    [NOVA REASONING]                         ║\n"
            "╠══════════════════════════════════════════════════════════════╣\n"
            "║  Model      : %-44s║\n"
            "║  Context    : %-44s║\n"
            "║  Mode       : %-44s║\n"
            "║  Timestamp  : %-44s║\n"
            "║  Exec Time  : %-44s║\n"
            "╠══════════════════════════════════════════════════════════════╣\n"
            "║  Input  : %-48s║\n"
            "║  Output : %-48s║\n"
            "╚══════════════════════════════════════════════════════════════╝",
            self._settings.NOVA_MODEL_ID,
            context,
            mode,
            timestamp,
            f"{elapsed_ms} ms",
            prompt_summary,
            response_summary,
        )

    @staticmethod
    def _truncate(text: str, max_len: int = 200) -> str:
        """Safely truncate text for logging — no sensitive data leaks."""
        clean = text.replace("\n", " ").strip()
        if len(clean) > max_len:
            return clean[:max_len - 3] + "..."
        return clean

    def _demo_response(self, context: str) -> str:
        """Return a realistic mock response for demo mode."""
        response = _DEMO_RESPONSES.get(context, '{"status": "ok"}')
        return response

    async def _call_bedrock(self, prompt: str, system_prompt: str) -> str:
        """Call the real Amazon Bedrock Nova API.

        Uses the Bedrock Runtime `converse` API which provides a standardized
        interface for Nova and other models.

        The synchronous boto3 call is offloaded to a thread via
        ``asyncio.to_thread`` so it does not block the event loop.
        """
        try:
            import boto3
            from botocore.exceptions import ClientError

            client = boto3.client(
                "bedrock-runtime",
                region_name=self._settings.NOVA_REGION,
            )

            messages = [
                {"role": "user", "content": [{"text": prompt}]}
            ]
            
            system = [{"text": system_prompt}] if system_prompt else []

            inference_config = {
                "maxTokens": self._settings.NOVA_MAX_TOKENS,
                "temperature": self._settings.NOVA_TEMPERATURE,
            }

            # Offload blocking boto3 call to thread pool
            response = await asyncio.to_thread(
                client.converse,
                modelId=self._settings.NOVA_MODEL_ID,
                messages=messages,
                system=system,
                inferenceConfig=inference_config,
            )

            # Extract content from Converse API response
            output_content = response["output"]["message"]["content"]
            # Combine all text blocks
            full_text = "".join(
                block["text"] for block in output_content if "text" in block
            )
            return full_text

        except ImportError:
            logger.error("boto3 not installed. Please install it for production mode.")
            raise NovaClientError("boto3 not installed")
        except Exception as exc:
            logger.exception("Nova API call failed")
            raise NovaClientError(f"Nova API call failed: {exc}") from exc
