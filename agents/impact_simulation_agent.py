"""
ImpactSimulationAgent — simulates "what-if" impact scenarios.

For a given threat type, estimates:
  • Affected systems
  • Risk level
  • Estimated downtime
  • Estimated financial impact
  • Blast radius and severity score
"""

from __future__ import annotations

import json
import logging
from typing import Any

from core.agent_base import BaseAgent
from services.nova_client import NovaClient

logger = logging.getLogger(__name__)

# ── Impact models (heuristic baselines per threat type) ─────────────────

_IMPACT_MODELS: dict[str, dict[str, Any]] = {
    "brute_force": {
        "affected_resources": ["ssh-gateway-01", "auth-server-01"],
        "risk_profile": "elevated",
        "operational_impact": "controlled intervention required",
        "resource_impact_scope": "intermediate",
        "health_score_reduction": 2.5,
        "analysis_context": (
            "Potential high-frequency access patterns detected on authentication endpoints. "
            "May impact service availability if connections are saturated. "
            "Recommended: verify access policy alignment."
        ),
    },
    "phishing": {
        "affected_resources": ["email-gateway", "identity-services"],
        "risk_profile": "elevated",
        "operational_impact": "verification of identity integrity required",
        "resource_impact_scope": "broad",
        "health_score_reduction": 3.0,
        "analysis_context": (
            "Anomalous messaging activity observed. May lead to unintended data "
            "synchronization or account configuration adjustments. "
            "Recommended: audit recent session tokens."
        ),
    },
    "data_loss": {
        "affected_resources": ["database-tier", "storage-volume"],
        "risk_profile": "critical",
        "operational_impact": "significant resource reallocation required",
        "resource_impact_scope": "extensive",
        "health_score_reduction": 4.5,
        "analysis_context": (
            "Unexpected outbound data flow detected. May result in resource "
            "exhaustion or misalignment with data locality policies. "
            "Recommended: review egress rules and volume quotas."
        ),
    },
    "privilege_adjustment": {
        "affected_resources": ["core-infrastructure", "management-plane"],
        "risk_profile": "critical",
        "operational_impact": "immediate system auditing required",
        "resource_impact_scope": "extensive",
        "health_score_reduction": 4.8,
        "analysis_context": (
            "Unusual administrative transitions observed. Could lead to "
            "system configuration drifts or unplanned operational changes. "
            "Recommended: validate command authorization chain."
        ),
    },
}

_DEFAULT_IMPACT = {
    "affected_resources": ["unidentified-resource"],
    "risk_profile": "nominal",
    "operational_impact": "standard maintenance",
    "resource_impact_scope": "minimal",
    "health_score_reduction": 1.0,
    "analysis_context": "Baseline patterns observed. Continued monitoring advised.",
}


class ImpactSimulationAgent(BaseAgent):
    """Simulates the potential impact of a detected threat."""

    def __init__(self, nova_client: NovaClient) -> None:
        super().__init__("ImpactSimulation")
        self._nova = nova_client

    # ── BaseAgent interface ─────────────────────────────────────────────

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract threat parameters for simulation."""
        return {
            "threat_type": data.get("threat_type", "unknown"),
            "confidence_score": data.get("confidence_score", 0.0),
            "patterns": data.get("suspicious_patterns", []),
            "anomaly_score": data.get("anomaly_score", 0.0),
            "log_summary": data.get("log_summary", ""),
        }

    def reason(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Run the impact simulation model."""
        threat_type = analysis["threat_type"]
        confidence = analysis.get("confidence_score", 0.5)

        # Get base impact model
        model = _IMPACT_MODELS.get(threat_type, _DEFAULT_IMPACT).copy()

        # Adjust score based on confidence
        score_reduction = model["health_score_reduction"] * (0.7 + 0.3 * confidence)
        model["adjusted_health_impact"] = round(score_reduction, 1)
        model["confidence_factor"] = confidence
        model["log_summary"] = analysis.get("log_summary", "")

        return model

    def act(self, reasoning: dict[str, Any]) -> dict[str, Any]:
        """Produce the final impact simulation report."""
        from core.async_utils import run_async

        # Build prompt with operational context
        nova_prompt = json.dumps({
            "heuristic_analysis": {
                "affected_resources": reasoning["affected_resources"],
                "risk_profile": reasoning["risk_profile"],
                "operational_impact": reasoning["operational_impact"],
                "resource_impact_scope": reasoning["resource_impact_scope"],
                "base_impact_score": reasoning["adjusted_health_impact"],
            },
            "log_summary": reasoning.get("log_summary", ""),
            "analysis_context": reasoning.get("analysis_context", ""),
        })

        # Get Nova-enhanced analysis
        try:
            nova_response = run_async(
                self._nova.invoke(
                    prompt=nova_prompt,
                    system_prompt=(
                        "You are a system reliability and risk analyst. You receive heuristic resource analysis and activity context. "
                        "Determine the REALISTIC operational impact based on the observations and patterns. "
                        "Focus on resource availability, configuration integrity, and scope of influence. "
                        "Avoid dramatic language; be objective and technical. "
                        "You MUST respond with ONLY valid JSON. "
                        "Use this exact schema: "
                        '{"affected_resources": ["<string>", ...], "risk_profile": "<nominal|elevated|critical>", '
                        '"operational_impact": "<string>", "resource_impact_scope": "<minimal|intermediate|extensive>", '
                        '"health_impact_score": <float 0.0-5.0>, "technical_summary": "<string>"}'
                    ),
                    context="impact_simulation",
                )
            )
            nova_data = json.loads(nova_response)
        except Exception:
            nova_data = {}

        return {
            "affected_systems": nova_data.get("affected_resources", reasoning["affected_resources"]),
            "risk_level": nova_data.get("risk_profile", reasoning["risk_profile"]),
            "estimated_downtime": nova_data.get("operational_impact", reasoning["operational_impact"]),
            "estimated_financial_impact": "Manual Audit Required",
            "blast_radius": nova_data.get("resource_impact_scope", reasoning["resource_impact_scope"]),
            "severity_score": nova_data.get("health_impact_score", reasoning["adjusted_health_impact"]) * 2, # Scale back to 0-10
            "scenario_description": nova_data.get("technical_summary", reasoning.get("analysis_context", "")),
        }
