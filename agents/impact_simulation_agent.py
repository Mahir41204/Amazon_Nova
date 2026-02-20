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
        "affected_systems": ["ssh-gateway-01", "auth-server-01"],
        "risk_level": "high",
        "estimated_downtime": "1-2 hours",
        "estimated_financial_impact": "$15,000 - $50,000",
        "blast_radius": "medium",
        "base_severity": 7.5,
        "scenario": (
            "Successful brute-force could grant attacker access to the SSH gateway, "
            "enabling lateral movement to internal systems. Risk of credential reuse "
            "across services if password policies are weak."
        ),
    },
    "phishing": {
        "affected_systems": ["email-gateway", "user-workstations", "identity-provider"],
        "risk_level": "high",
        "estimated_downtime": "2-4 hours",
        "estimated_financial_impact": "$25,000 - $100,000",
        "blast_radius": "high",
        "base_severity": 8.0,
        "scenario": (
            "Compromised credentials from phishing could grant access to corporate email, "
            "cloud services, and internal applications. Risk of business email compromise "
            "and further social engineering attacks."
        ),
    },
    "malware": {
        "affected_systems": ["endpoint-01", "file-server-01", "backup-server-01"],
        "risk_level": "critical",
        "estimated_downtime": "4-24 hours",
        "estimated_financial_impact": "$50,000 - $500,000",
        "blast_radius": "critical",
        "base_severity": 9.5,
        "scenario": (
            "Malware infection could spread to file servers and backup systems, "
            "potentially encrypting critical data (ransomware) or establishing "
            "persistent command-and-control channels for long-term espionage."
        ),
    },
    "data_exfiltration": {
        "affected_systems": ["db-primary-01", "app-server-01", "data-warehouse"],
        "risk_level": "critical",
        "estimated_downtime": "2-8 hours",
        "estimated_financial_impact": "$100,000 - $1,000,000",
        "blast_radius": "critical",
        "base_severity": 9.0,
        "scenario": (
            "Data exfiltration of customer records could result in regulatory fines "
            "(GDPR, CCPA), class-action lawsuits, and severe reputational damage. "
            "Estimated records at risk based on database size and access patterns."
        ),
    },
    "privilege_escalation": {
        "affected_systems": ["ssh-gateway-01", "db-primary-01", "app-server-01", "app-server-02"],
        "risk_level": "critical",
        "estimated_downtime": "2-4 hours",
        "estimated_financial_impact": "$45,000 - $120,000",
        "blast_radius": "high",
        "base_severity": 9.2,
        "scenario": (
            "With elevated privileges, attacker could modify system configurations, "
            "install backdoors, exfiltrate data, or disrupt services. Full root access "
            "means complete system compromise is possible."
        ),
    },
}

_DEFAULT_IMPACT = {
    "affected_systems": ["unknown-system"],
    "risk_level": "medium",
    "estimated_downtime": "1-2 hours",
    "estimated_financial_impact": "$10,000 - $25,000",
    "blast_radius": "low",
    "base_severity": 5.0,
    "scenario": "Insufficient data to accurately model impact. Manual assessment recommended.",
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
        }

    def reason(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Run the impact simulation model."""
        threat_type = analysis["threat_type"]
        confidence = analysis.get("confidence_score", 0.5)

        # Get base impact model
        model = _IMPACT_MODELS.get(threat_type, _DEFAULT_IMPACT).copy()

        # Adjust severity based on confidence
        severity = model["base_severity"] * (0.7 + 0.3 * confidence)
        model["adjusted_severity"] = round(severity, 1)
        model["confidence_factor"] = confidence

        return model

    async def act(self, reasoning: dict[str, Any]) -> dict[str, Any]:
        """Produce the final impact simulation report."""
        # Get Nova-enhanced simulation
        try:
            nova_response = await self._nova.invoke(
                prompt=json.dumps(reasoning),
                system_prompt="You are a cybersecurity impact analyst. Simulate the impact scenario.",
                context="impact_simulation",
            )
            nova_data = json.loads(nova_response)
        except Exception:
            nova_data = {}

        return {
            "affected_systems": nova_data.get("affected_systems", reasoning["affected_systems"]),
            "risk_level": nova_data.get("risk_level", reasoning["risk_level"]),
            "estimated_downtime": nova_data.get("estimated_downtime", reasoning["estimated_downtime"]),
            "estimated_financial_impact": nova_data.get(
                "estimated_financial_impact", reasoning["estimated_financial_impact"]
            ),
            "blast_radius": nova_data.get("blast_radius", reasoning["blast_radius"]),
            "severity_score": nova_data.get("severity_score", reasoning["adjusted_severity"]),
            "scenario_description": nova_data.get("scenario_description", reasoning.get("scenario", "")),
        }
