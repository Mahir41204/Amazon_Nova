"""
ReportingAgent — generates executive and technical incident reports.

Produces:
  • Executive summary (non-technical, for leadership)
  • Technical forensic report (for security team)
  • Prevention recommendations
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from core.agent_base import BaseAgent
from services.nova_client import NovaClient

logger = logging.getLogger(__name__)


class ReportingAgent(BaseAgent):
    """Generates comprehensive incident reports."""

    def __init__(self, nova_client: NovaClient) -> None:
        super().__init__("Reporting")
        self._nova = nova_client

    # ── BaseAgent interface ─────────────────────────────────────────────

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Collate all pipeline data for report generation."""
        return {
            "log_analysis": data.get("log_analysis", {}),
            "threat_classification": data.get("threat_classification", {}),
            "impact_simulation": data.get("impact_simulation", {}),
            "response": data.get("response", {}),
            "incident_id": data.get("incident_id", "N/A"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def reason(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Structure the report sections from collected data."""
        threat = analysis.get("threat_classification", {})
        impact = analysis.get("impact_simulation", {})
        response = analysis.get("response", {})
        log_data = analysis.get("log_analysis", {})

        # Executive summary components
        threat_type = threat.get("threat_type", "unknown").replace("_", " ").title()
        risk_level = impact.get("risk_level", "unknown")
        financial_impact = impact.get("estimated_financial_impact", "undetermined")
        actions_count = len(response.get("actions_taken", []))
        deferred_count = len(response.get("actions_deferred", []))
        auto_response = not response.get("requires_human_review", True)

        executive = {
            "headline": f"{threat_type} Attack {'Mitigated' if auto_response else 'Detected — Awaiting Review'}",
            "risk_level": risk_level,
            "financial_impact": financial_impact,
            "auto_mitigated": auto_response,
            "actions_taken": actions_count,
            "actions_pending": deferred_count,
        }

        # Technical report components
        technical = {
            "incident_id": analysis["incident_id"],
            "timestamp": analysis["timestamp"],
            "threat_type": threat.get("threat_type"),
            "confidence_score": threat.get("confidence_score"),
            "anomaly_score": log_data.get("anomaly_score"),
            "patterns_detected": log_data.get("suspicious_patterns", []),
            "affected_systems": impact.get("affected_systems", []),
            "severity_score": impact.get("severity_score"),
            "actions_taken": response.get("actions_taken", []),
            "actions_deferred": response.get("actions_deferred", []),
            "similar_incidents": threat.get("similar_incidents", []),
        }

        return {
            "executive": executive,
            "technical": technical,
            "threat_explanation": threat.get("explanation", ""),
            "scenario_description": impact.get("scenario_description", ""),
        }

    def act(self, reasoning: dict[str, Any]) -> dict[str, Any]:
        """Generate the final formatted reports."""
        from core.async_utils import run_async

        # Get Nova-enhanced report
        try:
            nova_response = run_async(
                self._nova.invoke(
                    prompt=json.dumps(reasoning),
                    system_prompt="You are a cybersecurity report writer. Generate executive and technical reports.",
                    context="report_generation",
                )
            )
            nova_data = json.loads(nova_response)
        except Exception:
            nova_data = {}

        exec_data = reasoning["executive"]

        # Build executive summary
        executive_summary = nova_data.get("executive_summary", self._build_executive_summary(exec_data, reasoning))

        # Build technical report
        technical_report = nova_data.get("technical_report", self._build_technical_report(reasoning))

        # Build prevention recommendations
        recommendations = self._build_recommendations(reasoning)

        return {
            "executive_summary": executive_summary,
            "technical_report": technical_report,
            "prevention_recommendations": recommendations,
            "nova_reasoning_summary": self._build_nova_reasoning_summary(reasoning),
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "incident_id": reasoning["technical"]["incident_id"],
            },
        }

    # ── Report builders ─────────────────────────────────────────────────

    @staticmethod
    def _build_executive_summary(exec_data: dict, reasoning: dict) -> str:
        """Build a human-readable executive summary."""
        status = "automatically mitigated" if exec_data["auto_mitigated"] else "detected and flagged for review"
        lines = [
            f"## {exec_data['headline']}",
            "",
            f"A cybersecurity incident has been {status}.",
            "",
            f"**Risk Level:** {exec_data['risk_level'].upper()}",
            f"**Potential Financial Impact:** {exec_data['financial_impact']}",
            f"**Automated Actions Taken:** {exec_data['actions_taken']}",
            f"**Actions Pending Review:** {exec_data['actions_pending']}",
            "",
        ]
        if reasoning.get("threat_explanation"):
            lines.append(f"**Analysis:** {reasoning['threat_explanation']}")

        return "\n".join(lines)

    @staticmethod
    def _build_technical_report(reasoning: dict) -> str:
        """Build a detailed technical forensic report."""
        tech = reasoning["technical"]
        lines = [
            f"# Technical Forensic Report — Incident {tech['incident_id']}",
            "",
            f"**Timestamp:** {tech['timestamp']}",
            f"**Threat Type:** {tech['threat_type']}",
            f"**Confidence:** {tech.get('confidence_score', 'N/A')}",
            f"**Anomaly Score:** {tech.get('anomaly_score', 'N/A')}",
            f"**Severity Score:** {tech.get('severity_score', 'N/A')}",
            "",
            "## Patterns Detected",
        ]
        for p in tech.get("patterns_detected", []):
            lines.append(f"- **[{p.get('severity', 'N/A').upper()}]** {p.get('pattern_type')}: {p.get('description')}")

        lines.extend(["", "## Affected Systems"])
        for s in tech.get("affected_systems", []):
            lines.append(f"- {s}")

        lines.extend(["", "## Actions Taken"])
        for a in tech.get("actions_taken", []):
            lines.append(
                f"- **{a['action_type']}** → {a['target']} "
                f"({'✅ Success' if a.get('success') else '❌ Failed'}"
                f"{', simulated' if a.get('simulated') else ''})"
            )

        if tech.get("actions_deferred"):
            lines.extend(["", "## Actions Deferred (Human Review Required)"])
            for a in tech["actions_deferred"]:
                lines.append(f"- **{a['action_type']}** → {a['target']}: {a.get('reason', '')}")

        if reasoning.get("scenario_description"):
            lines.extend(["", "## Impact Scenario", reasoning["scenario_description"]])

        return "\n".join(lines)

    @staticmethod
    def _build_recommendations(reasoning: dict) -> list[str]:
        """Generate prevention recommendations based on threat type."""
        threat_type = reasoning["technical"].get("threat_type", "unknown")

        common = [
            "Review and update access control policies",
            "Conduct security awareness training for all employees",
            "Implement continuous monitoring and alerting",
        ]

        specific: dict[str, list[str]] = {
            "brute_force": [
                "Implement SSH key-only authentication",
                "Deploy fail2ban with stricter thresholds",
                "Enable multi-factor authentication",
                "Implement account lockout policies",
            ],
            "phishing": [
                "Deploy email filtering and anti-phishing tools",
                "Implement DMARC, DKIM, and SPF",
                "Conduct regular phishing simulations",
            ],
            "malware": [
                "Update endpoint detection and response (EDR) solutions",
                "Implement application whitelisting",
                "Ensure regular patching cadence",
                "Segment networks to limit lateral movement",
            ],
            "data_exfiltration": [
                "Implement Data Loss Prevention (DLP) tools",
                "Monitor and alert on large data transfers",
                "Encrypt sensitive data at rest and in transit",
                "Review and restrict database access permissions",
            ],
            "privilege_escalation": [
                "Implement least-privilege access policies",
                "Review and restrict sudo/admin access",
                "Deploy privileged access management (PAM) tools",
                "Audit and rotate credentials regularly",
            ],
        }

        return specific.get(threat_type, []) + common

    def _build_nova_reasoning_summary(self, reasoning: dict[str, Any]) -> str:
        """Generate a 'Nova AI Reasoning Summary' via a dedicated Nova call.

        Synthesizes:
          • Why Nova classified the threat
          • Anomaly signals that influenced the decision
          • Confidence scoring rationale
          • Memory similarity influence (if applicable)
        """
        from core.async_utils import run_async

        reasoning_prompt = self._build_reasoning_prompt(reasoning)

        try:
            nova_response = run_async(
                self._nova.invoke(
                    prompt=reasoning_prompt,
                    system_prompt=(
                        "You are a cybersecurity AI analyst. Write a concise "
                        "'Nova AI Reasoning Summary' section that explains WHY "
                        "the threat was classified as it was, what anomaly signals "
                        "influenced the decision, how confidence was determined, "
                        "and whether past incident similarity contributed. "
                        "Write in third-person analytical tone. 3-5 sentences max."
                    ),
                    context="nova_reasoning_summary",
                )
            )
            # Try to parse JSON response, else use raw text
            try:
                data = json.loads(nova_response)
                return data.get("reasoning_summary", nova_response)
            except (json.JSONDecodeError, TypeError):
                return nova_response

        except Exception as exc:
            logger.warning("Nova reasoning summary generation failed: %s", exc)
            return self._fallback_reasoning_summary(reasoning)

    @staticmethod
    def _build_reasoning_prompt(reasoning: dict[str, Any]) -> str:
        """Build the prompt payload for Nova reasoning summary generation."""
        tech = reasoning.get("technical", {})
        return json.dumps({
            "threat_type": tech.get("threat_type"),
            "confidence_score": tech.get("confidence_score"),
            "anomaly_score": tech.get("anomaly_score"),
            "patterns_detected": [
                {"type": p.get("pattern_type"), "severity": p.get("severity")}
                for p in tech.get("patterns_detected", [])
            ],
            "threat_explanation": reasoning.get("threat_explanation", ""),
            "similar_incidents_count": len(tech.get("similar_incidents", [])),
            "similar_incidents": [
                {"id": s.get("incident_id"), "score": s.get("similarity_score")}
                for s in tech.get("similar_incidents", [])[:3]
            ],
        })

    @staticmethod
    def _fallback_reasoning_summary(reasoning: dict[str, Any]) -> str:
        """Static fallback if Nova reasoning summary call fails."""
        tech = reasoning.get("technical", {})
        threat = tech.get("threat_type", "unknown").replace("_", " ")
        confidence = tech.get("confidence_score")
        anomaly = tech.get("anomaly_score")
        similar = tech.get("similar_incidents", [])

        lines = [
            f"Nova classified this incident as **{threat}** based on the detected anomaly patterns.",
        ]
        if anomaly is not None:
            lines.append(f"The anomaly score of {anomaly} indicated significant deviation from baseline behavior.")
        if confidence is not None:
            lines.append(f"Confidence was assessed at {confidence:.2%} using weighted indicator matching.")
        if similar:
            lines.append(
                f"{len(similar)} similar past incident(s) from vector memory contributed "
                "to the confidence assessment."
            )
        if reasoning.get("threat_explanation"):
            lines.append(f"Key reasoning: {reasoning['threat_explanation'][:150]}")
        return " ".join(lines)
