"""
ThreatClassificationAgent — classifies anomalies into threat categories.

Classifies threats as: brute_force, phishing, malware, data_exfiltration,
privilege_escalation, or unknown.

Adjusts confidence based on similar past incidents from vector memory.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from core.agent_base import BaseAgent
from services.nova_client import NovaClient

logger = logging.getLogger(__name__)

# ── Classification rules (heuristic baseline) ──────────────────────────

_THREAT_SIGNATURES: dict[str, dict[str, Any]] = {
    "brute_force": {
        "indicators": ["login_failed", "brute_force", "failed_password", "authentication_failure"],
        "base_confidence": 0.80,
        "description": "Repeated authentication failures indicating automated credential guessing",
    },
    "phishing": {
        "indicators": ["phishing", "suspicious_url", "malicious_link", "credential_harvest"],
        "base_confidence": 0.70,
        "description": "Deceptive attempt to obtain sensitive information",
    },
    "malware": {
        "indicators": ["malware", "trojan", "ransomware", "suspicious_process", "c2_beacon"],
        "base_confidence": 0.75,
        "description": "Malicious software detected or suspected",
    },
    "data_exfiltration": {
        "indicators": ["exfiltration", "large_transfer", "database_dump", "data_export", "unusual_egress"],
        "base_confidence": 0.72,
        "description": "Unauthorized data transfer or extraction attempt",
    },
    "privilege_escalation": {
        "indicators": ["privilege_escalation", "sudo", "su_root", "root_access", "admin_elevation"],
        "base_confidence": 0.78,
        "description": "Unauthorized elevation of system privileges",
    },
}

_RECOMMENDED_ACTIONS: dict[str, str] = {
    "brute_force": "block_ip",
    "phishing": "disable_user",
    "malware": "quarantine_system",
    "data_exfiltration": "update_firewall",
    "privilege_escalation": "disable_user",
    "unknown": "flag_for_review",
}


class ThreatClassificationAgent(BaseAgent):
    """Classifies detected anomalies into specific threat categories."""

    def __init__(self, nova_client: NovaClient) -> None:
        super().__init__("ThreatClassification")
        self._nova = nova_client

    # ── BaseAgent interface ─────────────────────────────────────────────

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract classification-relevant features from anomaly data."""
        patterns = data.get("suspicious_patterns", [])
        anomaly_score = data.get("anomaly_score", 0.0)
        similar_incidents = data.get("similar_incidents", [])

        # Collect all indicators
        indicators: list[str] = []
        for pattern in patterns:
            indicators.append(pattern.get("pattern_type", ""))
            indicators.extend(
                word.lower()
                for word in pattern.get("description", "").split()
            )

        return {
            "indicators": indicators,
            "patterns": patterns,
            "anomaly_score": anomaly_score,
            "similar_incidents": similar_incidents,
        }

    def reason(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Match indicators to threat signatures and compute confidence."""
        indicators = set(analysis["indicators"])
        best_match: str = "unknown"
        best_score: float = 0.0

        for threat_type, signature in _THREAT_SIGNATURES.items():
            overlap = indicators & set(signature["indicators"])
            if overlap:
                score = signature["base_confidence"] + 0.05 * len(overlap)
                # Boost with anomaly score
                score = min(1.0, score * (0.5 + 0.5 * analysis["anomaly_score"]))
                if score > best_score:
                    best_score = score
                    best_match = threat_type

        # Adjust confidence based on similar past incidents
        similar = analysis.get("similar_incidents", [])
        if similar:
            # If similar incidents exist, boost confidence
            avg_similarity = sum(s.get("similarity_score", 0) for s in similar) / len(similar)
            confidence_boost = avg_similarity * 0.1
            best_score = min(1.0, best_score + confidence_boost)
            logger.info(
                "Confidence boosted by %.2f from %d similar incidents",
                confidence_boost,
                len(similar),
            )

        return {
            "threat_type": best_match,
            "confidence_score": round(best_score, 2),
            "matched_indicators": list(indicators),
            "similar_incidents": similar,
        }

    async def act(self, reasoning: dict[str, Any]) -> dict[str, Any]:
        """Produce the final classification output with Nova-enhanced explanation."""
        threat_type = reasoning["threat_type"]
        confidence = reasoning["confidence_score"]

        # Get Nova-enhanced explanation
        try:
            nova_response = await self._nova.invoke(
                prompt=json.dumps(reasoning),
                system_prompt="You are a threat classification expert. Classify the threat and explain your reasoning.",
                context="threat_classification",
            )
            nova_data = json.loads(nova_response)
        except Exception:
            nova_data = {}

        explanation = nova_data.get(
            "explanation",
            _THREAT_SIGNATURES.get(threat_type, {}).get(
                "description", "Threat type could not be determined from available indicators."
            ),
        )

        result = {
            "threat_type": nova_data.get("threat_type", threat_type),
            "confidence_score": nova_data.get("confidence_score", confidence),
            "explanation": explanation,
            "recommended_action": nova_data.get(
                "recommended_action",
                _RECOMMENDED_ACTIONS.get(threat_type, "flag_for_review"),
            ),
        }

        # Include similar incidents in output if present
        if reasoning.get("similar_incidents"):
            result["similar_incidents"] = reasoning["similar_incidents"]

        return result
