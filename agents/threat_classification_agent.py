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
    "high_frequency_auth": {
        "indicators": ["login_failed", "access_pattern", "failed_password", "authentication_failure"],
        "base_confidence": 0.80,
        "description": "Repeated authentication failures indicating automated access attempts",
    },
    "anomalous_messaging": {
        "indicators": ["suspicious_url", "messaging_pattern", "delivery_anomaly", "credential_sync"],
        "base_confidence": 0.70,
        "description": "Unusual messaging interaction with potential for unintended data synchronization",
    },
    "payload_execution": {
        "indicators": ["execution_pattern", "runtime_anomaly", "process_drift", "c2_pattern"],
        "base_confidence": 0.75,
        "description": "Detection of unauthorized or unexpected computational processes",
    },
    "egress_anomaly": {
        "indicators": ["data_egress", "large_transfer", "volume_spike", "outbound_drift", "unusual_egress"],
        "base_confidence": 0.72,
        "description": "Unplanned or substantial outbound data movement patterns",
    },
    "privilege_transition": {
        "indicators": ["privilege_shift", "elevation_pattern", "sudo_pattern", "root_transition", "administrative_elevation"],
        "base_confidence": 0.78,
        "description": "Observations of significant transitions in process authorization levels",
    },
}

_RECOMMENDED_ACTIONS: dict[str, str] = {
    "high_frequency_auth": "block_ip",
    "anomalous_messaging": "disable_user",
    "payload_execution": "quarantine_system",
    "egress_anomaly": "update_firewall",
    "privilege_transition": "disable_user",
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
            "raw_logs": data.get("raw_logs", []),
            "log_summary": data.get("log_summary", ""),
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
            "raw_logs": analysis.get("raw_logs", []),
            "log_summary": analysis.get("log_summary", ""),
        }

    def act(self, reasoning: dict[str, Any]) -> dict[str, Any]:
        """Produce the final classification output with Nova-enhanced explanation."""
        from core.async_utils import run_async

        threat_type = reasoning["threat_type"]
        confidence = reasoning["confidence_score"]

        # Build a richer prompt with all context
        raw_logs = reasoning.get("raw_logs", [])
        nova_prompt = json.dumps({
            "heuristic_classification": {
                "threat_type": threat_type,
                "confidence_score": confidence,
                "matched_indicators": reasoning.get("matched_indicators", []),
            },
            "log_summary": reasoning.get("log_summary", ""),
            "raw_log_lines": raw_logs[:20],
            "similar_incidents": reasoning.get("similar_incidents", [])[:3],
        })

        # Get Nova-enhanced explanation
        try:
            nova_response = run_async(
                self._nova.invoke(
                    prompt=nova_prompt,
                    system_prompt=(
                        "You are a behavioral patterns expert. You receive heuristic classification results and similar operational patterns. "
                        "Analyze the telemetry and provide an objective classification of the activity pattern. "
                        "Focus on the technical behavior rather than dramatic intent. "
                        "You MUST respond with ONLY valid JSON. "
                        "Use this exact schema: "
                        '{"threat_type": "<high_frequency_auth|anomalous_messaging|payload_execution|egress_anomaly|privilege_transition|unknown>", '
                        '"confidence_score": <float 0-1>, "explanation": "<string>", '
                        '"recommended_action": "<block_ip|disable_user|update_firewall|quarantine_system|flag_for_review>"}'
                    ),
                    context="threat_classification",
                )
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
