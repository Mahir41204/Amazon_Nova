"""
TraceRenderer — console-based real-time agent trace dashboard.

Renders a formatted pipeline summary after each stage completes,
providing judges and operators live visual feedback during pipeline
execution.  Pure presentation logic — no business rules.

Toggled via ``ENABLE_TRACE_DASHBOARD`` in settings.
"""

from __future__ import annotations

import logging
from typing import Any

from config.settings import get_settings

logger = logging.getLogger(__name__)

# ── Visual constants ────────────────────────────────────────────────────

_HEADER = "═" * 50
_THIN = "─" * 50
_STAGE_ICONS = {
    "log_analysis": "📊",
    "threat_classification": "🎯",
    "impact_simulation": "💥",
    "response": "🛡️",
    "reporting": "📝",
}
_STAGE_NUMBERS = {
    "log_analysis": 1,
    "threat_classification": 2,
    "impact_simulation": 3,
    "response": 4,
    "reporting": 5,
}
_STAGE_NAMES = {
    "log_analysis": "Log Intelligence Agent",
    "threat_classification": "Threat Classification Agent",
    "impact_simulation": "Impact Simulation Agent",
    "response": "Response Agent",
    "reporting": "Reporting Agent",
}


class TraceRenderer:
    """Console trace renderer for the multi-agent pipeline.

    Accepts structured stage outputs from the orchestrator
    and prints a formatted dashboard to stdout/logs.

    Usage::

        renderer = TraceRenderer()
        renderer.render_header(incident_id)
        renderer.render_stage("log_analysis", log_output)
        ...
        renderer.render_footer(total_seconds, financial_risk)
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._enabled = self._settings.ENABLE_TRACE_DASHBOARD

    @property
    def enabled(self) -> bool:
        """Whether the trace dashboard is active."""
        return self._enabled

    # ── Public rendering API ────────────────────────────────────────────

    def render_header(self, incident_id: str) -> None:
        """Print the pipeline header."""
        if not self._enabled:
            return
        print(
            f"\n{'═' * 50}\n"
            f"  🛡️  INCIDENT PIPELINE TRACE\n"
            f"{'═' * 50}\n"
            f"  Incident: {incident_id}\n"
            f"{'─' * 50}"
        )

    def render_stage(self, stage_name: str, result: dict[str, Any]) -> None:
        """Render a single pipeline stage with its key metrics."""
        if not self._enabled:
            return

        num = _STAGE_NUMBERS.get(stage_name, "?")
        icon = _STAGE_ICONS.get(stage_name, "▸")
        label = _STAGE_NAMES.get(stage_name, stage_name)
        details = self._extract_details(stage_name, result)

        lines = [f"\n  [{num}] {icon} {label}"]
        for key, value in details:
            lines.append(f"      → {key}: {value}")
        lines.append(f"  {'─' * 46}")

        print("\n".join(lines))

    def render_memory_lookup(self, count: int) -> None:
        """Render the vector memory lookup step."""
        if not self._enabled:
            return
        icon = "🧠" if count > 0 else "🔍"
        status = f"{count} similar incident(s) found" if count > 0 else "No prior matches"
        print(f"\n  [·] {icon} Vector Memory Lookup\n      → {status}")
        print(f"  {'─' * 46}")

    def render_footer(
        self,
        total_seconds: float,
        financial_risk: str,
        risk_before: str = "UNKNOWN",
        risk_after: str = "MITIGATED",
    ) -> None:
        """Print the metrics footer."""
        if not self._enabled:
            return
        print(
            f"\n{'═' * 50}\n"
            f"  ⏱  Total Response Time : {total_seconds:.2f} seconds\n"
            f"  🛡  Financial Risk Est  : {financial_risk}\n"
            f"  📉 Risk Score Change   : {risk_before} → {risk_after}\n"
            f"{'═' * 50}\n"
        )

    # ── Stage-specific detail extractors ────────────────────────────────

    def _extract_details(
        self, stage_name: str, result: dict[str, Any]
    ) -> list[tuple[str, str]]:
        """Extract human-readable key/value pairs from a stage result."""
        extractor = {
            "log_analysis": self._log_details,
            "threat_classification": self._threat_details,
            "impact_simulation": self._impact_details,
            "response": self._response_details,
            "reporting": self._reporting_details,
        }
        fn = extractor.get(stage_name)
        if fn:
            return fn(result)
        return [("Status", "Completed")]

    @staticmethod
    def _log_details(r: dict[str, Any]) -> list[tuple[str, str]]:
        anomaly = r.get("anomaly_score", "N/A")
        patterns = r.get("suspicious_patterns", [])
        return [
            ("Anomaly Score", f"{anomaly}"),
            ("Suspicious Patterns", f"{len(patterns)}"),
        ]

    @staticmethod
    def _threat_details(r: dict[str, Any]) -> list[tuple[str, str]]:
        threat = r.get("threat_type", "unknown").replace("_", " ").title()
        conf = r.get("confidence_score", 0)
        boost = r.get("memory_boost", 0)
        details = [
            ("Type", threat),
            ("Confidence", f"{conf:.0%}"),
        ]
        if boost:
            details.append(("Memory Boost", f"+{boost:.0%}"))
        return details

    @staticmethod
    def _impact_details(r: dict[str, Any]) -> list[tuple[str, str]]:
        return [
            ("Risk Level", r.get("risk_level", "N/A").upper()),
            ("Estimated Loss", r.get("estimated_financial_impact", "N/A")),
            ("Severity Score", f"{r.get('severity_score', 'N/A')}"),
        ]

    def _response_details(self, r: dict[str, Any]) -> list[tuple[str, str]]:
        decision = r.get("decision", "unknown").upper()
        threshold = self._settings.CONFIDENCE_THRESHOLD
        actions_taken = r.get("actions_taken", [])
        actions_deferred = r.get("actions_deferred", [])
        human_review = r.get("requires_human_review", True)

        details = [
            ("Threshold", f"{threshold:.0%}"),
            ("Decision", decision),
        ]

        if actions_taken:
            for a in actions_taken:
                status = "✅ EXECUTED" if a.get("success") else "⚠️ FAILED"
                sim = " (simulated)" if a.get("simulated") else ""
                details.append((
                    f"Action",
                    f"{a['action_type'].upper()} → {a['target']}{sim} [{status}]",
                ))
        if actions_deferred:
            for a in actions_deferred:
                details.append((
                    "Deferred",
                    f"{a['action_type'].upper()} → {a['target']}",
                ))
        if human_review:
            details.append(("Review", "⚠️  Flagged for human review"))

        return details

    @staticmethod
    def _reporting_details(r: dict[str, Any]) -> list[tuple[str, str]]:
        details = [("Executive Summary", "Generated ✓")]
        if r.get("nova_reasoning_summary"):
            details.append(("Nova Reasoning Summary", "Generated ✓"))
        recs = r.get("prevention_recommendations", [])
        if recs:
            details.append(("Recommendations", f"{len(recs)} provided"))
        return details
