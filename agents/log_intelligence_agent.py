"""
LogIntelligenceAgent — ingests raw logs and detects anomalous patterns.

Detects:
  • Brute-force attempts (repeated failed auth)
  • Unusual login spikes
  • Privilege escalation
  • Suspicious access patterns

Uses Nova reasoning for deep analysis in production;
rule-based heuristics + mock Nova in demo mode.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from core.agent_base import BaseAgent
from services.nova_client import NovaClient

logger = logging.getLogger(__name__)


class LogIntelligenceAgent(BaseAgent):
    """Parses system logs and surfaces anomalies with confidence scores."""

    def __init__(self, nova_client: NovaClient) -> None:
        super().__init__("LogIntelligence")
        self._nova = nova_client

    # ── BaseAgent interface ─────────────────────────────────────────────

    def analyze(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract events from raw log lines."""
        raw_logs: list[str] = data.get("logs", [])
        if not raw_logs:
            return {"events": [], "total": 0, "raw_logs": []}

        events = []
        for line in raw_logs:
            event = self._parse_log_line(line)
            if event:
                events.append(event)

        return {
            "events": events,
            "total": len(events),
            "raw_count": len(raw_logs),
            "raw_logs": raw_logs,
        }

    def reason(self, analysis: dict[str, Any]) -> dict[str, Any]:
        """Apply heuristic pattern detection and Nova reasoning."""
        events = analysis.get("events", [])
        if not events:
            return {
                "anomaly_score": 0.0,
                "suspicious_patterns": [],
                "summary": "No events to analyze.",
                "raw_logs": analysis.get("raw_logs", []),
            }

        patterns = []

        # ── Brute-force detection ───────────────────────────────────────
        bf = self._detect_brute_force(events)
        if bf:
            patterns.append(bf)

        # ── Login spike detection ───────────────────────────────────────
        spike = self._detect_login_spike(events)
        if spike:
            patterns.append(spike)

        # ── Privilege escalation detection ──────────────────────────────
        priv = self._detect_privilege_escalation(events)
        if priv:
            patterns.append(priv)

        # ── Suspicious access patterns ──────────────────────────────────
        access = self._detect_suspicious_access(events)
        if access:
            patterns.append(access)

        # Calculate composite anomaly score
        if patterns:
            severity_weights = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
            scores = [severity_weights.get(p.get("severity", "low"), 0.2) for p in patterns]
            anomaly_score = min(1.0, sum(scores) / len(scores) + 0.1 * len(scores))
        else:
            anomaly_score = 0.1

        return {
            "anomaly_score": round(anomaly_score, 2),
            "suspicious_patterns": patterns,
            "events_analyzed": len(events),
            "raw_logs": analysis.get("raw_logs", []),
        }

    def act(self, reasoning: dict[str, Any]) -> dict[str, Any]:
        """Produce the final structured output with Nova-enhanced summary."""
        from core.async_utils import run_async

        # Build prompt with raw logs so Nova can analyze independently
        raw_logs = reasoning.get("raw_logs", [])
        nova_prompt = json.dumps({
            "heuristic_results": {
                "anomaly_score": reasoning["anomaly_score"],
                "suspicious_patterns": reasoning.get("suspicious_patterns", []),
                "events_analyzed": reasoning.get("events_analyzed", 0),
            },
            "raw_log_lines": raw_logs[:50],  # Cap to avoid token overflow
        })

        # Get Nova-enhanced analysis summary
        try:
            nova_response = run_async(
                self._nova.invoke(
                    prompt=nova_prompt,
                    system_prompt=(
                        "You are a system behavioral analyst. You are given raw log lines AND heuristic analysis results. "
                        "Analyze the RAW LOG LINES independently for anomalous patterns. "
                        "Identify occurrences of high-frequency access attempts, privilege transitions, and unusual egress. "
                        "Provide an objective, technical assessment of the system activity. "
                        "You MUST respond with ONLY valid JSON (no markdown, no explanation outside JSON). "
                        "Use this exact schema: "
                        '{"anomaly_score": <float 0-1>, "suspicious_patterns": [{"pattern_type": "<string>", '
                        '"description": "<string>", "severity": "<low|medium|high|critical>", "source_ip": "<string or null>"}], '
                        '"summary": "<string>", "events_analyzed": <int>}'
                    ),
                    context="log_analysis",
                )
            )
            nova_data = json.loads(nova_response)
        except Exception:
            nova_data = {}

        return {
            "anomaly_score": nova_data.get("anomaly_score", reasoning["anomaly_score"]),
            "suspicious_patterns": nova_data.get("suspicious_patterns", reasoning.get("suspicious_patterns", [])),
            "summary": nova_data.get("summary", self._generate_summary(reasoning)),
            "events_analyzed": reasoning.get("events_analyzed", 0),
        }

    # ── Pattern detection heuristics ────────────────────────────────────

    def _detect_brute_force(self, events: list[dict]) -> dict[str, Any] | None:
        """Detect brute-force login attempts."""
        failed_logins: dict[str, list] = defaultdict(list)
        for e in events:
            if e.get("action") == "login_failed":
                source = e.get("source_ip", "unknown")
                failed_logins[source].append(e)

        for ip, attempts in failed_logins.items():
            if len(attempts) >= 5:
                return {
                    "pattern_type": "high_frequency_access",
                    "description": (
                        f"{len(attempts)} failed access attempts from {ip} "
                        f"targeting identity(ies): {', '.join(set(a.get('user', '?') for a in attempts))}"
                    ),
                    "severity": "high" if len(attempts) >= 10 else "medium",
                    "source_ip": ip,
                    "count": len(attempts),
                }
        return None

    def _detect_login_spike(self, events: list[dict]) -> dict[str, Any] | None:
        """Detect unusual login volume spikes."""
        login_events = [e for e in events if "login" in e.get("action", "")]
        if len(login_events) > 20:
            return {
                "pattern_type": "login_spike",
                "description": f"Unusual login volume: {len(login_events)} login events detected in log batch",
                "severity": "medium",
                "count": len(login_events),
            }
        return None

    def _detect_privilege_escalation(self, events: list[dict]) -> dict[str, Any] | None:
        """Detect privilege escalation attempts."""
        for e in events:
            action = e.get("action", "").lower()
            if any(kw in action for kw in ["sudo", "su_root", "privilege_elevation", "root_access"]):
                return {
                    "pattern_type": "privilege_transition",
                    "description": (
                        f"Identity '{e.get('user', 'unknown')}' transitioned privileges "
                        f"via {e.get('action')} on resource {e.get('target', 'unknown')}"
                    ),
                    "severity": "critical",
                    "user": e.get("user"),
                }
        return None

    def _detect_suspicious_access(self, events: list[dict]) -> dict[str, Any] | None:
        """Detect access to sensitive resources."""
        sensitive_keywords = ["passwd", "shadow", "ssh_key", "private_key", "database_dump", "exfiltration"]
        for e in events:
            target = e.get("target", "").lower()
            if any(kw in target for kw in sensitive_keywords):
                return {
                    "pattern_type": "suspicious_access",
                    "description": f"Access to sensitive resource: {e.get('target')} by user '{e.get('user', 'unknown')}'",
                    "severity": "high",
                    "target": e.get("target"),
                }
        return None

    # ── Helpers ─────────────────────────────────────────────────────────

    def _parse_log_line(self, line: str) -> dict[str, Any] | None:
        """Parse a single log line into a structured event dict.

        Supports both structured JSON logs and common syslog-style formats.
        """
        # Try JSON first
        if line.strip().startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass

        # Syslog-style parsing
        patterns = [
            # Failed SSH login
            (
                r"Failed password for (\w+) from ([\d.]+) port (\d+)",
                lambda m: {"action": "login_failed", "user": m.group(1), "source_ip": m.group(2), "port": m.group(3)},
            ),
            # Successful SSH login
            (
                r"Accepted (?:password|publickey) for (\w+) from ([\d.]+)",
                lambda m: {"action": "login_success", "user": m.group(1), "source_ip": m.group(2)},
            ),
            # Sudo / privilege escalation
            (
                r"(\w+) : .* COMMAND=(.*)",
                lambda m: {"action": "sudo", "user": m.group(1), "target": m.group(2)},
            ),
            # Generic auth failure
            (
                r"authentication failure.*user=(\w+)",
                lambda m: {"action": "login_failed", "user": m.group(1)},
            ),
        ]

        for pattern, builder in patterns:
            match = re.search(pattern, line)
            if match:
                event = builder(match)
                event["raw"] = line
                return event

        # Fallback: return raw line as event
        return {"action": "unknown", "raw": line}

    @staticmethod
    def _generate_summary(reasoning: dict[str, Any]) -> str:
        """Generate a text summary from the reasoning output."""
        patterns = reasoning.get("suspicious_patterns", [])
        if not patterns:
            return "No significant anomalies detected in the analyzed logs."

        parts = [f"Detected {len(patterns)} suspicious pattern(s):"]
        for p in patterns:
            parts.append(f"  - [{p['severity'].upper()}] {p['pattern_type']}: {p['description']}")
        return "\n".join(parts)
