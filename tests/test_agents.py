"""
Unit tests for all five Nova agents.

Tests verify each agent's analyze(), reason(), and act() methods
produce correctly structured outputs.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DEMO_MODE"] = "true"

import pytest

from agents.log_intelligence_agent import LogIntelligenceAgent
from agents.threat_classification_agent import ThreatClassificationAgent
from agents.impact_simulation_agent import ImpactSimulationAgent
from agents.response_agent import ResponseAgent
from agents.reporting_agent import ReportingAgent


# ═══════════════════════════════════════════════════════════════════════
# Log Intelligence Agent
# ═══════════════════════════════════════════════════════════════════════


class TestLogIntelligenceAgent:
    """Tests for the LogIntelligenceAgent."""

    def test_analyze_parses_syslog_lines(self, nova_client, sample_logs):
        agent = LogIntelligenceAgent(nova_client)
        result = agent.analyze({"logs": sample_logs})

        assert "events" in result
        assert result["total"] > 0
        assert result["raw_count"] == len(sample_logs)

    def test_analyze_handles_empty_input(self, nova_client):
        agent = LogIntelligenceAgent(nova_client)
        result = agent.analyze({"logs": []})
        assert result["total"] == 0

    def test_reason_detects_brute_force(self, nova_client, sample_logs):
        agent = LogIntelligenceAgent(nova_client)
        analysis = agent.analyze({"logs": sample_logs})
        reasoning = agent.reason(analysis)

        assert "anomaly_score" in reasoning
        assert reasoning["anomaly_score"] > 0.5
        assert len(reasoning["suspicious_patterns"]) > 0

        # Should detect brute force pattern
        pattern_types = [p["pattern_type"] for p in reasoning["suspicious_patterns"]]
        assert "brute_force" in pattern_types

    def test_execute_full_pipeline(self, nova_client, sample_logs):
        agent = LogIntelligenceAgent(nova_client)
        result = agent.execute({"logs": sample_logs})

        assert result["agent"] == "LogIntelligence"
        assert "result" in result
        assert "execution_time_ms" in result
        assert result["result"]["anomaly_score"] > 0

    def test_analyze_json_logs(self, nova_client):
        json_logs = [
            '{"action": "login_failed", "user": "admin", "source_ip": "10.0.0.1"}',
            '{"action": "login_failed", "user": "admin", "source_ip": "10.0.0.1"}',
            '{"action": "login_failed", "user": "admin", "source_ip": "10.0.0.1"}',
            '{"action": "login_failed", "user": "admin", "source_ip": "10.0.0.1"}',
            '{"action": "login_failed", "user": "admin", "source_ip": "10.0.0.1"}',
        ]
        agent = LogIntelligenceAgent(nova_client)
        analysis = agent.analyze({"logs": json_logs})
        assert analysis["total"] == 5


# ═══════════════════════════════════════════════════════════════════════
# Threat Classification Agent
# ═══════════════════════════════════════════════════════════════════════


class TestThreatClassificationAgent:
    """Tests for the ThreatClassificationAgent."""

    def test_classifies_brute_force(self, nova_client):
        agent = ThreatClassificationAgent(nova_client)
        input_data = {
            "anomaly_score": 0.85,
            "suspicious_patterns": [
                {"pattern_type": "brute_force", "description": "50 failed logins", "severity": "high"}
            ],
        }
        result = agent.execute(input_data)
        assert result["result"]["threat_type"] in ("brute_force", "unknown")
        assert "confidence_score" in result["result"]

    def test_classifies_with_similar_incidents(self, nova_client):
        agent = ThreatClassificationAgent(nova_client)
        input_data = {
            "anomaly_score": 0.80,
            "suspicious_patterns": [
                {"pattern_type": "brute_force", "description": "failed logins", "severity": "high"}
            ],
            "similar_incidents": [
                {"incident_id": "test-1", "similarity_score": 0.9, "threat_type": "brute_force"}
            ],
        }
        result = agent.execute(input_data)
        assert result["result"]["confidence_score"] > 0

    def test_handles_unknown_patterns(self, nova_client):
        agent = ThreatClassificationAgent(nova_client)
        input_data = {
            "anomaly_score": 0.3,
            "suspicious_patterns": [
                {"pattern_type": "mysterious_thing", "description": "something weird", "severity": "low"}
            ],
        }
        result = agent.execute(input_data)
        assert "threat_type" in result["result"]


# ═══════════════════════════════════════════════════════════════════════
# Impact Simulation Agent
# ═══════════════════════════════════════════════════════════════════════


class TestImpactSimulationAgent:
    """Tests for the ImpactSimulationAgent."""

    def test_simulates_brute_force_impact(self, nova_client):
        agent = ImpactSimulationAgent(nova_client)
        result = agent.execute({"threat_type": "brute_force", "confidence_score": 0.9})

        res = result["result"]
        assert "affected_systems" in res
        assert "risk_level" in res
        assert "severity_score" in res
        assert len(res["affected_systems"]) > 0

    def test_simulates_malware_impact(self, nova_client):
        agent = ImpactSimulationAgent(nova_client)
        result = agent.execute({"threat_type": "malware", "confidence_score": 0.95})
        assert result["result"]["risk_level"] in ("critical", "high", "medium", "low")

    def test_handles_unknown_threat(self, nova_client):
        agent = ImpactSimulationAgent(nova_client)
        result = agent.execute({"threat_type": "unknown", "confidence_score": 0.5})
        assert "severity_score" in result["result"]


# ═══════════════════════════════════════════════════════════════════════
# Response Agent
# ═══════════════════════════════════════════════════════════════════════


class TestResponseAgent:
    """Tests for the ResponseAgent."""

    def test_executes_when_above_threshold(self, nova_client, nova_act_client):
        agent = ResponseAgent(nova_client, nova_act_client)
        input_data = {
            "confidence_score": 0.95,
            "threat_type": "brute_force",
            "recommended_action": "block_ip",
            "suspicious_patterns": [{"source_ip": "10.0.0.1", "pattern_type": "brute_force"}],
        }
        result = agent.execute(input_data)
        res = result["result"]

        assert res["decision"] == "execute"
        assert len(res["actions_taken"]) > 0
        assert res["requires_human_review"] is False

    def test_defers_when_below_threshold(self, nova_client, nova_act_client):
        agent = ResponseAgent(nova_client, nova_act_client)
        input_data = {
            "confidence_score": 0.50,
            "threat_type": "brute_force",
            "recommended_action": "block_ip",
        }
        result = agent.execute(input_data)
        res = result["result"]

        assert res["decision"] == "defer"
        assert len(res["actions_deferred"]) > 0
        assert res["requires_human_review"] is True

    def test_actions_are_simulated_in_demo(self, nova_client, nova_act_client):
        agent = ResponseAgent(nova_client, nova_act_client)
        input_data = {
            "confidence_score": 0.95,
            "threat_type": "brute_force",
            "recommended_action": "block_ip",
        }
        result = agent.execute(input_data)
        for action in result["result"]["actions_taken"]:
            assert action["simulated"] is True


# ═══════════════════════════════════════════════════════════════════════
# Reporting Agent
# ═══════════════════════════════════════════════════════════════════════


class TestReportingAgent:
    """Tests for the ReportingAgent."""

    def test_generates_reports(self, nova_client):
        agent = ReportingAgent(nova_client)
        input_data = {
            "incident_id": "test-123",
            "log_analysis": {"anomaly_score": 0.85, "suspicious_patterns": []},
            "threat_classification": {"threat_type": "brute_force", "confidence_score": 0.92, "explanation": "test"},
            "impact_simulation": {"risk_level": "high", "affected_systems": ["server-01"]},
            "response": {"actions_taken": [], "actions_deferred": [], "requires_human_review": False},
        }
        result = agent.execute(input_data)
        res = result["result"]

        assert "executive_summary" in res
        assert "technical_report" in res
        assert "prevention_recommendations" in res
        assert len(res["prevention_recommendations"]) > 0
