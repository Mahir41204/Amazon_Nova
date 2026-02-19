"""
Integration tests for the full orchestrator pipeline.

Tests the complete flow: logs → all agents → report,
including confidence gating and vector memory.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DEMO_MODE"] = "true"

import pytest
import asyncio

from core.orchestrator import Orchestrator
from core.state_manager import StateManager
from services.nova_client import NovaClient
from services.nova_act_client import NovaActClient
from services.embeddings_service import EmbeddingsService
from demo.synthetic_logs import generate_brute_force_logs


def _create_orchestrator(tmp_path) -> Orchestrator:
    """Create an orchestrator with temp storage."""
    os.environ["VECTOR_STORE_PATH"] = str(tmp_path / "test_vectors.json")
    os.environ["INCIDENT_STORE_PATH"] = str(tmp_path / "test_incidents.json")

    from config.settings import get_settings
    get_settings.cache_clear()

    from memory.vector_store import VectorStore
    from memory.incident_repository import IncidentRepository

    return Orchestrator(
        nova_client=NovaClient(),
        nova_act_client=NovaActClient(),
        embeddings_service=EmbeddingsService(),
        vector_store=VectorStore(),
        incident_repository=IncidentRepository(),
        state_manager=StateManager(),
    )


class TestOrchestrator:
    """Integration tests for the Orchestrator pipeline."""

    def test_full_pipeline_completes(self, tmp_path):
        """Full pipeline should run successfully with synthetic logs."""
        orchestrator = _create_orchestrator(tmp_path)
        logs = generate_brute_force_logs()

        result = asyncio.run(orchestrator.analyze_logs(logs))

        assert result["status"] == "completed"
        assert "incident_id" in result
        assert "stages" in result
        assert "decision_log" in result

    def test_all_stages_present(self, tmp_path):
        """All pipeline stages should produce output."""
        orchestrator = _create_orchestrator(tmp_path)
        logs = generate_brute_force_logs()

        result = asyncio.run(orchestrator.analyze_logs(logs))
        stages = result["stages"]

        expected_stages = [
            "log_analysis",
            "threat_classification",
            "impact_simulation",
            "response",
            "reporting",
        ]
        for stage in expected_stages:
            assert stage in stages, f"Missing stage: {stage}"
            assert stages[stage] is not None

    def test_incident_stored_in_repository(self, tmp_path):
        """Completed incidents should be persisted in the repository."""
        orchestrator = _create_orchestrator(tmp_path)
        logs = generate_brute_force_logs()

        result = asyncio.run(orchestrator.analyze_logs(logs))
        incident_id = result["incident_id"]

        stored = orchestrator.get_incident(incident_id)
        assert stored is not None
        assert stored["incident_id"] == incident_id

    def test_incident_listing(self, tmp_path):
        """Listed incidents should include the completed one."""
        orchestrator = _create_orchestrator(tmp_path)
        logs = generate_brute_force_logs()

        asyncio.run(orchestrator.analyze_logs(logs))
        incidents = orchestrator.list_incidents()

        assert len(incidents) >= 1
        assert incidents[0]["status"] == "completed"

    def test_second_incident_uses_memory(self, tmp_path):
        """A second run should find the first incident via vector memory."""
        orchestrator = _create_orchestrator(tmp_path)
        logs = generate_brute_force_logs()

        # First run — stores in memory
        result1 = asyncio.run(orchestrator.analyze_logs(logs))

        # Second run — should find similar incident
        result2 = asyncio.run(orchestrator.analyze_logs(logs))

        assert result2["status"] == "completed"
        # Decision log should mention similar incidents
        decisions = [d["decision"] for d in result2["decision_log"]]
        found_similar = any("similar" in d.lower() for d in decisions)
        assert found_similar, "Second run should detect similar past incidents"

    def test_simulate_threat(self, tmp_path):
        """Impact simulation endpoint should work independently."""
        orchestrator = _create_orchestrator(tmp_path)

        result = asyncio.run(orchestrator.simulate_threat("brute_force"))

        assert "affected_systems" in result
        assert "risk_level" in result
        assert "severity_score" in result

    def test_decision_log_populated(self, tmp_path):
        """Decision log should capture all pipeline decisions."""
        orchestrator = _create_orchestrator(tmp_path)
        logs = generate_brute_force_logs()

        result = asyncio.run(orchestrator.analyze_logs(logs))
        decisions = result["decision_log"]

        assert len(decisions) > 3  # At minimum: start, agents, complete
        assert any("Pipeline started" in d["decision"] for d in decisions)
        assert any("Pipeline completed" in d["decision"] for d in decisions)
