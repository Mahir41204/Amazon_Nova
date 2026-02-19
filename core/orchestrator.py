"""
Orchestrator — central controller for the multi-agent pipeline.

Receives log input, calls agents sequentially, maintains state,
enforces confidence safety rules, and logs the full decision pipeline.

No agent should bypass the orchestrator.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from config.settings import get_settings
from core.state_manager import StateManager
from core.exceptions import OrchestrationError
from core.trace_dashboard import TraceRenderer
from agents.log_intelligence_agent import LogIntelligenceAgent
from agents.threat_classification_agent import ThreatClassificationAgent
from agents.impact_simulation_agent import ImpactSimulationAgent
from agents.response_agent import ResponseAgent
from agents.reporting_agent import ReportingAgent
from memory.vector_store import VectorStore
from memory.incident_repository import IncidentRepository
from services.nova_client import NovaClient
from services.nova_act_client import NovaActClient
from services.embeddings_service import EmbeddingsService

logger = logging.getLogger(__name__)


class Orchestrator:
    """Central orchestrator that drives the full incident-response pipeline.

    Pipeline stages:
        1. Log Intelligence → anomaly detection
        2. Vector memory lookup → similar past incidents
        3. Threat Classification → threat type + confidence
        4. Impact Simulation → blast-radius analysis
        5. Response → automated (or deferred) defensive actions
        6. Reporting → executive & technical reports
        7. Memory storage → embed and persist for future learning

    All dependencies are injected via the constructor.
    """

    def __init__(
        self,
        *,
        nova_client: NovaClient,
        nova_act_client: NovaActClient,
        embeddings_service: EmbeddingsService,
        vector_store: VectorStore,
        incident_repository: IncidentRepository,
        state_manager: StateManager,
    ) -> None:
        self._settings = get_settings()
        self._state = state_manager
        self._vector_store = vector_store
        self._incident_repo = incident_repository
        self._embeddings = embeddings_service

        # ── Agents (injected with their dependencies) ───────────────────
        self._log_agent = LogIntelligenceAgent(nova_client)
        self._threat_agent = ThreatClassificationAgent(nova_client)
        self._impact_agent = ImpactSimulationAgent(nova_client)
        self._response_agent = ResponseAgent(nova_client, nova_act_client)
        self._reporting_agent = ReportingAgent(nova_client)

        # ── Trace dashboard (presentation only) ─────────────────────────
        self._trace = TraceRenderer()

    # ── Public API ──────────────────────────────────────────────────────

    async def analyze_logs(self, raw_logs: list[str]) -> dict[str, Any]:
        """Run the full pipeline on a batch of raw log lines.

        Returns the complete incident record including all agent
        outputs, actions, and reports.
        """
        pipeline_start = time.perf_counter()
        input_data = {"logs": raw_logs}

        # 1. Create incident
        incident_id = self._state.create_incident(input_data)
        self._state.add_decision(incident_id, "Pipeline started")
        logger.info("═══ Pipeline started for incident %s ═══", incident_id)

        try:
            # ── Header ──────────────────────────────────────────────────
            self._trace.render_header(incident_id)

            # 2. Log Intelligence
            log_output = self._run_agent(
                self._log_agent, input_data, incident_id, "log_analysis"
            )
            self._trace.render_stage("log_analysis", log_output)

            # 3. Vector memory — find similar past incidents
            similar_incidents = self._find_similar_incidents(log_output)
            self._state.add_decision(
                incident_id,
                f"Found {len(similar_incidents)} similar past incidents",
            )
            self._trace.render_memory_lookup(len(similar_incidents))

            # 4. Threat Classification (with similar incidents for confidence boost)
            classification_input = {
                **log_output,
                "similar_incidents": [
                    {"incident_id": s.incident_id, "similarity_score": s.similarity_score, **s.metadata}
                    for s in similar_incidents
                ],
            }
            threat_output = self._run_agent(
                self._threat_agent, classification_input, incident_id, "threat_classification"
            )
            self._trace.render_stage("threat_classification", threat_output)

            # 5. Impact Simulation
            impact_input = {
                **threat_output,
                "suspicious_patterns": log_output.get("suspicious_patterns", []),
                "anomaly_score": log_output.get("anomaly_score", 0),
            }
            impact_output = self._run_agent(
                self._impact_agent, impact_input, incident_id, "impact_simulation"
            )
            self._trace.render_stage("impact_simulation", impact_output)

            # 6. Response (with confidence gating)
            response_input = {
                **threat_output,
                "risk_level": impact_output.get("risk_level", "unknown"),
                "suspicious_patterns": log_output.get("suspicious_patterns", []),
            }
            response_output = self._run_agent(
                self._response_agent, response_input, incident_id, "response"
            )
            self._trace.render_stage("response", response_output)

            # Log confidence decision
            if response_output.get("requires_human_review"):
                self._state.add_decision(
                    incident_id,
                    f"Confidence {response_output.get('confidence_score', 0):.2%} below threshold — deferred to human review",
                )
            else:
                self._state.add_decision(
                    incident_id,
                    f"Confidence {response_output.get('confidence_score', 0):.2%} — automated response executed",
                )

            # 7. Reporting
            report_input = {
                "incident_id": incident_id,
                "log_analysis": log_output,
                "threat_classification": threat_output,
                "impact_simulation": impact_output,
                "response": response_output,
            }
            report_output = self._run_agent(
                self._reporting_agent, report_input, incident_id, "reporting"
            )
            self._trace.render_stage("reporting", report_output)

            # 8. Store in memory for future learning
            self._store_incident_memory(incident_id, log_output, threat_output)

            # Finalize
            elapsed_ms = round((time.perf_counter() - pipeline_start) * 1000, 2)
            elapsed_seconds = elapsed_ms / 1000
            self._state.add_decision(incident_id, f"Pipeline completed in {elapsed_ms}ms")
            full_state = self._state.finalize(incident_id)

            # Persist to incident repository
            self._incident_repo.save(full_state)

            # ── Footer with metrics ─────────────────────────────────────
            financial_risk = impact_output.get("estimated_financial_impact", "N/A")
            risk_before = impact_output.get("risk_level", "UNKNOWN").upper()
            risk_after = "MITIGATED" if not response_output.get("requires_human_review") else "PENDING REVIEW"
            self._trace.render_footer(
                total_seconds=elapsed_seconds,
                financial_risk=financial_risk,
                risk_before=risk_before,
                risk_after=risk_after,
            )

            logger.info(
                "═══ Pipeline completed for incident %s in %.2f ms ═══",
                incident_id,
                elapsed_ms,
            )

            return full_state

        except Exception as exc:
            self._state.add_decision(incident_id, f"Pipeline failed: {exc}")
            self._state.finalize(incident_id, status="failed")
            logger.exception("Pipeline failed for incident %s", incident_id)
            raise OrchestrationError(f"Pipeline failed: {exc}") from exc

    async def handle_realtime_incident(
        self,
        source_ip: str,
        event_window: list[Any],
        suspicion_score: float = 0.0,
    ) -> dict[str, Any]:
        """Handle a realtime incident triggered by the daemon's threshold engine.

        Bridges the event-driven trigger to the existing pipeline by
        converting window events into raw log lines.

        Args:
            source_ip: The IP that triggered the incident.
            event_window: List of LogEvent objects from the sliding window.
            suspicion_score: The computed suspicion score at trigger time.

        Returns:
            The full pipeline result (same as ``analyze_logs``).
        """
        # Convert events to raw log lines
        raw_logs = []
        for event in event_window:
            if hasattr(event, "message"):
                raw_logs.append(event.message)
            else:
                raw_logs.append(str(event))

        if not raw_logs:
            logger.warning("handle_realtime_incident called with empty window for %s", source_ip)
            return {}

        logger.info(
            "═══ Realtime incident for %s — score=%.2f, events=%d ═══",
            source_ip,
            suspicion_score,
            len(raw_logs),
        )

        result = await self.analyze_logs(raw_logs)

        # Enrich with realtime metadata
        result["realtime_metadata"] = {
            "source_ip": source_ip,
            "suspicion_score": suspicion_score,
            "event_count": len(event_window),
            "trigger_type": "threshold_exceeded",
        }

        return result

    async def handle_multisource_incident(
        self,
        source_ip: str,
        event_window: list[Any],
        suspicion_score: float = 0.0,
        source_breakdown: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Handle a multi-source correlated incident.

        Unlike ``handle_realtime_incident`` which receives only log events,
        this method receives events from ALL sensor sources (log, network,
        auth, process) along with correlation metadata.

        Args:
            source_ip: The IP that triggered the incident.
            event_window: List of multi-source events.
            suspicion_score: The correlated suspicion score.
            source_breakdown: Per-source score breakdown from CorrelationEngine.

        Returns:
            The full pipeline result enriched with multi-source context.
        """
        # Build enriched log lines with source context
        raw_logs = []
        source_counts: dict[str, int] = {}

        for event in event_window:
            if hasattr(event, "message"):
                raw_logs.append(event.message)
            elif hasattr(event, "source"):
                # TelemetryEvent-style
                source = getattr(event, "source", "unknown")
                source_counts[source] = source_counts.get(source, 0) + 1
                event_type = getattr(event, "event_type", "unknown")
                severity = getattr(event, "severity_hint", 0.0)
                raw_logs.append(
                    f"[{source}:{event_type}] severity={severity:.2f} "
                    f"ip={getattr(event, 'ip', 'N/A')}"
                )
            else:
                raw_logs.append(str(event))

        if not raw_logs:
            logger.warning(
                "handle_multisource_incident called with empty window for %s",
                source_ip,
            )
            return {}

        logger.info(
            "═══ Multi-source incident for %s — score=%.2f, events=%d, sources=%s ═══",
            source_ip,
            suspicion_score,
            len(raw_logs),
            source_counts,
        )

        result = await self.analyze_logs(raw_logs)

        # Enrich with multi-source metadata
        result["realtime_metadata"] = {
            "source_ip": source_ip,
            "suspicion_score": suspicion_score,
            "event_count": len(event_window),
            "trigger_type": "multi_source_correlation",
            "source_breakdown": source_breakdown or {},
            "source_counts": source_counts,
        }

        return result


    async def simulate_threat(self, threat_type: str) -> dict[str, Any]:
        """Run impact simulation only for a given threat type.

        Useful for "what-if" analysis without log input.
        """
        simulation_input = {
            "threat_type": threat_type,
            "confidence_score": 1.0,  # manual simulation = full confidence
        }
        result = self._impact_agent.execute(simulation_input)
        return result.get("result", result)

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Retrieve a stored incident by ID."""
        return self._incident_repo.get(incident_id)

    def list_incidents(self) -> list[dict[str, Any]]:
        """List all stored incidents."""
        return self._incident_repo.list_all()

    # ── Private helpers ─────────────────────────────────────────────────

    def _run_agent(
        self,
        agent: Any,
        input_data: dict[str, Any],
        incident_id: str,
        stage_name: str,
    ) -> dict[str, Any]:
        """Run a single agent and log its output to state."""
        self._state.add_decision(incident_id, f"Running {agent.name} agent")
        logger.info("──── Running %s agent ────", agent.name)

        output = agent.execute(input_data)
        result = output.get("result", output)

        self._state.update_stage(incident_id, stage_name, output)
        return result

    def _find_similar_incidents(self, log_output: dict[str, Any]) -> list:
        """Search vector memory for similar past incidents."""
        summary = log_output.get("summary", "")
        patterns = log_output.get("suspicious_patterns", [])
        text = summary + " " + " ".join(
            p.get("description", "") for p in patterns
        )

        if not text.strip():
            return []

        embedding = self._embeddings.embed(text)
        return self._vector_store.search(embedding)

    def _store_incident_memory(
        self,
        incident_id: str,
        log_output: dict[str, Any],
        threat_output: dict[str, Any],
    ) -> None:
        """Embed and store the incident for future similarity search."""
        summary = log_output.get("summary", "")
        threat_type = threat_output.get("threat_type", "unknown")
        text = f"{threat_type}: {summary}"

        embedding = self._embeddings.embed(text)
        metadata = {
            "threat_type": threat_type,
            "confidence_score": threat_output.get("confidence_score", 0),
            "anomaly_score": log_output.get("anomaly_score", 0),
            "summary": summary[:200],
        }
        self._vector_store.store(incident_id, embedding, metadata)
        logger.info("Stored incident %s in vector memory", incident_id)
