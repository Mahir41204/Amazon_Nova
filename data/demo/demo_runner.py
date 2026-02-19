"""
Demo runner — orchestrates a complete demo of the pipeline.

Generates synthetic attack logs, runs the full pipeline, and
prints a formatted summary for hackathon presentation.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

# Ensure the project root is on sys.path
sys.path.insert(0, ".")

from config.settings import get_settings
from core.orchestrator import Orchestrator
from core.state_manager import StateManager
from memory.vector_store import VectorStore
from memory.incident_repository import IncidentRepository
from services.nova_client import NovaClient
from services.nova_act_client import NovaActClient
from services.embeddings_service import EmbeddingsService
from demo.synthetic_logs import (
    generate_brute_force_logs,
    generate_phishing_logs,
    generate_data_exfiltration_logs,
)

logger = logging.getLogger(__name__)


def _setup_logging() -> None:
    """Configure structured logging for the demo."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s",
        datefmt="%H:%M:%S",
    )


def _create_orchestrator() -> Orchestrator:
    """Wire up all dependencies and create the orchestrator."""
    nova_client = NovaClient()
    nova_act_client = NovaActClient()
    embeddings_service = EmbeddingsService()
    vector_store = VectorStore()
    incident_repo = IncidentRepository()
    state_manager = StateManager()

    return Orchestrator(
        nova_client=nova_client,
        nova_act_client=nova_act_client,
        embeddings_service=embeddings_service,
        vector_store=vector_store,
        incident_repository=incident_repo,
        state_manager=state_manager,
    )


async def run_demo() -> None:
    """Execute the full demo pipeline."""
    _setup_logging()
    settings = get_settings()

    print("\n" + "═" * 70)
    print("  🛡️  NOVA AUTONOMOUS CYBER DEFENSE COMMANDER — DEMO")
    print("═" * 70)
    print(f"  Mode: {'DEMO (simulated)' if settings.DEMO_MODE else 'PRODUCTION'}")
    print(f"  Confidence Threshold: {settings.CONFIDENCE_THRESHOLD:.0%}")
    print("═" * 70 + "\n")

    orchestrator = _create_orchestrator()

    # ── Scenario 1: SSH Brute Force ─────────────────────────────────────
    print("\n🔴 SCENARIO 1: SSH Brute Force Attack")
    print("─" * 50)
    brute_logs = generate_brute_force_logs()
    print(f"  Generated {len(brute_logs)} synthetic log lines")
    print("  Running full pipeline...\n")

    result1 = await orchestrator.analyze_logs(brute_logs)
    _print_result(result1)

    # ── Scenario 2: Phishing Attack ─────────────────────────────────────
    print("\n\n🟠 SCENARIO 2: Phishing Attack")
    print("─" * 50)
    phish_logs = generate_phishing_logs()
    print(f"  Generated {len(phish_logs)} synthetic log lines")
    print("  Running full pipeline...\n")

    result2 = await orchestrator.analyze_logs(phish_logs)
    _print_result(result2)

    # ── Scenario 3: Data Exfiltration ───────────────────────────────────
    print("\n\n🟡 SCENARIO 3: Data Exfiltration")
    print("─" * 50)
    exfil_logs = generate_data_exfiltration_logs()
    print(f"  Generated {len(exfil_logs)} synthetic log lines")
    print("  Running full pipeline...\n")

    result3 = await orchestrator.analyze_logs(exfil_logs)
    _print_result(result3)

    # ── Summary ─────────────────────────────────────────────────────────
    print("\n" + "═" * 70)
    print("  ✅ DEMO COMPLETE — 3 attack scenarios processed")
    print("═" * 70)
    print("  The system demonstrated:")
    print("  • Multi-agent log analysis and anomaly detection")
    print("  • Nova-powered threat classification with confidence scoring")
    print("  • Impact simulation with financial estimates")
    print("  • Confidence-gated automated response (Nova Act)")
    print("  • Vector-memory learning from past incidents")
    print("  • Executive and technical report generation")
    print("═" * 70 + "\n")


def _print_result(result: dict) -> None:
    """Pretty-print a pipeline result."""
    stages = result.get("stages", {})

    # Log Analysis
    log_stage = stages.get("log_analysis", {}).get("result", {})
    print(f"  📊 Anomaly Score: {log_stage.get('anomaly_score', 'N/A')}")
    patterns = log_stage.get("suspicious_patterns", [])
    for p in patterns:
        print(f"     ⚠️  [{p.get('severity', '?').upper()}] {p.get('pattern_type')}: {p.get('description', '')[:80]}")

    # Threat Classification
    threat_stage = stages.get("threat_classification", {}).get("result", {})
    print(f"\n  🎯 Threat Type: {threat_stage.get('threat_type', 'N/A')}")
    print(f"  🎯 Confidence: {threat_stage.get('confidence_score', 'N/A')}")

    # Impact
    impact_stage = stages.get("impact_simulation", {}).get("result", {})
    print(f"\n  💥 Risk Level: {impact_stage.get('risk_level', 'N/A')}")
    print(f"  💰 Financial Impact: {impact_stage.get('estimated_financial_impact', 'N/A')}")
    print(f"  📈 Severity Score: {impact_stage.get('severity_score', 'N/A')}")

    # Response
    response_stage = stages.get("response", {}).get("result", {})
    actions = response_stage.get("actions_taken", [])
    deferred = response_stage.get("actions_deferred", [])
    review = response_stage.get("requires_human_review", True)

    if actions:
        print(f"\n  🛡️  Automated Actions ({len(actions)}):")
        for a in actions:
            sim = " (simulated)" if a.get("simulated") else ""
            print(f"     ✅ {a['action_type']} → {a['target']}{sim}")
    if deferred:
        print(f"\n  ⏸️  Deferred Actions ({len(deferred)}):")
        for a in deferred:
            print(f"     🔸 {a['action_type']} → {a['target']}: {a.get('reason', '')[:60]}")
    if review:
        print("  ⚠️  Flagged for human review")
    else:
        print("  ✅ Fully automated response executed")

    # Report snippet
    report_stage = stages.get("reporting", {}).get("result", {})
    exec_summary = report_stage.get("executive_summary", "")
    if exec_summary:
        # Print first 3 lines of executive summary
        lines = exec_summary.strip().split("\n")[:3]
        print(f"\n  📝 Report Preview:")
        for line in lines:
            print(f"     {line}")

    print(f"\n  🆔 Incident ID: {result.get('incident_id', 'N/A')}")


if __name__ == "__main__":
    asyncio.run(run_demo())
