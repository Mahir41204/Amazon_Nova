"""
Shared test fixtures and configuration for pytest.
"""

from __future__ import annotations

import os
import sys
import pytest

# Ensure project root is importable
_project_root = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, _project_root)
# The demo package lives at data/demo/ but is imported as `demo.*`
sys.path.insert(0, os.path.join(_project_root, "data"))

# Force demo mode for all tests
os.environ["DEMO_MODE"] = "true"
os.environ["VECTOR_STORE_PATH"] = "data/test_vector_store.json"
os.environ["INCIDENT_STORE_PATH"] = "data/test_incidents.json"


@pytest.fixture
def nova_client():
    """Provide a NovaClient in demo mode."""
    from services.nova_client import NovaClient
    return NovaClient()


@pytest.fixture
def nova_act_client():
    """Provide a NovaActClient in demo mode."""
    from services.nova_act_client import NovaActClient
    return NovaActClient()


@pytest.fixture
def embeddings_service():
    """Provide an EmbeddingsService."""
    from services.embeddings_service import EmbeddingsService
    return EmbeddingsService()


@pytest.fixture
def vector_store(tmp_path):
    """Provide a fresh VectorStore in a temp directory."""
    os.environ["VECTOR_STORE_PATH"] = str(tmp_path / "test_vectors.json")
    from config.settings import get_settings
    get_settings.cache_clear()
    from memory.vector_store import VectorStore
    store = VectorStore()
    yield store
    get_settings.cache_clear()


@pytest.fixture
def incident_repo(tmp_path):
    """Provide a fresh IncidentRepository in a temp directory."""
    os.environ["INCIDENT_STORE_PATH"] = str(tmp_path / "test_incidents.json")
    from config.settings import get_settings
    get_settings.cache_clear()
    from memory.incident_repository import IncidentRepository
    repo = IncidentRepository()
    yield repo
    get_settings.cache_clear()


@pytest.fixture
def sample_logs():
    """Provide sample brute-force logs for testing."""
    from demo.synthetic_logs import generate_brute_force_logs
    return generate_brute_force_logs()
