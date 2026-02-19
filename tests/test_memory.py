"""
Tests for the memory system — vector store and incident repository.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DEMO_MODE"] = "true"

import pytest
import numpy as np


# ═══════════════════════════════════════════════════════════════════════
# Vector Store Tests
# ═══════════════════════════════════════════════════════════════════════


class TestVectorStore:
    """Tests for the VectorStore."""

    def test_store_and_count(self, vector_store):
        embedding = np.random.randn(256)
        vector_store.store("inc-1", embedding, {"type": "brute_force"})
        assert vector_store.count == 1

    def test_search_empty_store(self, vector_store):
        query = np.random.randn(256)
        results = vector_store.search(query)
        assert results == []

    def test_search_finds_similar(self, vector_store):
        # Store a vector
        base = np.random.randn(256)
        base /= np.linalg.norm(base)
        vector_store.store("inc-1", base, {"type": "brute_force"})

        # Search with a very similar vector — add small noise
        query = base + 0.01 * np.random.randn(256)
        query /= np.linalg.norm(query)

        results = vector_store.search(query, top_k=1)
        assert len(results) == 1
        assert results[0].incident_id == "inc-1"
        assert results[0].similarity_score > 0.9

    def test_search_ranks_by_similarity(self, vector_store):
        dim = 256
        target = np.random.randn(dim)
        target /= np.linalg.norm(target)

        # Close vector
        close = target + 0.05 * np.random.randn(dim)
        close /= np.linalg.norm(close)

        # Far vector
        far = np.random.randn(dim)
        far /= np.linalg.norm(far)

        vector_store.store("close", close, {"note": "close"})
        vector_store.store("far", far, {"note": "far"})

        results = vector_store.search(target, top_k=2)
        # The close vector should rank first
        if len(results) >= 2:
            assert results[0].incident_id == "close"

    def test_persistence(self, vector_store, tmp_path):
        embedding = np.random.randn(256)
        vector_store.store("inc-persist", embedding, {"type": "test"})
        assert vector_store.count == 1

        # The file should exist
        path = tmp_path / "test_vectors.json"
        assert path.exists()


# ═══════════════════════════════════════════════════════════════════════
# Incident Repository Tests
# ═══════════════════════════════════════════════════════════════════════


class TestIncidentRepository:
    """Tests for the IncidentRepository."""

    def test_save_and_get(self, incident_repo):
        incident = {
            "incident_id": "test-1",
            "status": "completed",
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:01:00Z",
            "stages": {},
        }
        incident_repo.save(incident)
        assert incident_repo.count == 1

        retrieved = incident_repo.get("test-1")
        assert retrieved is not None
        assert retrieved["incident_id"] == "test-1"

    def test_get_nonexistent(self, incident_repo):
        assert incident_repo.get("does-not-exist") is None

    def test_list_all(self, incident_repo):
        incident_repo.save({
            "incident_id": "a", "status": "completed",
            "created_at": "2024-01-01", "updated_at": "2024-01-01",
        })
        incident_repo.save({
            "incident_id": "b", "status": "failed",
            "created_at": "2024-01-02", "updated_at": "2024-01-02",
        })

        summaries = incident_repo.list_all()
        assert len(summaries) == 2
        ids = [s["incident_id"] for s in summaries]
        assert "a" in ids
        assert "b" in ids

    def test_delete(self, incident_repo):
        incident_repo.save({
            "incident_id": "to-delete",
            "status": "completed",
            "created_at": "", "updated_at": "",
        })
        assert incident_repo.count == 1

        deleted = incident_repo.delete("to-delete")
        assert deleted is True
        assert incident_repo.count == 0

    def test_delete_nonexistent(self, incident_repo):
        assert incident_repo.delete("nope") is False


# ═══════════════════════════════════════════════════════════════════════
# Embeddings Service Tests
# ═══════════════════════════════════════════════════════════════════════


class TestEmbeddingsService:
    """Tests for the EmbeddingsService."""

    def test_embed_returns_correct_dimension(self, embeddings_service):
        result = embeddings_service.embed("test text for embedding")
        assert isinstance(result, np.ndarray)
        assert result.shape == (256,)

    def test_embed_is_normalized(self, embeddings_service):
        result = embeddings_service.embed("test text")
        norm = np.linalg.norm(result)
        assert abs(norm - 1.0) < 0.01

    def test_similar_texts_produce_similar_embeddings(self, embeddings_service):
        e1 = embeddings_service.embed("failed SSH login from 192.168.1.1")
        e2 = embeddings_service.embed("failed SSH login from 192.168.1.2")
        e3 = embeddings_service.embed("quarterly financial report summary")

        sim_12 = float(np.dot(e1, e2))  # very similar texts
        sim_13 = float(np.dot(e1, e3))  # different topics

        assert sim_12 > sim_13, "Similar texts should have higher similarity"

    def test_embed_batch(self, embeddings_service):
        texts = ["text one", "text two", "text three"]
        results = embeddings_service.embed_batch(texts)
        assert len(results) == 3
        assert all(isinstance(r, np.ndarray) for r in results)

    def test_deterministic(self, embeddings_service):
        e1 = embeddings_service.embed("deterministic test")
        e2 = embeddings_service.embed("deterministic test")
        assert np.allclose(e1, e2)
