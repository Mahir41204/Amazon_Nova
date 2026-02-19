"""
VectorStore — in-memory vector store for semantic similarity search.

Uses numpy cosine similarity.  Provides persistence to JSON for
demo convenience.  Designed to be swapped out for ChromaDB / Pinecone
in production.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from config.settings import get_settings

logger = logging.getLogger(__name__)


@dataclass
class SimilarIncident:
    """A past incident returned by similarity search."""

    incident_id: str
    similarity_score: float
    metadata: dict[str, Any] = field(default_factory=dict)


class VectorStore:
    """In-memory vector similarity store backed by numpy.

    Stores (id, embedding, metadata) triples and supports top-k
    cosine-similarity search.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._ids: list[str] = []
        self._vectors: list[np.ndarray] = []
        self._metadata: list[dict[str, Any]] = []
        self._load()

    # ── Public API ──────────────────────────────────────────────────────

    def store(
        self,
        incident_id: str,
        embedding: np.ndarray,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Store a new incident embedding."""
        self._ids.append(incident_id)
        self._vectors.append(embedding)
        self._metadata.append(metadata or {})
        self._persist()
        logger.info("Stored vector for incident %s (total: %d)", incident_id, len(self._ids))

    def search(
        self,
        query_embedding: np.ndarray,
        top_k: int | None = None,
    ) -> list[SimilarIncident]:
        """Find the most similar past incidents.

        Args:
            query_embedding: The embedding to compare against.
            top_k: Number of results to return (defaults to config value).

        Returns:
            Sorted list of ``SimilarIncident`` objects, most similar first.
        """
        if not self._vectors:
            return []

        top_k = top_k or self._settings.SIMILARITY_TOP_K
        matrix = np.array(self._vectors)
        query = query_embedding.reshape(1, -1)

        # Cosine similarity
        similarities = self._cosine_similarity(query, matrix).flatten()

        # Get top-k indices
        k = min(top_k, len(similarities))
        top_indices = np.argsort(similarities)[-k:][::-1]

        results = []
        for idx in top_indices:
            score = float(similarities[idx])
            if score > 0.0:  # only return non-trivial matches
                results.append(
                    SimilarIncident(
                        incident_id=self._ids[idx],
                        similarity_score=round(score, 4),
                        metadata=self._metadata[idx],
                    )
                )

        logger.info("Vector search returned %d similar incidents", len(results))
        return results

    @property
    def count(self) -> int:
        """Number of stored vectors."""
        return len(self._ids)

    # ── Cosine similarity ───────────────────────────────────────────────

    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> np.ndarray:
        """Compute cosine similarity between a query vector and a matrix."""
        norm_a = np.linalg.norm(a, axis=1, keepdims=True)
        norm_b = np.linalg.norm(b, axis=1, keepdims=True)
        # Avoid division by zero
        norm_a = np.maximum(norm_a, 1e-10)
        norm_b = np.maximum(norm_b, 1e-10)
        return (a @ b.T) / (norm_a * norm_b.T)

    # ── Persistence ─────────────────────────────────────────────────────

    def _persist(self) -> None:
        """Save vectors to JSON file."""
        path = Path(self._settings.VECTOR_STORE_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "ids": self._ids,
            "vectors": [v.tolist() for v in self._vectors],
            "metadata": self._metadata,
        }
        path.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        """Load vectors from JSON file if it exists."""
        path = Path(self._settings.VECTOR_STORE_PATH)
        if path.exists():
            try:
                data = json.loads(path.read_text())
                self._ids = data.get("ids", [])
                self._vectors = [np.array(v) for v in data.get("vectors", [])]
                self._metadata = data.get("metadata", [])
                logger.info("Loaded %d vectors from %s", len(self._ids), path)
            except Exception as exc:
                logger.warning("Failed to load vector store: %s", exc)
