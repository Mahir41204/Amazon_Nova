"""
EmbeddingsService — generates text embeddings for vector similarity search.

Uses a lightweight TF-IDF / hashing approach for zero-dependency demo mode.
The interface is pluggable — swap in Nova Titan Embeddings for production.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from typing import Any

import numpy as np

from config.settings import get_settings

logger = logging.getLogger(__name__)


class EmbeddingsService:
    """Generate fixed-dimension embeddings from text.

    Demo mode uses a deterministic hashing approach that produces
    semantically *approximate* embeddings — good enough for similar-
    incident retrieval in demonstrations.

    Production mode would call Amazon Titan Embeddings via Bedrock.
    """

    # ┌─────────────────────────────────────────────────────────────────┐
    # │  PRODUCTION INTEGRATION GUIDE                                  │
    # ├─────────────────────────────────────────────────────────────────┤
    # │                                                                │
    # │  To replace hash-based embeddings with Amazon Titan:           │
    # │                                                                │
    # │  1. Install boto3:                                             │
    # │     pip install boto3                                          │
    # │                                                                │
    # │  2. Add a _call_titan() method:                                │
    # │     import boto3                                               │
    # │     client = boto3.client("bedrock-runtime", region_name=...)  │
    # │     response = client.invoke_model(                            │
    # │         modelId="amazon.titan-embed-text-v2:0",                │
    # │         body=json.dumps({"inputText": text}),                  │
    # │         contentType="application/json",                        │
    # │     )                                                          │
    # │     result = json.loads(response["body"].read())               │
    # │     return np.array(result["embedding"])                       │
    # │                                                                │
    # │  3. Update embed() to call _call_titan() when not DEMO_MODE   │
    # │                                                                │
    # │  4. Set VECTOR_DIMENSION to match Titan output (1024)          │
    # │                                                                │
    # └─────────────────────────────────────────────────────────────────┘

    def __init__(self) -> None:
        self._settings = get_settings()
        self._dimension = self._settings.VECTOR_DIMENSION
        self._validate_production_config()

    def _validate_production_config(self) -> None:
        """Warn if production mode is on but using hash fallback."""
        if self._settings.ENABLE_PRODUCTION_MODE and not self._settings.DEMO_MODE:
            logger.warning(
                "PRODUCTION MODE: EmbeddingsService is using hash-based fallback. "
                "For production quality, integrate Amazon Titan Embeddings via Bedrock."
            )

    def embed(self, text: str) -> np.ndarray:
        """Return a unit-normalised embedding vector for *text*.

        Args:
            text: The input string (log summary, incident description, etc.)

        Returns:
            A numpy array of shape ``(VECTOR_DIMENSION,)`` with L2 norm ≈ 1.
        """
        if self._settings.DEMO_MODE:
            return self._hash_embed(text)

        try:
            return self._call_titan(text)
        except Exception:
            logger.exception("Titan embedding failed, falling back to hash")
            return self._hash_embed(text)

    def _call_titan(self, text: str) -> np.ndarray:
        """Call Amazon Titan Embeddings v2 via Bedrock."""
        try:
            import boto3
            import json
            
            client = boto3.client(
                "bedrock-runtime",
                region_name=self._settings.NOVA_REGION,
            )
            
            # Titan Embeddings v2 supports flexible dimensions.
            # We request the dimension defined in settings (e.g. 256, 512, 1024)
            payload = {
                "inputText": text,
                "dimensions": self._settings.VECTOR_DIMENSION,
                "normalize": True
            }
            
            response = client.invoke_model(
                modelId="amazon.titan-embed-text-v2:0",
                body=json.dumps(payload),
                contentType="application/json",
                accept="application/json"
            )
            
            body = json.loads(response["body"].read())
            return np.array(body["embedding"])
            
        except ImportError:
            logger.error("boto3 not installed. Please install it for production mode.")
            raise
        except Exception:
            raise

    def embed_batch(self, texts: list[str]) -> list[np.ndarray]:
        """Embed multiple texts."""
        return [self.embed(t) for t in texts]

    # ── Private helpers ─────────────────────────────────────────────────

    def _hash_embed(self, text: str) -> np.ndarray:
        """Deterministic hashing-based embedding.

        1. Tokenize and clean the text.
        2. For each token, hash to a bucket index and accumulate a weight.
        3. L2-normalise the resulting vector.

        This gives consistent embeddings so similar texts produce similar
        vectors — sufficient for demo-quality semantic search.
        """
        tokens = self._tokenize(text)
        vector = np.zeros(self._dimension, dtype=np.float64)

        for i, token in enumerate(tokens):
            # Positional decay — earlier tokens matter slightly more
            weight = 1.0 / (1.0 + math.log1p(i))

            # Hash token to multiple bucket indices (simulates projection)
            for seed in range(3):
                h = hashlib.sha256(f"{seed}:{token}".encode()).hexdigest()
                idx = int(h[:8], 16) % self._dimension
                sign = 1.0 if int(h[8:10], 16) % 2 == 0 else -1.0
                vector[idx] += sign * weight

        # L2-normalise
        norm = np.linalg.norm(vector)
        if norm > 0:
            vector /= norm

        return vector

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Simple whitespace + punctuation tokenizer with lowering."""
        text = text.lower()
        tokens = re.findall(r"[a-z0-9]+", text)
        return tokens
