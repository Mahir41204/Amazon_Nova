"""
Custom exception hierarchy for Nova Cyber Defense Commander.

Provides specific, meaningful exceptions for every failure mode
so callers can handle errors precisely.
"""

from __future__ import annotations


class NovaBaseError(Exception):
    """Root exception for the Nova system."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class AgentError(NovaBaseError):
    """Raised when an agent encounters an unrecoverable error."""

    def __init__(self, agent_name: str, message: str, details: dict | None = None) -> None:
        self.agent_name = agent_name
        super().__init__(f"[{agent_name}] {message}", details)


class OrchestrationError(NovaBaseError):
    """Raised when the orchestrator pipeline fails."""


class SecurityError(NovaBaseError):
    """Raised on authentication / authorization failures."""


class ValidationError(NovaBaseError):
    """Raised when input validation fails."""


class ConfidenceThresholdError(NovaBaseError):
    """Raised when confidence is below the action threshold."""

    def __init__(self, confidence: float, threshold: float) -> None:
        self.confidence = confidence
        self.threshold = threshold
        super().__init__(
            f"Confidence {confidence:.2%} is below threshold {threshold:.2%}. "
            "Action deferred to human review.",
            {"confidence": confidence, "threshold": threshold},
        )


class NovaClientError(NovaBaseError):
    """Raised when communication with the Nova API fails."""


class NovaActClientError(NovaBaseError):
    """Raised when communication with the Nova Act API fails."""


class MemoryError(NovaBaseError):
    """Raised when the memory / vector store encounters an error."""


class RateLimitExceededError(NovaBaseError):
    """Raised when rate limit is exceeded."""

    def __init__(self) -> None:
        super().__init__("Rate limit exceeded. Please try again later.")
