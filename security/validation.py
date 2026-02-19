"""
Validation — input sanitization and prompt injection prevention.

Validates:
  • Log format and structure
  • Prompt injection patterns
  • Payload size limits
"""

from __future__ import annotations

import logging
import re
from typing import Any

from core.exceptions import ValidationError

logger = logging.getLogger(__name__)

# ── Constants ───────────────────────────────────────────────────────────

MAX_LOG_LINES = 10_000
MAX_LINE_LENGTH = 10_000
MAX_PAYLOAD_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

# Patterns that indicate prompt injection attempts
_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?prior", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+are", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"BEGIN\s+INJECTION", re.IGNORECASE),
    re.compile(r"override\s+safety", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
]


def validate_log_input(logs: list[str]) -> list[str]:
    """Validate and sanitize a list of log lines.

    Args:
        logs: Raw log lines from user input.

    Returns:
        Sanitized log lines.

    Raises:
        ValidationError: If input is malformed or too large.
    """
    if not isinstance(logs, list):
        raise ValidationError("'logs' must be a list of strings")

    if len(logs) == 0:
        raise ValidationError("'logs' must not be empty")

    if len(logs) > MAX_LOG_LINES:
        raise ValidationError(
            f"Too many log lines: {len(logs)} (max: {MAX_LOG_LINES})"
        )

    sanitized: list[str] = []
    for i, line in enumerate(logs):
        if not isinstance(line, str):
            raise ValidationError(f"Log line {i} is not a string")

        if len(line) > MAX_LINE_LENGTH:
            logger.warning("Truncating oversized log line %d (%d chars)", i, len(line))
            line = line[:MAX_LINE_LENGTH]

        # Check for prompt injection
        detect_prompt_injection(line, context=f"log line {i}")

        sanitized.append(line)

    logger.info("Validated %d log lines", len(sanitized))
    return sanitized


def detect_prompt_injection(text: str, context: str = "input") -> None:
    """Scan text for known prompt injection patterns.

    Raises:
        ValidationError: If a prompt injection pattern is detected.
    """
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            logger.warning(
                "PROMPT INJECTION DETECTED in %s: matched pattern '%s'",
                context,
                pattern.pattern,
            )
            raise ValidationError(
                f"Potential prompt injection detected in {context}. "
                "Input has been rejected for security reasons."
            )


def validate_threat_type(threat_type: str) -> str:
    """Validate a threat type string.

    Raises:
        ValidationError: If the threat type is invalid.
    """
    valid_types = {
        "brute_force",
        "phishing",
        "malware",
        "data_exfiltration",
        "privilege_escalation",
        "unknown",
    }
    cleaned = threat_type.strip().lower()
    if cleaned not in valid_types:
        raise ValidationError(
            f"Invalid threat type: '{threat_type}'. Valid types: {valid_types}"
        )
    return cleaned


def validate_payload_size(content_length: int | None) -> None:
    """Check that the request payload is within size limits.

    Raises:
        ValidationError: If the payload is too large.
    """
    if content_length and content_length > MAX_PAYLOAD_SIZE_BYTES:
        raise ValidationError(
            f"Payload too large: {content_length} bytes "
            f"(max: {MAX_PAYLOAD_SIZE_BYTES} bytes)"
        )
