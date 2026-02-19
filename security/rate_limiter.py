"""
RateLimiter — token-bucket rate limiter for FastAPI.

Configurable requests-per-minute per client IP.
Implemented as ASGI middleware.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from config.settings import get_settings

logger = logging.getLogger(__name__)


class RateLimiter(BaseHTTPMiddleware):
    """Token-bucket rate limiter middleware.

    Tracks requests per client IP and returns 429 when the
    configured RPM is exceeded.
    """

    def __init__(self, app: Any) -> None:
        super().__init__(app)
        self._settings = get_settings()
        self._rpm = self._settings.RATE_LIMIT_RPM
        self._buckets: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"tokens": self._rpm, "last_refill": time.time()}
        )

    async def dispatch(self, request: Request, call_next: Any) -> Any:
        """Check rate limit before processing the request."""
        # Skip rate limiting for health checks
        if request.url.path == "/health":
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        bucket = self._buckets[client_ip]

        # Refill tokens
        now = time.time()
        elapsed = now - bucket["last_refill"]
        refill = elapsed * (self._rpm / 60.0)  # tokens per second
        bucket["tokens"] = min(self._rpm, bucket["tokens"] + refill)
        bucket["last_refill"] = now

        # Check tokens
        if bucket["tokens"] < 1.0:
            logger.warning("Rate limit exceeded for IP %s", client_ip)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded. Please try again later.",
                    "retry_after_seconds": int(60 / self._rpm),
                },
            )

        # Consume a token
        bucket["tokens"] -= 1.0
        return await call_next(request)
