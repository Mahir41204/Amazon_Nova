"""
Auth — JWT-based authentication with Role-Based Access Control.

Roles:
  • Admin  — can trigger analysis, execute actions, view everything
  • Viewer — can read reports and incident data only

Demo mode ships with default admin/viewer credentials.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from typing import Any, Callable

from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from config.settings import get_settings
from core.exceptions import SecurityError

logger = logging.getLogger(__name__)

security_scheme = HTTPBearer()


class Role(str, Enum):
    """User roles for RBAC."""
    ADMIN = "admin"
    VIEWER = "viewer"


# ── Demo user store ─────────────────────────────────────────────────────

def _get_users() -> dict[str, dict[str, str]]:
    """Return the user store.  In production, replace with a real DB."""
    settings = get_settings()
    return {
        settings.ADMIN_USERNAME: {
            "password": settings.ADMIN_PASSWORD,
            "role": Role.ADMIN,
        },
        settings.VIEWER_USERNAME: {
            "password": settings.VIEWER_PASSWORD,
            "role": Role.VIEWER,
        },
    }


# ── Token management ───────────────────────────────────────────────────

def authenticate_user(username: str, password: str) -> dict[str, Any]:
    """Validate credentials and return user info.

    Raises:
        SecurityError: If credentials are invalid.
    """
    users = _get_users()
    user = users.get(username)
    if not user or user["password"] != password:
        logger.warning("Failed login attempt for user '%s'", username)
        raise SecurityError("Invalid credentials")
    logger.info("User '%s' authenticated successfully (role: %s)", username, user["role"])
    return {"username": username, "role": user["role"]}


def create_token(username: str, role: str) -> str:
    """Create a signed JWT token."""
    settings = get_settings()
    expires = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRY_MINUTES)
    payload = {
        "sub": username,
        "role": role,
        "exp": expires,
        "iat": datetime.now(timezone.utc),
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    logger.info("JWT token created for user '%s' (expires: %s)", username, expires)
    return token


def verify_token(token: str) -> dict[str, Any]:
    """Verify and decode a JWT token.

    Returns:
        Dict with ``sub`` (username) and ``role``.

    Raises:
        SecurityError: If token is invalid or expired.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return {"username": payload["sub"], "role": payload["role"]}
    except JWTError as exc:
        raise SecurityError(f"Invalid token: {exc}") from exc


# ── FastAPI dependencies ────────────────────────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> dict[str, Any]:
    """FastAPI dependency — extract and verify the current user from the JWT."""
    try:
        return verify_token(credentials.credentials)
    except SecurityError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_role(required_role: Role) -> Callable:
    """FastAPI dependency factory — ensure the user has the required role.

    Usage::

        @router.post("/analyze-log")
        async def analyze(user = Depends(require_role(Role.ADMIN))):
            ...
    """
    async def role_checker(
        user: dict[str, Any] = Depends(get_current_user),
    ) -> dict[str, Any]:
        user_role = user.get("role", "")
        # Admin has access to everything
        if user_role == Role.ADMIN:
            return user
        if user_role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires '{required_role}' role. You have '{user_role}'.",
            )
        return user

    return role_checker
