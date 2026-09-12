"""
Authentication and authorization middleware for screenshot-to-code API.
Implements API key validation and org isolation.
"""

from fastapi import Header, HTTPException, status
from typing import Optional
import os
from errors import UnauthorizedError

# Server-level API secret: set API_SECRET_KEY env var to protect the backend.
# In production (IS_PROD=true), requests without this key are rejected.
# In development, auth is skipped when API_SECRET_KEY is not set.
_SERVER_API_KEY = os.environ.get("API_SECRET_KEY", "")
_IS_PROD = os.environ.get("IS_PROD", "").strip().lower() in {"1", "true", "yes", "on"}


class AuthContext:
    """Request authentication context."""
    def __init__(self, user_id: str, org_id: str, role: str):
        self.user_id = user_id
        self.org_id = org_id
        self.role = role


def _dev_context() -> AuthContext:
    return AuthContext(user_id="dev-user", org_id="dev-org", role="admin")


def _key_context(api_key: str) -> AuthContext:
    """Derive a stable, isolated AuthContext from a key string (dev mode only)."""
    import hashlib
    h = hashlib.sha256(api_key.encode()).hexdigest()[:12]
    return AuthContext(user_id=f"user-{h}", org_id=f"org-{h}", role="admin")


async def validate_auth_header(auth_header: str) -> AuthContext:
    """
    Validate authorization header and return AuthContext.
    Supports: Bearer <api_key> format.
    Looks up API key in database when available.
    In dev mode (IS_PROD not set, no API_SECRET_KEY), accepts any non-empty key.
    Raises UnauthorizedError if invalid.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        raise UnauthorizedError("Invalid authorization format. Use: Bearer <api_key>")

    api_key = auth_header[7:].strip()
    if not api_key:
        raise UnauthorizedError("Empty API key")

    # Try database lookup (if db module is available)
    try:
        from db import db
        db_key = await db.api_key.find_unique(where={"key": api_key})
        if db_key:
            return AuthContext(
                user_id=db_key.user_id or "",
                org_id=db_key.org_id,
                role="user",
            )
    except (ImportError, ModuleNotFoundError, Exception):
        pass

    # Exact server key match
    if _SERVER_API_KEY and api_key == _SERVER_API_KEY:
        return _dev_context()

    # In dev mode with no server key configured, accept any non-empty key
    # and derive a stable isolated context from it (supports multi-tenant tests)
    if not _IS_PROD and not _SERVER_API_KEY:
        return _key_context(api_key)

    raise UnauthorizedError("Invalid API key")


async def get_auth_context(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> AuthContext:
    """
    Extract and validate authentication from request headers.
    Supports: Bearer token or X-API-Key header.
    In development without API_SECRET_KEY set, returns a dev context.
    In production (IS_PROD=true), API_SECRET_KEY is required.
    """
    # In dev with no server key configured, skip auth
    if not _IS_PROD and not _SERVER_API_KEY:
        return _dev_context()

    api_key = None

    if x_api_key:
        api_key = x_api_key
    elif authorization:
        if authorization.startswith("Bearer "):
            api_key = authorization[7:]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization format. Use: Bearer <api_key>",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication. Provide X-API-Key or Authorization header.",
        )

    # Try database lookup
    try:
        from db import db
        db_key = await db.api_key.find_unique(where={"key": api_key})
        if db_key:
            return AuthContext(
                user_id=db_key.user_id or "",
                org_id=db_key.org_id,
                role="user",
            )
    except (ImportError, ModuleNotFoundError, Exception):
        pass

    # Exact server key match
    if _SERVER_API_KEY and api_key == _SERVER_API_KEY:
        return _dev_context()

    # In dev mode with no server key, accept any non-empty key
    if not _IS_PROD and not _SERVER_API_KEY:
        return _key_context(api_key)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key.",
    )

def require_role(*allowed_roles):
    """Decorator to enforce role-based access control."""
    def decorator(func):
        async def wrapper(*args, auth_context: AuthContext, **kwargs):
            if auth_context.role not in allowed_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required role: {', '.join(allowed_roles)}"
                )
            return await func(*args, auth_context=auth_context, **kwargs)
        return wrapper
    return decorator
