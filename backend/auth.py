"""
Authentication and authorization middleware for screenshot-to-code API.
Implements simple API key validation and org isolation.
"""

from fastapi import Header, HTTPException, status
from typing import Optional
import os
from errors import UnauthorizedError

# Simple in-memory user store (replace with database in production)
# Format: {api_key: {user_id, org_id, role}}
VALID_KEYS = {
    "demo-key-123": {"user_id": "user-1", "org_id": "org-1", "role": "admin"},
    "test-key-456": {"user_id": "user-2", "org_id": "org-2", "role": "user"},
}

class AuthContext:
    """Request authentication context."""
    def __init__(self, user_id: str, org_id: str, role: str):
        self.user_id = user_id
        self.org_id = org_id
        self.role = role

def validate_auth_header(auth_header: str) -> AuthContext:
    """
    Validate authorization header and return AuthContext.
    Supports: Bearer <api_key> format.
    Raises UnauthorizedError if invalid.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        raise UnauthorizedError("Invalid authorization format. Use: Bearer <api_key>")

    api_key = auth_header[7:]

    if api_key not in VALID_KEYS:
        raise UnauthorizedError("Invalid API key")

    creds = VALID_KEYS[api_key]
    return AuthContext(
        user_id=creds["user_id"],
        org_id=creds["org_id"],
        role=creds["role"]
    )

async def get_auth_context(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
) -> AuthContext:
    """
    Extract and validate authentication from request headers.
    Supports: Bearer token or X-API-Key header.
    """
    api_key = None
    
    # Try X-API-Key header first
    if x_api_key:
        api_key = x_api_key
    # Try Authorization: Bearer <key>
    elif authorization:
        if authorization.startswith("Bearer "):
            api_key = authorization[7:]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization format. Use: Bearer <api_key>"
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication. Provide X-API-Key or Authorization header."
        )
    
    # Validate API key
    if api_key not in VALID_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key."
        )
    
    creds = VALID_KEYS[api_key]
    return AuthContext(
        user_id=creds["user_id"],
        org_id=creds["org_id"],
        role=creds["role"]
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
