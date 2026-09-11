"""WebSocket authentication middleware"""

from fastapi import WebSocket, status
from fastapi.security import HTTPBearer
from auth import AuthContext, validate_auth_header
from errors import UnauthorizedError


async def get_ws_auth_context(websocket: WebSocket) -> AuthContext:
    """Extract and validate auth from WebSocket query params or headers"""
    # Try Authorization header first
    auth_header = websocket.headers.get("Authorization")
    if auth_header:
        try:
            return validate_auth_header(auth_header)
        except UnauthorizedError:
            pass

    # Try X-API-Key header
    api_key = websocket.headers.get("X-API-Key")
    if api_key:
        try:
            return validate_auth_header(f"Bearer {api_key}")
        except UnauthorizedError:
            pass

    # Try query parameter (for WebSocket compatibility)
    token = websocket.query_params.get("token")
    if token:
        try:
            return validate_auth_header(f"Bearer {token}")
        except UnauthorizedError:
            pass

    await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Unauthorized")
    raise UnauthorizedError("No valid authentication provided")
