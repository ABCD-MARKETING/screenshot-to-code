"""
End-to-end tests for WebSocket authentication and communication.
Tests WebSocket auth context extraction and message handling.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from ws_auth import get_ws_auth_context
from errors import UnauthorizedError
from fastapi import WebSocket, status


@pytest.mark.asyncio
async def test_websocket_auth_with_authorization_header():
    """Test WebSocket auth extraction from Authorization header."""
    ws = AsyncMock(spec=WebSocket)
    ws.headers = {"Authorization": "Bearer demo-key-123"}
    ws.query_params = {}
    ws.scope = {}

    auth_context = await get_ws_auth_context(ws)
    assert auth_context.org_id == "org-1"
    assert auth_context.role == "admin"
    assert auth_context.user_id == "user-1"


@pytest.mark.asyncio
async def test_websocket_auth_with_x_api_key_header():
    """Test WebSocket auth extraction from X-API-Key header."""
    ws = AsyncMock(spec=WebSocket)
    ws.headers = {"X-API-Key": "demo-key-123"}
    ws.query_params = {}

    auth_context = await get_ws_auth_context(ws)
    assert auth_context.org_id == "org-1"
    assert auth_context.role == "admin"


@pytest.mark.asyncio
async def test_websocket_auth_with_query_param():
    """Test WebSocket auth extraction from query parameter."""
    ws = AsyncMock(spec=WebSocket)
    ws.headers = {}
    ws.query_params = {"token": "test-key-456"}

    auth_context = await get_ws_auth_context(ws)
    assert auth_context.org_id == "org-2"
    assert auth_context.role == "user"


@pytest.mark.asyncio
async def test_websocket_auth_no_credentials():
    """Test WebSocket closes connection when no auth provided."""
    ws = AsyncMock(spec=WebSocket)
    ws.headers = {}
    ws.query_params = {}
    ws.send_json = AsyncMock()
    ws.close = AsyncMock()

    with pytest.raises(UnauthorizedError):
        await get_ws_auth_context(ws)

    # Verify WebSocket was closed with proper code
    ws.send_json.assert_called_once()
    ws.close.assert_called_once_with(
        code=status.WS_1008_POLICY_VIOLATION,
        reason="Unauthorized"
    )


@pytest.mark.asyncio
async def test_websocket_auth_invalid_header_format():
    """Test WebSocket rejects invalid Authorization header."""
    ws = AsyncMock(spec=WebSocket)
    ws.headers = {"Authorization": "InvalidFormat"}
    ws.query_params = {}
    ws.send_json = AsyncMock()
    ws.close = AsyncMock()

    with pytest.raises(UnauthorizedError):
        await get_ws_auth_context(ws)

    ws.close.assert_called_once()


@pytest.mark.asyncio
async def test_websocket_auth_invalid_key():
    """Test WebSocket rejects invalid API key."""
    ws = AsyncMock(spec=WebSocket)
    ws.headers = {"Authorization": "Bearer invalid-key"}
    ws.query_params = {}
    ws.send_json = AsyncMock()
    ws.close = AsyncMock()

    with pytest.raises(UnauthorizedError):
        await get_ws_auth_context(ws)

    ws.close.assert_called_once()


@pytest.mark.asyncio
async def test_websocket_auth_prefers_authorization_header():
    """Test WebSocket prefers Authorization header over X-API-Key."""
    ws = AsyncMock(spec=WebSocket)
    # Both headers present; Authorization should win
    ws.headers = {
        "Authorization": "Bearer demo-key-123",
        "X-API-Key": "test-key-456"
    }
    ws.query_params = {"token": "invalid-token"}

    auth_context = await get_ws_auth_context(ws)
    # Should use Authorization header (demo-key-123, org-1)
    assert auth_context.org_id == "org-1"
    assert auth_context.role == "admin"


@pytest.mark.asyncio
async def test_websocket_auth_prefers_x_api_key_over_query():
    """Test WebSocket prefers X-API-Key header over query param."""
    ws = AsyncMock(spec=WebSocket)
    ws.headers = {"X-API-Key": "test-key-456"}
    ws.query_params = {"token": "demo-key-123"}

    auth_context = await get_ws_auth_context(ws)
    # Should use X-API-Key (test-key-456, org-2)
    assert auth_context.org_id == "org-2"
    assert auth_context.role == "user"


@pytest.mark.asyncio
async def test_websocket_multi_tenant_isolation():
    """Test WebSocket auth isolates tenants correctly."""
    # Create two WebSockets with different keys
    ws1 = AsyncMock(spec=WebSocket)
    ws1.headers = {"Authorization": "Bearer demo-key-123"}
    ws1.query_params = {}

    ws2 = AsyncMock(spec=WebSocket)
    ws2.headers = {"Authorization": "Bearer test-key-456"}
    ws2.query_params = {}

    ctx1 = await get_ws_auth_context(ws1)
    ctx2 = await get_ws_auth_context(ws2)

    # Different orgs
    assert ctx1.org_id == "org-1"
    assert ctx2.org_id == "org-2"
    assert ctx1.org_id != ctx2.org_id

    # Different roles
    assert ctx1.role == "admin"
    assert ctx2.role == "user"
    assert ctx1.role != ctx2.role
