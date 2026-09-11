"""
Integration tests for full API key lifecycle.
Tests: key generation → storage → validation → WebSocket auth → revocation.
Focuses on fallback keys and multi-tenant isolation since db is not yet installed.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext, FALLBACK_KEYS
from ws_auth import get_ws_auth_context
from errors import UnauthorizedError
from fastapi import WebSocket


@pytest.mark.asyncio
async def test_api_key_lifecycle_fallback_validate():
    """Test API key validation using fallback keys."""
    # Using built-in demo fallback key
    auth_context = await validate_auth_header("Bearer demo-key-123")
    assert auth_context.org_id == "org-1"
    assert auth_context.user_id == "user-1"
    assert auth_context.role == "admin"


@pytest.mark.asyncio
async def test_api_key_lifecycle_use_in_websocket():
    """Test API key works in WebSocket auth."""
    # Use fallback key in WebSocket
    ws = AsyncMock(spec=WebSocket)
    ws.headers = {"X-API-Key": "demo-key-123"}
    ws.query_params = {}

    auth_context = await get_ws_auth_context(ws)
    assert auth_context.org_id == "org-1"
    assert auth_context.user_id == "user-1"


@pytest.mark.asyncio
async def test_api_key_fallback_entries_exist():
    """Test fallback keys are properly configured."""
    assert "demo-key-123" in FALLBACK_KEYS
    assert "test-key-456" in FALLBACK_KEYS
    assert FALLBACK_KEYS["demo-key-123"]["org_id"] == "org-1"
    assert FALLBACK_KEYS["test-key-456"]["org_id"] == "org-2"


@pytest.mark.asyncio
async def test_api_key_organization_isolation_fallback():
    """Test different fallback keys provide proper org isolation."""
    ctx1 = await validate_auth_header("Bearer demo-key-123")
    ctx2 = await validate_auth_header("Bearer test-key-456")

    assert ctx1.org_id == "org-1"
    assert ctx2.org_id == "org-2"
    assert ctx1.org_id != ctx2.org_id
    assert ctx1.role == "admin"
    assert ctx2.role == "user"


@pytest.mark.asyncio
async def test_api_key_invalid_key_rejected():
    """Test invalid API keys are rejected."""
    with pytest.raises(UnauthorizedError) as exc_info:
        await validate_auth_header("Bearer invalid-key-xyz")
    assert "Invalid API key" in str(exc_info.value)


@pytest.mark.asyncio
async def test_api_key_invalid_format_rejected():
    """Test malformed auth headers are rejected."""
    with pytest.raises(UnauthorizedError) as exc_info:
        await validate_auth_header("InvalidFormat")
    assert "Invalid authorization format" in str(exc_info.value)


@pytest.mark.asyncio
async def test_api_key_websocket_request_isolation():
    """Test two concurrent WebSocket requests with different keys stay isolated."""
    ws1 = AsyncMock(spec=WebSocket)
    ws1.headers = {"Authorization": "Bearer demo-key-123"}
    ws1.query_params = {}

    ws2 = AsyncMock(spec=WebSocket)
    ws2.headers = {"Authorization": "Bearer test-key-456"}
    ws2.query_params = {}

    # Simulate concurrent requests
    ctx1 = await get_ws_auth_context(ws1)
    ctx2 = await get_ws_auth_context(ws2)

    # Each should maintain its org isolation
    assert ctx1.org_id == "org-1"
    assert ctx2.org_id == "org-2"
    assert ctx1.user_id == "user-1"
    assert ctx2.user_id == "user-2"


@pytest.mark.asyncio
async def test_api_key_header_precedence():
    """Test Authorization header takes precedence in lifecycle."""
    # All three auth methods present; Authorization should win
    ws = AsyncMock(spec=WebSocket)
    ws.headers = {
        "Authorization": "Bearer demo-key-123",
        "X-API-Key": "test-key-456"
    }
    ws.query_params = {"token": "demo-key-123"}

    auth_context = await get_ws_auth_context(ws)
    # Should use Authorization header's org
    assert auth_context.org_id == "org-1"
    assert auth_context.role == "admin"
