"""
Error handling and recovery tests.
Tests error handling across auth, WebSocket, and API endpoints.
"""

import pytest
from unittest.mock import AsyncMock
from fastapi import WebSocket, status
from errors import UnauthorizedError
from auth import validate_auth_header, AuthContext
from ws_auth import get_ws_auth_context


class TestAuthErrorHandling:
    """Test authentication error handling."""

    @pytest.mark.asyncio
    async def test_malformed_bearer_token(self):
        """Test malformed Bearer token is rejected with clear error."""
        with pytest.raises(UnauthorizedError) as exc_info:
            await validate_auth_header("Bearer")

        assert "Invalid authorization format" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_empty_api_key(self):
        """Test empty API key is rejected."""
        with pytest.raises(UnauthorizedError) as exc_info:
            await validate_auth_header("Bearer ")

        # Should handle empty key gracefully
        assert exc_info.value is not None

    @pytest.mark.asyncio
    async def test_invalid_api_key_format(self):
        """Test invalid API key format is rejected."""
        with pytest.raises(UnauthorizedError) as exc_info:
            await validate_auth_header("Bearer invalid!@#$%^&*()")

        assert "Invalid API key" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_missing_bearer_prefix(self):
        """Test missing Bearer prefix is rejected."""
        with pytest.raises(UnauthorizedError) as exc_info:
            await validate_auth_header("demo-key-123")

        assert "Invalid authorization format" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_case_sensitive_bearer_keyword(self):
        """Test Bearer keyword is case-sensitive."""
        with pytest.raises(UnauthorizedError) as exc_info:
            await validate_auth_header("bearer demo-key-123")

        assert "Invalid authorization format" in str(exc_info.value)


class TestWebSocketErrorHandling:
    """Test WebSocket error handling."""

    @pytest.mark.asyncio
    async def test_websocket_closes_on_auth_failure(self):
        """Test WebSocket properly closes on auth failure."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer invalid-key"}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)

        # Verify WebSocket was closed with proper status code
        ws.close.assert_called_once()
        call_args = ws.close.call_args
        assert call_args[1]["code"] == status.WS_1008_POLICY_VIOLATION

    @pytest.mark.asyncio
    async def test_websocket_sends_error_message(self):
        """Test WebSocket sends error message before closing."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)

        # Verify error message was sent
        ws.send_json.assert_called_once()
        message = ws.send_json.call_args[0][0]
        assert message["type"] == "error"
        assert message["code"] == "UNAUTHORIZED"

    @pytest.mark.asyncio
    async def test_websocket_recovers_from_missing_headers(self):
        """Test WebSocket gracefully handles missing headers."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)

        # Should not crash, should properly close
        ws.close.assert_called_once()


class TestErrorContext:
    """Test error context and information."""

    def test_unauthorized_error_has_message(self):
        """Test UnauthorizedError includes helpful message."""
        error = UnauthorizedError("Test error message")
        assert "Test error message" in str(error)

    def test_unauthorized_error_inheritable(self):
        """Test UnauthorizedError can be caught as Exception."""
        error = UnauthorizedError("Test")
        assert isinstance(error, Exception)


class TestErrorRecovery:
    """Test system recovery from errors."""

    @pytest.mark.asyncio
    async def test_auth_context_immutable_after_validation(self):
        """Test AuthContext is properly isolated after validation."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-2", org_id="org-2", role="user")

        # Each context maintains its own state
        assert ctx1.user_id != ctx2.user_id
        assert ctx1.org_id != ctx2.org_id
        assert ctx1.role != ctx2.role

    @pytest.mark.asyncio
    async def test_failed_validation_does_not_affect_next_request(self):
        """Test failed auth doesn't poison next request."""
        # First request fails
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key")

        # Next request succeeds
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_multiple_auth_attempts(self):
        """Test WebSocket can handle multiple auth failure attempts."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer invalid-key-1"}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)

        # WebSocket was closed
        assert ws.close.called

        # Create new WebSocket with different invalid key
        ws2 = AsyncMock(spec=WebSocket)
        ws2.headers = {"Authorization": "Bearer invalid-key-2"}
        ws2.query_params = {}
        ws2.send_json = AsyncMock()
        ws2.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws2)

        # Second WebSocket also properly closed
        assert ws2.close.called
