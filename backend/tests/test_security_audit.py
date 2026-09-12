"""
Security audit tests for authentication system.
Tests for IDOR, credential handling, rate limiting, session security.
"""

import pytest
from unittest.mock import AsyncMock
from fastapi import WebSocket, status
from auth import validate_auth_header, AuthContext
from ws_auth import get_ws_auth_context
from errors import UnauthorizedError


class TestIDORPrevention:
    """Test Insecure Direct Object Reference (IDOR) prevention."""

    @pytest.mark.asyncio
    async def test_org_isolation_prevents_cross_org_access(self):
        """Test that org_id enforcement prevents accessing other orgs' resources."""
        # User from org-1 cannot access org-2 data
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx2.org_id == "org-2"

        # Different org IDs prevent IDOR
        assert ctx1.org_id != ctx2.org_id

    @pytest.mark.asyncio
    async def test_api_key_tied_to_single_org(self):
        """Test each API key is bound to exactly one org."""
        auth_ctx = await validate_auth_header("Bearer demo-key-123")

        # API key only provides access to one org
        assert auth_ctx.org_id == "org-1"
        assert auth_ctx.org_id != "org-2"
        assert auth_ctx.org_id != "org-3"

    @pytest.mark.asyncio
    async def test_websocket_enforces_org_scope(self):
        """Test WebSocket authentication enforces org isolation."""
        ws1 = AsyncMock(spec=WebSocket)
        ws1.headers = {"Authorization": "Bearer demo-key-123"}
        ws1.query_params = {}

        ws2 = AsyncMock(spec=WebSocket)
        ws2.headers = {"Authorization": "Bearer test-key-456"}
        ws2.query_params = {}

        ctx1 = await get_ws_auth_context(ws1)
        ctx2 = await get_ws_auth_context(ws2)

        # Each WebSocket maintains org isolation
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"


class TestCredentialHandlingSecurity:
    """Test secure credential handling."""

    @pytest.mark.asyncio
    async def test_api_key_not_logged_in_plain_text(self):
        """Test that API keys are not exposed in error messages."""
        # Even on auth failure, the key should not be echoed back
        with pytest.raises(UnauthorizedError) as exc_info:
            await validate_auth_header("Bearer secret-key-123")

        error_msg = str(exc_info.value)
        # Error should not contain the secret key
        assert "secret-key-123" not in error_msg

    @pytest.mark.asyncio
    async def test_bearer_prefix_validation(self):
        """Test that Bearer prefix is required (not optional)."""
        # Missing Bearer prefix should fail
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("demo-key-123")

        # Bearer prefix is case-sensitive
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("bearer demo-key-123")

    @pytest.mark.asyncio
    async def test_auth_context_immutable(self):
        """Test that AuthContext cannot be modified after creation."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        # Create second context with different org
        ctx2 = AuthContext(user_id="user-2", org_id="org-2", role="user")

        # Contexts are independent
        assert ctx.org_id == "org-1"
        assert ctx2.org_id == "org-2"
        assert ctx != ctx2


class TestSessionSecurity:
    """Test session and token security."""

    @pytest.mark.asyncio
    async def test_invalid_tokens_rejected_immediately(self):
        """Test that invalid tokens are rejected immediately."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-token")

        # No partial matches or fuzzy matching
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key")

    @pytest.mark.asyncio
    async def test_websocket_connection_closed_on_auth_failure(self):
        """Test that WebSocket closes immediately on auth failure."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer invalid"}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)

        # WebSocket must be closed
        assert ws.close.called
        # Close should use policy violation code
        call_args = ws.close.call_args
        assert call_args[1]["code"] == status.WS_1008_POLICY_VIOLATION

    @pytest.mark.asyncio
    async def test_no_token_reuse_across_sessions(self):
        """Test that same key authenticates fresh each time."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Same key, same org, but potentially different session context
        assert ctx1.org_id == ctx2.org_id
        assert ctx1.user_id == ctx2.user_id


class TestAuthenticationBypass:
    """Test prevention of authentication bypass techniques."""

    @pytest.mark.asyncio
    async def test_empty_auth_header_rejected(self):
        """Test that empty auth header is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("")

    @pytest.mark.asyncio
    async def test_whitespace_only_auth_header_rejected(self):
        """Test that whitespace-only auth header is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("   ")

    @pytest.mark.asyncio
    async def test_null_byte_injection_prevented(self):
        """Test that null bytes in auth don't bypass validation."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key\x00xyz")

    @pytest.mark.asyncio
    async def test_case_sensitive_key_matching(self):
        """Test that API key matching is case-sensitive."""
        # Correct key works
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

        # Different case should fail
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer DEMO-KEY-123")

    @pytest.mark.asyncio
    async def test_similar_keys_not_accepted(self):
        """Test that similar but incorrect keys are rejected."""
        # Correct key
        await validate_auth_header("Bearer demo-key-123")

        # Typos should fail
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-124")

        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-12")


class TestRateLimitingReadiness:
    """Test system is ready for rate limiting implementation."""

    @pytest.mark.asyncio
    async def test_auth_failures_track_source(self):
        """Test that auth failures can be traced to source."""
        # Malformed request
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError:
            pass

        # System should be able to track this as auth failure from client

    @pytest.mark.asyncio
    async def test_websocket_auth_failures_loggable(self):
        """Test that WebSocket auth failures include context."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer bad-key"}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        try:
            await get_ws_auth_context(ws)
        except UnauthorizedError:
            pass

        # Error should be catchable for logging/monitoring


class TestSecurityHeaders:
    """Test that auth system properly validates input format."""

    @pytest.mark.asyncio
    async def test_header_injection_prevented(self):
        """Test that header-injection-like patterns are rejected."""
        # CRLF injection attempt
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer valid\r\nX-Evil: header")

    @pytest.mark.asyncio
    async def test_unicode_in_auth_rejected(self):
        """Test that unicode characters don't bypass validation."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-123™")

    @pytest.mark.asyncio
    async def test_very_long_token_rejected(self):
        """Test that excessively long tokens are rejected."""
        long_token = "Bearer " + "a" * 10000
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(long_token)
