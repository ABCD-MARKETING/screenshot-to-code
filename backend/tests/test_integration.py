"""
Integration tests for authentication system components.
Tests complete workflows: auth → context → enforcement.
"""

import pytest
from unittest.mock import AsyncMock
from fastapi import WebSocket, status
from auth import validate_auth_header, get_auth_context, AuthContext
from ws_auth import get_ws_auth_context
from errors import UnauthorizedError


class TestAuthToContextFlow:
    """Test the complete flow from auth header to context."""

    @pytest.mark.asyncio
    async def test_bearer_token_to_auth_context(self):
        """Test that Bearer token correctly produces AuthContext."""
        # Validate auth header
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Should produce valid AuthContext
        assert isinstance(ctx, AuthContext)
        assert ctx.user_id == "user-1"
        assert ctx.org_id == "org-1"
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_different_keys_produce_different_contexts(self):
        """Test that different keys produce different contexts."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        # Different keys → different contexts
        assert ctx1.user_id != ctx2.user_id
        assert ctx1.org_id != ctx2.org_id
        assert ctx1.role != ctx2.role

    @pytest.mark.asyncio
    async def test_multiple_validations_produce_consistent_contexts(self):
        """Test that validating the same key multiple times produces consistent results."""
        contexts = []

        for _ in range(5):
            ctx = await validate_auth_header("Bearer demo-key-123")
            contexts.append(ctx)

        # All contexts should have the same values
        for ctx in contexts:
            assert ctx.user_id == "user-1"
            assert ctx.org_id == "org-1"
            assert ctx.role == "admin"


class TestWebSocketAuthToContext:
    """Test WebSocket auth flow from header to context."""

    @pytest.mark.asyncio
    async def test_websocket_authorization_header_to_context(self):
        """Test that WebSocket with Authorization header produces context."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer demo-key-123"}
        ws.query_params = {}

        ctx = await get_ws_auth_context(ws)

        assert isinstance(ctx, AuthContext)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_x_api_key_header_to_context(self):
        """Test that WebSocket with X-API-Key header produces context."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"X-API-Key": "demo-key-123"}
        ws.query_params = {}

        ctx = await get_ws_auth_context(ws)

        assert isinstance(ctx, AuthContext)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_header_precedence(self):
        """Test that WebSocket auth header precedence is correct."""
        ws = AsyncMock(spec=WebSocket)
        # Both headers present; X-API-Key takes precedence? Or Authorization?
        # Check the actual implementation order
        ws.headers = {
            "Authorization": "Bearer demo-key-123",  # org-1
            "X-API-Key": "test-key-456"  # org-2
        }
        ws.query_params = {}

        ctx = await get_ws_auth_context(ws)

        # Per ws_auth.py, Authorization takes precedence
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_query_param_fallback(self):
        """Test that WebSocket falls back to query param when headers missing."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {}
        ws.query_params = {"token": "demo-key-123"}  # WebSocket uses 'token' param

        ctx = await get_ws_auth_context(ws)

        assert ctx.org_id == "org-1"


class TestAuthEnforcement:
    """Test enforcement of auth decisions across the system."""

    @pytest.mark.asyncio
    async def test_invalid_auth_rejected_consistently(self):
        """Test that invalid auth is rejected at all layers."""
        # HTTP layer
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key")

        # WebSocket layer
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer invalid-key"}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)

    @pytest.mark.asyncio
    async def test_missing_auth_rejected_consistently(self):
        """Test that missing auth is rejected at all layers."""
        # HTTP layer - missing auth is caught
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("")

        # WebSocket layer - missing auth is caught
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)


class TestOrgIsolationConsistency:
    """Test that org isolation is consistent across auth methods."""

    @pytest.mark.asyncio
    async def test_org_isolation_in_bearer_auth(self):
        """Test org isolation when using Bearer token."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"
        assert ctx1.org_id != ctx2.org_id

    @pytest.mark.asyncio
    async def test_org_isolation_in_websocket_auth(self):
        """Test org isolation when using WebSocket."""
        ws1 = AsyncMock(spec=WebSocket)
        ws1.headers = {"Authorization": "Bearer demo-key-123"}
        ws1.query_params = {}

        ws2 = AsyncMock(spec=WebSocket)
        ws2.headers = {"Authorization": "Bearer test-key-456"}
        ws2.query_params = {}

        ctx1 = await get_ws_auth_context(ws1)
        ctx2 = await get_ws_auth_context(ws2)

        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_org_isolation_across_auth_methods(self):
        """Test that org isolation works across different auth methods."""
        # Bearer token
        http_ctx = await validate_auth_header("Bearer demo-key-123")

        # WebSocket with same key
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer demo-key-123"}
        ws.query_params = {}
        ws_ctx = await get_ws_auth_context(ws)

        # Should get same org
        assert http_ctx.org_id == ws_ctx.org_id == "org-1"


class TestErrorRecoveryIntegration:
    """Test error recovery across integrated components."""

    @pytest.mark.asyncio
    async def test_failed_auth_does_not_affect_next_request(self):
        """Test that a failed auth doesn't poison subsequent requests."""
        # First request fails
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key")

        # Second request succeeds
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_failed_websocket_does_not_affect_next_connection(self):
        """Test that a failed WebSocket connection doesn't affect the next one."""
        # First connection fails
        ws1 = AsyncMock(spec=WebSocket)
        ws1.headers = {"Authorization": "Bearer invalid-key"}
        ws1.query_params = {}
        ws1.send_json = AsyncMock()
        ws1.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws1)

        # Second connection succeeds
        ws2 = AsyncMock(spec=WebSocket)
        ws2.headers = {"Authorization": "Bearer demo-key-123"}
        ws2.query_params = {}

        ctx = await get_ws_auth_context(ws2)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_mixed_valid_invalid_auth_requests(self):
        """Test handling mixed valid and invalid auth in sequence."""
        # Request 1: invalid
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer bad-key")

        # Request 2: valid (org-1)
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        # Request 3: invalid
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer another-bad-key")

        # Request 4: valid (org-2)
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx2.org_id == "org-2"


class TestContextUsage:
    """Test that AuthContext is usable for downstream operations."""

    @pytest.mark.asyncio
    async def test_context_provides_required_fields_for_queries(self):
        """Test that AuthContext provides all fields needed for backend queries."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Backend would use these fields to filter/enforce access
        assert hasattr(ctx, "org_id")  # For WHERE org_id = ?
        assert hasattr(ctx, "user_id")  # For audit/logging
        assert hasattr(ctx, "role")  # For RBAC

    @pytest.mark.asyncio
    async def test_context_fields_are_accessible(self):
        """Test that context fields are accessible for downstream code."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Downstream code can access these without exceptions
        org_id = ctx.org_id
        user_id = ctx.user_id
        role = ctx.role

        assert org_id == "org-1"
        assert user_id == "user-1"
        assert role == "admin"

    @pytest.mark.asyncio
    async def test_context_can_be_passed_to_handlers(self):
        """Test that context can be passed to request handlers."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Simulate passing context to a handler
        async def handler(auth: AuthContext) -> str:
            return f"org={auth.org_id},user={auth.user_id}"

        result = await handler(auth=ctx)

        assert "org=org-1" in result
        assert "user=user-1" in result


class TestCompleteAuthFlow:
    """Test complete end-to-end authentication flows."""

    @pytest.mark.asyncio
    async def test_http_request_complete_flow(self):
        """Test complete HTTP request authentication flow."""
        # 1. Receive auth header
        auth_header = "Bearer demo-key-123"

        # 2. Validate header
        ctx = await validate_auth_header(auth_header)

        # 3. Verify context is valid
        assert isinstance(ctx, AuthContext)
        assert ctx.org_id == "org-1"

        # 4. Use context for downstream operations (simulated)
        org_filter = ctx.org_id
        assert org_filter == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_complete_flow(self):
        """Test complete WebSocket authentication flow."""
        # 1. WebSocket connects with auth header
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer demo-key-123"}
        ws.query_params = {}

        # 2. Validate WebSocket auth
        ctx = await get_ws_auth_context(ws)

        # 3. Verify context is valid
        assert isinstance(ctx, AuthContext)
        assert ctx.org_id == "org-1"

        # 4. Use context for message filtering (simulated)
        message = {"org_id": ctx.org_id, "data": "test"}
        assert message["org_id"] == "org-1"

    @pytest.mark.asyncio
    async def test_multi_tenant_request_flow(self):
        """Test multi-tenant request handling."""
        # Org-1 request
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        # Backend would execute: SELECT * FROM data WHERE org_id = 'org-1'

        # Org-2 request (same API, different tenant)
        ctx2 = await validate_auth_header("Bearer test-key-456")
        # Backend would execute: SELECT * FROM data WHERE org_id = 'org-2'

        # Each org sees only their data
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"


class TestAuthenticationStateInvariance:
    """Test that auth state remains consistent throughout request lifecycle."""

    @pytest.mark.asyncio
    async def test_context_values_do_not_change_during_request(self):
        """Test that context values remain stable during request processing."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        initial_org = ctx.org_id
        initial_user = ctx.user_id
        initial_role = ctx.role

        # Simulate request processing
        for _ in range(10):
            # Context values should not change
            assert ctx.org_id == initial_org
            assert ctx.user_id == initial_user
            assert ctx.role == initial_role

    @pytest.mark.asyncio
    async def test_separate_requests_have_separate_contexts(self):
        """Test that separate requests maintain separate authentication contexts."""
        contexts = []

        for _ in range(3):
            ctx = await validate_auth_header("Bearer demo-key-123")
            contexts.append(ctx)

        # Each request has its own context instance
        assert len({id(c) for c in contexts}) == 3

        # But all have the same values
        for ctx in contexts:
            assert ctx.org_id == "org-1"
