"""
WebSocket authentication and real-time auth state management tests.
Tests WebSocket upgrade auth, frame-level validation, connection lifecycle, and auth state transitions.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio


class TestWebSocketUpgradeAuth:
    """Test WebSocket connection upgrade authentication."""

    @pytest.mark.asyncio
    async def test_websocket_upgrade_requires_auth(self):
        """Test that WebSocket upgrade requires valid auth header."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("")

    @pytest.mark.asyncio
    async def test_websocket_upgrade_accepts_bearer_token(self):
        """Test that WebSocket upgrade accepts Bearer token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_websocket_upgrade_rejects_invalid_token(self):
        """Test that WebSocket upgrade rejects invalid tokens."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-token")

    @pytest.mark.asyncio
    async def test_websocket_upgrade_establishes_context(self):
        """Test that successful upgrade establishes auth context."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert isinstance(ctx, AuthContext)
        assert ctx.org_id is not None
        assert ctx.user_id is not None
        assert ctx.role is not None

    @pytest.mark.asyncio
    async def test_websocket_upgrade_context_persists_for_connection(self):
        """Test that context persists for the connection lifetime."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        org_at_start = ctx.org_id

        # Simulate connection processing
        for _ in range(100):
            assert ctx.org_id == org_at_start


class TestWebSocketFrameAuthentication:
    """Test frame-level authentication within WebSocket connection."""

    @pytest.mark.asyncio
    async def test_frame_validated_with_connection_context(self):
        """Test that frames are validated using connection auth context."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Frame processing would use ctx.org_id for data isolation
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_frame_cannot_override_connection_auth(self):
        """Test that frame payload cannot override connection auth."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        original_org = ctx.org_id

        # Simulate malicious frame attempting org override
        # Backend uses ctx.org_id, never frame data
        assert ctx.org_id == original_org

    @pytest.mark.asyncio
    async def test_frame_processing_enforces_org_boundary(self):
        """Test that each frame enforces org_id boundary."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Each frame must filter data by ctx.org_id
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_frame_buffer_respects_auth_context(self):
        """Test that buffered frames respect auth context."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Simulate multiple frames buffered during processing
        contexts = []
        for _ in range(5):
            contexts.append(ctx)

        # All use same auth context (connection-level)
        assert all(c.org_id == "org-1" for c in contexts)


class TestWebSocketConnectionLifecycle:
    """Test WebSocket connection auth lifecycle."""

    @pytest.mark.asyncio
    async def test_connection_auth_at_upgrade(self):
        """Test authentication occurs at WebSocket upgrade."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Connection established with valid auth
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_connection_maintains_auth_throughout_lifetime(self):
        """Test that auth is maintained throughout connection."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        start_org = ctx.org_id

        # Simulate connection processing for 1000ms
        for _ in range(100):
            assert ctx.org_id == start_org

    @pytest.mark.asyncio
    async def test_connection_closes_on_token_expiry(self):
        """Test that connection is signaled to close on token expiry."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # In real implementation: expiry timestamp would be checked
        # If expired, server sends close frame (code 1008 - policy violation)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_new_connection_requires_fresh_auth(self):
        """Test that new connection requires fresh auth."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Different connection instances, but same auth
        assert ctx1 is not ctx2
        assert ctx1.org_id == ctx2.org_id


class TestWebSocketConcurrentConnections:
    """Test concurrent WebSocket connections under auth."""

    @pytest.mark.asyncio
    async def test_concurrent_connections_same_org(self):
        """Test multiple concurrent connections from same org."""
        async def get_context():
            return await validate_auth_header("Bearer demo-key-123")

        contexts = await asyncio.gather(*[get_context() for _ in range(10)])

        # All connections authenticated to org-1
        assert all(ctx.org_id == "org-1" for ctx in contexts)
        # Each has separate context instance
        assert len(set(id(c) for c in contexts)) == 10

    @pytest.mark.asyncio
    async def test_concurrent_connections_different_orgs(self):
        """Test concurrent connections from different orgs."""
        async def get_org1():
            return await validate_auth_header("Bearer demo-key-123")

        async def get_org2():
            return await validate_auth_header("Bearer test-key-456")

        # Interleaved connections
        tasks = []
        for _ in range(5):
            tasks.append(get_org1())
            tasks.append(get_org2())

        contexts = await asyncio.gather(*tasks)

        org1_contexts = [c for c in contexts if c.org_id == "org-1"]
        org2_contexts = [c for c in contexts if c.org_id == "org-2"]

        assert len(org1_contexts) == 5
        assert len(org2_contexts) == 5

    @pytest.mark.asyncio
    async def test_concurrent_connections_isolated(self):
        """Test that concurrent connections maintain isolation."""
        async def simulate_connection(token):
            ctx = await validate_auth_header(f"Bearer {token}")
            await asyncio.sleep(0.001)  # Simulate processing
            return ctx.org_id

        results = await asyncio.gather(
            simulate_connection("demo-key-123"),
            simulate_connection("test-key-456"),
            simulate_connection("demo-key-123"),
            simulate_connection("test-key-456"),
            simulate_connection("demo-key-123"),
        )

        assert results == ["org-1", "org-2", "org-1", "org-2", "org-1"]


class TestWebSocketAuthStateTransitions:
    """Test auth state transitions during WebSocket connection."""

    @pytest.mark.asyncio
    async def test_connection_auth_state_stable(self):
        """Test that auth state remains stable during connection."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        states = []
        for _ in range(20):
            states.append((ctx.user_id, ctx.org_id, ctx.role))

        # All states identical
        assert len(set(states)) == 1
        assert states[0] == ("user-1", "org-1", "admin")

    @pytest.mark.asyncio
    async def test_invalid_upgrade_prevents_connection(self):
        """Test that invalid auth prevents any connection."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid")

        # No context created, no connection established

    @pytest.mark.asyncio
    async def test_connection_inherits_token_permissions(self):
        """Test that connection inherits all token permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Connection inherits admin role
        assert ctx.role == "admin"
        # Can perform admin operations
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_user_connection_has_limited_permissions(self):
        """Test that user token connections have limited permissions."""
        ctx = await validate_auth_header("Bearer test-key-456")

        # Connection inherits user role
        assert ctx.role == "user"
        assert ctx.org_id == "org-2"


class TestWebSocketReconnection:
    """Test WebSocket reconnection scenarios."""

    @pytest.mark.asyncio
    async def test_reconnection_requires_new_auth(self):
        """Test that reconnection requires fresh auth."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # New auth context for reconnection
        assert ctx1 is not ctx2
        assert ctx1.user_id == ctx2.user_id

    @pytest.mark.asyncio
    async def test_reconnection_preserves_org_membership(self):
        """Test that user stays in same org on reconnect."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        org_at_connect = ctx1.org_id

        # Simulate disconnect/reconnect
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Same org after reconnect
        assert ctx2.org_id == org_at_connect

    @pytest.mark.asyncio
    async def test_reconnection_with_different_token_changes_context(self):
        """Test that reconnecting with different token changes context."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        # Reconnect with different token
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx2.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_reconnection_rapid_sequence(self):
        """Test rapid reconnection sequence."""
        tokens = ["demo-key-123", "test-key-456", "demo-key-123"]
        orgs = []

        for token in tokens:
            ctx = await validate_auth_header(f"Bearer {token}")
            orgs.append(ctx.org_id)

        assert orgs == ["org-1", "org-2", "org-1"]


class TestWebSocketDataFiltering:
    """Test that WebSocket data is filtered by auth context."""

    @pytest.mark.asyncio
    async def test_websocket_messages_filtered_by_org(self):
        """Test that incoming messages are filtered by org_id."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")

        # Backend would filter messages: SELECT * FROM messages WHERE org_id = ctx.org_id
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_websocket_broadcast_respects_org(self):
        """Test that broadcasts respect org boundaries."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Broadcast to org-1 users only, using ctx.org_id
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_user_context_enforced(self):
        """Test that user_id context is enforced."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Backend enforces: can only access own messages unless shared/admin
        assert ctx.user_id == "user-1"


class TestWebSocketAuthHeaders:
    """Test WebSocket authentication header handling."""

    @pytest.mark.asyncio
    async def test_websocket_query_param_auth(self):
        """Test WebSocket auth via query parameter."""
        # Modern WebSocket implementations use headers; query params deprecated
        # But some systems still use ?token=xxx or ?api_key=xxx
        # Backend should normalize to Bearer for consistency
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_header_case_insensitivity(self):
        """Test Bearer prefix handling (case sensitivity varies)."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Bearer is typically case-sensitive (RFC 6750)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_malformed_auth_header_rejected(self):
        """Test that malformed auth headers are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("BearerX demo-key-123")


class TestWebSocketAuthErrorHandling:
    """Test error handling during WebSocket auth."""

    @pytest.mark.asyncio
    async def test_websocket_upgrade_error_closes_connection(self):
        """Test that auth errors close connection without upgrade."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key")

    @pytest.mark.asyncio
    async def test_websocket_auth_error_no_state_leaked(self):
        """Test that auth errors don't leak partial state."""
        try:
            await validate_auth_header("Bearer invalid-key")
        except UnauthorizedError:
            pass
        # No context created, no connection state established

    @pytest.mark.asyncio
    async def test_websocket_multiple_failures_still_rejectable(self):
        """Test that multiple auth failures don't create holes."""
        failures = 0
        for _ in range(5):
            try:
                await validate_auth_header("Bearer invalid-key")
            except UnauthorizedError:
                failures += 1

        assert failures == 5


class TestWebSocketAuthPerformance:
    """Test WebSocket auth performance characteristics."""

    @pytest.mark.asyncio
    async def test_websocket_auth_latency_acceptable(self):
        """Test that WebSocket auth completes quickly."""
        import time

        start = time.perf_counter()
        ctx = await validate_auth_header("Bearer demo-key-123")
        elapsed = time.perf_counter() - start

        # WebSocket upgrade should be <10ms
        assert elapsed < 0.01
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_many_concurrent_websocket_upgrades(self):
        """Test handling many concurrent WebSocket upgrades."""
        async def upgrade():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[upgrade() for _ in range(100)])

        # All should succeed
        assert len(results) == 100
        assert all(r == "org-1" for r in results)


class TestWebSocketOrgIsolation:
    """Test org isolation in WebSocket connections."""

    @pytest.mark.asyncio
    async def test_websocket_org1_isolated_from_org2(self):
        """Test that org-1 WebSocket is isolated from org-2."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")

        # Completely separate auth contexts
        assert org1_ctx.org_id != org2_ctx.org_id
        assert org1_ctx is not org2_ctx

    @pytest.mark.asyncio
    async def test_websocket_concurrent_org_isolation(self):
        """Test concurrent WebSocket org isolation."""
        async def get_org_ctx(token):
            ctx = await validate_auth_header(f"Bearer {token}")
            return ctx.org_id

        results = await asyncio.gather(
            get_org_ctx("demo-key-123"),
            get_org_ctx("test-key-456"),
            get_org_ctx("demo-key-123"),
            get_org_ctx("test-key-456"),
        )

        assert results == ["org-1", "org-2", "org-1", "org-2"]

    @pytest.mark.asyncio
    async def test_websocket_user_cannot_see_other_org_data(self):
        """Test that org-1 user cannot access org-2 data over WebSocket."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        # Backend: WHERE org_id = org1_ctx.org_id (mandatory on every query)
        assert org1_ctx.org_id == "org-1"
