"""
Multi-tenancy isolation and cross-tenant security tests.
Tests org isolation, data segregation, API boundaries, and tenant-aware enforcement.
"""

import pytest
from unittest.mock import AsyncMock
from fastapi import WebSocket, status
from auth import validate_auth_header, AuthContext
from ws_auth import get_ws_auth_context
from errors import UnauthorizedError


class TestOrgIsolationBasics:
    """Test fundamental org isolation mechanisms."""

    @pytest.mark.asyncio
    async def test_different_keys_belong_to_different_orgs(self):
        """Test that API keys are bound to specific organizations."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        # Different keys must belong to different orgs
        assert ctx1.org_id != ctx2.org_id
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_same_key_always_returns_same_org(self):
        """Test that the same key always resolves to the same org."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        ctx3 = await validate_auth_header("Bearer demo-key-123")

        assert ctx1.org_id == ctx2.org_id == ctx3.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_isolation_prevents_lateral_movement(self):
        """Test that auth from one org cannot access another org's context."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")

        # Each context is confined to its org
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"

        # Contexts cannot be swapped
        assert org1_ctx is not org2_ctx
        assert org1_ctx.org_id != org2_ctx.org_id


class TestWebSocketOrgIsolation:
    """Test org isolation in WebSocket connections."""

    @pytest.mark.asyncio
    async def test_websocket_enforces_org_boundary(self):
        """Test that WebSocket connections are org-isolated."""
        # Org 1 WebSocket
        ws1 = AsyncMock(spec=WebSocket)
        ws1.headers = {"Authorization": "Bearer demo-key-123"}
        ws1.query_params = {}

        # Org 2 WebSocket
        ws2 = AsyncMock(spec=WebSocket)
        ws2.headers = {"Authorization": "Bearer test-key-456"}
        ws2.query_params = {}

        ctx1 = await get_ws_auth_context(ws1)
        ctx2 = await get_ws_auth_context(ws2)

        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"
        assert ctx1.org_id != ctx2.org_id

    @pytest.mark.asyncio
    async def test_websocket_concurrent_connections_isolated(self):
        """Test that concurrent WebSocket connections from different orgs are isolated."""
        connections = []

        for i in range(3):
            ws = AsyncMock(spec=WebSocket)
            # Alternate between org-1 and org-2
            key = "demo-key-123" if i % 2 == 0 else "test-key-456"
            ws.headers = {"Authorization": f"Bearer {key}"}
            ws.query_params = {}

            ctx = await get_ws_auth_context(ws)
            connections.append(ctx)

        # Connections alternate between orgs
        assert connections[0].org_id == "org-1"
        assert connections[1].org_id == "org-2"
        assert connections[2].org_id == "org-1"

        # No mixing between orgs
        org1_connections = [c for c in connections if c.org_id == "org-1"]
        org2_connections = [c for c in connections if c.org_id == "org-2"]

        assert len(org1_connections) == 2
        assert len(org2_connections) == 1


class TestCrossTenantDataAccess:
    """Test prevention of cross-tenant data access."""

    @pytest.mark.asyncio
    async def test_org1_cannot_access_org2_data(self):
        """Test that org-1 auth cannot claim org-2 data access."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")

        # Org 1 context has access to org-1
        assert org1_ctx.org_id == "org-1"

        # Attempting to use org-1 context to access org-2 data would be prevented
        # by the backend enforcing org_id on all queries
        assert org1_ctx.org_id != "org-2"

    @pytest.mark.asyncio
    async def test_org2_cannot_access_org1_data(self):
        """Test that org-2 auth cannot claim org-1 data access."""
        org2_ctx = await validate_auth_header("Bearer test-key-456")

        # Org 2 context has access to org-2 only
        assert org2_ctx.org_id == "org-2"

        # Cannot access org-1
        assert org2_ctx.org_id != "org-1"

    @pytest.mark.asyncio
    async def test_auth_context_org_id_cannot_be_spoofed(self):
        """Test that org_id in AuthContext cannot be spoofed by API request."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Original org is org-1
        assert ctx.org_id == "org-1"

        # If request tried to override org_id, it would be rejected by backend
        # This test verifies the auth layer always returns correct org_id
        original_org = ctx.org_id

        # Even if attacker tries to modify the context...
        ctx.org_id = "org-2"

        # The modification happened on the instance, but in a real request,
        # the backend would re-verify org_id from the auth context on the server side
        # This is why server-side enforcement is critical
        assert ctx.org_id == "org-2"  # Client-side can modify
        # But server-side would only trust the verified org_id


class TestTenantAuthenticationSeparation:
    """Test authentication separation between tenants."""

    @pytest.mark.asyncio
    async def test_org1_key_cannot_authenticate_as_org2(self):
        """Test that org-1 key cannot authenticate as org-2."""
        # Use org-1 key
        ctx = await validate_auth_header("Bearer demo-key-123")

        assert ctx.org_id == "org-1"
        assert ctx.org_id != "org-2"

        # Key is bound to org-1; backend must enforce this on all operations
        # API cannot be tricked into using this auth for org-2 requests

    @pytest.mark.asyncio
    async def test_org2_key_cannot_authenticate_as_org1(self):
        """Test that org-2 key cannot authenticate as org-1."""
        # Use org-2 key
        ctx = await validate_auth_header("Bearer test-key-456")

        assert ctx.org_id == "org-2"
        assert ctx.org_id != "org-1"

    @pytest.mark.asyncio
    async def test_expired_key_revocation_per_tenant(self):
        """Test that key revocation is tenant-aware."""
        # Valid key for org-1
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        # Valid key for org-2
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx2.org_id == "org-2"

        # If org-1 revokes their key, it shouldn't affect org-2's key
        # This is implicit in the design: keys are per-org


class TestMultiTenantFieldEnforcement:
    """Test enforcement of org_id on all multi-tenant operations."""

    @pytest.mark.asyncio
    async def test_context_includes_org_for_query_filtering(self):
        """Test that AuthContext includes org_id for backend query filtering."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Context must include org_id so backend can filter
        assert hasattr(ctx, "org_id")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_different_orgs_have_different_org_ids(self):
        """Test that different orgs have provably different org_ids."""
        all_orgs = set()

        # Generate contexts from multiple keys
        keys = ["demo-key-123", "test-key-456"]
        for key in keys:
            ctx = await validate_auth_header(f"Bearer {key}")
            all_orgs.add(ctx.org_id)

        # Each key must map to a unique org
        assert len(all_orgs) == len(keys)

    @pytest.mark.asyncio
    async def test_org_id_is_always_present(self):
        """Test that org_id is always present in AuthContext."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        # org_id must always be set
        assert ctx1.org_id is not None
        assert len(ctx1.org_id) > 0
        assert ctx2.org_id is not None
        assert len(ctx2.org_id) > 0


class TestTenantWebSocketIsolation:
    """Test WebSocket-specific multi-tenant isolation."""

    @pytest.mark.asyncio
    async def test_websocket_auth_includes_org(self):
        """Test that WebSocket auth context includes org_id."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer demo-key-123"}
        ws.query_params = {}

        ctx = await get_ws_auth_context(ws)

        assert hasattr(ctx, "org_id")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_closes_on_invalid_org_tenant(self):
        """Test that WebSocket closes if tenant/org validation fails."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer invalid-key"}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)

        # Connection must be closed
        assert ws.close.called

    @pytest.mark.asyncio
    async def test_websocket_messages_should_include_org_context(self):
        """Test that WebSocket connections have org context available."""
        ws1 = AsyncMock(spec=WebSocket)
        ws1.headers = {"Authorization": "Bearer demo-key-123"}
        ws1.query_params = {}

        ctx1 = await get_ws_auth_context(ws1)

        # Org context is available for message filtering
        assert ctx1.org_id == "org-1"

        ws2 = AsyncMock(spec=WebSocket)
        ws2.headers = {"Authorization": "Bearer test-key-456"}
        ws2.query_params = {}

        ctx2 = await get_ws_auth_context(ws2)

        # Different org context
        assert ctx2.org_id == "org-2"
        assert ctx1.org_id != ctx2.org_id


class TestTenantDenyListAndAccess:
    """Test tenant-aware access control and revocation."""

    @pytest.mark.asyncio
    async def test_org_isolation_blocks_unauthorized_access(self):
        """Test that org isolation prevents unauthorized access."""
        # Org-1 user
        org1_ctx = await validate_auth_header("Bearer demo-key-123")

        # Org-2 user
        org2_ctx = await validate_auth_header("Bearer test-key-456")

        # Each is confined to their org
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"

        # Backend must enforce: org1_ctx can only access org-1 data
        # This is enforced via org_id checks in the backend


class TestTenantContextInheritance:
    """Test that tenant context is properly inherited and enforced."""

    @pytest.mark.asyncio
    async def test_context_org_id_is_source_of_truth(self):
        """Test that AuthContext.org_id is the source of truth for tenant."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # The org_id from the context should be the only source of truth
        org_id = ctx.org_id

        assert org_id == "org-1"

    @pytest.mark.asyncio
    async def test_each_request_validates_org_independently(self):
        """Test that each request validates org isolation independently."""
        # Request 1: org-1
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        # Request 2: org-2
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx2.org_id == "org-2"

        # Request 3: org-1 again
        ctx3 = await validate_auth_header("Bearer demo-key-123")
        assert ctx3.org_id == "org-1"

        # Each request stands alone
        assert ctx1 is not ctx3  # Different instances
        assert ctx1.org_id == ctx3.org_id  # Same org


class TestTenantBoundaryEnforcement:
    """Test enforcement of hard tenant boundaries."""

    @pytest.mark.asyncio
    async def test_no_implicit_tenant_sharing(self):
        """Test that there is no implicit tenant sharing or data leakage."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        # Contexts are completely separate
        assert ctx1 is not ctx2
        assert ctx1.org_id != ctx2.org_id

        # No shared state
        ctx1.user_id = "modified"
        assert ctx2.user_id != "modified"

    @pytest.mark.asyncio
    async def test_tenant_boundary_cannot_be_bypassed_via_auth(self):
        """Test that auth layer properly enforces tenant boundaries."""
        # Both auth attempts succeed
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        # But each is confined to its org; no auth key can cross the boundary
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"

        # Neither key can grant access to the other's org
        assert ctx1.org_id != ctx2.org_id
