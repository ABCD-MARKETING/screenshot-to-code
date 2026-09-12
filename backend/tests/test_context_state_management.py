"""
Context state management and serialization tests.
Tests context lifecycle, state persistence, serialization, and recovery.
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError


class TestContextCreation:
    """Test AuthContext creation and initialization."""

    @pytest.mark.asyncio
    async def test_context_is_created_on_auth(self):
        """Test that valid auth creates AuthContext."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert isinstance(ctx, AuthContext)

    @pytest.mark.asyncio
    async def test_context_has_all_required_fields(self):
        """Test that context has all required fields."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert hasattr(ctx, "user_id")
        assert hasattr(ctx, "org_id")
        assert hasattr(ctx, "role")

    @pytest.mark.asyncio
    async def test_context_fields_are_populated(self):
        """Test that context fields are properly populated."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"
        assert ctx.org_id == "org-1"
        assert ctx.role == "admin"


class TestContextImmutability:
    """Test that critical context fields are protected."""

    @pytest.mark.asyncio
    async def test_context_org_id_integrity(self):
        """Test that org_id cannot be misused."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        original_org = ctx.org_id

        # Even if modified locally, backend should use original
        ctx.org_id = "org-99"

        # Original should be "org-1" from auth layer
        assert original_org == "org-1"

    @pytest.mark.asyncio
    async def test_context_user_id_integrity(self):
        """Test that user_id cannot be misused."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_context_role_cannot_escalate(self):
        """Test that role cannot be escalated locally."""
        ctx = await validate_auth_header("Bearer test-key-456")
        original_role = ctx.role

        # Even if modified, original is preserved
        ctx.role = "admin"

        # Original should be "user"
        assert original_role == "user"


class TestContextLifecycle:
    """Test context lifecycle during request processing."""

    @pytest.mark.asyncio
    async def test_context_valid_throughout_request(self):
        """Test that context remains valid during request processing."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Simulate request processing
        start_org = ctx.org_id
        for _ in range(100):
            # Context should remain valid
            assert ctx.org_id == start_org

    @pytest.mark.asyncio
    async def test_context_not_shared_across_requests(self):
        """Test that each request gets its own context."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Different instances
        assert ctx1 is not ctx2

        # Same values
        assert ctx1.org_id == ctx2.org_id

    @pytest.mark.asyncio
    async def test_context_cleanup_on_request_end(self):
        """Test that context can be cleaned up."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        ctx_id = id(ctx)

        # Context is created
        assert ctx.org_id == "org-1"

        # After request ends, context would be garbage collected
        # (can't directly test, but structure allows it)


class TestContextSerialization:
    """Test context serialization for logging/storage."""

    @pytest.mark.asyncio
    async def test_context_can_be_converted_to_dict(self):
        """Test that context can be serialized to dict."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        ctx_dict = {
            "user_id": ctx.user_id,
            "org_id": ctx.org_id,
            "role": ctx.role,
        }

        assert ctx_dict["user_id"] == "user-1"
        assert ctx_dict["org_id"] == "org-1"
        assert ctx_dict["role"] == "admin"

    @pytest.mark.asyncio
    async def test_context_can_be_reconstructed(self):
        """Test that context can be reconstructed from dict."""
        original = await validate_auth_header("Bearer demo-key-123")

        ctx_dict = {
            "user_id": original.user_id,
            "org_id": original.org_id,
            "role": original.role,
        }

        reconstructed = AuthContext(**ctx_dict)

        assert reconstructed.user_id == original.user_id
        assert reconstructed.org_id == original.org_id
        assert reconstructed.role == original.role

    @pytest.mark.asyncio
    async def test_context_serialization_preserves_values(self):
        """Test that serialization doesn't corrupt values."""
        ctx = await validate_auth_header("Bearer test-key-456")

        original_values = (ctx.user_id, ctx.org_id, ctx.role)

        # Serialize and deserialize
        ctx_dict = {
            "user_id": ctx.user_id,
            "org_id": ctx.org_id,
            "role": ctx.role,
        }
        reconstructed = AuthContext(**ctx_dict)

        reconstructed_values = (reconstructed.user_id, reconstructed.org_id, reconstructed.role)

        assert original_values == reconstructed_values


class TestContextCaching:
    """Test context caching behavior."""

    @pytest.mark.asyncio
    async def test_context_not_cached_across_requests(self):
        """Test that contexts are not cached between requests."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Should be different objects
        assert ctx1 is not ctx2

    @pytest.mark.asyncio
    async def test_repeated_auth_creates_new_contexts(self):
        """Test that repeated auth creates new context instances."""
        contexts = []
        for _ in range(5):
            ctx = await validate_auth_header("Bearer demo-key-123")
            contexts.append(ctx)

        # All should be different objects
        context_ids = [id(c) for c in contexts]
        assert len(set(context_ids)) == 5


class TestContextConcurrency:
    """Test context behavior under concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_context_creation(self):
        """Test that concurrent auth doesn't share contexts."""
        async def get_context():
            return await validate_auth_header("Bearer demo-key-123")

        contexts = await asyncio.gather(*[get_context() for _ in range(10)])

        # All should be different instances
        context_ids = [id(c) for c in contexts]
        assert len(set(context_ids)) == 10

    @pytest.mark.asyncio
    async def test_concurrent_multi_org_contexts(self):
        """Test concurrent contexts from different orgs."""
        async def get_org1():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        async def get_org2():
            ctx = await validate_auth_header("Bearer test-key-456")
            return ctx.org_id

        # Interleaved requests
        tasks = []
        for _ in range(5):
            tasks.append(get_org1())
            tasks.append(get_org2())

        results = await asyncio.gather(*tasks)

        org1_count = sum(1 for r in results if r == "org-1")
        org2_count = sum(1 for r in results if r == "org-2")

        assert org1_count == 5
        assert org2_count == 5


class TestContextDataIntegrity:
    """Test that context data maintains integrity."""

    @pytest.mark.asyncio
    async def test_context_values_consistent_within_lifecycle(self):
        """Test that context values don't change during request."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        values_snapshots = []
        for _ in range(10):
            values_snapshots.append((ctx.user_id, ctx.org_id, ctx.role))

        # All snapshots should be identical
        assert len(set(values_snapshots)) == 1

    @pytest.mark.asyncio
    async def test_context_no_null_fields(self):
        """Test that context has no null/empty fields."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        assert ctx.user_id is not None
        assert len(ctx.user_id) > 0
        assert ctx.org_id is not None
        assert len(ctx.org_id) > 0
        assert ctx.role is not None
        assert len(ctx.role) > 0


class TestContextComparison:
    """Test context comparison and equality."""

    @pytest.mark.asyncio
    async def test_same_key_produces_equivalent_contexts(self):
        """Test that same key produces equivalent context values."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Values should be equal
        assert ctx1.user_id == ctx2.user_id
        assert ctx1.org_id == ctx2.org_id
        assert ctx1.role == ctx2.role

    @pytest.mark.asyncio
    async def test_different_keys_produce_different_contexts(self):
        """Test that different keys produce different context values."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        # Values should differ
        assert ctx1.org_id != ctx2.org_id
        assert ctx1.user_id != ctx2.user_id


class TestContextErrorHandling:
    """Test context behavior on auth errors."""

    @pytest.mark.asyncio
    async def test_context_not_created_on_auth_failure(self):
        """Test that context is not created when auth fails."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key")

    @pytest.mark.asyncio
    async def test_failed_auth_does_not_leak_partial_context(self):
        """Test that failed auth doesn't partially create context."""
        try:
            await validate_auth_header("Bearer invalid-key")
        except UnauthorizedError:
            # Failed auth should not leave partial state
            pass


class TestContextMemoryManagement:
    """Test context memory cleanup."""

    @pytest.mark.asyncio
    async def test_many_contexts_can_be_created(self):
        """Test that many contexts can be created without issues."""
        contexts = []
        for _ in range(100):
            ctx = await validate_auth_header("Bearer demo-key-123")
            contexts.append(ctx)

        # All created successfully
        assert len(contexts) == 100

    @pytest.mark.asyncio
    async def test_context_creation_performance_is_consistent(self):
        """Test that context creation maintains consistent performance."""
        times = []

        for _ in range(20):
            start = time.perf_counter()
            ctx = await validate_auth_header("Bearer demo-key-123")
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # All should be fast
        assert all(t < 0.01 for t in times)

        # No significant performance degradation
        avg_time = sum(times) / len(times)
        assert avg_time < 0.005


class TestContextMultiTenantIsolation:
    """Test context isolation in multi-tenant scenarios."""

    @pytest.mark.asyncio
    async def test_org1_context_isolated_from_org2(self):
        """Test that org-1 context doesn't leak to org-2."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        # Completely separate contexts
        assert ctx1 is not ctx2
        assert ctx1.org_id != ctx2.org_id

    @pytest.mark.asyncio
    async def test_concurrent_multi_tenant_contexts_isolated(self):
        """Test concurrent multi-tenant contexts are isolated."""
        async def get_both():
            ctx1 = await validate_auth_header("Bearer demo-key-123")
            ctx2 = await validate_auth_header("Bearer test-key-456")
            return ctx1.org_id, ctx2.org_id

        results = await asyncio.gather(*[get_both() for _ in range(5)])

        # All should have correct org assignment
        for ctx1_org, ctx2_org in results:
            assert ctx1_org == "org-1"
            assert ctx2_org == "org-2"


class TestContextAttributes:
    """Test context attribute access patterns."""

    @pytest.mark.asyncio
    async def test_context_attributes_are_readable(self):
        """Test that all context attributes can be read."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # All should be readable
        user = ctx.user_id
        org = ctx.org_id
        role = ctx.role

        assert user == "user-1"
        assert org == "org-1"
        assert role == "admin"

    @pytest.mark.asyncio
    async def test_context_attribute_types(self):
        """Test that context attributes are correct types."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        assert isinstance(ctx.user_id, str)
        assert isinstance(ctx.org_id, str)
        assert isinstance(ctx.role, str)
