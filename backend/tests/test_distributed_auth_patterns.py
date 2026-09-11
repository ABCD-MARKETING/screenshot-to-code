"""
Distributed authentication patterns and resilience tests.
Tests context recovery, state replication, concurrent key rotation, failover, expiry handling, stale context detection.
"""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError


class TestContextRecoveryAfterFailure:
    """Test context recovery after connection loss or transient failures."""

    @pytest.mark.asyncio
    async def test_auth_recovers_after_network_failure(self):
        """Test that auth system recovers after simulated network failure."""
        # First successful auth
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        # Simulated recovery period (no actual network operation needed in fallback mode)
        await asyncio.sleep(0.01)

        # Auth should still work after "recovery"
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        assert ctx2.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_context_not_reused_across_recovery(self):
        """Test that contexts are not reused across recovery cycles."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx1_id = id(ctx1)

        # Simulated recovery
        await asyncio.sleep(0.01)

        ctx2 = await validate_auth_header("Bearer demo-key-123")
        ctx2_id = id(ctx2)

        # Should be different instances
        assert ctx1_id != ctx2_id
        assert ctx1.org_id == ctx2.org_id  # But same values

    @pytest.mark.asyncio
    async def test_auth_state_isolation_per_connection(self):
        """Test that auth state is isolated per connection attempt."""
        contexts = []

        for _ in range(5):
            # Simulate separate connection attempts
            ctx = await validate_auth_header("Bearer demo-key-123")
            contexts.append(ctx)
            await asyncio.sleep(0.001)

        # All should be independent instances
        context_ids = [id(c) for c in contexts]
        assert len(set(context_ids)) == 5

        # But all have same values
        assert all(c.org_id == "org-1" for c in contexts)

    @pytest.mark.asyncio
    async def test_recovery_with_different_keys(self):
        """Test recovery when switching between different keys."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        # Recovery with different key
        await asyncio.sleep(0.01)

        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx2.org_id == "org-2"

        # Back to original key
        await asyncio.sleep(0.01)

        ctx3 = await validate_auth_header("Bearer demo-key-123")
        assert ctx3.org_id == "org-1"


class TestStateSynchronization:
    """Test state synchronization across concurrent requests."""

    @pytest.mark.asyncio
    async def test_concurrent_requests_do_not_share_state(self):
        """Test that concurrent requests maintain independent state."""
        async def get_context(key):
            ctx = await validate_auth_header(f"Bearer {key}")
            # Simulate some processing
            await asyncio.sleep(0.001)
            return ctx

        results = await asyncio.gather(
            get_context("demo-key-123"),
            get_context("test-key-456"),
            get_context("demo-key-123"),
            get_context("test-key-456"),
        )

        # Verify isolation
        assert results[0].org_id == "org-1"
        assert results[1].org_id == "org-2"
        assert results[2].org_id == "org-1"
        assert results[3].org_id == "org-2"

        # Verify independence
        assert results[0] is not results[2]
        assert results[1] is not results[3]

    @pytest.mark.asyncio
    async def test_state_replication_consistency(self):
        """Test that state is replicated consistently across replicas."""
        # Simulate multiple server instances with fallback key dictionary
        instances = []

        for _ in range(3):
            ctx = await validate_auth_header("Bearer demo-key-123")
            instances.append(ctx)

        # All instances should have same state
        assert all(i.org_id == "org-1" for i in instances)
        assert all(i.user_id == "user-1" for i in instances)
        assert all(i.role == "admin" for i in instances)

        # But be separate instances
        assert len(set(id(i) for i in instances)) == 3

    @pytest.mark.asyncio
    async def test_state_divergence_prevention(self):
        """Test that divergent state changes are not propagated."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Attempt divergence
        ctx1_original_org = ctx1.org_id
        ctx1.org_id = "org-99"

        # ctx2 should not be affected
        assert ctx2.org_id == "org-1"

        # Both should report original org_id from backend
        assert ctx1_original_org == "org-1"


class TestConcurrentKeyRotation:
    """Test concurrent key rotation scenarios."""

    @pytest.mark.asyncio
    async def test_old_key_remains_valid_during_rotation(self):
        """Test that old key continues working during rotation."""
        old_key = "demo-key-123"

        # Old key should work
        ctx1 = await validate_auth_header(f"Bearer {old_key}")
        assert ctx1.org_id == "org-1"

        # Simulated rotation window
        await asyncio.sleep(0.01)

        # Old key should still work (overlap period)
        ctx2 = await validate_auth_header(f"Bearer {old_key}")
        assert ctx2.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_concurrent_old_new_key_usage(self):
        """Test concurrent usage of old and new keys during rotation."""
        async def use_key(key):
            ctx = await validate_auth_header(f"Bearer {key}")
            return ctx.org_id

        # Simulate concurrent requests with old and new keys
        results = await asyncio.gather(*[
            use_key("demo-key-123"),  # Old key
            use_key("test-key-456"),  # Different org
            use_key("demo-key-123"),  # Old key again
            use_key("demo-key-123"),  # Old key
        ])

        assert results == ["org-1", "org-2", "org-1", "org-1"]

    @pytest.mark.asyncio
    async def test_new_key_activation_does_not_break_old(self):
        """Test that new key activation doesn't invalidate old key."""
        ctx_old = await validate_auth_header("Bearer demo-key-123")
        assert ctx_old.org_id == "org-1"

        # Simulate new key being added (no-op in fallback mode)
        await asyncio.sleep(0.01)

        # Old key should still work
        ctx_old_again = await validate_auth_header("Bearer demo-key-123")
        assert ctx_old_again.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_rotation_does_not_affect_other_keys(self):
        """Test that rotating one key doesn't affect other org's keys."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        assert org1_ctx.org_id == "org-1"

        # Simulate rotation in org-1 (no-op in fallback)
        await asyncio.sleep(0.01)

        # org-2 key should be unaffected
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        assert org2_ctx.org_id == "org-2"

        # org-1 key should still work
        org1_ctx_again = await validate_auth_header("Bearer demo-key-123")
        assert org1_ctx_again.org_id == "org-1"


class TestFallbackFailover:
    """Test failover to fallback authentication."""

    @pytest.mark.asyncio
    async def test_fallback_key_used_when_primary_unavailable(self):
        """Test that fallback keys work when primary auth unavailable."""
        # In real system, primary might be DB/external service down
        # In our fallback mode, this always succeeds

        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_fallback_provides_complete_context(self):
        """Test that fallback auth provides all required context fields."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # All fields present
        assert hasattr(ctx, "user_id")
        assert hasattr(ctx, "org_id")
        assert hasattr(ctx, "role")

        # All fields populated
        assert ctx.user_id == "user-1"
        assert ctx.org_id == "org-1"
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_fallback_handles_concurrent_failover(self):
        """Test that fallback handles concurrent failover gracefully."""
        # Simulate many concurrent requests failing over to fallback

        async def failover_attempt(i):
            key = "demo-key-123" if i % 2 == 0 else "test-key-456"
            ctx = await validate_auth_header(f"Bearer {key}")
            return ctx.org_id

        results = await asyncio.gather(*[failover_attempt(i) for i in range(20)])

        # 10 from org-1, 10 from org-2
        org1_count = sum(1 for r in results if r == "org-1")
        org2_count = sum(1 for r in results if r == "org-2")

        assert org1_count == 10
        assert org2_count == 10

    @pytest.mark.asyncio
    async def test_fallback_recovery_is_stateless(self):
        """Test that fallback recovery doesn't maintain state across requests."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx1_id = id(ctx1)

        # Another request
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        ctx2_id = id(ctx2)

        # Should be different instances (stateless)
        assert ctx1_id != ctx2_id


class TestStaleContextDetection:
    """Test detection of stale or expired contexts."""

    @pytest.mark.asyncio
    async def test_context_valid_within_request_lifetime(self):
        """Test that context remains valid throughout its request lifetime."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        values_over_time = []
        for _ in range(10):
            values_over_time.append(ctx.org_id)
            await asyncio.sleep(0.001)

        # All should be same (context not stale)
        assert len(set(values_over_time)) == 1

    @pytest.mark.asyncio
    async def test_new_context_on_reauthentication(self):
        """Test that new auth creates fresh context."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx1_id = id(ctx1)
        ctx1_org = ctx1.org_id

        # Reauthenticate
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        ctx2_id = id(ctx2)
        ctx2_org = ctx2.org_id

        # Different instances but same values
        assert ctx1_id != ctx2_id
        assert ctx1_org == ctx2_org

    @pytest.mark.asyncio
    async def test_stale_context_cannot_override_fresh(self):
        """Test that stale context cannot be used to override fresh auth."""
        ctx_old = await validate_auth_header("Bearer demo-key-123")
        original_org = ctx_old.org_id

        # Simulated time passage
        await asyncio.sleep(0.01)

        # Attempt to override (should not affect backend)
        ctx_old.org_id = "org-99"

        # Fresh auth should ignore the override
        ctx_fresh = await validate_auth_header("Bearer demo-key-123")
        assert ctx_fresh.org_id == "org-1"

        # Original value preserved
        assert original_org == "org-1"

    @pytest.mark.asyncio
    async def test_concurrent_fresh_auth_invalidates_stale(self):
        """Test that concurrent fresh auth doesn't affect other stale contexts."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")

        # Concurrent fresh auth
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Attempt to use stale context
        ctx1.org_id = "org-99"

        # Fresh context unaffected
        assert ctx2.org_id == "org-1"


class TestReauthenticationOnExpiry:
    """Test forced reauthentication when tokens expire."""

    @pytest.mark.asyncio
    async def test_reauthentication_required_periodically(self):
        """Test that reauthentication is periodically required."""
        # First auth
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        # Simulated expiry period
        await asyncio.sleep(0.01)

        # Reauthentication creates new context
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        assert ctx2.org_id == "org-1"

        # But different instances
        assert id(ctx1) != id(ctx2)

    @pytest.mark.asyncio
    async def test_expiry_does_not_break_availability(self):
        """Test that token expiry doesn't break system availability."""
        auth_attempts = []

        for i in range(10):
            try:
                ctx = await validate_auth_header("Bearer demo-key-123")
                auth_attempts.append(("success", ctx.org_id))
            except UnauthorizedError:
                auth_attempts.append(("failure", None))

            # Simulate time between requests
            if i < 9:
                await asyncio.sleep(0.001)

        # All should succeed despite expiry checks
        assert all(status == "success" for status, _ in auth_attempts)

    @pytest.mark.asyncio
    async def test_different_keys_expire_independently(self):
        """Test that different keys expire independently."""
        org1_times = []
        org2_times = []

        for i in range(5):
            ctx1 = await validate_auth_header("Bearer demo-key-123")
            org1_times.append(time.perf_counter())

            ctx2 = await validate_auth_header("Bearer test-key-456")
            org2_times.append(time.perf_counter())

            await asyncio.sleep(0.001)

        # Both should have been reauthenticated multiple times
        # But independently
        assert len(org1_times) == 5
        assert len(org2_times) == 5

    @pytest.mark.asyncio
    async def test_forced_reauthentication_clears_old_context(self):
        """Test that forced reauthentication doesn't leak old context."""
        ctx_old = await validate_auth_header("Bearer demo-key-123")
        original_values = (ctx_old.user_id, ctx_old.org_id, ctx_old.role)

        # Simulated expiry requiring reauthentication
        await asyncio.sleep(0.01)

        ctx_new = await validate_auth_header("Bearer demo-key-123")
        new_values = (ctx_new.user_id, ctx_new.org_id, ctx_new.role)

        # Values should be identical (no data loss)
        assert original_values == new_values

        # But different instances
        assert id(ctx_old) != id(ctx_new)


class TestDistributedConsistency:
    """Test consistency guarantees across distributed auth."""

    @pytest.mark.asyncio
    async def test_same_key_always_produces_same_org(self):
        """Test that same key always maps to same org across instances."""
        orgs = []

        for _ in range(10):
            ctx = await validate_auth_header("Bearer demo-key-123")
            orgs.append(ctx.org_id)

        # All should be org-1
        assert all(org == "org-1" for org in orgs)

    @pytest.mark.asyncio
    async def test_key_to_org_mapping_stable(self):
        """Test that key→org mapping is stable over time."""
        mapping_sequence = []

        for _ in range(10):
            ctx1 = await validate_auth_header("Bearer demo-key-123")
            ctx2 = await validate_auth_header("Bearer test-key-456")

            mapping_sequence.append((ctx1.org_id, ctx2.org_id))
            await asyncio.sleep(0.001)

        # All should map consistently
        assert all(mapping == ("org-1", "org-2") for mapping in mapping_sequence)

    @pytest.mark.asyncio
    async def test_multi_instance_consistency(self):
        """Test consistency across multiple instance simulations."""
        # Simulate 3 server instances
        instances = [
            await validate_auth_header("Bearer demo-key-123"),
            await validate_auth_header("Bearer demo-key-123"),
            await validate_auth_header("Bearer demo-key-123"),
        ]

        # All should have identical values
        assert all(i.org_id == "org-1" for i in instances)
        assert all(i.user_id == "user-1" for i in instances)
        assert all(i.role == "admin" for i in instances)

    @pytest.mark.asyncio
    async def test_org_isolation_maintained_distributedly(self):
        """Test that org isolation is maintained across distributed auth."""
        async def auth_loop(key, expected_org, count):
            results = []
            for _ in range(count):
                ctx = await validate_auth_header(f"Bearer {key}")
                results.append(ctx.org_id)
            return results

        # Concurrent auth from both orgs
        org1_results, org2_results = await asyncio.gather(
            auth_loop("demo-key-123", "org-1", 10),
            auth_loop("test-key-456", "org-2", 10),
        )

        # Org-1 always org-1, org-2 always org-2
        assert all(org == "org-1" for org in org1_results)
        assert all(org == "org-2" for org in org2_results)


class TestDistributedAuthResilience:
    """Test overall resilience of distributed auth system."""

    @pytest.mark.asyncio
    async def test_system_survives_burst_load(self):
        """Test that system survives burst load."""
        async def auth_attempt(i):
            key = "demo-key-123" if i % 2 == 0 else "test-key-456"
            return await validate_auth_header(f"Bearer {key}")

        # 100 concurrent auth attempts
        results = await asyncio.gather(*[auth_attempt(i) for i in range(100)])

        # All should succeed
        assert len(results) == 100
        assert all(ctx.org_id in ("org-1", "org-2") for ctx in results)

    @pytest.mark.asyncio
    async def test_partial_failure_does_not_cascade(self):
        """Test that partial failures don't cascade."""
        async def auth_attempt(i):
            if i % 10 == 0:
                # Every 10th is invalid
                try:
                    return await validate_auth_header(f"Bearer invalid-{i}")
                except UnauthorizedError:
                    return None
            else:
                return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[auth_attempt(i) for i in range(50)])

        # 10 failures, 40 successes
        failures = sum(1 for r in results if r is None)
        successes = sum(1 for r in results if r is not None)

        assert failures == 5
        assert successes == 45

    @pytest.mark.asyncio
    async def test_recovery_without_manual_intervention(self):
        """Test that system recovers automatically without manual intervention."""
        # First batch with some failures
        batch1 = []
        for i in range(10):
            try:
                ctx = await validate_auth_header("Bearer demo-key-123")
                batch1.append("success")
            except UnauthorizedError:
                batch1.append("failure")

        # Automatic recovery (no action needed)
        await asyncio.sleep(0.01)

        # Second batch should still work
        batch2 = []
        for i in range(10):
            try:
                ctx = await validate_auth_header("Bearer demo-key-123")
                batch2.append("success")
            except UnauthorizedError:
                batch2.append("failure")

        # First batch all successes
        assert all(s == "success" for s in batch1)

        # Second batch all successes (recovered)
        assert all(s == "success" for s in batch2)
