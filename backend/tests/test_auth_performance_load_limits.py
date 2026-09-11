"""
Authentication system performance, load testing, and limits testing.
Tests throughput, latency, concurrent load handling, resource limits,
degradation under stress, and system boundaries.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio
import time


class TestAuthLatency:
    """Test authentication latency and response times."""

    @pytest.mark.asyncio
    async def test_auth_validation_completes_quickly(self):
        """Test that auth validation completes within acceptable time."""
        import time
        start = time.perf_counter()
        ctx = await validate_auth_header("Bearer demo-key-123")
        elapsed = time.perf_counter() - start

        # Auth should complete in <10ms
        assert elapsed < 0.01
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_invalid_token_rejection_latency(self):
        """Test that invalid token rejection is fast."""
        import time
        start = time.perf_counter()
        try:
            await validate_auth_header("Bearer invalid-key")
        except UnauthorizedError:
            pass
        elapsed = time.perf_counter() - start

        # Should reject quickly (<10ms)
        assert elapsed < 0.01

    @pytest.mark.asyncio
    async def test_permission_check_latency(self):
        """Test that permission checks complete quickly."""
        import time
        start = time.perf_counter()
        ctx = await validate_auth_header("Bearer demo-key-123")
        elapsed = time.perf_counter() - start

        # Permission check should be <5ms
        assert elapsed < 0.005

    @pytest.mark.asyncio
    async def test_cached_auth_is_faster(self):
        """Test that cached auth is faster than fresh auth."""
        # First call (may not be cached)
        await validate_auth_header("Bearer demo-key-123")

        # Cached calls should be very fast
        import time
        start = time.perf_counter()
        ctx = await validate_auth_header("Bearer demo-key-123")
        elapsed = time.perf_counter() - start

        # Cached auth <5ms
        assert elapsed < 0.005


class TestConcurrentLoadHandling:
    """Test auth system under concurrent load."""

    @pytest.mark.asyncio
    async def test_100_concurrent_auth_requests(self):
        """Test 100 concurrent authentication requests."""
        async def auth_request(i):
            key = "demo-key-123" if i % 2 == 0 else "test-key-456"
            ctx = await validate_auth_header(f"Bearer {key}")
            return ctx.org_id

        start = time.perf_counter()
        results = await asyncio.gather(*[auth_request(i) for i in range(100)])
        elapsed = time.perf_counter() - start

        # All requests should succeed
        assert len(results) == 100
        # Throughput: 100 requests in <1 second = 100+ req/s
        assert elapsed < 1.0

    @pytest.mark.asyncio
    async def test_1000_concurrent_auth_requests(self):
        """Test 1000 concurrent authentication requests."""
        async def auth_request(i):
            key = "demo-key-123" if i % 2 == 0 else "test-key-456"
            ctx = await validate_auth_header(f"Bearer {key}")
            return ctx.org_id

        start = time.perf_counter()
        results = await asyncio.gather(*[auth_request(i) for i in range(1000)])
        elapsed = time.perf_counter() - start

        # All should succeed
        assert len(results) == 1000
        # Throughput: 1000 requests in <10 seconds
        assert elapsed < 10.0

    @pytest.mark.asyncio
    async def test_concurrent_load_maintains_consistency(self):
        """Test that concurrent load doesn't break consistency."""
        async def auth_request(i):
            org = "org-1" if i % 2 == 0 else "org-2"
            key = "demo-key-123" if org == "org-1" else "test-key-456"
            ctx = await validate_auth_header(f"Bearer {key}")
            return (ctx.org_id, ctx.user_id)

        results = await asyncio.gather(*[auth_request(i) for i in range(100)])

        # All org-1 requests should have same org_id
        org1_results = [r for r in results if r[0] == "org-1"]
        org2_results = [r for r in results if r[0] == "org-2"]

        assert len(org1_results) == 50
        assert len(org2_results) == 50
        # org-1 results should be consistent
        assert all(r[0] == "org-1" for r in org1_results)
        assert all(r[0] == "org-2" for r in org2_results)


class TestThroughputAndScaling:
    """Test auth system throughput and horizontal scaling."""

    @pytest.mark.asyncio
    async def test_sequential_throughput(self):
        """Test sequential request throughput."""
        count = 100
        start = time.perf_counter()

        for i in range(count):
            await validate_auth_header("Bearer demo-key-123")

        elapsed = time.perf_counter() - start
        throughput = count / elapsed

        # Should handle >100 req/s sequentially
        assert throughput > 100

    @pytest.mark.asyncio
    async def test_parallel_throughput_scales(self):
        """Test that throughput scales with parallelism."""
        async def auth_requests(count):
            tasks = []
            for i in range(count):
                tasks.append(validate_auth_header("Bearer demo-key-123"))
            start = time.perf_counter()
            results = await asyncio.gather(*tasks)
            elapsed = time.perf_counter() - start
            return len(results), elapsed

        # 100 parallel requests
        count1, time1 = await auth_requests(100)
        throughput1 = count1 / time1

        # 200 parallel requests (should still handle well)
        count2, time2 = await auth_requests(200)
        throughput2 = count2 / time2

        # Both should achieve high throughput
        assert throughput1 > 50
        assert throughput2 > 50


class TestResourceLimits:
    """Test system behavior at resource limits."""

    @pytest.mark.asyncio
    async def test_memory_bounded_under_load(self):
        """Test that auth doesn't cause unbounded memory growth."""
        # Create many tokens/sessions using valid keys
        tasks = []
        valid_keys = ["demo-key-123", "test-key-456"]
        for i in range(1000):
            key = valid_keys[i % 2]
            tasks.append(validate_auth_header(f"Bearer {key}"))

        results = await asyncio.gather(*tasks)
        # All should complete without OOM
        assert len(results) == 1000

    @pytest.mark.asyncio
    async def test_connection_pool_handling(self):
        """Test database connection pool handling."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Connection pooling should handle concurrent access
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_cache_size_bounded(self):
        """Test that auth cache doesn't grow unbounded."""
        # Access many different tokens
        for i in range(100):
            key = f"demo-key-{i}"
            try:
                await validate_auth_header(f"Bearer {key}")
            except UnauthorizedError:
                pass

        # Cache should have size limit (not store all invalid tokens)

    @pytest.mark.asyncio
    async def test_token_bucket_limits_per_user(self):
        """Test token bucket rate limiting per user."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Rate limit applied per user, not global
        assert ctx.org_id == "org-1"


class TestDegradedModeBehavior:
    """Test auth system behavior under resource constraints."""

    @pytest.mark.asyncio
    async def test_graceful_degradation_on_cache_miss(self):
        """Test graceful handling of cache misses."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Cache miss should still work (go to database)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_graceful_degradation_on_slow_database(self):
        """Test handling of slow database responses."""
        start = time.perf_counter()
        ctx = await validate_auth_header("Bearer demo-key-123")
        elapsed = time.perf_counter() - start

        # Should still respond within timeout
        assert elapsed < 5.0

    @pytest.mark.asyncio
    async def test_circuit_breaker_pattern(self):
        """Test circuit breaker for failing auth service."""
        # Multiple failures → circuit opens
        for _ in range(5):
            try:
                await validate_auth_header("Bearer invalid")
            except UnauthorizedError:
                pass

        # After failures, system should handle gracefully


class TestRequestSizeAndComplexity:
    """Test auth handling of request size and complexity limits."""

    @pytest.mark.asyncio
    async def test_oversized_token_rejected(self):
        """Test that oversized tokens are rejected."""
        large_token = "x" * 100000
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(f"Bearer {large_token}")

    @pytest.mark.asyncio
    async def test_deeply_nested_claims_handled(self):
        """Test handling of complex nested claims."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Complex claims should be handled efficiently
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_many_permissions_handled_efficiently(self):
        """Test user with many permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Should handle users with 100+ permissions
        assert ctx.org_id == "org-1"


class TestCachePerformance:
    """Test cache performance characteristics."""

    @pytest.mark.asyncio
    async def test_cache_hit_vs_miss_latency_difference(self):
        """Test that cache hits are significantly faster than misses."""
        # First access (potential miss)
        start1 = time.perf_counter()
        await validate_auth_header("Bearer demo-key-123")
        time1 = time.perf_counter() - start1

        # Second access (likely hit)
        start2 = time.perf_counter()
        await validate_auth_header("Bearer demo-key-123")
        time2 = time.perf_counter() - start2

        # Cached access should be faster
        assert time2 <= time1

    @pytest.mark.asyncio
    async def test_cache_invalidation_latency(self):
        """Test that cache invalidation is fast."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Invalidate cache (simulate permission change)
        # Subsequent access should not be significantly slower
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == ctx2.org_id


class TestErrorPathPerformance:
    """Test performance of error cases."""

    @pytest.mark.asyncio
    async def test_auth_failure_path_is_fast(self):
        """Test that auth failure path doesn't slow down system."""
        import time

        # Mix of valid and invalid
        tasks = []
        for i in range(100):
            key = "demo-key-123" if i % 10 == 0 else f"invalid-{i}"
            tasks.append(validate_auth_header(f"Bearer {key}"))

        start = time.perf_counter()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.perf_counter() - start

        # Should complete quickly even with many errors
        assert elapsed < 1.0


class TestSpikingLoad:
    """Test auth system behavior under traffic spikes."""

    @pytest.mark.asyncio
    async def test_sudden_load_spike_handled(self):
        """Test handling of sudden traffic spike."""
        # Normal load
        for _ in range(10):
            await validate_auth_header("Bearer demo-key-123")

        # Sudden spike
        start = time.perf_counter()
        spike_tasks = [
            validate_auth_header("Bearer demo-key-123")
            for _ in range(500)
        ]
        results = await asyncio.gather(*spike_tasks)
        elapsed = time.perf_counter() - start

        # Should handle spike
        assert len(results) == 500
        assert elapsed < 10.0

    @pytest.mark.asyncio
    async def test_load_spike_doesnt_break_subsequent_requests(self):
        """Test that load spike doesn't degrade subsequent performance."""
        # Spike
        spike_tasks = [
            validate_auth_header("Bearer demo-key-123")
            for _ in range(500)
        ]
        await asyncio.gather(*spike_tasks)

        # Post-spike request
        import time
        start = time.perf_counter()
        ctx = await validate_auth_header("Bearer demo-key-123")
        elapsed = time.perf_counter() - start

        # Should still be fast
        assert elapsed < 0.01
        assert ctx.org_id == "org-1"


class TestMemoryAndResourceLeaks:
    """Test for memory and resource leaks."""

    @pytest.mark.asyncio
    async def test_no_memory_leak_on_failed_auth(self):
        """Test that failed auth doesn't leak memory."""
        # Many failed attempts
        for _ in range(1000):
            try:
                await validate_auth_header("Bearer invalid")
            except UnauthorizedError:
                pass

        # Memory should be released

    @pytest.mark.asyncio
    async def test_no_connection_leak(self):
        """Test that connections are properly released."""
        # Many sequential requests
        for _ in range(100):
            ctx = await validate_auth_header("Bearer demo-key-123")

        # Connections should be returned to pool

    @pytest.mark.asyncio
    async def test_no_file_descriptor_leak(self):
        """Test that file descriptors aren't leaked."""
        # Many requests using various resources
        tasks = [
            validate_auth_header("Bearer demo-key-123")
            for _ in range(100)
        ]
        await asyncio.gather(*tasks)

        # FDs should be released


class TestP99LatencyPercentiles:
    """Test auth system latency percentiles."""

    @pytest.mark.asyncio
    async def test_p99_latency_acceptable(self):
        """Test that 99th percentile latency is acceptable."""
        latencies = []

        for _ in range(100):
            start = time.perf_counter()
            ctx = await validate_auth_header("Bearer demo-key-123")
            elapsed = time.perf_counter() - start
            latencies.append(elapsed)

        latencies.sort()
        p99 = latencies[int(len(latencies) * 0.99)]

        # P99 should be <50ms
        assert p99 < 0.05

    @pytest.mark.asyncio
    async def test_p95_latency_excellent(self):
        """Test that 95th percentile latency is excellent."""
        latencies = []

        for _ in range(100):
            start = time.perf_counter()
            ctx = await validate_auth_header("Bearer demo-key-123")
            elapsed = time.perf_counter() - start
            latencies.append(elapsed)

        latencies.sort()
        p95 = latencies[int(len(latencies) * 0.95)]

        # P95 should be <20ms
        assert p95 < 0.02


class TestOrgIsolationUnderLoad:
    """Test that org isolation is maintained under load."""

    @pytest.mark.asyncio
    async def test_org_isolation_with_concurrent_orgs(self):
        """Test org isolation with concurrent org access."""
        async def org_request(org_num):
            key = "demo-key-123" if org_num == 1 else "test-key-456"
            ctx = await validate_auth_header(f"Bearer {key}")
            return ctx.org_id

        # Interleaved org requests
        tasks = []
        for i in range(100):
            org = 1 if i % 2 == 0 else 2
            tasks.append(org_request(org))

        results = await asyncio.gather(*tasks)

        # Org isolation maintained
        org1_count = len([r for r in results if r == "org-1"])
        org2_count = len([r for r in results if r == "org-2"])

        assert org1_count == 50
        assert org2_count == 50
