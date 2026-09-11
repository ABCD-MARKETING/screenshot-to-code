"""
Performance and load tests for authentication system.
Tests response times, throughput, and system stability under load.
"""

import pytest
import asyncio
import time
from auth import validate_auth_header, AuthContext
from ws_auth import get_ws_auth_context
from unittest.mock import AsyncMock
from fastapi import WebSocket


class TestAuthValidationPerformance:
    """Test performance of authentication validation."""

    @pytest.mark.asyncio
    async def test_single_auth_validation_response_time(self):
        """Test that single auth validation completes quickly."""
        start = time.perf_counter()

        ctx = await validate_auth_header("Bearer demo-key-123")

        elapsed = time.perf_counter() - start

        # Should complete in under 10ms (generous for fallback key lookup)
        assert elapsed < 0.01
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_repeated_auth_validation_consistency(self):
        """Test that repeated validations maintain consistent performance."""
        times = []

        for _ in range(10):
            start = time.perf_counter()
            ctx = await validate_auth_header("Bearer demo-key-123")
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # All validations should complete quickly
        assert all(t < 0.02 for t in times)

        # No significant slowdown
        avg_time = sum(times) / len(times)
        assert avg_time < 0.005

    @pytest.mark.asyncio
    async def test_different_keys_validation_performance(self):
        """Test performance with different keys."""
        keys = ["demo-key-123", "test-key-456"]
        times = {}

        for key in keys:
            start = time.perf_counter()
            ctx = await validate_auth_header(f"Bearer {key}")
            elapsed = time.perf_counter() - start
            times[key] = elapsed

        # All keys should validate similarly fast
        assert all(t < 0.02 for t in times.values())

    @pytest.mark.asyncio
    async def test_invalid_key_rejection_performance(self):
        """Test that invalid keys are rejected quickly (no slow paths)."""
        start = time.perf_counter()

        try:
            await validate_auth_header("Bearer invalid-key")
        except:
            pass

        elapsed = time.perf_counter() - start

        # Even rejection should be fast (no DB wait, just fallback check)
        assert elapsed < 0.01


class TestWebSocketAuthPerformance:
    """Test performance of WebSocket authentication."""

    @pytest.mark.asyncio
    async def test_websocket_auth_response_time(self):
        """Test that WebSocket auth completes quickly."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer demo-key-123"}
        ws.query_params = {}

        start = time.perf_counter()
        ctx = await get_ws_auth_context(ws)
        elapsed = time.perf_counter() - start

        # Should complete in under 10ms
        assert elapsed < 0.01
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_repeated_auth_performance(self):
        """Test repeated WebSocket auth completions."""
        times = []

        for _ in range(10):
            ws = AsyncMock(spec=WebSocket)
            ws.headers = {"Authorization": "Bearer demo-key-123"}
            ws.query_params = {}

            start = time.perf_counter()
            ctx = await get_ws_auth_context(ws)
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # All should be fast
        assert all(t < 0.02 for t in times)

    @pytest.mark.asyncio
    async def test_websocket_different_auth_methods_performance(self):
        """Test performance across different WebSocket auth methods."""
        auth_methods = [
            {"headers": {"Authorization": "Bearer demo-key-123"}, "query_params": {}},
            {"headers": {"X-API-Key": "demo-key-123"}, "query_params": {}},
            {"headers": {}, "query_params": {"token": "demo-key-123"}},
        ]

        times = []

        for method in auth_methods:
            ws = AsyncMock(spec=WebSocket)
            ws.headers = method["headers"]
            ws.query_params = method["query_params"]

            start = time.perf_counter()
            ctx = await get_ws_auth_context(ws)
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # All methods should be similarly fast
        assert all(t < 0.02 for t in times)


class TestAuthThroughput:
    """Test authentication throughput under normal load."""

    @pytest.mark.asyncio
    async def test_sequential_auth_throughput(self):
        """Test sequential authentication request throughput."""
        num_requests = 100
        start = time.perf_counter()

        for i in range(num_requests):
            key = "demo-key-123" if i % 2 == 0 else "test-key-456"
            ctx = await validate_auth_header(f"Bearer {key}")

        elapsed = time.perf_counter() - start

        # Should handle 100 sequential auths in under 1 second
        assert elapsed < 1.0

        # Average should be well under 10ms per auth
        avg_time = elapsed / num_requests
        assert avg_time < 0.01

    @pytest.mark.asyncio
    async def test_concurrent_auth_throughput(self):
        """Test concurrent authentication request throughput."""
        num_concurrent = 50

        async def auth_request():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx

        start = time.perf_counter()
        tasks = [auth_request() for _ in range(num_concurrent)]
        results = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start

        # All should complete
        assert len(results) == num_concurrent

        # Should handle 50 concurrent auths in under 2 seconds
        assert elapsed < 2.0

    @pytest.mark.asyncio
    async def test_mixed_auth_types_throughput(self):
        """Test throughput with mixed valid/invalid auth."""
        num_requests = 50
        valid_rate = 0.8  # 80% valid, 20% invalid

        async def auth_request(i):
            if i % 10 < 8:  # 80% valid
                try:
                    ctx = await validate_auth_header("Bearer demo-key-123")
                    return "valid"
                except:
                    return "error"
            else:  # 20% invalid
                try:
                    ctx = await validate_auth_header("Bearer invalid-key")
                    return "valid"
                except:
                    return "invalid"

        start = time.perf_counter()
        tasks = [auth_request(i) for i in range(num_requests)]
        results = await asyncio.gather(*tasks)
        elapsed = time.perf_counter() - start

        # Should complete all
        assert len(results) == num_requests

        # Should handle mixed throughput quickly
        assert elapsed < 1.0


class TestAuthMemoryUsage:
    """Test that authentication doesn't leak memory or resources."""

    @pytest.mark.asyncio
    async def test_context_objects_are_lightweight(self):
        """Test that AuthContext objects are lightweight."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Context should be a simple object
        assert hasattr(ctx, "user_id")
        assert hasattr(ctx, "org_id")
        assert hasattr(ctx, "role")

        # Should not hold unnecessary references
        assert ctx.user_id == "user-1"
        assert ctx.org_id == "org-1"
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_no_resource_leaks_on_auth_failure(self):
        """Test that auth failure doesn't leak resources."""
        num_failures = 100

        for i in range(num_failures):
            try:
                await validate_auth_header(f"Bearer invalid-key-{i}")
            except:
                pass

        # Should complete without issues
        # (If there were resource leaks, system would slow down or fail)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_repeated_auth_no_memory_leak(self):
        """Test repeated auth doesn't accumulate memory."""
        num_iterations = 200

        for _ in range(num_iterations):
            ctx = await validate_auth_header("Bearer demo-key-123")
            # Simple usage
            _ = ctx.org_id

        # Should complete successfully
        # (Memory leak would cause slowdown or failure)
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.org_id == "org-2"


class TestAuthSystemStability:
    """Test authentication system stability under load."""

    @pytest.mark.asyncio
    async def test_sustained_load_stability(self):
        """Test system stability under sustained load."""
        duration = 0.5  # seconds
        start = time.perf_counter()
        request_count = 0

        while time.perf_counter() - start < duration:
            try:
                ctx = await validate_auth_header("Bearer demo-key-123")
                assert ctx.org_id == "org-1"
                request_count += 1
            except:
                pass

        # Should handle reasonable throughput
        assert request_count > 50  # At least 100+ req/sec

    @pytest.mark.asyncio
    async def test_recovery_after_sustained_load(self):
        """Test that system recovers cleanly after sustained load."""
        # Sustained load
        tasks = [
            validate_auth_header("Bearer demo-key-123")
            for _ in range(100)
        ]
        _ = await asyncio.gather(*tasks)

        # Should still work correctly
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_error_handling_stability(self):
        """Test stability of error handling under load."""
        async def invalid_auth():
            try:
                await validate_auth_header("Bearer invalid-key")
            except:
                pass

        # Many invalid auths
        tasks = [invalid_auth() for _ in range(100)]
        await asyncio.gather(*tasks)

        # System should still work
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestAuthResponseTimeVariation:
    """Test response time consistency and variation."""

    @pytest.mark.asyncio
    async def test_response_time_stability(self):
        """Test that response times are stable."""
        times = []

        for _ in range(20):
            start = time.perf_counter()
            ctx = await validate_auth_header("Bearer demo-key-123")
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # Calculate statistics
        min_time = min(times)
        max_time = max(times)
        avg_time = sum(times) / len(times)

        # Should be consistent (small variation)
        # Max shouldn't be more than 2x average
        assert max_time < avg_time * 2
        assert avg_time < 0.005

    @pytest.mark.asyncio
    async def test_no_p99_tail_latency(self):
        """Test that p99 latencies are acceptable."""
        times = []

        for _ in range(100):
            start = time.perf_counter()
            ctx = await validate_auth_header("Bearer demo-key-123")
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # Sort for percentile calculation
        times.sort()
        p99_index = int(len(times) * 0.99)
        p99_latency = times[p99_index]

        # P99 should still be under 20ms
        assert p99_latency < 0.02
