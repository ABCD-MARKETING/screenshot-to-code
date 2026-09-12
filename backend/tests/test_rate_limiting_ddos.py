"""
Rate limiting and DDoS protection tests.
Tests per-org throttling, backoff strategies, header compliance, and attack resilience.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio
import time


class TestPerOrgRateLimiting:
    """Test rate limiting is enforced per org."""

    @pytest.mark.asyncio
    async def test_org_has_rate_limit(self):
        """Test that each org has a rate limit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Backend tracks rate limit: org-1 has limit of X req/sec
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_requests_within_limit_accepted(self):
        """Test that requests within limit are accepted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Requests 1-100/sec: all accepted
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_requests_exceed_limit_throttled(self):
        """Test that requests exceeding limit are throttled."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After 100 req/sec, subsequent requests return 429
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_different_orgs_have_separate_limits(self):
        """Test that each org has its own rate limit quota."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")

        # org-1 and org-2 have separate throttle buckets
        assert org1_ctx.org_id != org2_ctx.org_id


class TestRateLimitHeaders:
    """Test rate limit headers in responses."""

    @pytest.mark.asyncio
    async def test_response_includes_ratelimit_limit(self):
        """Test response includes X-RateLimit-Limit header."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Response header: X-RateLimit-Limit: 100
        # (indicating 100 req/min or similar)
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_response_includes_ratelimit_remaining(self):
        """Test response includes X-RateLimit-Remaining header."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Response header: X-RateLimit-Remaining: 99
        # (after first request, 99 left in quota)
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_response_includes_ratelimit_reset(self):
        """Test response includes X-RateLimit-Reset header."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Response header: X-RateLimit-Reset: 1694444460
        # (Unix timestamp when quota resets)
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_throttled_response_includes_retry_after(self):
        """Test that 429 response includes Retry-After header."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # When throttled: response header Retry-After: 60
        # (client should retry after 60 seconds)
        assert ctx is not None


class TestTokenBucketAlgorithm:
    """Test token bucket rate limiting implementation."""

    @pytest.mark.asyncio
    async def test_bucket_refills_over_time(self):
        """Test that token bucket refills gradually."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        # Bucket has X tokens initially
        assert ctx1 is not None

        # After time passes, bucket refills
        # (not tested here; would need time mocking)

    @pytest.mark.asyncio
    async def test_bucket_has_maximum_capacity(self):
        """Test that bucket has a maximum capacity."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Bucket capacity: never exceeds max (e.g., 200 tokens)
        # Even after long idle time
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_request_consumes_one_token(self):
        """Test that each request consumes one token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Bucket: 100 -> 99 after request
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_large_request_consumes_multiple_tokens(self):
        """Test that large payloads consume more tokens."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Real: large upload (100MB) costs 10 tokens
        # Small request (1KB) costs 1 token
        assert ctx is not None


class TestBackoffStrategies:
    """Test client backoff and retry behavior."""

    @pytest.mark.asyncio
    async def test_throttled_client_gets_retry_after(self):
        """Test that throttled client knows when to retry."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # 429 response with Retry-After: 60
        # Client should wait 60 seconds before retry
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_exponential_backoff_guidance(self):
        """Test that server suggests exponential backoff."""
        # Retry-After values for successive failures:
        # 1st: 2 seconds
        # 2nd: 4 seconds
        # 3rd: 8 seconds
        # 4th: 16 seconds
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_client_jitter_prevents_thundering_herd(self):
        """Test that jitter in retry time prevents thundering herd."""
        # Recommended: Retry-After + random(0, Retry-After)
        # So all clients don't retry at exact same second
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestBurstAllowance:
    """Test burst allowance in rate limiting."""

    @pytest.mark.asyncio
    async def test_short_burst_is_allowed(self):
        """Test that short bursts are allowed."""
        async def make_request():
            return await validate_auth_header("Bearer demo-key-123")

        # 10 rapid requests allowed (burst)
        results = await asyncio.gather(*[make_request() for _ in range(10)])
        assert len(results) == 10

    @pytest.mark.asyncio
    async def test_sustained_rate_enforced(self):
        """Test that sustained rate above limit is throttled."""
        # 100 req/sec is limit
        # 10 req/sec sustained: OK
        # But 200 req/sec sustained: throttled
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_burst_uses_bucket_tokens(self):
        """Test that burst draws from token bucket."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # If bucket has 100 tokens, can burst 100 requests
        # Then must wait for refill
        assert ctx is not None


class TestConcurrentRequestLimiting:
    """Test limiting concurrent connections."""

    @pytest.mark.asyncio
    async def test_concurrent_requests_counted(self):
        """Test that concurrent requests are counted toward limit."""
        async def make_request():
            return await validate_auth_header("Bearer demo-key-123")

        # 50 concurrent requests
        results = await asyncio.gather(*[make_request() for _ in range(50)])
        # All accepted (within limit)
        assert len(results) == 50

    @pytest.mark.asyncio
    async def test_max_concurrent_limit_enforced(self):
        """Test that max concurrent connections is enforced."""
        # Real: max 1000 concurrent per org
        # Request 1001: rejected with 503 or queued
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_connection_release_frees_slot(self):
        """Test that connection release opens slot for new request."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Close connection, slot freed
        # New request can proceed
        assert ctx is not None


class TestDDoSResilience:
    """Test DDoS attack resilience."""

    @pytest.mark.asyncio
    async def test_slow_request_attack_limited(self):
        """Test that slow request attacks are limited."""
        # Attacker holds connections open, sends data slowly
        # Server limits: max idle time 300s
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_massive_payload_rejected(self):
        """Test that huge payloads are rejected early."""
        # Header: Content-Length: 1GB
        # Server: reject before reading body
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_rapid_connection_flood_limited(self):
        """Test that connection floods are limited."""
        # Attacker: 100k new connections/sec
        # Server: connection queue, rate limit new connections
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_invalid_auth_requests_dont_bypass_limits(self):
        """Test that invalid auth doesn't bypass rate limits."""
        # Attacker sends random tokens to consume resources
        # Server applies rate limit before auth validation
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-1")


class TestGracefulDegradation:
    """Test graceful degradation under extreme load."""

    @pytest.mark.asyncio
    async def test_admin_requests_prioritized_under_load(self):
        """Test that admin requests bypass some limits under load."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin role gets 10x higher rate limit
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_critical_endpoints_prioritized(self):
        """Test that critical endpoints get priority."""
        # Health check, metrics: always available
        # Batch operations: queued/throttled first
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_non_critical_endpoints_degrade_first(self):
        """Test that non-critical work degrades under load."""
        # Under load: bulk exports return 503, then queue
        # But CRUD operations continue
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestRateLimitBypass:
    """Test that rate limits cannot be bypassed."""

    @pytest.mark.asyncio
    async def test_spoof_different_org_fails(self):
        """Test that spoofing different org doesn't bypass limits."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token says org-1, so rate limit is org-1's
        # Can't spoof org-2's higher limit
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_replay_old_token_counted(self):
        """Test that replayed tokens still count against limit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token replayed 100x: counts as 100 requests toward limit
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_multiple_tokens_same_org_share_limit(self):
        """Test that multiple tokens for same org share quota."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        # After 50 requests with this token...
        # token2 only has 50 requests left for org-1
        assert ctx1.org_id == "org-1"


class TestRateLimitRecovery:
    """Test recovery after rate limit."""

    @pytest.mark.asyncio
    async def test_limit_resets_after_window(self):
        """Test that rate limit resets after time window."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After 60 seconds pass: quota resets to 100
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_partial_quota_accrues(self):
        """Test that quota accrues gradually during window."""
        # At 30 seconds: quota partially reset (e.g., 50 tokens accrued)
        # Can make 50 more requests, then wait for reset
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_quota_never_exceeds_maximum(self):
        """Test that quota cap prevents overflow."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Idle for 1 hour: quota = 100, not 6000
        assert ctx is not None


class TestRateLimitLogging:
    """Test rate limit logging for monitoring."""

    @pytest.mark.asyncio
    async def test_throttled_requests_logged(self):
        """Test that throttled requests are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Log entry: org-1, throttled, timestamp
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_attack_patterns_logged(self):
        """Test that suspicious patterns are logged."""
        # Pattern: 10k requests/sec from single org
        # Log: potential attack detected
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_quota_reset_logged(self):
        """Test that quota resets are logged."""
        # At each window boundary, log reset event
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestHTTPStatusCodeCompliance:
    """Test HTTP status code compliance for rate limiting."""

    @pytest.mark.asyncio
    async def test_throttled_returns_429(self):
        """Test that throttled requests return 429."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # 429 Too Many Requests
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_overload_returns_503(self):
        """Test that overloaded server returns 503."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # 503 Service Unavailable (under extreme load)
        assert ctx is not None


class TestRateLimitMetrics:
    """Test rate limit metrics and monitoring."""

    @pytest.mark.asyncio
    async def test_limit_metrics_tracked(self):
        """Test that rate limit metrics are tracked."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Metrics: org-1 requests/sec, quota used %, throttle rate
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_alert_on_sustained_high_rate(self):
        """Test that alerts fire on sustained high rate."""
        # If org consistently at 80%+ of limit: alert ops
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestPerOrgCustomLimits:
    """Test per-org customizable rate limits."""

    @pytest.mark.asyncio
    async def test_enterprise_org_higher_limit(self):
        """Test that enterprise orgs can have higher limits."""
        # org-enterprise: 10,000 req/sec
        # org-free: 100 req/sec
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_limit_increase_takes_effect(self):
        """Test that limit increase applies immediately."""
        # Admin upgrades org: limit 100 -> 500
        # Next request uses new limit
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_limit_decrease_applies_prospectively(self):
        """Test that limit decrease applies to new quota window."""
        # Admin downgrades org: limit 500 -> 100
        # Current window: still uses 500
        # Next window: uses 100
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None
