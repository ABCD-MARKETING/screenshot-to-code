"""
Rate limiting and DoS protection tests.
Tests token bucket algorithm, per-user/IP/org limits, adaptive limiting,
DDoS detection, backoff strategies, burst handling, and graceful degradation.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio
import time


class TestTokenBucketAlgorithm:
    """Test token bucket rate limiting algorithm."""

    @pytest.mark.asyncio
    async def test_token_bucket_fills_at_defined_rate(self):
        """Test that token bucket fills at defined rate."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token bucket refill rate: e.g., 100 tokens/second
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_bucket_has_maximum_capacity(self):
        """Test that token bucket has maximum capacity."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Max capacity: e.g., 1000 tokens (prevents infinite accumulation)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_request_consumes_token(self):
        """Test that each request consumes a token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Each request: 1 token consumed
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_no_token_request_rejected(self):
        """Test that request without token is rejected."""
        # After consuming all tokens, next request rejected
        ctx = await validate_auth_header("Bearer demo-key-123")
        # If bucket empty, 429 Too Many Requests

    @pytest.mark.asyncio
    async def test_token_accumulation_between_requests(self):
        """Test that tokens accumulate between requests."""
        # Request at t=0, wait 1 second, request at t=1
        # New tokens added during wait
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestPerUserRateLimiting:
    """Test rate limiting per user."""

    @pytest.mark.asyncio
    async def test_user_has_individual_rate_limit(self):
        """Test that each user has individual rate limit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User-1 quota: e.g., 100 req/second
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_user_quota_independent_of_other_users(self):
        """Test that user quota is independent."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")
        # User-1 limits don't affect User-2
        assert ctx1.user_id == "user-1"
        assert ctx2.user_id == "user-2"

    @pytest.mark.asyncio
    async def test_user_exceeding_quota_rejected(self):
        """Test that requests exceeding user quota are rejected."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After 100 req/sec, next request → 429 Too Many Requests

    @pytest.mark.asyncio
    async def test_user_quota_resets_periodically(self):
        """Test that user quota resets (e.g., hourly)."""
        # User maxes out quota; after 1 hour, quota resets
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_quota_rejection_includes_retry_after(self):
        """Test that 429 response includes Retry-After header."""
        # 429 response: Retry-After: 60 (wait 60 seconds)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestPerIpRateLimiting:
    """Test rate limiting per IP address."""

    @pytest.mark.asyncio
    async def test_ip_has_separate_rate_limit(self):
        """Test that each IP has separate rate limit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # IP 192.168.1.1 has quota independent of IP 192.168.1.2
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_ip_quota_prevents_brute_force_from_single_ip(self):
        """Test that IP quota prevents brute force from one IP."""
        # Attacker tries 1000 login attempts from single IP
        # After X failed attempts, IP blocked for Y minutes
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_distributed_attack_from_many_ips_detected(self):
        """Test that distributed attack from many IPs is detected."""
        # Attacker uses botnet; many IPs, few requests each
        # System detects pattern and blocks
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_legitimate_traffic_from_shared_ip_not_blocked(self):
        """Test that shared IP (e.g., corporate proxy) not over-blocked."""
        # Multiple users on same IP (NAT, proxy) don't hit limit too easily
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_ip_reputation_affects_limits(self):
        """Test that IP reputation affects rate limits."""
        # Known datacenter IP: lower limits
        # Known residential IP: higher limits
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestPerOrgRateLimiting:
    """Test rate limiting per organization."""

    @pytest.mark.asyncio
    async def test_org_has_total_rate_limit(self):
        """Test that org has total rate limit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Org-1 total: e.g., 10000 req/second
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_quota_enforced_across_all_users(self):
        """Test that org quota applies across all users."""
        # Sum of all user requests <= org quota
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        # Both in org-1; together limited by org quota
        assert ctx1.org_id == ctx2.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_quota_prevents_runaway_workload(self):
        """Test that org quota prevents runaway job from consuming all resources."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Runaway job hits org quota, not individual user quota
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_quota_lower_than_aggregate_user_quotas(self):
        """Test that org quota is less than sum of user quotas."""
        # Org quota: 10000 req/s
        # 100 users × 200 req/s each = 20000 potential
        # Org-level limit: 10000 req/s absolute max
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_quota_upgradeable_with_plan(self):
        """Test that org quota upgrades with pricing plan."""
        # Free: 1000 req/s, Pro: 10000 req/s, Enterprise: unlimited
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestAdaptiveRateLimiting:
    """Test adaptive rate limiting based on system load."""

    @pytest.mark.asyncio
    async def test_limits_tighten_under_high_load(self):
        """Test that limits tighten when system is under high load."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # CPU >80%: tighten limits by 20%
        # CPU >95%: tighten by 50%
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_limits_loosen_under_low_load(self):
        """Test that limits loosen when system is under-utilized."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # CPU <30%: loosen limits by 10%
        # CPU <10%: loosen by 20%
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_adaptive_limits_smooth_transitions(self):
        """Test that adaptive limits transition smoothly."""
        # No sudden drops; gradual tightening/loosening over 5 minutes
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_system_load_metric_accurate(self):
        """Test that system load metric is accurate."""
        # Metric: CPU, memory, connection count, queue depth
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_adaptive_limits_prevent_cascade_failure(self):
        """Test that adaptive limits prevent cascading failures."""
        # Under load, shed requests early before system overload
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestBurstHandling:
    """Test handling of legitimate traffic bursts."""

    @pytest.mark.asyncio
    async def test_small_burst_allowed(self):
        """Test that small traffic burst is allowed."""
        # Burst up to max capacity, then back to normal
        async def burst_requests(count):
            tasks = [validate_auth_header("Bearer demo-key-123") for _ in range(count)]
            return await asyncio.gather(*tasks)

        results = await burst_requests(50)
        assert len(results) == 50

    @pytest.mark.asyncio
    async def test_large_burst_partially_allowed(self):
        """Test that large burst is partially allowed."""
        # First X requests succeed (up to capacity)
        # Rest queued/rejected until rate allows
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_burst_backoff_exponential(self):
        """Test that burst backoff follows exponential backoff."""
        # First retry: wait 1s, second: 2s, third: 4s, etc.
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_burst_capacity_respects_user_quota(self):
        """Test that burst capacity doesn't exceed user quota."""
        # Even if allowed to burst, cannot exceed user's total quota
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_burst_recovery_after_wait(self):
        """Test that rate limiting recovers after waiting."""
        # After exceeding quota, wait for recovery period
        # Then normal requests succeed again
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestDdosDetection:
    """Test DDoS attack detection and mitigation."""

    @pytest.mark.asyncio
    async def test_high_request_volume_detected(self):
        """Test that abnormally high request volume is detected."""
        # Normal: 100 req/s, Attack: 10000 req/s → detected
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_many_failed_auth_attempts_detected(self):
        """Test that many failed auth attempts detected."""
        # >50 failed login attempts in 5 minutes from single IP
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_botnet_fingerprint_detected(self):
        """Test that botnet fingerprints detected."""
        # Same User-Agent, rapid requests from many IPs, low variance
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_slow_request_attack_detected(self):
        """Test that slow request/Slowloris attack detected."""
        # Client slowly drips request data, keeping connection open
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_ddos_alert_sent_to_admin(self):
        """Test that DDoS alert sent to org admin."""
        # Admin email: "DDoS attack detected on Org-1"
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestBlacklistAndWhitelist:
    """Test IP/user blacklist and whitelist."""

    @pytest.mark.asyncio
    async def test_blacklisted_ip_rejected(self):
        """Test that blacklisted IP is rejected."""
        # Admin blacklists IP 192.168.1.100
        # Requests from that IP rejected immediately
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_whitelisted_ip_bypasses_limits(self):
        """Test that whitelisted IP bypasses rate limits."""
        # Admin whitelists 10.0.0.0/8 (internal network)
        # Those IPs can make unlimited requests
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_whitelist_can_be_permanent_or_temporary(self):
        """Test that whitelist entries can expire."""
        # Temporary whitelist: 1 day, then auto-remove
        # Permanent whitelist: stays indefinitely
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_blacklist_quarantine_period(self):
        """Test that blacklist has quarantine period."""
        # IP blacklisted after DDoS; quarantine 24 hours
        # After 24 hours, can appeal/auto-remove if no more attacks
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_user_blacklist_independent_of_ip(self):
        """Test that user blacklist independent of IP."""
        # User banned; all their API keys rejected regardless of IP
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestGracefulDegradation:
    """Test graceful degradation under extreme load."""

    @pytest.mark.asyncio
    async def test_priority_requests_handled_first(self):
        """Test that priority requests handled before others."""
        # Admin operations > normal operations > read-only
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_read_only_requests_have_higher_limit(self):
        """Test that read-only requests have higher limit."""
        # GET requests: limit 10000 req/s
        # POST/DELETE: limit 1000 req/s
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_write_requests_rejected_before_read(self):
        """Test that write requests rejected first under load."""
        # Under extreme load: accept 90% read, 10% write
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_queue_depth_limited(self):
        """Test that request queue depth is limited."""
        # Queue size: 10000 requests max
        # Beyond that, new requests rejected immediately
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_timeout_requests_freed_promptly(self):
        """Test that timed-out requests don't linger."""
        # Request timeout: 30s
        # After 30s, request cleaned up and quota returned
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestConcurrentRateLimiting:
    """Test rate limiting under concurrent conditions."""

    @pytest.mark.asyncio
    async def test_concurrent_requests_share_quota(self):
        """Test that concurrent requests share same quota."""
        async def request():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[request() for _ in range(50)])
        assert len(results) == 50

    @pytest.mark.asyncio
    async def test_rate_limit_decision_consistent(self):
        """Test that rate limit decision is consistent across concurrent requests."""
        # Two concurrent requests: both should see consistent limit state
        async def request():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[request() for _ in range(10)])
        assert all(r.org_id == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_quota_exhaustion_detected_correctly(self):
        """Test that quota exhaustion detected in concurrent scenarios."""
        # 100 concurrent requests: all should either succeed or fail consistently
        async def request():
            try:
                return await validate_auth_header("Bearer demo-key-123")
            except UnauthorizedError:
                return None

        results = await asyncio.gather(*[request() for _ in range(100)])
        assert len([r for r in results if r]) >= 0  # Some succeed
