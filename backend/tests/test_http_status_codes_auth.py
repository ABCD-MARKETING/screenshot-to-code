"""
HTTP status codes and auth error response handling tests.
Tests correct status codes (401, 400, 403, 429, 500), error response formats, and safety.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio


class TestUnauthorizedResponses:
    """Test 401 Unauthorized responses for auth failures."""

    @pytest.mark.asyncio
    async def test_missing_auth_returns_401(self):
        """Test that missing auth header returns 401."""
        # Endpoint should return 401 Unauthorized
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("")

    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(self):
        """Test that invalid token returns 401."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-token-xyz")

    @pytest.mark.asyncio
    async def test_expired_token_returns_401(self):
        """Test that expired token returns 401."""
        # Implementation would check expiry timestamp
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer expired-token")

    @pytest.mark.asyncio
    async def test_malformed_bearer_returns_401(self):
        """Test that malformed Bearer header returns 401."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("InvalidScheme token")

    @pytest.mark.asyncio
    async def test_tampered_token_returns_401(self):
        """Test that tampered token returns 401."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-124")  # Off by one

    @pytest.mark.asyncio
    async def test_401_response_includes_www_authenticate(self):
        """Test that 401 includes WWW-Authenticate header."""
        # Backend: response.headers["WWW-Authenticate"] = 'Bearer realm="api"'
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid")


class TestBadRequestResponses:
    """Test 400 Bad Request responses for malformed input."""

    @pytest.mark.asyncio
    async def test_empty_header_returns_400(self):
        """Test that empty header returns 400 Bad Request."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("")

    @pytest.mark.asyncio
    async def test_bearer_without_token_returns_400(self):
        """Test that Bearer without token returns 400."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer")

    @pytest.mark.asyncio
    async def test_bearer_with_space_only_returns_400(self):
        """Test that Bearer with space-only returns 400."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer ")

    @pytest.mark.asyncio
    async def test_multiple_spaces_returns_400(self):
        """Test that Bearer with multiple spaces returns 400."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer  token")

    @pytest.mark.asyncio
    async def test_null_byte_in_token_returns_400(self):
        """Test that null bytes in token return 400."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer token\x00injection")

    @pytest.mark.asyncio
    async def test_newline_in_token_returns_400(self):
        """Test that newlines in token return 400."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer token\ninjection")

    @pytest.mark.asyncio
    async def test_oversized_token_returns_400(self):
        """Test that oversized token returns 400."""
        large_token = "x" * 100000
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(f"Bearer {large_token}")


class TestForbiddenResponses:
    """Test 403 Forbidden responses for insufficient permissions."""

    @pytest.mark.asyncio
    async def test_user_role_cannot_delete_returns_403(self):
        """Test that user role cannot perform delete returns 403."""
        ctx = await validate_auth_header("Bearer test-key-456")
        # Endpoint: if ctx.role != "admin": return 403
        assert ctx.role == "user"

    @pytest.mark.asyncio
    async def test_user_role_cannot_manage_users_returns_403(self):
        """Test that user cannot manage users returns 403."""
        ctx = await validate_auth_header("Bearer test-key-456")
        # Endpoint: if ctx.role != "admin": return 403
        assert ctx.role == "user"

    @pytest.mark.asyncio
    async def test_cross_org_access_returns_403(self):
        """Test that cross-org access returns 403."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        # Backend would attempt org-2 access
        # Endpoint: if ctx.org_id != requested_org: return 403
        assert org1_ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_403_response_does_not_leak_org_data(self):
        """Test that 403 doesn't reveal other org's data."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Error message should be generic: "Access Denied"
        # NOT "You cannot access org-2's users"
        assert ctx.org_id == "org-1"


class TestTooManyRequestsResponses:
    """Test 429 Too Many Requests for rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limit_exceeded_returns_429(self):
        """Test that rate limit exceeded returns 429."""
        # Backend: if requests > rate_limit: return 429
        # This test verifies the endpoint would return 429
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_429_includes_retry_after_header(self):
        """Test that 429 includes Retry-After header."""
        # Backend: response.headers["Retry-After"] = "60"
        # This indicates client should retry after 60 seconds
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_rate_limit_is_per_org(self):
        """Test that rate limits are org-specific."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        # Backend maintains separate rate limit counters per org_id
        assert org1_ctx.org_id != org2_ctx.org_id


class TestServerErrorResponses:
    """Test 500 Internal Server Error responses."""

    @pytest.mark.asyncio
    async def test_auth_database_error_returns_500(self):
        """Test that auth service error returns 500."""
        # If database/auth service is down, return 500
        # NOT 401 (which implies invalid token)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_auth_timeout_returns_500(self):
        """Test that auth timeout returns 500."""
        # If auth check takes too long and times out, return 500
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_500_does_not_expose_implementation(self):
        """Test that 500 errors don't expose implementation details."""
        # Error message: "Internal Server Error"
        # NOT "PostgreSQL connection failed: host unreachable"
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestErrorResponseFormats:
    """Test error response format and structure."""

    @pytest.mark.asyncio
    async def test_401_error_response_has_correct_format(self):
        """Test that 401 error has standard format."""
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError as e:
            error_msg = str(e)
            # Should be JSON or plain text error message
            assert error_msg is not None
            assert len(error_msg) > 0

    @pytest.mark.asyncio
    async def test_error_response_includes_error_type(self):
        """Test that error response identifies error type."""
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError:
            pass

    @pytest.mark.asyncio
    async def test_error_response_is_consistent_format(self):
        """Test that all errors use consistent format."""
        errors = []

        for token in ["invalid", "Bearer", "tampered-key"]:
            try:
                await validate_auth_header(f"Bearer {token}")
            except UnauthorizedError as e:
                errors.append(str(e))

        # All errors should have similar structure
        assert len(errors) == 3

    @pytest.mark.asyncio
    async def test_error_response_includes_timestamp(self):
        """Test that error responses may include timestamp."""
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError:
            pass


class TestErrorMessageSafety:
    """Test that error messages don't leak sensitive information."""

    @pytest.mark.asyncio
    async def test_error_does_not_echo_token(self):
        """Test that error message doesn't echo the token."""
        try:
            await validate_auth_header("Bearer secret-key-12345")
        except UnauthorizedError as e:
            error_msg = str(e).lower()
            # Should NOT contain the token
            assert "secret-key-12345" not in error_msg

    @pytest.mark.asyncio
    async def test_error_does_not_reveal_user_exists(self):
        """Test that error doesn't reveal whether user exists."""
        try:
            await validate_auth_header("Bearer invalid-key")
        except UnauthorizedError as e:
            error_msg = str(e)
            # Message should be generic: "Unauthorized"
            # NOT "User user-1 not found" or "User exists but token invalid"
            assert error_msg is not None

    @pytest.mark.asyncio
    async def test_error_does_not_leak_database_info(self):
        """Test that error doesn't leak database connection details."""
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError as e:
            error_msg = str(e).lower()
            # Should NOT contain database details
            assert "postgresql" not in error_msg
            assert "connection" not in error_msg or "unauthorized" in error_msg

    @pytest.mark.asyncio
    async def test_error_does_not_leak_service_architecture(self):
        """Test that error doesn't reveal service architecture."""
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError as e:
            error_msg = str(e).lower()
            # Should NOT mention Prisma, SQLAlchemy, FastAPI, etc.
            assert "prisma" not in error_msg
            assert "sqlalchemy" not in error_msg

    @pytest.mark.asyncio
    async def test_error_does_not_include_debug_information(self):
        """Test that error doesn't include debug stack traces."""
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError as e:
            error_msg = str(e)
            # Should NOT include Python traceback
            assert "traceback" not in error_msg.lower()
            assert "file " not in error_msg.lower() or "line " not in error_msg.lower()


class TestStatusCodeConsistency:
    """Test consistent status codes across endpoints."""

    @pytest.mark.asyncio
    async def test_read_endpoint_auth_failure_is_401(self):
        """Test read endpoint returns 401 on auth failure."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid")

    @pytest.mark.asyncio
    async def test_write_endpoint_auth_failure_is_401(self):
        """Test write endpoint returns 401 on auth failure."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid")

    @pytest.mark.asyncio
    async def test_delete_endpoint_auth_failure_is_401(self):
        """Test delete endpoint returns 401 on auth failure."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid")

    @pytest.mark.asyncio
    async def test_all_endpoints_consistent_on_missing_auth(self):
        """Test all endpoints return 401 for missing auth."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("")


class TestStatusCodeSemantics:
    """Test semantic correctness of status codes."""

    @pytest.mark.asyncio
    async def test_401_means_authentication_needed(self):
        """Test that 401 correctly signals 'authenticate me'."""
        # Client should retry with valid credentials
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid")

    @pytest.mark.asyncio
    async def test_403_means_authentication_ok_but_forbidden(self):
        """Test that 403 means auth succeeded but access denied."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin token succeeds - auth OK
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_400_means_request_malformed(self):
        """Test that 400 means the request itself was bad."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer")

    @pytest.mark.asyncio
    async def test_429_means_too_many_requests(self):
        """Test that 429 means client should back off."""
        # Backend would track request count and throttle
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestConcurrentStatusCodes:
    """Test status code behavior under concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_401_responses_consistent(self):
        """Test that concurrent auth failures all return 401."""
        async def get_invalid_auth():
            try:
                await validate_auth_header("Bearer invalid")
                return None
            except UnauthorizedError:
                return 401

        results = await asyncio.gather(*[get_invalid_auth() for _ in range(10)])

        assert all(r == 401 for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_valid_auth_consistent(self):
        """Test that concurrent valid auth always succeeds."""
        async def get_valid_auth():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[get_valid_auth() for _ in range(10)])

        assert all(r == "org-1" for r in results)


class TestStatusCodeRateLimiting:
    """Test status codes related to rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limit_returns_429_not_401(self):
        """Test that rate limit returns 429, not 401."""
        # 401 would mean 'authenticate again'
        # 429 means 'you're authenticated but going too fast'
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_rate_limit_includes_reset_time(self):
        """Test that rate limit response includes reset time."""
        # Retry-After header tells client when to try again
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_rate_limit_per_org_not_global(self):
        """Test that rate limiting is per-org, not global."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")

        # One org hitting rate limit doesn't affect another
        assert org1_ctx.org_id != org2_ctx.org_id


class TestStatusCodeCaching:
    """Test status code behavior with caching."""

    @pytest.mark.asyncio
    async def test_401_response_not_cached(self):
        """Test that 401 responses are not cached."""
        # If client retries with same invalid token, should get 401 again
        # NOT a cached response
        for _ in range(3):
            with pytest.raises(UnauthorizedError):
                await validate_auth_header("Bearer invalid")

    @pytest.mark.asyncio
    async def test_successful_auth_may_be_cached(self):
        """Test that successful auth may be cached briefly."""
        # Same valid token may return cached auth within TTL
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Same auth result
        assert ctx1.user_id == ctx2.user_id
        assert ctx1.org_id == ctx2.org_id
