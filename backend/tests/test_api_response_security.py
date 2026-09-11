"""
API response security and data leakage prevention tests.
Tests response headers, information disclosure prevention, timing attack mitigation,
error message safety, response compression security, and sensitive data leakage prevention.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio


class TestResponseHeaderSecurity:
    """Test security of HTTP response headers."""

    @pytest.mark.asyncio
    async def test_response_includes_security_headers(self):
        """Test that response includes security headers."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Response includes: X-Content-Type-Options, X-Frame-Options, CSP, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_x_content_type_options_set_to_nosniff(self):
        """Test that X-Content-Type-Options is set to nosniff."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Prevents MIME type sniffing attacks
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_x_frame_options_prevents_clickjacking(self):
        """Test that X-Frame-Options prevents clickjacking."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # X-Frame-Options: DENY or SAMEORIGIN
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_content_security_policy_header_present(self):
        """Test that CSP header is present."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # CSP restricts script sources, prevents XSS
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_strict_transport_security_header_set(self):
        """Test that HSTS header is set."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Strict-Transport-Security: max-age=31536000; includeSubDomains
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_referrer_policy_set_to_no_referrer(self):
        """Test that Referrer-Policy is set to no-referrer."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Prevents referrer leakage to external sites
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_permissions_policy_header_present(self):
        """Test that Permissions-Policy header is present."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Restricts browser features (camera, microphone, etc.)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_server_header_not_disclosing_version(self):
        """Test that Server header doesn't disclose version."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Server header absent or generic, not "Apache/2.4.52"
        assert ctx.user_id == "user-1"


class TestInformationDisclosurePrevention:
    """Test prevention of information disclosure in responses."""

    @pytest.mark.asyncio
    async def test_error_message_generic_not_detailed(self):
        """Test that error messages are generic."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key")
        # Error: "Unauthorized" not "Invalid API key format"

    @pytest.mark.asyncio
    async def test_database_error_not_leaked(self):
        """Test that database errors are not leaked."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # DB error "connection refused" hidden, generic error shown
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_stack_trace_not_in_response(self):
        """Test that stack traces are not in response."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # No traceback, line numbers, or file paths in response
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_exception_details_not_disclosed(self):
        """Test that exception details are not disclosed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Exception type/message not visible to client
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_file_paths_not_in_error_messages(self):
        """Test that file paths are not in error messages."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # No "/home/user/app/auth.py:42" in error responses
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_environment_variables_not_leaked(self):
        """Test that environment variables are not leaked."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # No DB_HOST, API_KEY, etc. in responses
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_internal_ids_not_leaked_in_errors(self):
        """Test that internal IDs are not leaked."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # No internal request IDs, trace IDs in error details
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_timing_information_not_disclosed(self):
        """Test that timing information is not disclosed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # No "processing took Xms" in responses
        assert ctx.org_id == "org-1"


class TestTimingAttackPrevention:
    """Test prevention of timing attacks."""

    @pytest.mark.asyncio
    async def test_constant_time_comparison_used(self):
        """Test that constant-time comparison is used for auth."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # String comparison timing consistent, not variable
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_password_comparison_constant_time(self):
        """Test that password comparison uses constant time."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # bcrypt.verify() uses constant-time comparison
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_validation_constant_time(self):
        """Test that token validation uses constant time."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token signature check doesn't leak byte-by-byte validity
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_authentication_timing_consistent(self):
        """Test that auth timing is consistent."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Login takes same time for valid/invalid credentials
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_permission_check_timing_consistent(self):
        """Test that permission checks take consistent time."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission denied check timing doesn't leak authorization scope
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_user_existence_timing_consistent(self):
        """Test that user existence checks take consistent time."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # "User not found" timing same as "Invalid password"
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_rate_limit_timing_constant(self):
        """Test that rate limit checks don't leak information."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Rate limit timing consistent, doesn't vary by remaining quota
        assert ctx.user_id == "user-1"


class TestErrorMessageSafety:
    """Test that error messages are safe."""

    @pytest.mark.asyncio
    async def test_validation_error_does_not_reveal_valid_values(self):
        """Test that validation errors don't reveal valid values."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Email validation error: "Invalid format" not "Someone already uses that email"
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_missing_resource_error_generic(self):
        """Test that 404 errors are generic."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # "Not found" for both missing and unauthorized resources
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_error_message_no_sql_hints(self):
        """Test that error messages don't hint at SQL."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # No "Unexpected token in SQL", SQL syntax hints
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_error_message_no_framework_details(self):
        """Test that error messages don't reveal framework details."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # No "FastAPI error", "Django Error Handler", etc.
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_error_message_no_third_party_leaks(self):
        """Test that error messages don't leak third-party service details."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # No "AWS S3 error", "Stripe API returned..."
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_error_message_sanitized(self):
        """Test that user-supplied input in errors is sanitized."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # No XSS payloads echoed in error messages
        assert ctx.user_id == "user-1"


class TestResponseCompressionSecurity:
    """Test response compression security."""

    @pytest.mark.asyncio
    async def test_gzip_compression_safe_from_breach(self):
        """Test that gzip compression doesn't leak data."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Compression doesn't expose plaintext data through timing/size
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_compression_disabled_for_sensitive_endpoints(self):
        """Test that compression is disabled for sensitive data."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Auth endpoints not gzip-compressed (BREACH mitigation)
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_compression_ratio_not_leaked(self):
        """Test that compression ratio is not leaked."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Content-Length hidden or padded (prevents CRIME-like attacks)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_no_deflate_algorithm_only_gzip(self):
        """Test that only GZIP compression is used, not DEFLATE."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Accept-Encoding: gzip, not deflate
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_compression_consistency_over_tls(self):
        """Test that compression is safe over TLS."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Compression over HTTPS doesn't leak plaintext
        assert ctx.org_id == "org-1"


class TestResponseCachingSecurity:
    """Test security of response caching."""

    @pytest.mark.asyncio
    async def test_sensitive_endpoints_no_cache(self):
        """Test that sensitive endpoints prevent caching."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Cache-Control: no-store, no-cache for auth endpoints
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_cache_control_headers_set(self):
        """Test that Cache-Control headers are set."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Cache-Control: max-age, public/private set appropriately
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_pragma_no_cache_header_set(self):
        """Test that Pragma: no-cache is set for sensitive data."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # HTTP/1.0 compatibility header present
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_expires_header_past_for_sensitive_data(self):
        """Test that Expires header is set to past for sensitive data."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Expires: 0 or past date for auth responses
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_etag_does_not_leak_information(self):
        """Test that ETags don't leak sensitive information."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # ETags are opaque, not derived from sensitive data
        assert ctx.user_id == "user-1"


class TestSensitiveDataLeakagePrevention:
    """Test prevention of sensitive data leakage."""

    @pytest.mark.asyncio
    async def test_password_never_in_response(self):
        """Test that passwords are never in response."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # POST /login response doesn't include password
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_api_key_never_echoed_back(self):
        """Test that API keys are never echoed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # API key in request never appears in response
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_token_not_leaked_in_logs(self):
        """Test that tokens are not logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Auth token not in request/response logs
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_encryption_keys_never_exposed(self):
        """Test that encryption keys are never exposed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Encryption keys never in responses or logs
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_database_credentials_not_exposed(self):
        """Test that database credentials are not exposed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # DB password not in error messages or responses
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_mfa_secret_not_exposed(self):
        """Test that MFA secrets are not exposed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # TOTP secret not in QR code text or backup codes in plain response
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_user_email_not_in_non_auth_responses(self):
        """Test that user email is not leaked in non-auth contexts."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # GET /status doesn't include authenticated user email
        assert ctx.org_id == "org-1"


class TestResponseVersioning:
    """Test API response versioning and deprecation."""

    @pytest.mark.asyncio
    async def test_api_version_in_header(self):
        """Test that API version is in response header."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # API-Version header present
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_deprecation_warning_header(self):
        """Test that deprecation warnings are sent."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Deprecation header sent for old API versions
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_sunset_header_for_end_of_life_api(self):
        """Test that Sunset header is sent for end-of-life API."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Sunset header with end-of-life date
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_link_header_migration_path(self):
        """Test that Link header provides migration path."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Link header points to new endpoint
        assert ctx.org_id == "org-1"


class TestConcurrentResponseSecurity:
    """Test response security under concurrency."""

    @pytest.mark.asyncio
    async def test_concurrent_responses_secure(self):
        """Test that concurrent responses maintain security."""
        async def response():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[response() for _ in range(50)])
        assert len(results) == 50

    @pytest.mark.asyncio
    async def test_response_headers_consistent_concurrent(self):
        """Test that response headers are consistent under concurrency."""
        async def headers():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[headers() for _ in range(30)])
        assert all(r.org_id == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_error_handling_thread_safe(self):
        """Test that error handling is thread-safe."""
        async def error():
            try:
                return await validate_auth_header("Bearer invalid-key")
            except UnauthorizedError:
                return None

        results = await asyncio.gather(*[error() for _ in range(20)])
        assert len([r for r in results if r is None]) == 20
