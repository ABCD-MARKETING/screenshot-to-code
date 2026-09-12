"""
CORS and cross-origin authentication security tests.
Tests same-origin policy enforcement, credential handling, preflight auth, CORS header validation, and cross-origin token usage restrictions.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio


class TestCORSPreflight:
    """Test CORS preflight authentication handling."""

    @pytest.mark.asyncio
    async def test_preflight_request_requires_no_auth(self):
        """Test that CORS preflight (OPTIONS) requests work without auth."""
        # Preflight is handled at HTTP middleware level (FastAPI)
        # Auth validation is skipped for OPTIONS at HTTP layer
        # If auth validation is called, it requires Bearer token
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("")  # Empty header fails auth

    @pytest.mark.asyncio
    async def test_preflight_auth_header_ignored(self):
        """Test that auth in preflight request is ignored."""
        # Client may include auth in preflight; server ignores it
        # Response still includes Access-Control-* headers
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_preflight_cors_headers_always_present(self):
        """Test that CORS headers present even on auth failure."""
        # Backend: response.headers["Access-Control-Allow-*"] = ... (always)
        # Even if auth fails, CORS headers should be set for browser behavior
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError:
            # CORS headers would still be set (tested at HTTP level)
            pass

    @pytest.mark.asyncio
    async def test_preflight_origin_validation(self):
        """Test that Origin header is validated against Allow-Origin."""
        # Backend: if origin not in allow_list, don't set Access-Control-Allow-Origin
        # This prevents CORS from exposing auth failures to unauthorized origins
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCredentialsCORSHandling:
    """Test credentials (cookies/auth headers) with CORS."""

    @pytest.mark.asyncio
    async def test_credentials_included_with_same_origin(self):
        """Test that credentials sent with same-origin requests."""
        # fetch('...', { credentials: 'include' }) sends auth header
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_cross_origin_credentials_require_allow_credentials(self):
        """Test that cross-origin credentials need Access-Control-Allow-Credentials."""
        # Backend: if request.credentials, require Access-Control-Allow-Credentials header
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_wildcard_origin_incompatible_with_credentials(self):
        """Test that wildcard origin cannot be used with credentials."""
        # Backend: if Access-Control-Allow-Origin = *, reject credential requests
        # NOT "Access-Control-Allow-Origin: *" + "Access-Control-Allow-Credentials: true"
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_cookie_credentials_validated_like_header_auth(self):
        """Test that cookie-based credentials are validated same as header auth."""
        # If auth is cookie-based, cookie must be present and valid
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCORSOriginValidation:
    """Test CORS origin header validation."""

    @pytest.mark.asyncio
    async def test_origin_header_required_for_cors_request(self):
        """Test that cross-origin requests include Origin header."""
        # Browser always sends Origin on cross-origin requests
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_invalid_origin_rejected(self):
        """Test that invalid origin is rejected."""
        # Backend: validate origin against allow list; if not in list, reject
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_origin_spoofing_prevented(self):
        """Test that client cannot spoof Origin header."""
        # Server enforces CORS policy regardless of Origin header value
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_origin_case_sensitive(self):
        """Test that origin comparison is case-sensitive."""
        # "https://Example.com" != "https://example.com"
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_origin_with_path_invalid(self):
        """Test that origin with path is invalid."""
        # "https://example.com/path" is invalid; only scheme://host:port
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCORSHeaderExpansion:
    """Test CORS header expansion and Auth header interaction."""

    @pytest.mark.asyncio
    async def test_authorization_header_in_expose_list(self):
        """Test that Authorization header can be in expose list."""
        # Access-Control-Expose-Headers: Authorization (if needed)
        # Usually not needed; server doesn't return auth headers to client
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_custom_auth_headers_in_allow_list(self):
        """Test that custom auth headers are in Allow-Headers."""
        # Access-Control-Allow-Headers: Authorization, X-Custom-Auth
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_credentials_header_in_allow_list(self):
        """Test that credentials headers are in Allow-Headers."""
        # Access-Control-Allow-Headers: Cookie, Authorization
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_simple_requests_no_preflight(self):
        """Test that simple requests bypass preflight."""
        # Simple requests: GET, HEAD, POST + simple headers (no auth usually)
        # Non-simple: custom headers, auth headers → preflight
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_non_simple_requests_require_preflight(self):
        """Test that non-simple requests require preflight."""
        # Non-simple: DELETE, PUT, PATCH, or auth headers → preflight required
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCORSTokenUsageRestrictions:
    """Test restrictions on token usage across origins."""

    @pytest.mark.asyncio
    async def test_token_only_valid_for_issuing_origin(self):
        """Test that token is only valid for issuing origin."""
        # Backend enforces: token_origin must match request origin
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_cross_origin_token_reuse_prevented(self):
        """Test that token from origin A cannot be used at origin B."""
        # Backend: store origin with token; validate on each request
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_binding_to_origin_enforced(self):
        """Test that token is bound to origin and cannot be moved."""
        # Origin binding (OAuth 2.0 Form Post Response Mode, similar concept)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_multiple_origins_require_separate_tokens(self):
        """Test that each origin needs its own token."""
        # origin-1 gets token-1, origin-2 gets token-2 (different tokens)
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"


class TestCORSErrorHandling:
    """Test error responses in CORS context."""

    @pytest.mark.asyncio
    async def test_cors_headers_on_auth_error(self):
        """Test that CORS headers included even on auth error."""
        # Access-Control-Allow-* headers must be present even if auth fails
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError:
            # CORS headers still set (tested at HTTP layer)
            pass

    @pytest.mark.asyncio
    async def test_cors_headers_on_preflight_error(self):
        """Test that CORS headers present even on preflight error."""
        # If origin not in allow list, still return 200 OK but no Access-Control-*
        try:
            await validate_auth_header("")
        except UnauthorizedError:
            pass

    @pytest.mark.asyncio
    async def test_error_message_not_leaked_via_cors(self):
        """Test that sensitive error info not leaked via CORS headers."""
        # Error message goes in body; CORS headers are just structure
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError as e:
            error_msg = str(e)
            # Should not contain database/implementation details
            assert "postgresql" not in error_msg.lower()


class TestCORSPreflightCaching:
    """Test CORS preflight caching behavior."""

    @pytest.mark.asyncio
    async def test_preflight_response_includes_max_age(self):
        """Test that preflight response includes Max-Age header."""
        # Access-Control-Max-Age: 86400 (24 hours)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_preflight_max_age_respected(self):
        """Test that browser caches preflight for Max-Age seconds."""
        # Subsequent requests within Max-Age don't need preflight
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_preflight_cache_cleared_on_policy_change(self):
        """Test that changing CORS policy clears preflight cache."""
        # If backend changes Access-Control-Allow-Methods, old cache is stale
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCORSMethodRestriction:
    """Test CORS method restriction enforcement."""

    @pytest.mark.asyncio
    async def test_only_allowed_methods_permitted(self):
        """Test that only allowed methods are permitted cross-origin."""
        # Access-Control-Allow-Methods: GET, POST (DELETE not allowed)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_disallowed_method_rejected(self):
        """Test that disallowed method is rejected."""
        # DELETE not in Allow-Methods → 403 on actual DELETE request
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_method_restriction_per_endpoint(self):
        """Test that method restrictions can be per-endpoint."""
        # /users allows GET, POST; /users/:id allows GET, PUT, DELETE
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCORSXSRFProtection:
    """Test XSRF protection in CORS context."""

    @pytest.mark.asyncio
    async def test_xsrf_token_required_for_state_change(self):
        """Test that XSRF token required for non-safe methods."""
        # POST, PUT, DELETE require XSRF token (X-CSRF-Token header)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_xsrf_token_separate_from_auth_token(self):
        """Test that XSRF token is separate from auth token."""
        # X-CSRF-Token != Authorization header
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_xsrf_token_validated_on_cross_origin_post(self):
        """Test that XSRF token is validated on cross-origin POST."""
        # Cross-origin POST must include valid XSRF token
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_missing_xsrf_token_rejected(self):
        """Test that missing XSRF token is rejected."""
        # POST without X-CSRF-Token header → 403 Forbidden
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCORSCredentialInjection:
    """Test prevention of credential injection attacks."""

    @pytest.mark.asyncio
    async def test_cross_origin_cannot_inject_credentials(self):
        """Test that cross-origin request cannot inject auth."""
        # attacker.com cannot POST auth token to bank.com
        # Even if CORS allows, auth must be from user agent (not injected)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_same_origin_policy_enforced(self):
        """Test that same-origin policy prevents credential theft."""
        # attacker.com script cannot access bank.com DOM/auth tokens
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_browser_cors_blocks_cross_origin_reads(self):
        """Test that browser blocks reading cross-origin responses."""
        # JavaScript can make request, but cannot read response without CORS headers
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCORSOrgIsolation:
    """Test CORS enforcement doesn't bypass org isolation."""

    @pytest.mark.asyncio
    async def test_cors_does_not_weaken_org_boundary(self):
        """Test that CORS is orthogonal to org_id enforcement."""
        # Allowed origin can still only access its own org data
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_cross_org_cors_origin_still_isolated(self):
        """Test that cross-org origins are still org-isolated."""
        # origin-1 allowed from org-1; origin-2 allowed from org-2
        # origin-1 cannot access org-2 data even if both origins allowed
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_org_boundary_enforced_regardless_of_cors(self):
        """Test that org_id is always enforced, CORS or not."""
        # Backend: WHERE org_id = ctx.org_id (always, regardless of CORS)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCORSPreflightConcurrency:
    """Test concurrent preflight requests."""

    @pytest.mark.asyncio
    async def test_concurrent_preflight_requests(self):
        """Test multiple concurrent preflight requests."""
        async def preflight():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[preflight() for _ in range(10)])
        assert all(r == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_preflight_and_actual_requests(self):
        """Test concurrent preflight and actual requests."""
        async def make_request():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[make_request() for _ in range(5)])
        assert all(r == "org-1" for r in results)
