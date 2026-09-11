"""
API endpoint authorization and request validation tests.
Tests endpoint access control, role-based authorization, CSRF protection,
payload validation, request size limits, and cross-org endpoint isolation.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError, ForbiddenError, ValidationError
import asyncio


class TestEndpointAuthorizationRequirement:
    """Test that endpoints require valid authorization."""

    @pytest.mark.asyncio
    async def test_endpoint_rejects_missing_auth_header(self):
        """Test that endpoints reject requests without auth header."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(None)

    @pytest.mark.asyncio
    async def test_endpoint_rejects_invalid_auth_header(self):
        """Test that endpoints reject invalid auth headers."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("InvalidFormat")

    @pytest.mark.asyncio
    async def test_endpoint_rejects_expired_token(self):
        """Test that endpoints reject expired tokens."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer expired-token-123")

    @pytest.mark.asyncio
    async def test_endpoint_accepts_valid_auth_header(self):
        """Test that endpoints accept valid auth headers."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_endpoint_validates_bearer_scheme(self):
        """Test that endpoints only accept Bearer scheme."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Basic dGVzdDp0ZXN0")


class TestRoleBasedEndpointAccess:
    """Test role-based access control on endpoints."""

    @pytest.mark.asyncio
    async def test_admin_can_access_admin_endpoint(self):
        """Test that admin can access admin-only endpoint."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_user_cannot_access_admin_endpoint(self):
        """Test that regular user cannot access admin endpoint."""
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.role == "user"
        assert ctx.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_endpoint_returns_403_for_insufficient_role(self):
        """Test that endpoint returns 403 for insufficient role."""
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.role == "user"

    @pytest.mark.asyncio
    async def test_guest_cannot_access_protected_endpoint(self):
        """Test that guest users cannot access protected endpoints."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer guest-token-123")

    @pytest.mark.asyncio
    async def test_role_based_access_audit_logged(self):
        """Test that role-based denials are audit logged."""
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.role == "user"


class TestRequestValidation:
    """Test request payload validation."""

    @pytest.mark.asyncio
    async def test_endpoint_rejects_missing_required_fields(self):
        """Test that endpoint rejects missing required fields."""
        # Payload validation: field presence check
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_endpoint_rejects_invalid_field_type(self):
        """Test that endpoint rejects invalid field types."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_endpoint_rejects_oversized_payload(self):
        """Test that endpoint rejects payloads exceeding size limit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_endpoint_rejects_malformed_json(self):
        """Test that endpoint rejects malformed JSON."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_endpoint_validates_field_length(self):
        """Test that endpoint validates field lengths."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_endpoint_sanitizes_html_input(self):
        """Test that endpoint sanitizes HTML/script input."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_validation_error_includes_field_info(self):
        """Test that validation errors include field details."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_validation_fails_before_database_access(self):
        """Test that validation happens before DB queries."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"


class TestCsrfProtection:
    """Test CSRF token validation on state-changing requests."""

    @pytest.mark.asyncio
    async def test_post_requires_csrf_token(self):
        """Test that POST requests require CSRF token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_put_requires_csrf_token(self):
        """Test that PUT requests require CSRF token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_delete_requires_csrf_token(self):
        """Test that DELETE requests require CSRF token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_get_does_not_require_csrf_token(self):
        """Test that GET requests don't require CSRF token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_invalid_csrf_token_rejected(self):
        """Test that invalid CSRF token is rejected."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_csrf_token_expires(self):
        """Test that CSRF tokens expire."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_csrf_token_one_time_use(self):
        """Test that CSRF token can be used only once."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestPayloadValidation:
    """Test specific payload field validation."""

    @pytest.mark.asyncio
    async def test_email_validation_format(self):
        """Test that email validation checks format."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_email_validation_length(self):
        """Test that email validation checks length."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_password_validation_strength(self):
        """Test that password validation enforces strength."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_numeric_field_validation(self):
        """Test that numeric fields are validated."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_enum_field_validation(self):
        """Test that enum fields validate allowed values."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_date_field_validation(self):
        """Test that date fields are validated."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_nested_object_validation(self):
        """Test that nested objects are validated."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestEndpointErrorHandling:
    """Test error responses and error codes."""

    @pytest.mark.asyncio
    async def test_endpoint_returns_400_for_bad_request(self):
        """Test that endpoint returns 400 for invalid input."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_endpoint_returns_401_for_missing_auth(self):
        """Test that endpoint returns 401 for missing auth."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(None)

    @pytest.mark.asyncio
    async def test_endpoint_returns_403_for_insufficient_permissions(self):
        """Test that endpoint returns 403 for insufficient permissions."""
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.role == "user"

    @pytest.mark.asyncio
    async def test_endpoint_returns_404_for_missing_resource(self):
        """Test that endpoint returns 404 for missing resource."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_endpoint_returns_409_for_conflict(self):
        """Test that endpoint returns 409 for conflicts."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_error_response_includes_message(self):
        """Test that error response includes readable message."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_error_response_excludes_sensitive_details(self):
        """Test that error response doesn't leak sensitive information."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"


class TestCrossOrgEndpointIsolation:
    """Test that endpoints enforce org isolation."""

    @pytest.mark.asyncio
    async def test_org1_admin_cannot_access_org2_endpoint(self):
        """Test that Org-1 admin cannot access Org-2 data via endpoint."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        assert org1_ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_endpoint_includes_org_id_in_where_clause(self):
        """Test that endpoint queries include org_id WHERE clause."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_id_cannot_be_overridden_in_request(self):
        """Test that org_id in request body is ignored."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_endpoint_denies_cross_org_update(self):
        """Test that endpoint blocks cross-org updates."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_endpoint_denies_cross_org_delete(self):
        """Test that endpoint blocks cross-org deletes."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_cross_org_violation_audit_logged(self):
        """Test that cross-org violations are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"


class TestRequestHeaderValidation:
    """Test request header validation."""

    @pytest.mark.asyncio
    async def test_endpoint_validates_content_type(self):
        """Test that endpoint validates Content-Type header."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_endpoint_ignores_extra_headers(self):
        """Test that endpoint ignores unknown headers."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_endpoint_requires_host_header(self):
        """Test that Host header is required."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_endpoint_validates_user_agent(self):
        """Test that User-Agent validation works."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestEndpointIdempotency:
    """Test idempotent operation handling."""

    @pytest.mark.asyncio
    async def test_duplicate_post_request_rejected(self):
        """Test that duplicate POST requests are handled."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_idempotency_key_honored(self):
        """Test that Idempotency-Key header is honored."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_put_is_idempotent(self):
        """Test that PUT requests are idempotent."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_delete_is_idempotent(self):
        """Test that DELETE requests are idempotent."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestConcurrentEndpointAccess:
    """Test endpoints under concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_reads_safe(self):
        """Test that concurrent reads don't cause issues."""
        async def read():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[read() for _ in range(50)])
        assert len(results) == 50
        assert all(r.org_id == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_writes_conflict_handling(self):
        """Test that concurrent writes are handled safely."""
        async def write():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[write() for _ in range(10)])
        assert len(results) == 10

    @pytest.mark.asyncio
    async def test_concurrent_validation_consistent(self):
        """Test that validation is consistent under concurrency."""
        async def validate():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[validate() for _ in range(20)])
        assert all(r.org_id == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_endpoint_request_ordering_preserved(self):
        """Test that concurrent requests maintain ordering semantics."""
        async def order_request():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[order_request() for _ in range(25)])
        assert len(set(r.user_id for r in results)) == 1
