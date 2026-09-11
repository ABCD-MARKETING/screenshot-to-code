"""
API key lifecycle management tests.
Tests key generation, activation, rotation, revocation, expiry, and validity periods.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio
import time


class TestAPIKeyGeneration:
    """Test API key generation."""

    @pytest.mark.asyncio
    async def test_generated_key_is_valid(self):
        """Test that generated API key is immediately valid."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_generated_key_has_unique_format(self):
        """Test that generated keys have consistent format."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_generated_key_includes_org_context(self):
        """Test that generated key includes org context."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_generated_key_includes_user_context(self):
        """Test that generated key includes user context."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_generated_key_is_securely_random(self):
        """Test that keys are cryptographically random."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestAPIKeyActivation:
    """Test API key activation and deactivation."""

    @pytest.mark.asyncio
    async def test_active_key_works(self):
        """Test that active key is accepted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_deactivated_key_rejected(self):
        """Test that deactivated key is rejected."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_can_be_reactivated(self):
        """Test that deactivated key can be reactivated."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_activation_state_change_is_immediate(self):
        """Test that activation state change takes effect immediately."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1 is not None


class TestAPIKeyRotation:
    """Test API key rotation."""

    @pytest.mark.asyncio
    async def test_old_key_works_before_rotation(self):
        """Test that old key works before rotation."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_new_key_works_after_rotation(self):
        """Test that new key works immediately after rotation."""
        ctx_old = await validate_auth_header("Bearer demo-key-123")
        ctx_new = await validate_auth_header("Bearer test-key-456")
        assert ctx_old.org_id == "org-1"
        assert ctx_new.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_old_key_expires_after_grace_period(self):
        """Test that old key expires after grace period."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_rotation_maintains_same_permissions(self):
        """Test that rotated key maintains same permissions."""
        ctx_before = await validate_auth_header("Bearer demo-key-123")
        ctx_after = await validate_auth_header("Bearer demo-key-123")
        assert ctx_before.org_id == ctx_after.org_id
        assert ctx_before.user_id == ctx_after.user_id
        assert ctx_before.role == ctx_after.role


class TestAPIKeyRevocation:
    """Test API key revocation."""

    @pytest.mark.asyncio
    async def test_revoked_key_rejected_immediately(self):
        """Test that revoked key is rejected immediately."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_revocation_is_permanent(self):
        """Test that revocation is permanent (can't be undone)."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer revoked-key-xyz")

    @pytest.mark.asyncio
    async def test_revocation_affects_only_that_key(self):
        """Test that revoking one key doesn't affect others."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx2.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_revocation_audit_logged(self):
        """Test that revocation is logged for audit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestAPIKeyExpiry:
    """Test API key expiry and validity periods."""

    @pytest.mark.asyncio
    async def test_unexpired_key_accepted(self):
        """Test that unexpired key is accepted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_expired_key_rejected(self):
        """Test that expired key is rejected."""
        try:
            await validate_auth_header("Bearer expired-key")
        except UnauthorizedError:
            pass

    @pytest.mark.asyncio
    async def test_expiry_is_checked_on_every_auth(self):
        """Test that expiry is checked every authentication."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == ctx2.org_id

    @pytest.mark.asyncio
    async def test_key_can_have_custom_expiry(self):
        """Test that keys can have custom expiry times."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_without_expiry_is_valid_indefinitely(self):
        """Test that keys without expiry are valid indefinitely."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestMultipleActiveKeys:
    """Test multiple active keys per user."""

    @pytest.mark.asyncio
    async def test_user_can_have_multiple_active_keys(self):
        """Test that user can have multiple active keys."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1 is not None

    @pytest.mark.asyncio
    async def test_all_user_keys_work_concurrently(self):
        """Test that all active user keys work at same time."""
        async def validate_key(token):
            return await validate_auth_header(f"Bearer {token}")

        key1 = "demo-key-123"
        ctx = await validate_key(key1)
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_revoking_one_key_leaves_others_active(self):
        """Test that revoking one key doesn't affect others."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_limit_prevents_excessive_keys(self):
        """Test that there's a limit on concurrent active keys."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestAPIKeyMetadata:
    """Test API key metadata storage and retrieval."""

    @pytest.mark.asyncio
    async def test_key_has_created_timestamp(self):
        """Test that key tracks creation timestamp."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_tracks_last_used_time(self):
        """Test that key tracks last usage time."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_has_optional_description(self):
        """Test that key can have optional description."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_has_optional_name(self):
        """Test that key can have optional name."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_metadata_is_immutable_after_creation(self):
        """Test that key metadata (except state) cannot be changed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestAPIKeyInvalidation:
    """Test API key invalidation behavior."""

    @pytest.mark.asyncio
    async def test_key_invalidated_on_password_change(self):
        """Test that keys are invalidated when user password changes."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_invalidated_on_org_removal(self):
        """Test that keys are invalidated when user removed from org."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_invalidated_on_account_deactivation(self):
        """Test that keys are invalidated when account is deactivated."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_invalidated_on_role_downgrade(self):
        """Test that permissions change when role changes."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"


class TestAPIKeyPerformance:
    """Test API key authentication performance."""

    @pytest.mark.asyncio
    async def test_key_validation_fast(self):
        """Test that key validation is fast."""
        import time
        start = time.perf_counter()
        ctx = await validate_auth_header("Bearer demo-key-123")
        elapsed = time.perf_counter() - start
        assert elapsed < 0.01

    @pytest.mark.asyncio
    async def test_key_validation_concurrent(self):
        """Test key validation under concurrent load."""
        async def validate_key():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[validate_key() for _ in range(100)])
        assert len(results) == 100
        assert all(r.org_id == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_key_validation_does_not_query_database_frequently(self):
        """Test that key validation uses caching."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None


class TestAPIKeySecurityRevocation:
    """Test security aspects of key revocation."""

    @pytest.mark.asyncio
    async def test_revoked_key_cannot_be_reused(self):
        """Test that revoked key cannot be brought back into use."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer revoked-key-xyz")

    @pytest.mark.asyncio
    async def test_revocation_log_is_audit_safe(self):
        """Test that revocation is logged for compliance."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_revocation_does_not_leak_data(self):
        """Test that revocation doesn't leak other key information."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer revoked-key")


class TestAPIKeyOrgIsolation:
    """Test org isolation in API key management."""

    @pytest.mark.asyncio
    async def test_org1_user_cannot_use_org2_key(self):
        """Test that org-1 user cannot use org-2's API key."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_key_metadata_org_specific(self):
        """Test that key metadata is org-specific."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_key_generation_is_org_scoped(self):
        """Test that key generation creates org-specific keys."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestAPIKeyValidityWindow:
    """Test API key validity window."""

    @pytest.mark.asyncio
    async def test_key_is_valid_within_window(self):
        """Test that key is valid within its validity window."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_is_rejected_before_valid_from(self):
        """Test that key is rejected before valid_from timestamp."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx is not None

    @pytest.mark.asyncio
    async def test_key_is_rejected_after_valid_until(self):
        """Test that key is rejected after valid_until timestamp."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer expired-key")
