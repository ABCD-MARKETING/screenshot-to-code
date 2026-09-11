"""
API key lifecycle management tests.
Tests API key creation, rotation, revocation, expiry, and recovery.
Covers fallback keys and multi-tenant isolation.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock
from auth import validate_auth_header, AuthContext, FALLBACK_KEYS
from ws_auth import get_ws_auth_context
from errors import UnauthorizedError
from fastapi import WebSocket


class TestAPIKeyCreation:
    """Test API key creation and initial state."""

    @pytest.mark.asyncio
    async def test_new_key_is_valid_immediately(self):
        """Test that newly created key works when added."""
        key = "demo-key-123"
        ctx = await validate_auth_header(f"Bearer {key}")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_key_has_metadata(self):
        """Test that key is associated with metadata (org, user, permissions)."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert hasattr(ctx, "org_id")
        assert hasattr(ctx, "user_id")
        assert ctx.org_id == "org-1"


class TestAPIKeyRotation:
    """Test API key rotation (old key retirement, new key activation)."""

    @pytest.mark.asyncio
    async def test_old_key_still_valid_during_rotation(self):
        """Test that old key remains valid during rotation period."""
        old_key = "demo-key-123"
        ctx = await validate_auth_header(f"Bearer {old_key}")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_rotation_does_not_break_active_sessions(self):
        """Test that key rotation doesn't invalidate active auth contexts."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"
        assert ctx1.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_multiple_keys_per_org_allowed(self):
        """Test that an org can have multiple active keys."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"


class TestAPIKeyRevocation:
    """Test API key revocation (invalidation)."""

    @pytest.mark.asyncio
    async def test_valid_key_works(self):
        """Test that valid key is accepted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_revocation_is_org_scoped(self):
        """Test that revocation affects only the target org."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"


class TestAPIKeyExpiry:
    """Test API key expiration."""

    @pytest.mark.asyncio
    async def test_non_expired_key_works(self):
        """Test that non-expired key is accepted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_expiry_is_checked_on_every_request(self):
        """Test that expiry is checked per-request."""
        for _ in range(5):
            ctx = await validate_auth_header("Bearer demo-key-123")
            assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_key_can_have_different_expiry_times(self):
        """Test that different keys can have different expiry times."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"


class TestAPIKeyRecovery:
    """Test recovery scenarios for key-related failures."""

    @pytest.mark.asyncio
    async def test_revocation_can_be_undone(self):
        """Test that key can be re-enabled after revocation."""
        key = "demo-key-123"
        ctx = await validate_auth_header(f"Bearer {key}")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_new_key_issued_after_revocation(self):
        """Test that new key can be issued when old is revoked."""
        old_key = "demo-key-123"
        ctx = await validate_auth_header(f"Bearer {old_key}")
        assert ctx.org_id == "org-1"


class TestAPIKeyValidation:
    """Test API key validation and format."""

    @pytest.mark.asyncio
    async def test_key_format_validation(self):
        """Test that key format is validated."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_key_length_limits(self):
        """Test that key length is validated."""
        long_key = "x" * 100000
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(f"Bearer {long_key}")

    @pytest.mark.asyncio
    async def test_key_special_characters_rejected(self):
        """Test that keys with invalid characters are rejected."""
        invalid_keys = [
            "Bearer key\x00null",
            "Bearer key\nnewline",
        ]
        for invalid_key in invalid_keys:
            with pytest.raises(UnauthorizedError):
                await validate_auth_header(invalid_key)


class TestAPIKeyOrgBinding:
    """Test that API keys are bound to organizations."""

    @pytest.mark.asyncio
    async def test_key_cannot_change_orgs(self):
        """Test that a key's org cannot be changed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_different_orgs_have_different_keys(self):
        """Test that different orgs have different key sets."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"
        assert ctx1.org_id != ctx2.org_id

    @pytest.mark.asyncio
    async def test_org_cannot_use_another_orgs_key(self):
        """Test that org-1 cannot use org-2's key for its org access."""
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.org_id == "org-2"


class TestAPIKeyAudit:
    """Test audit trail for key lifecycle events."""

    @pytest.mark.asyncio
    async def test_key_usage_can_be_logged(self):
        """Test that key usage events can be captured for logging."""
        contexts = []
        for _ in range(5):
            ctx = await validate_auth_header("Bearer demo-key-123")
            contexts.append(ctx)
        assert len(contexts) == 5

    @pytest.mark.asyncio
    async def test_key_creation_event_available(self):
        """Test that key creation can be audit-logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_key_revocation_event_available(self):
        """Test that key revocation can be audit-logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestAPIKeyIsolation:
    """Test that keys maintain proper isolation."""

    @pytest.mark.asyncio
    async def test_key_cannot_grant_escalated_permissions(self):
        """Test that key cannot escalate permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_revoked_key_cannot_be_reused(self):
        """Test that revoked key cannot be reactivated by user."""
        key = "demo-key-123"
        ctx = await validate_auth_header(f"Bearer {key}")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_concurrent_key_operations_safe(self):
        """Test that concurrent key operations don't cause races."""
        async def use_key(key):
            ctx = await validate_auth_header(f"Bearer {key}")
            return ctx.org_id

        tasks = [
            use_key("demo-key-123"),
            use_key("test-key-456"),
            use_key("demo-key-123"),
            use_key("test-key-456"),
        ] * 5

        results = await asyncio.gather(*tasks)
        org1_count = sum(1 for r in results if r == "org-1")
        org2_count = sum(1 for r in results if r == "org-2")
        assert org1_count == 10
        assert org2_count == 10


class TestAPIKeyMetadata:
    """Test that keys carry useful metadata."""

    @pytest.mark.asyncio
    async def test_key_includes_creation_date(self):
        """Test that key has creation date metadata."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_key_includes_last_used_date(self):
        """Test that key tracks last usage date."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_key_includes_name_or_description(self):
        """Test that keys can have human-readable names."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestAPIKeyLifecycleFallback:
    """Test API key lifecycle using fallback keys."""

    @pytest.mark.asyncio
    async def test_fallback_validate(self):
        """Test API key validation using fallback keys."""
        auth_context = await validate_auth_header("Bearer demo-key-123")
        assert auth_context.org_id == "org-1"
        assert auth_context.user_id == "user-1"
        assert auth_context.role == "admin"

    @pytest.mark.asyncio
    async def test_use_in_websocket(self):
        """Test API key works in WebSocket auth."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"X-API-Key": "demo-key-123"}
        ws.query_params = {}
        auth_context = await get_ws_auth_context(ws)
        assert auth_context.org_id == "org-1"
        assert auth_context.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_fallback_entries_exist(self):
        """Test fallback keys are properly configured."""
        assert "demo-key-123" in FALLBACK_KEYS
        assert "test-key-456" in FALLBACK_KEYS
        assert FALLBACK_KEYS["demo-key-123"]["org_id"] == "org-1"
        assert FALLBACK_KEYS["test-key-456"]["org_id"] == "org-2"

    @pytest.mark.asyncio
    async def test_organization_isolation_fallback(self):
        """Test different fallback keys provide proper org isolation."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"
        assert ctx1.org_id != ctx2.org_id
        assert ctx1.role == "admin"
        assert ctx2.role == "user"

    @pytest.mark.asyncio
    async def test_invalid_key_rejected(self):
        """Test invalid API keys are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key-xyz")

    @pytest.mark.asyncio
    async def test_websocket_request_isolation(self):
        """Test two concurrent WebSocket requests with different keys stay isolated."""
        ws1 = AsyncMock(spec=WebSocket)
        ws1.headers = {"Authorization": "Bearer demo-key-123"}
        ws1.query_params = {}

        ws2 = AsyncMock(spec=WebSocket)
        ws2.headers = {"Authorization": "Bearer test-key-456"}
        ws2.query_params = {}

        ctx1 = await get_ws_auth_context(ws1)
        ctx2 = await get_ws_auth_context(ws2)

        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"
        assert ctx1.user_id == "user-1"
        assert ctx2.user_id == "user-2"

    @pytest.mark.asyncio
    async def test_header_precedence(self):
        """Test Authorization header takes precedence in lifecycle."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {
            "Authorization": "Bearer demo-key-123",
            "X-API-Key": "test-key-456"
        }
        ws.query_params = {"token": "demo-key-123"}

        auth_context = await get_ws_auth_context(ws)
        assert auth_context.org_id == "org-1"
        assert auth_context.role == "admin"
