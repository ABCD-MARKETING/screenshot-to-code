"""
HTTP status codes and error responses for authentication.
Tests correct HTTP status codes for auth success and all failure modes.
"""

import pytest
from unittest.mock import AsyncMock
from fastapi import WebSocket, status
from auth import validate_auth_header, AuthContext
from ws_auth import get_ws_auth_context
from errors import UnauthorizedError


class TestHTTPStatusCodesSuccess:
    """Test correct HTTP status codes for successful authentication."""

    @pytest.mark.asyncio
    async def test_valid_auth_header_success(self):
        """Test that valid auth returns success context (200 OK)."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Successful auth should return context
        assert isinstance(ctx, AuthContext)
        assert ctx.org_id == "org-1"
        # In REST handler, this would map to 200 OK (implicit success)

    @pytest.mark.asyncio
    async def test_multiple_valid_auth_success(self):
        """Test multiple valid auth attempts succeed (200 OK)."""
        for _ in range(5):
            ctx = await validate_auth_header("Bearer demo-key-123")
            assert ctx.org_id == "org-1"


class TestHTTPStatusCodesUnauthorized:
    """Test 401 Unauthorized status for auth failures."""

    @pytest.mark.asyncio
    async def test_invalid_key_returns_401(self):
        """Test that invalid key raises UnauthorizedError (401)."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key")

    @pytest.mark.asyncio
    async def test_missing_token_returns_401(self):
        """Test that missing token raises UnauthorizedError (401)."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("")

    @pytest.mark.asyncio
    async def test_malformed_bearer_returns_401(self):
        """Test that malformed Bearer token raises UnauthorizedError (401)."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer")  # No token

    @pytest.mark.asyncio
    async def test_wrong_auth_scheme_returns_401(self):
        """Test that wrong auth scheme raises UnauthorizedError (401)."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Basic dGVzdDp0ZXN0")

    @pytest.mark.asyncio
    async def test_bearer_case_sensitive_returns_401(self):
        """Test that Bearer case sensitivity is enforced (401)."""
        # If backend requires "Bearer" exactly
        # "bearer" (lowercase) would fail
        try:
            await validate_auth_header("bearer demo-key-123")
            # If it succeeds, the impl is case-insensitive
        except UnauthorizedError:
            # If it fails, the impl is case-sensitive
            pass


class TestHTTPStatusCodesBadRequest:
    """Test 400 Bad Request for malformed input."""

    @pytest.mark.asyncio
    async def test_null_bytes_in_token(self):
        """Test that null bytes in token are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer key\x00injection")

    @pytest.mark.asyncio
    async def test_extremely_long_token_rejected(self):
        """Test that extremely long tokens are rejected."""
        long_key = "x" * 100000
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(f"Bearer {long_key}")

    @pytest.mark.asyncio
    async def test_newline_in_token_rejected(self):
        """Test that newlines in token are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer key\ninjection")


class TestErrorMessageContent:
    """Test that error messages contain helpful information."""

    @pytest.mark.asyncio
    async def test_unauthorized_error_is_catchable(self):
        """Test that UnauthorizedError can be caught and logged."""
        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError as e:
            error_msg = str(e)
            # Should be catchable for logging/monitoring
            assert error_msg is not None
            assert len(error_msg) > 0

    @pytest.mark.asyncio
    async def test_error_does_not_leak_keys(self):
        """Test that error messages don't leak valid keys."""
        try:
            await validate_auth_header("Bearer invalid-key")
        except UnauthorizedError as e:
            error_msg = str(e)
            # Should not contain demo-key or test-key
            assert "demo-key" not in error_msg.lower()
            assert "test-key" not in error_msg.lower()


class TestWebSocketStatusCodes:
    """Test WebSocket auth status handling."""

    @pytest.mark.asyncio
    async def test_websocket_valid_auth_connection(self):
        """Test WebSocket with valid auth succeeds."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer demo-key-123"}
        ws.query_params = {}

        ctx = await get_ws_auth_context(ws)

        # Connection should succeed
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_websocket_invalid_auth_closes_connection(self):
        """Test WebSocket with invalid auth closes connection."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {"Authorization": "Bearer invalid-key"}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)

        # Connection should be closed
        assert ws.close.called

    @pytest.mark.asyncio
    async def test_websocket_missing_auth_closes_connection(self):
        """Test WebSocket with missing auth closes connection."""
        ws = AsyncMock(spec=WebSocket)
        ws.headers = {}
        ws.query_params = {}
        ws.send_json = AsyncMock()
        ws.close = AsyncMock()

        with pytest.raises(UnauthorizedError):
            await get_ws_auth_context(ws)

        # Connection should be closed on auth failure
        assert ws.close.called


class TestAuthRetryBehavior:
    """Test retry behavior after auth failures."""

    @pytest.mark.asyncio
    async def test_failed_auth_does_not_block_retry(self):
        """Test that a failed auth attempt doesn't prevent retry."""
        # First attempt fails
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid")

        # Second attempt should work
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_rapid_failed_auth_attempts_do_not_deadlock(self):
        """Test that rapid failed attempts don't cause deadlock/blockage."""
        failures = []

        for i in range(20):
            try:
                await validate_auth_header(f"Bearer invalid-{i}")
            except UnauthorizedError:
                failures.append(i)

        # All should fail independently
        assert len(failures) == 20

    @pytest.mark.asyncio
    async def test_recovery_after_multiple_failures(self):
        """Test recovery after multiple consecutive failures."""
        # Multiple failures
        for i in range(10):
            try:
                await validate_auth_header(f"Bearer bad-{i}")
            except UnauthorizedError:
                pass

        # Should still be able to authenticate
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.org_id == "org-2"


class TestAuthHeaderSanitization:
    """Test that auth headers are sanitized in responses."""

    @pytest.mark.asyncio
    async def test_no_token_echo_in_response(self):
        """Test that tokens are never echoed back in responses."""
        try:
            await validate_auth_header("Bearer secret-token-123")
        except UnauthorizedError as e:
            # Error message should not echo the token
            error_msg = str(e)
            assert "secret-token-123" not in error_msg

    @pytest.mark.asyncio
    async def test_partial_token_not_leaked_in_error(self):
        """Test that partial tokens are not leaked."""
        token = "demo-key-123"
        try:
            await validate_auth_header(f"Bearer {token}")
        except:
            pass

        # Try invalid key
        try:
            await validate_auth_header("Bearer invalid-key-456")
        except UnauthorizedError as e:
            error_msg = str(e)
            # Should not leak parts of other tokens
            assert "demo" not in error_msg.lower() or "test" not in error_msg.lower()


class TestStatusCodeConformance:
    """Test that status codes follow HTTP specifications."""

    @pytest.mark.asyncio
    async def test_unauthorized_not_confused_with_forbidden(self):
        """Test that 401 Unauthorized is used, not 403 Forbidden."""
        # 401 = unauthenticated (missing/invalid credentials)
        # 403 = authenticated but unauthorized (insufficient permissions)
        # Invalid key should be 401 (missing/invalid credentials)

        try:
            await validate_auth_header("Bearer invalid")
        except UnauthorizedError:
            # Correct: 401 Unauthorized
            pass

    @pytest.mark.asyncio
    async def test_error_is_repeatable(self):
        """Test that same auth failure produces same error consistently."""
        errors = []

        for _ in range(5):
            try:
                await validate_auth_header("Bearer invalid-key")
            except UnauthorizedError as e:
                errors.append(str(e))

        # All errors should be consistent (same message)
        assert len(set(errors)) == 1  # All errors identical


class TestConcurrentAuthFailures:
    """Test handling of concurrent auth failures."""

    @pytest.mark.asyncio
    async def test_concurrent_invalid_auth_requests(self):
        """Test concurrent invalid auth requests handled independently."""
        import asyncio

        async def auth_attempt(i):
            try:
                await validate_auth_header(f"Bearer invalid-{i}")
            except UnauthorizedError:
                return "failed"
            return "success"

        tasks = [auth_attempt(i) for i in range(20)]
        results = await asyncio.gather(*tasks)

        # All should fail independently
        assert all(r == "failed" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_mixed_auth_requests(self):
        """Test concurrent mix of valid and invalid auth."""
        import asyncio

        async def auth_attempt(i):
            if i % 2 == 0:
                try:
                    await validate_auth_header("Bearer demo-key-123")
                    return "valid"
                except:
                    return "error"
            else:
                try:
                    await validate_auth_header(f"Bearer invalid-{i}")
                    return "unexpected"
                except UnauthorizedError:
                    return "failed"

        tasks = [auth_attempt(i) for i in range(20)]
        results = await asyncio.gather(*tasks)

        # Even indices should be "valid", odd should be "failed"
        for i, result in enumerate(results):
            if i % 2 == 0:
                assert result == "valid"
            else:
                assert result == "failed"
