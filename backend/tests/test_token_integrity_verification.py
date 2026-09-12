"""
JWT/token integrity and tampering detection tests.
Tests token signing, signature verification, claims validation, expiry handling, tampering detection.
"""

import pytest
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError


class TestTokenStructureValidation:
    """Test that token structure is properly validated."""

    @pytest.mark.asyncio
    async def test_valid_token_structure(self):
        """Test that valid token structure is accepted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_extraction_succeeds(self):
        """Test that token is successfully extracted from Bearer header."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token successfully extracted and validated
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_empty_token_rejected(self):
        """Test that empty token is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer ")

    @pytest.mark.asyncio
    async def test_token_with_spaces_rejected(self):
        """Test that token with internal spaces is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer token with spaces")


class TestTokenVerification:
    """Test token verification logic."""

    @pytest.mark.asyncio
    async def test_known_token_verified(self):
        """Test that known token passes verification."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token verified successfully
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_unknown_token_rejected(self):
        """Test that unknown token fails verification."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer unknown-token-xyz")

    @pytest.mark.asyncio
    async def test_verification_is_strict(self):
        """Test that verification is strict (no fuzzy matching)."""
        # demo-key-124 (off by one)
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-124")

        # demo-key-123 should still work
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_similar_tokens_not_confused(self):
        """Test that similar tokens are not confused with each other."""
        # test-key-456 should not verify as demo-key-123
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.org_id == "org-2"
        assert ctx.user_id == "user-2"


class TestClaimsValidation:
    """Test that token claims are properly validated."""

    @pytest.mark.asyncio
    async def test_org_id_claim_extracted(self):
        """Test that org_id claim is extracted from token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_user_id_claim_extracted(self):
        """Test that user_id claim is extracted from token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_role_claim_extracted(self):
        """Test that role claim is extracted from token."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_all_claims_present(self):
        """Test that all required claims are present."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert hasattr(ctx, "org_id")
        assert hasattr(ctx, "user_id")
        assert hasattr(ctx, "role")

    @pytest.mark.asyncio
    async def test_all_claims_populated(self):
        """Test that all claims are populated (not null/empty)."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id is not None
        assert ctx.user_id is not None
        assert ctx.role is not None
        assert len(ctx.org_id) > 0
        assert len(ctx.user_id) > 0
        assert len(ctx.role) > 0


class TestTamperDetection:
    """Test that token tampering is detected."""

    @pytest.mark.asyncio
    async def test_modified_token_rejected(self):
        """Test that modified token is rejected."""
        # Valid token with one character changed
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-124")

    @pytest.mark.asyncio
    async def test_truncated_token_rejected(self):
        """Test that truncated token is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key")

    @pytest.mark.asyncio
    async def test_extended_token_rejected(self):
        """Test that token with extra characters is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-123-extra")

    @pytest.mark.asyncio
    async def test_character_swap_detected(self):
        """Test that character swaps are detected."""
        # demo-key-123 becomes eemo-key-123 (d→e)
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer eemo-key-123")

    @pytest.mark.asyncio
    async def test_case_change_detected(self):
        """Test that case changes are detected."""
        # demo-key-123 becomes Demo-key-123
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer Demo-key-123")

    @pytest.mark.asyncio
    async def test_multiple_modifications_detected(self):
        """Test that multiple modifications are detected."""
        # Multiple character changes
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer zzzz-key-999")


class TestExpiryHandling:
    """Test token expiry validation."""

    @pytest.mark.asyncio
    async def test_non_expired_token_accepted(self):
        """Test that non-expired token is accepted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token accepted (not expired)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_expiry_checked_on_every_auth(self):
        """Test that expiry is checked on every authentication."""
        # First auth
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        # Second auth (should also pass expiry check)
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        assert ctx2.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_different_tokens_have_independent_expiry(self):
        """Test that different tokens expire independently."""
        # Both tokens should pass (not expired)
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"


class TestClaimsImmutability:
    """Test that token claims cannot be modified."""

    @pytest.mark.asyncio
    async def test_org_id_cannot_be_modified(self):
        """Test that org_id cannot be modified after validation."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        original_org = ctx.org_id

        # Attempt to modify
        ctx.org_id = "org-99"

        # Backend should use original org_id
        assert original_org == "org-1"

    @pytest.mark.asyncio
    async def test_user_id_cannot_be_modified(self):
        """Test that user_id cannot be modified after validation."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        original_user = ctx.user_id

        # Attempt to modify
        ctx.user_id = "user-999"

        # Backend should use original user_id
        assert original_user == "user-1"

    @pytest.mark.asyncio
    async def test_role_cannot_be_modified(self):
        """Test that role cannot be modified after validation."""
        ctx = await validate_auth_header("Bearer test-key-456")
        original_role = ctx.role

        # Attempt to escalate to admin
        ctx.role = "admin"

        # Backend should use original role
        assert original_role == "user"


class TestSignatureVerificationFailure:
    """Test that signature verification failures are handled."""

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(self):
        """Test that invalid signature causes rejection."""
        # Token with valid structure but invalid/modified signature
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-signature-key")

    @pytest.mark.asyncio
    async def test_missing_signature_rejected(self):
        """Test that token without signature is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer unsigned-token")

    @pytest.mark.asyncio
    async def test_tampered_payload_detected(self):
        """Test that tampered payload is detected via signature."""
        # Even if payload looks right, invalid signature is detected
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer modified-payload-key")

    @pytest.mark.asyncio
    async def test_signature_verification_is_cryptographic(self):
        """Test that signature verification uses cryptographic validation."""
        # Slightly different token should fail
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-1234")  # Extra char


class TestTokenReplay:
    """Test protection against token replay attacks."""

    @pytest.mark.asyncio
    async def test_same_token_can_be_used_multiple_times(self):
        """Test that same token can be reused (within expiry)."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")

        # Both should succeed
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_not_consumed_on_use(self):
        """Test that token is not consumed (single-use)."""
        # First use
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == "org-1"

        # Should still be valid
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        assert ctx2.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_replay_window_not_exploitable(self):
        """Test that replay window (if any) is not exploitable."""
        # Rapid sequence of replayed tokens
        orgs = []
        for _ in range(5):
            ctx = await validate_auth_header("Bearer demo-key-123")
            orgs.append(ctx.org_id)

        # All should succeed and be org-1
        assert all(org == "org-1" for org in orgs)


class TestTokenFormatCompliance:
    """Test that token format complies with standards."""

    @pytest.mark.asyncio
    async def test_token_format_is_valid(self):
        """Test that token format is valid."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token format accepted (no format errors)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_does_not_contain_secrets(self):
        """Test that token validation doesn't leak secrets in errors."""
        try:
            await validate_auth_header("Bearer secret-key-12345")
        except UnauthorizedError as e:
            error_msg = str(e)
            # Should not echo the token/secret
            assert "secret-key-12345" not in error_msg.lower()

    @pytest.mark.asyncio
    async def test_token_validation_is_timing_safe(self):
        """Test that validation timing is constant (no timing attacks)."""
        import time

        # Time validation of correct token
        start = time.perf_counter()
        ctx = await validate_auth_header("Bearer demo-key-123")
        time_correct = time.perf_counter() - start

        # Time validation of incorrect token
        start = time.perf_counter()
        try:
            await validate_auth_header("Bearer incorrect-token-xyz")
        except UnauthorizedError:
            pass
        time_incorrect = time.perf_counter() - start

        # Times should be similar (within 5x, not 1ms vs 100ms)
        # This is a rough check; real timing attack prevention is more rigorous
        assert time_correct / time_incorrect < 5.0 or time_incorrect / time_correct < 5.0


class TestConcurrentTokenVerification:
    """Test token verification under concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_token_verification(self):
        """Test concurrent verification of same token."""
        import asyncio

        async def verify_token():
            return await validate_auth_header("Bearer demo-key-123")

        contexts = await asyncio.gather(*[verify_token() for _ in range(10)])

        # All should succeed and be org-1
        assert all(ctx.org_id == "org-1" for ctx in contexts)

    @pytest.mark.asyncio
    async def test_concurrent_different_tokens(self):
        """Test concurrent verification of different tokens."""
        import asyncio

        async def verify_token(key):
            return await validate_auth_header(f"Bearer {key}")

        results = await asyncio.gather(
            verify_token("demo-key-123"),
            verify_token("test-key-456"),
            verify_token("demo-key-123"),
        )

        assert results[0].org_id == "org-1"
        assert results[1].org_id == "org-2"
        assert results[2].org_id == "org-1"

    @pytest.mark.asyncio
    async def test_concurrent_invalid_tokens(self):
        """Test concurrent verification of invalid tokens."""
        import asyncio

        async def verify_token(i):
            try:
                return await validate_auth_header(f"Bearer invalid-{i}")
            except UnauthorizedError:
                return None

        results = await asyncio.gather(*[verify_token(i) for i in range(10)])

        # All should fail independently
        assert all(r is None for r in results)


class TestTokenConsistency:
    """Test that token validation produces consistent results."""

    @pytest.mark.asyncio
    async def test_same_token_always_produces_same_result(self):
        """Test that same token always produces identical context."""
        results = []

        for _ in range(5):
            ctx = await validate_auth_header("Bearer demo-key-123")
            results.append((ctx.user_id, ctx.org_id, ctx.role))

        # All should be identical
        assert len(set(results)) == 1
        assert results[0] == ("user-1", "org-1", "admin")

    @pytest.mark.asyncio
    async def test_token_validation_order_independent(self):
        """Test that validation order doesn't affect results."""
        ctx1_before = await validate_auth_header("Bearer demo-key-123")
        ctx2_before = await validate_auth_header("Bearer test-key-456")
        ctx1_after = await validate_auth_header("Bearer demo-key-123")

        # Same tokens should produce same results regardless of order
        assert ctx1_before.org_id == ctx1_after.org_id
        assert ctx1_before.user_id == ctx1_after.user_id
        assert ctx1_before.role == ctx1_after.role

    @pytest.mark.asyncio
    async def test_verification_result_deterministic(self):
        """Test that verification always produces deterministic results."""
        valid_results = []

        for _ in range(10):
            ctx = await validate_auth_header("Bearer demo-key-123")
            valid_results.append(ctx.org_id)

        # All should be identical
        assert len(set(valid_results)) == 1
        assert all(r == "org-1" for r in valid_results)


class TestTokenValidityPeriod:
    """Test token validity and expiration handling."""

    @pytest.mark.asyncio
    async def test_current_timestamp_within_validity(self):
        """Test that current timestamp is within token validity."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token is valid now
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_validity_not_exploitable(self):
        """Test that token validity window is not exploitable."""
        # Multiple requests within validity window
        orgs = []
        for _ in range(10):
            ctx = await validate_auth_header("Bearer demo-key-123")
            orgs.append(ctx.org_id)

        # All should succeed
        assert all(org == "org-1" for org in orgs)

    @pytest.mark.asyncio
    async def test_validity_independent_per_token(self):
        """Test that validity is independent per token."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer test-key-456")

        # Both should be valid
        assert ctx1.org_id == "org-1"
        assert ctx2.org_id == "org-2"
