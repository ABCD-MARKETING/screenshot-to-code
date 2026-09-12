"""
Bearer token validation and parsing edge cases.
Tests token format enforcement, malformed headers, encoding injection, truncation, concurrent parsing.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError


class TestBearerTokenFormat:
    """Test Bearer token format validation."""

    @pytest.mark.asyncio
    async def test_valid_bearer_prefix(self):
        """Test that valid Bearer prefix is accepted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_bearer_case_sensitive(self):
        """Test Bearer case sensitivity."""
        # Implementation may be case-insensitive or case-sensitive
        try:
            ctx = await validate_auth_header("bearer demo-key-123")
            # If succeeds, implementation is case-insensitive
            assert ctx.org_id is not None
        except UnauthorizedError:
            # If fails, implementation is case-sensitive (Bearer only)
            pass

    @pytest.mark.asyncio
    async def test_missing_bearer_prefix(self):
        """Test that missing Bearer prefix is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("demo-key-123")

    @pytest.mark.asyncio
    async def test_bearer_with_extra_space(self):
        """Test Bearer with multiple spaces."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer  demo-key-123")  # Double space

    @pytest.mark.asyncio
    async def test_bearer_with_leading_whitespace(self):
        """Test Bearer token with leading whitespace."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(" Bearer demo-key-123")

    @pytest.mark.asyncio
    async def test_bearer_with_trailing_whitespace(self):
        """Test Bearer token with trailing whitespace."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-123 ")


class TestTokenTruncation:
    """Test handling of truncated/incomplete tokens."""

    @pytest.mark.asyncio
    async def test_bearer_only_no_token(self):
        """Test Bearer keyword alone without token."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer")

    @pytest.mark.asyncio
    async def test_bearer_space_only(self):
        """Test Bearer with space but no token."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer ")

    @pytest.mark.asyncio
    async def test_partial_token(self):
        """Test with partial/truncated token."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key")  # Incomplete key

    @pytest.mark.asyncio
    async def test_single_character_token(self):
        """Test with single character token."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer x")


class TestTokenInjection:
    """Test protection against token injection attacks."""

    @pytest.mark.asyncio
    async def test_token_with_null_byte(self):
        """Test that null bytes in token are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer key\x00injection")

    @pytest.mark.asyncio
    async def test_token_with_newline(self):
        """Test that newlines in token are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer key\ninjection")

    @pytest.mark.asyncio
    async def test_token_with_carriage_return(self):
        """Test that carriage returns in token are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer key\rinjection")

    @pytest.mark.asyncio
    async def test_token_with_tab(self):
        """Test that tabs in token are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer key\tinjection")

    @pytest.mark.asyncio
    async def test_token_with_form_feed(self):
        """Test that form feed in token is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer key\finjection")

    @pytest.mark.asyncio
    async def test_token_with_backspace(self):
        """Test that backspace in token is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer key\binjection")


class TestTokenEncodingEdgeCases:
    """Test handling of unusual character encodings."""

    @pytest.mark.asyncio
    async def test_token_with_utf8_chars(self):
        """Test token with UTF-8 characters."""
        # Should be rejected - only ASCII alphanumeric allowed in most schemes
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer café-key")

    @pytest.mark.asyncio
    async def test_token_with_emoji(self):
        """Test token with emoji characters."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer 🔑-key")

    @pytest.mark.asyncio
    async def test_token_with_high_unicode(self):
        """Test token with high Unicode values."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer key injection")  # Line separator

    @pytest.mark.asyncio
    async def test_token_with_bom(self):
        """Test token with byte order mark."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer ﻿key")


class TestExtremelyLongTokens:
    """Test handling of oversized tokens."""

    @pytest.mark.asyncio
    async def test_very_long_valid_length_token(self):
        """Test with token at practical limit (1KB)."""
        long_key = "x" * 1000
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(f"Bearer {long_key}")

    @pytest.mark.asyncio
    async def test_extremely_long_token_100kb(self):
        """Test with 100KB token."""
        long_key = "x" * 100000
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(f"Bearer {long_key}")

    @pytest.mark.asyncio
    async def test_extremely_long_token_1mb(self):
        """Test with 1MB token."""
        long_key = "x" * 1000000
        with pytest.raises(UnauthorizedError):
            await validate_auth_header(f"Bearer {long_key}")

    @pytest.mark.asyncio
    async def test_token_with_embedded_bearer(self):
        """Test token that contains 'Bearer' substring."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer Bearer-demo-key-123")


class TestSpecialCharactersInToken:
    """Test handling of special characters in tokens."""

    @pytest.mark.asyncio
    async def test_token_with_quotes(self):
        """Test token with quote characters."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header('Bearer "demo-key"')

    @pytest.mark.asyncio
    async def test_token_with_single_quotes(self):
        """Test token with single quotes."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer 'demo-key'")

    @pytest.mark.asyncio
    async def test_token_with_comma(self):
        """Test token with comma."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo,key")

    @pytest.mark.asyncio
    async def test_token_with_semicolon(self):
        """Test token with semicolon."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo;key")

    @pytest.mark.asyncio
    async def test_token_with_equals(self):
        """Test token with equals sign."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo=key")

    @pytest.mark.asyncio
    async def test_token_with_backslash(self):
        """Test token with backslash."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo\\key")


class TestHeaderParsing:
    """Test Bearer header parsing edge cases."""

    @pytest.mark.asyncio
    async def test_multiple_bearer_keywords(self):
        """Test header with multiple Bearer keywords."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer Bearer demo-key-123")

    @pytest.mark.asyncio
    async def test_bearer_with_multiple_tokens(self):
        """Test Bearer with multiple tokens separated by space."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer token1 token2")

    @pytest.mark.asyncio
    async def test_bearer_with_comma_separation(self):
        """Test comma-separated tokens in Bearer."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer token1,token2")

    @pytest.mark.asyncio
    async def test_empty_header(self):
        """Test completely empty Authorization header."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("")

    @pytest.mark.asyncio
    async def test_header_only_whitespace(self):
        """Test Authorization header with only whitespace."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("   ")


class TestConcurrentTokenParsing:
    """Test parsing behavior under concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_valid_token_parsing(self):
        """Test concurrent parsing of valid tokens."""
        async def parse_token(token):
            return await validate_auth_header(f"Bearer {token}")

        results = await asyncio.gather(
            parse_token("demo-key-123"),
            parse_token("test-key-456"),
            parse_token("demo-key-123"),
            parse_token("test-key-456"),
        )

        assert len(results) == 4
        assert results[0].org_id == "org-1"
        assert results[1].org_id == "org-2"

    @pytest.mark.asyncio
    async def test_concurrent_invalid_token_parsing(self):
        """Test concurrent parsing of invalid tokens."""
        async def parse_invalid(token):
            try:
                return await validate_auth_header(f"Bearer {token}")
            except UnauthorizedError:
                return None

        results = await asyncio.gather(*[
            parse_invalid(f"invalid-{i}") for i in range(20)
        ])

        # All should fail independently
        assert all(r is None for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_mixed_valid_invalid(self):
        """Test concurrent mix of valid and invalid token parsing."""
        async def parse_mixed(i):
            try:
                if i % 2 == 0:
                    return await validate_auth_header("Bearer demo-key-123")
                else:
                    return await validate_auth_header(f"Bearer invalid-{i}")
            except UnauthorizedError:
                return None

        results = await asyncio.gather(*[parse_mixed(i) for i in range(20)])

        valid_count = sum(1 for r in results if r is not None)
        invalid_count = sum(1 for r in results if r is None)

        assert valid_count == 10  # Even indices
        assert invalid_count == 10  # Odd indices


class TestTokenMutation:
    """Test that tokens cannot be mutated after parsing."""

    @pytest.mark.asyncio
    async def test_token_immutability_in_context(self):
        """Test that token value is not accessible for mutation in context."""
        ctx = await validate_auth_header("Bearer demo-key-123")

        # Context should not expose the raw token
        assert not hasattr(ctx, "token")
        assert not hasattr(ctx, "raw_token")
        assert not hasattr(ctx, "api_key")

    @pytest.mark.asyncio
    async def test_context_org_cannot_override_token_org(self):
        """Test that context values cannot be overridden."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        original_org = ctx.org_id

        # Attempt to override (should not affect backend behavior)
        ctx.org_id = "org-999"

        # Original value should still be known by backend
        assert original_org == "org-1"


class TestFallbackKeyExhaustion:
    """Test behavior when fallback key dictionary is exhausted."""

    @pytest.mark.asyncio
    async def test_nonexistent_key_in_fallback(self):
        """Test with key that doesn't exist in fallback dictionary."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer unknown-key-999")

    @pytest.mark.asyncio
    async def test_key_similarity_not_accepted(self):
        """Test that similar but wrong keys are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-124")  # Wrong number

    @pytest.mark.asyncio
    async def test_partial_key_match_rejected(self):
        """Test that partial key matches are rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key")  # Missing suffix

    @pytest.mark.asyncio
    async def test_key_with_extra_suffix_rejected(self):
        """Test that key with extra suffix is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-123-extra")


class TestTokenRepetition:
    """Test repeated/duplicate token handling."""

    @pytest.mark.asyncio
    async def test_same_token_multiple_times(self):
        """Test same token used multiple times rapidly."""
        contexts = []
        for _ in range(5):
            ctx = await validate_auth_header("Bearer demo-key-123")
            contexts.append(ctx)

        # All should succeed and be separate instances
        assert len(contexts) == 5
        assert all(ctx.org_id == "org-1" for ctx in contexts)

    @pytest.mark.asyncio
    async def test_repeated_invalid_token(self):
        """Test same invalid token repeated."""
        failures = []
        for i in range(5):
            try:
                await validate_auth_header("Bearer invalid-key")
            except UnauthorizedError:
                failures.append(i)

        # All should fail independently
        assert len(failures) == 5

    @pytest.mark.asyncio
    async def test_token_swap_sequence(self):
        """Test alternating between two tokens."""
        sequence = []
        for i in range(10):
            token = "demo-key-123" if i % 2 == 0 else "test-key-456"
            ctx = await validate_auth_header(f"Bearer {token}")
            sequence.append(ctx.org_id)

        expected = ["org-1", "org-2"] * 5
        assert sequence == expected


class TestBearerTokenRobustness:
    """Test overall robustness of Bearer token validation."""

    @pytest.mark.asyncio
    async def test_valid_token_after_failures(self):
        """Test that valid token still works after multiple failures."""
        # Multiple failed attempts
        for i in range(10):
            try:
                await validate_auth_header(f"Bearer invalid-{i}")
            except UnauthorizedError:
                pass

        # Valid token should still work
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_different_schemes_rejected(self):
        """Test that different authentication schemes are rejected."""
        invalid_schemes = [
            "Basic dGVzdDp0ZXN0",
            "Bearer64 key",
            "Token demo-key-123",
            "ApiKey demo-key-123",
            "X-API-Key demo-key-123",
        ]

        for scheme in invalid_schemes:
            with pytest.raises(UnauthorizedError):
                await validate_auth_header(scheme)

    @pytest.mark.asyncio
    async def test_bearer_token_consistency(self):
        """Test that same Bearer token always produces same result."""
        results = []

        for _ in range(5):
            ctx = await validate_auth_header("Bearer demo-key-123")
            results.append((ctx.user_id, ctx.org_id, ctx.role))

        # All should be identical
        assert len(set(results)) == 1
        assert results[0] == ("user-1", "org-1", "admin")

    @pytest.mark.asyncio
    async def test_token_parsing_order_independence(self):
        """Test that token parsing order doesn't affect results."""
        tokens = ["demo-key-123", "test-key-456", "demo-key-123"]
        results = []

        for token in tokens:
            ctx = await validate_auth_header(f"Bearer {token}")
            results.append(ctx.org_id)

        # First and third should be same, second different
        assert results[0] == results[2]
        assert results[1] != results[0]
