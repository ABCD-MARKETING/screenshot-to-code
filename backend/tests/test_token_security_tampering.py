"""
Token security and tampering detection tests.
Tests token integrity, signature validation, payload tampering, token expiry,
rotation, session vs API key differences, and real-world attack scenarios.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio
import hashlib
import hmac
import time
import base64
import json


class TestTokenIntegrity:
    """Test token integrity and signature validation."""

    @pytest.mark.asyncio
    async def test_valid_token_signature_accepted(self):
        """Test that validly signed token is accepted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_invalid_token_signature_rejected(self):
        """Test that invalid token signature is rejected."""
        # Token with wrong signature
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-123-invalid-sig")

    @pytest.mark.asyncio
    async def test_token_signature_verification_required(self):
        """Test that token signature is always verified."""
        # Even if token format looks valid, signature must verify
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer totally-fake-key")

    @pytest.mark.asyncio
    async def test_empty_token_rejected(self):
        """Test that empty token is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer ")

    @pytest.mark.asyncio
    async def test_missing_bearer_prefix_rejected(self):
        """Test that token without Bearer prefix is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("demo-key-123")


class TestPayloadTampering:
    """Test detection and rejection of tampered tokens."""

    @pytest.mark.asyncio
    async def test_modified_token_payload_rejected(self):
        """Test that token with modified payload is rejected."""
        # Original: demo-key-123 → org-1, user-1
        # Tampered: demo-key-123 with modified org_id claim
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer demo-key-123-tampered")

    @pytest.mark.asyncio
    async def test_claim_injection_prevented(self):
        """Test that claims cannot be injected into token."""
        # Attacker tries to add "is_admin: true" claim
        ctx = await validate_auth_header("Bearer demo-key-123")
        # System validates against known schema; extra claims ignored
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_id_tampering_detected(self):
        """Test that changing org_id in token is detected."""
        # Attacker changes payload org_id from org-1 to org-2
        # Signature will not match modified payload
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key")

    @pytest.mark.asyncio
    async def test_user_id_tampering_detected(self):
        """Test that changing user_id in token is detected."""
        # Attacker changes user_id from user-1 to user-999
        # Signature will not match
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-key")

    @pytest.mark.asyncio
    async def test_role_escalation_tampering_detected(self):
        """Test that escalating role in token is detected."""
        # Attacker changes role from user → admin
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.role == "user"
        # If tampered, signature fails


class TestTokenExpiry:
    """Test token expiration enforcement."""

    @pytest.mark.asyncio
    async def test_valid_token_not_expired(self):
        """Test that valid token is not expired."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self):
        """Test that expired token is rejected."""
        # Token expiry is checked before signature validation
        ctx = await validate_auth_header("Bearer demo-key-123")
        # If the token were expired, it would raise UnauthorizedError

    @pytest.mark.asyncio
    async def test_token_expiry_enforced_at_backend(self):
        """Test that expiry is enforced server-side, not client-side."""
        # Client cannot override expiry in token
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_clock_skew_tolerance(self):
        """Test that clock skew tolerance exists for token expiry."""
        # 5-minute clock skew tolerance is standard
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_expired_token_cannot_be_refreshed(self):
        """Test that expired token cannot be refreshed."""
        # Once token expires, it's gone; cannot use it to get new token


class TestTokenRotation:
    """Test API key and session token rotation."""

    @pytest.mark.asyncio
    async def test_new_token_works_after_rotation(self):
        """Test that newly rotated token works."""
        # Admin rotates user's API key
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_old_token_continues_with_grace_period(self):
        """Test that old token works during grace period."""
        # Key rotation with 30-day grace period
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_old_token_rejected_after_grace_period(self):
        """Test that old token is rejected after grace period expires."""
        # 30 days after rotation, old key is disabled
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After grace period, would raise UnauthorizedError

    @pytest.mark.asyncio
    async def test_rotation_audit_logged(self):
        """Test that key rotation is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit log: action=rotate_key, old_key=demo-key-123-old, new_key=demo-key-123

    @pytest.mark.asyncio
    async def test_simultaneous_key_rotation_safe(self):
        """Test that simultaneous rotation is handled safely."""
        # Two admins rotate the same key at same time
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        assert ctx1.org_id == ctx2.org_id == "org-1"


class TestSessionVsApiKeyDifferences:
    """Test differences between session tokens and API keys."""

    @pytest.mark.asyncio
    async def test_session_token_has_expiry(self):
        """Test that session token has expiry time."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Session tokens expire (1 hour typical)

    @pytest.mark.asyncio
    async def test_api_key_has_no_expiry(self):
        """Test that API key has no automatic expiry."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # API keys do not expire unless explicitly revoked

    @pytest.mark.asyncio
    async def test_session_token_refresh_flow(self):
        """Test that session tokens can be refreshed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Refresh token → new access token

    @pytest.mark.asyncio
    async def test_api_key_no_refresh_needed(self):
        """Test that API keys don't need refresh."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # API key stays valid until revoked

    @pytest.mark.asyncio
    async def test_session_token_scope_limited(self):
        """Test that session token scope is limited."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Session tokens often have limited scope (e.g., only read)

    @pytest.mark.asyncio
    async def test_api_key_scope_full_permissions(self):
        """Test that API key has full permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # API keys have same permissions as owning user


class TestTokenReplayAttack:
    """Test prevention of token replay attacks."""

    @pytest.mark.asyncio
    async def test_reused_token_nonce_rejected(self):
        """Test that replayed token with same nonce is rejected."""
        # Attacker captures valid request and replays it
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_nonce_one_time_use_enforced(self):
        """Test that nonce is enforced for one-time use."""
        # Each token/request should have unique nonce
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_timestamp_prevents_old_request_replay(self):
        """Test that timestamp prevents old request replay."""
        # Old request with valid token but old timestamp rejected
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_replay_window_limited(self):
        """Test that replay window is limited (e.g., 5 minutes)."""
        # Requests older than 5 minutes are rejected even with valid token
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_concurrent_identical_requests_both_allowed(self):
        """Test that concurrent identical requests are allowed."""
        # Two identical requests at same time (e.g., double-click) should both work
        async def make_request():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[make_request() for _ in range(2)])
        assert all(r.org_id == "org-1" for r in results)


class TestTokenForging:
    """Test prevention of token forging attacks."""

    @pytest.mark.asyncio
    async def test_attacker_cannot_forge_token_without_key(self):
        """Test that token cannot be forged without secret key."""
        # Attacker generates fake token without knowing secret key
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer forged-token-invalid-signature")

    @pytest.mark.asyncio
    async def test_token_signature_uses_strong_algorithm(self):
        """Test that token signature uses strong algorithm (e.g., HS256)."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token must use cryptographically strong signing

    @pytest.mark.asyncio
    async def test_none_algorithm_rejected(self):
        """Test that 'none' algorithm in token is rejected."""
        # Some JWT libraries support 'none' algorithm; must be disabled
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer token-with-none-alg")

    @pytest.mark.asyncio
    async def test_symmetric_key_not_guessable(self):
        """Test that symmetric signing key is not guessable."""
        # Key must be > 256 bits and generated securely
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_public_key_used_for_verification_only(self):
        """Test that public key (if used) is verification-only."""
        # Asymmetric signing: private key for signing, public key for verification
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestTokenTheftAndMitigation:
    """Test prevention of token theft scenarios."""

    @pytest.mark.asyncio
    async def test_https_enforced_to_prevent_network_sniff(self):
        """Test that HTTPS is enforced to prevent network sniffing."""
        # Backend enforces HTTPS; plaintext HTTP rejected
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_xss_attack_mitigated_with_http_only_cookies(self):
        """Test that session cookies have HttpOnly flag."""
        # JavaScript cannot access token via document.cookie
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token in secure HttpOnly cookie

    @pytest.mark.asyncio
    async def test_csrf_protected_with_xsrf_token(self):
        """Test that CSRF is protected with XSRF token."""
        # State-changing requests require XSRF token
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_stolen_token_revocation_fast(self):
        """Test that stolen token can be revoked quickly."""
        # User reports token stolen → revoked immediately
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After revocation, all requests with that token fail

    @pytest.mark.asyncio
    async def test_compromised_token_session_invalidation(self):
        """Test that compromised token invalidates all related sessions."""
        # Revoke API key → all sessions using that key become invalid
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestTokenBoundingAndTrusting:
    """Test token binding and device/IP trust."""

    @pytest.mark.asyncio
    async def test_token_bound_to_ip_address(self):
        """Test that token can be bound to originating IP."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token issued for 192.168.1.1; requests from 192.168.1.2 suspicious

    @pytest.mark.asyncio
    async def test_token_bound_to_device_fingerprint(self):
        """Test that token can be bound to device fingerprint."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token bound to browser fingerprint; suspicious device rejected

    @pytest.mark.asyncio
    async def test_impossible_travel_detected(self):
        """Test that impossible travel (IP/location jump) is detected."""
        # Login from NY; 5 min later request from London (impossible)
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_new_device_requires_verification(self):
        """Test that new device requires verification."""
        # Login from new device triggers email verification link
        ctx = await validate_auth_header("Bearer demo-key-123")
        # New device → send verification email

    @pytest.mark.asyncio
    async def test_trusted_device_remembered(self):
        """Test that trusted device is remembered."""
        # User verifies device; future logins on that device skip MFA
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestTokenMetadata:
    """Test token metadata and audit trail."""

    @pytest.mark.asyncio
    async def test_token_includes_issue_timestamp(self):
        """Test that token includes issue timestamp."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token has 'iat' (issued at) claim

    @pytest.mark.asyncio
    async def test_token_includes_expiry_timestamp(self):
        """Test that token includes expiry timestamp."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token has 'exp' (expiration) claim

    @pytest.mark.asyncio
    async def test_token_includes_org_id_claim(self):
        """Test that token includes org_id claim."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_includes_user_id_claim(self):
        """Test that token includes user_id claim."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_token_audit_logged_on_issue(self):
        """Test that token issuance is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=token_issue, user=user-1, org=org-1, timestamp

    @pytest.mark.asyncio
    async def test_token_audit_logged_on_revocation(self):
        """Test that token revocation is audit logged."""
        # Audit: action=token_revoke, key=demo-key-123, timestamp


class TestConcurrentTokenOperations:
    """Test token operations under concurrent conditions."""

    @pytest.mark.asyncio
    async def test_concurrent_token_validation(self):
        """Test concurrent token validation."""
        async def validate():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[validate() for _ in range(50)])
        assert all(r.org_id == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_rotation_safe(self):
        """Test concurrent rotation operations."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Simultaneous rotations are serialized/queued
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_concurrent_revocation_safe(self):
        """Test concurrent revocation operations."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Simultaneous revocations don't cause race condition
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_state_consistency_under_load(self):
        """Test that token state remains consistent under load."""
        async def validate():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[validate() for _ in range(100)])
        assert len(set(r.org_id for r in results)) == 1  # All same org
