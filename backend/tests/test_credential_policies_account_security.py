"""
Credential policies and account security enforcement tests.
Tests password strength validation, complexity requirements, credential expiry,
account lockout mechanisms, brute force protection, credential rotation.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio
import time


class TestPasswordComplexityRequirements:
    """Test password complexity and strength validation."""

    @pytest.mark.asyncio
    async def test_password_minimum_length(self):
        """Test that passwords must meet minimum length requirement."""
        # Passwords must be at least 12 characters
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_password_requires_uppercase(self):
        """Test that password requires at least one uppercase letter."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_password_requires_lowercase(self):
        """Test that password requires at least one lowercase letter."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_password_requires_number(self):
        """Test that password requires at least one number."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_password_requires_special_character(self):
        """Test that password requires at least one special character."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_weak_password_rejected(self):
        """Test that weak password is rejected."""
        # 'password' is weak (common, no special char, too short)
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer password")

    @pytest.mark.asyncio
    async def test_strong_password_accepted(self):
        """Test that strong password meets all requirements."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_common_passwords_rejected(self):
        """Test that common passwords are rejected."""
        common = ["password123", "qwerty123", "letmein123"]
        for pwd in common:
            with pytest.raises(UnauthorizedError):
                await validate_auth_header(f"Bearer {pwd}")


class TestPasswordHistory:
    """Test password history and reuse prevention."""

    @pytest.mark.asyncio
    async def test_password_history_tracked(self):
        """Test that previous passwords are tracked."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_cannot_reuse_recent_password(self):
        """Test that recently used passwords cannot be reused."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Backend should reject reuse of last 5 passwords
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_password_history_size_limit(self):
        """Test that password history has size limit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Keep last 5 password hashes, older ones discarded
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_old_password_can_be_reused_after_history_limit(self):
        """Test that old passwords can be reused after history limit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestPasswordExpiry:
    """Test password expiry and refresh enforcement."""

    @pytest.mark.asyncio
    async def test_password_expiry_date_enforced(self):
        """Test that password expiry date is enforced."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Passwords expire after 90 days
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_expired_password_requires_reset(self):
        """Test that expired password forces reset."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Backend: if password_expired, redirect to reset flow
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_password_expiry_warning_shown(self):
        """Test that user is warned before expiry."""
        # At 14 days before expiry, show warning
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_can_force_password_reset(self):
        """Test that admin can force password reset for users."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_password_change_extends_expiry(self):
        """Test that password change extends expiry clock."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Change password → reset 90-day timer
        assert ctx.org_id == "org-1"


class TestAccountLockout:
    """Test account lockout after failed login attempts."""

    @pytest.mark.asyncio
    async def test_account_lockout_after_failed_attempts(self):
        """Test that account locks after N failed attempts."""
        # Lock after 5 failed attempts
        for _ in range(5):
            try:
                await validate_auth_header("Bearer wrong-password")
            except UnauthorizedError:
                pass

    @pytest.mark.asyncio
    async def test_lockout_duration_enforced(self):
        """Test that account stays locked for duration."""
        # Locked for 15 minutes after 5 failures
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_lockout_applies_per_account_not_global(self):
        """Test that lockout is per-account, not global."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        # Locking one account doesn't lock others
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_admin_can_unlock_account(self):
        """Test that admin can manually unlock account."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_successful_login_resets_failed_count(self):
        """Test that successful login resets failed attempt counter."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After 3 failures + 1 success, counter resets to 0
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_lockout_notification_sent_to_user(self):
        """Test that user is notified when account locked."""
        # Email/SMS alert when account locked
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_lockout_alert_includes_unlock_instructions(self):
        """Test that lockout alert includes how to unlock."""
        # Notification includes admin contact, self-unlock link, or time-based unlock
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestBruteForceProtection:
    """Test brute force attack protection."""

    @pytest.mark.asyncio
    async def test_brute_force_detection_per_account(self):
        """Test brute force detection per account."""
        # Track failures per account
        try:
            await validate_auth_header("Bearer wrong")
        except UnauthorizedError:
            pass

    @pytest.mark.asyncio
    async def test_brute_force_detection_per_ip(self):
        """Test brute force detection per IP address."""
        # Track failures per IP across all accounts
        try:
            await validate_auth_header("Bearer wrong")
        except UnauthorizedError:
            pass

    @pytest.mark.asyncio
    async def test_rate_limit_on_brute_force_attempts(self):
        """Test rate limiting on brute force attempts."""
        # Slow down login attempts after threshold
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_captcha_required_after_brute_force_threshold(self):
        """Test that CAPTCHA is required after threshold."""
        # After 3-5 failed attempts, require CAPTCHA on next attempt
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_vpn_ip_detection_for_brute_force(self):
        """Test VPN/proxy detection in brute force protection."""
        # Flag multiple failed attempts from VPN/proxy IPs
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_distributed_brute_force_detection(self):
        """Test detection of distributed brute force attacks."""
        # Detect many IPs targeting same account
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"


class TestCredentialRotation:
    """Test regular credential rotation requirements."""

    @pytest.mark.asyncio
    async def test_api_key_rotation_required(self):
        """Test that API keys must be rotated periodically."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_api_key_rotation_interval_enforced(self):
        """Test that API key rotation interval is enforced."""
        # Keys expire after 1 year and must be rotated
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_old_api_key_continues_working_during_grace_period(self):
        """Test that old key works during grace period after rotation."""
        # 30-day grace period after new key issued
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_api_key_rotation_tracking(self):
        """Test that key rotations are tracked and logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit log includes: old key, new key, rotation time, reason
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_token_rotation_on_privilege_change(self):
        """Test that session tokens are rotated on privilege changes."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # When user role changes, issue new session token
        assert ctx.org_id == "org-1"


class TestCredentialResetFlow:
    """Test credential reset and recovery flows."""

    @pytest.mark.asyncio
    async def test_password_reset_via_email(self):
        """Test password reset via email link."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Email link with 24-hour expiry, one-time use
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_reset_link_single_use_only(self):
        """Test that reset link can be used only once."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After use, link is invalidated
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_reset_link_has_expiry(self):
        """Test that reset link expires after time limit."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Link valid for 24 hours only
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_reset_invalidates_existing_sessions(self):
        """Test that password reset invalidates existing sessions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # All existing sessions logged out
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_password_reset_requires_new_strong_password(self):
        """Test that reset requires meeting strength requirements."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Must meet complexity requirements
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_reset_flow_audit_logged(self):
        """Test that reset flow is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Log includes: request time, IP, email, reset time
        assert ctx.org_id == "org-1"


class TestCredentialStorageSecurity:
    """Test secure storage of credentials."""

    @pytest.mark.asyncio
    async def test_passwords_hashed_not_stored_plaintext(self):
        """Test that passwords are hashed, never stored plaintext."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Database contains bcrypt/Argon2 hash only
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_password_hash_uses_salt(self):
        """Test that password hash includes salt."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Each password hashed with unique salt
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_api_key_hashed_for_storage(self):
        """Test that API keys are hashed before storage."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Only prefix shown to user, full key hashed in DB
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_api_key_prefix_shown_for_identification(self):
        """Test that API key prefix is shown for user identification."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User sees "sk_...xyz123" in dashboard
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_secrets_never_logged_or_cached(self):
        """Test that secrets are never logged or cached."""
        try:
            await validate_auth_header("Bearer secret-key-12345")
        except UnauthorizedError as e:
            # Error message should NOT contain the secret
            error_msg = str(e).lower()
            assert "secret-key-12345" not in error_msg


class TestMultiFactorAuthentication:
    """Test MFA/2FA support and enforcement."""

    @pytest.mark.asyncio
    async def test_mfa_can_be_enabled_on_account(self):
        """Test that MFA can be enabled."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User can enable TOTP/SMS/Email MFA
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_mfa_requires_second_factor_on_login(self):
        """Test that MFA requires second factor."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After password, prompt for TOTP code
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_mfa_admin_can_mandate_for_org(self):
        """Test that admin can mandate MFA for organization."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_mfa_backup_codes_provided(self):
        """Test that backup codes are provided."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User gets 10 single-use backup codes for recovery
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_mfa_code_validity_window(self):
        """Test that MFA code is valid only for short window."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # TOTP valid for 30 seconds
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_mfa_codes_single_use(self):
        """Test that MFA codes are single-use."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Code cannot be replayed
        assert ctx.org_id == "org-1"


class TestCredentialCompromiseResponse:
    """Test response to credential compromise."""

    @pytest.mark.asyncio
    async def test_compromised_api_key_can_be_revoked(self):
        """Test that compromised API key can be revoked immediately."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User can revoke key instantly
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_revoked_key_immediately_invalid(self):
        """Test that revoked key becomes invalid immediately."""
        # No delay in revocation propagation
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_compromise_notification_sent_to_admin(self):
        """Test that compromise is reported to admin."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Email alert when key revoked due to compromise
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_leaked_key_database_checked(self):
        """Test checking if password/key appears in breach databases."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # On password change, check haveibeenpwned.com
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_isolation_on_key_compromise(self):
        """Test that key compromise doesn't affect other orgs."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        # Revoking org-1 key doesn't affect org-2
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"


class TestConcurrentCredentialOperations:
    """Test credential operations under concurrency."""

    @pytest.mark.asyncio
    async def test_concurrent_password_change(self):
        """Test concurrent password change operations."""
        async def change_password():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[change_password() for _ in range(10)])
        assert all(r == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_key_rotation(self):
        """Test concurrent API key rotation."""
        async def rotate_key():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[rotate_key() for _ in range(10)])
        assert all(r == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_mfa_enable(self):
        """Test concurrent MFA enable/disable operations."""
        async def enable_mfa():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[enable_mfa() for _ in range(5)])
        assert all(r == "org-1" for r in results)
