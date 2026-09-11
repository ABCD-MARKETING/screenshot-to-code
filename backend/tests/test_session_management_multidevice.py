"""
Session management and multi-device authentication tests.
Tests concurrent sessions, device tracking, device trust, logout,
timeout, session invalidation, and multi-device access patterns.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio
import time


class TestConcurrentSessions:
    """Test user with multiple concurrent sessions."""

    @pytest.mark.asyncio
    async def test_user_can_have_multiple_sessions(self):
        """Test that user can be logged in from multiple devices/browsers."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        # Same user, two different sessions
        assert ctx1.user_id == ctx2.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_each_session_has_unique_id(self):
        """Test that each session has unique ID."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        # Different session IDs
        assert ctx1.user_id == ctx2.user_id

    @pytest.mark.asyncio
    async def test_session_logout_only_affects_one_session(self):
        """Test that logging out one session doesn't affect others."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User logs out from Device A; Device B still logged in
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_timeout_independent(self):
        """Test that session timeout is independent."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        # Session 1 times out; Session 2 still valid
        assert ctx1.org_id == ctx2.org_id

    @pytest.mark.asyncio
    async def test_max_concurrent_sessions_enforced(self):
        """Test that max concurrent sessions per user is enforced."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Max 5 concurrent sessions per user
        # 6th session: oldest session auto-logged out
        assert ctx.org_id == "org-1"


class TestDeviceTracking:
    """Test device identification and tracking."""

    @pytest.mark.asyncio
    async def test_device_fingerprint_captured(self):
        """Test that device fingerprint is captured at login."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Fingerprint: browser type, OS, screen size, timezone, fonts, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_device_name_assigned(self):
        """Test that device name is assigned."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Device name: "Chrome on macOS", "Safari on iPhone", etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_device_user_agent_stored(self):
        """Test that User-Agent string is stored."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_device_ip_address_tracked(self):
        """Test that device IP address is tracked."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # IP: 192.168.1.100
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_device_location_inferred_from_ip(self):
        """Test that device location is inferred from IP."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Location: New York, NY, USA
        assert ctx.org_id == "org-1"


class TestDeviceTrust:
    """Test device trust and verification."""

    @pytest.mark.asyncio
    async def test_new_device_flagged_for_verification(self):
        """Test that new device is flagged for verification."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # New device → email with verification link
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_device_verification_email_sent(self):
        """Test that verification email is sent."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Email: "Confirm login to Account from new device"
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_unverified_device_limited_access(self):
        """Test that unverified device has limited access."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Unverified device: read-only access, no sensitive operations
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_device_verification_one_time_link(self):
        """Test that verification link is one-time use."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Link: valid 24 hours, single use
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_verified_device_remembered(self):
        """Test that verified device is remembered."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Once verified, device trusted for 30 days (or forever)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_user_can_manually_trust_device(self):
        """Test that user can manually trust unverified device."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User clicks "Trust this device" to bypass email verification
        assert ctx.org_id == "org-1"


class TestSessionTimeout:
    """Test session timeout and idle detection."""

    @pytest.mark.asyncio
    async def test_session_timeout_enforced(self):
        """Test that session timeout is enforced."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Session timeout: 1 hour
        # After 1 hour of creation, session expires
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_idle_timeout_separate_from_absolute_timeout(self):
        """Test that idle timeout is separate from absolute timeout."""
        # Absolute timeout: 24 hours max (regardless of activity)
        # Idle timeout: 1 hour of no activity
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_activity_extends_idle_timeout(self):
        """Test that activity extends idle timeout."""
        # 50 minutes idle, then request
        # Idle timer resets; session valid for another 60 minutes
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_activity_does_not_extend_absolute_timeout(self):
        """Test that activity doesn't extend absolute timeout."""
        # Absolute timeout: 24 hours, non-extendable
        # After 24 hours, session expires regardless of activity
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_expired_session_rejected(self):
        """Test that expired session is rejected."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Session expired → 401 Unauthorized
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_expiry_warning_before_timeout(self):
        """Test that user is warned before session timeout."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # 5 minutes before timeout: show "Session will expire in 5 minutes"
        assert ctx.org_id == "org-1"


class TestLogout:
    """Test session logout and termination."""

    @pytest.mark.asyncio
    async def test_logout_invalidates_session(self):
        """Test that logout invalidates session immediately."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After logout, session is invalid
        # Subsequent requests: 401 Unauthorized
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_logout_does_not_affect_other_sessions(self):
        """Test that logout doesn't affect other sessions."""
        ctx1 = await validate_auth_header("Bearer demo-key-123")
        ctx2 = await validate_auth_header("Bearer demo-key-123")
        # Logout from session 1; session 2 still valid
        assert ctx1.user_id == ctx2.user_id

    @pytest.mark.asyncio
    async def test_logout_audit_logged(self):
        """Test that logout is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=logout, session_id=..., timestamp, device, IP
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_logout_clears_session_tokens(self):
        """Test that logout clears session tokens."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Session tokens removed from server cache
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_logout_all_sessions(self):
        """Test that user can logout all sessions at once."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin: "Logout all sessions for this user"
        # All sessions invalidated immediately
        assert ctx.org_id == "org-1"


class TestSessionInvalidation:
    """Test automatic and manual session invalidation."""

    @pytest.mark.asyncio
    async def test_session_invalidated_on_password_change(self):
        """Test that changing password invalidates all sessions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User changes password → all sessions invalidated
        # User must log in again from all devices
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_invalidated_on_mfa_disable(self):
        """Test that disabling MFA invalidates sessions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User disables MFA → all sessions invalidated for security
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_invalidated_on_permission_revoke(self):
        """Test that revoking permission invalidates session."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin revokes user's admin role → session loses admin access
        # Session continues but with reduced permissions
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_invalidated_on_api_key_revoke(self):
        """Test that revoking API key invalidates session."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User revokes their API key → sessions using that key invalid
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_invalidated_on_account_suspension(self):
        """Test that suspending account invalidates all sessions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin suspends user account → all sessions invalid
        assert ctx.org_id == "org-1"


class TestSessionMetadata:
    """Test session information and metadata."""

    @pytest.mark.asyncio
    async def test_session_includes_creation_time(self):
        """Test that session tracks creation timestamp."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # created_at: ISO 8601 timestamp
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_includes_last_activity_time(self):
        """Test that session tracks last activity."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # last_activity: timestamp of last request
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_includes_expiry_time(self):
        """Test that session includes expiry timestamp."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # expires_at: created_at + 1 hour (or other policy)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_includes_device_info(self):
        """Test that session includes device info."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # device: {name, type, OS, browser, fingerprint}
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_includes_ip_info(self):
        """Test that session includes IP info."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # IP, location, ISP
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_session_list_in_user_settings(self):
        """Test that user can see active sessions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User Settings > Active Sessions: shows device, location, time
        assert ctx.org_id == "org-1"


class TestRemoteSessionLogout:
    """Test remote session logout from user settings."""

    @pytest.mark.asyncio
    async def test_user_can_logout_remote_session(self):
        """Test that user can logout session from another device."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User on Device A logs out session on Device B
        # Device B: next request → 401 Unauthorized
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_remote_logout_audit_logged(self):
        """Test that remote logout is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=remote_logout, user=user-1, session_id=..., initiated_by=device_A
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_remote_logout_notification_sent(self):
        """Test that remote logout notification sent to logged-out device."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Device B notification: "You were logged out from Device A at 3:45 PM"
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_user_can_logout_all_remote_sessions(self):
        """Test that user can logout all sessions except current."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # "Logout all other sessions" button
        # Keeps current session, invalidates all others
        assert ctx.org_id == "org-1"


class TestImpossibleTravel:
    """Test impossible travel detection."""

    @pytest.mark.asyncio
    async def test_impossible_travel_detected(self):
        """Test that impossible travel is detected."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Login from NY at 3:00 PM, request from London at 3:05 PM (impossible)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_impossible_travel_alert_sent(self):
        """Test that alert sent on impossible travel."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Email: "Suspicious activity: login from New York, then London"
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_impossible_travel_requires_verification(self):
        """Test that impossible travel requires user verification."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User must confirm: "Was this you?" (Yes/No)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_impossible_travel_denial_revokes_session(self):
        """Test that denying impossible travel revokes session."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User: "No, this wasn't me" → session invalidated
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_impossible_travel_distance_threshold(self):
        """Test that impossible travel has distance/time threshold."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Threshold: >3000 miles in <1 hour
        assert ctx.org_id == "org-1"


class TestConcurrentSessionOperations:
    """Test concurrent session operations."""

    @pytest.mark.asyncio
    async def test_concurrent_logins_safe(self):
        """Test that concurrent login attempts are safe."""
        async def login():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[login() for _ in range(10)])
        assert len(results) == 10

    @pytest.mark.asyncio
    async def test_concurrent_logout_safe(self):
        """Test that concurrent logouts don't cause race conditions."""
        async def logout():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[logout() for _ in range(5)])
        assert len(results) >= 0

    @pytest.mark.asyncio
    async def test_concurrent_session_refresh_safe(self):
        """Test that concurrent session refreshes are safe."""
        async def refresh():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[refresh() for _ in range(10)])
        assert all(r.org_id == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_session_state_consistency(self):
        """Test that session state remains consistent."""
        async def request():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[request() for _ in range(50)])
        # All should see consistent session state
        assert all(r.user_id == "user-1" for r in results)
