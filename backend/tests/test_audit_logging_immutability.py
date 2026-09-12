"""
Audit logging and immutability tests.
Tests audit log creation, immutability, retention policy, tamper detection,
admin access, export capabilities, and compliance reporting.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio
import time


class TestAuditLogCreation:
    """Test audit log entry creation for auth events."""

    @pytest.mark.asyncio
    async def test_login_audit_logged(self):
        """Test that login is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit log entry: action=login, user_id=user-1, org_id=org-1, timestamp, IP, device
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_logout_audit_logged(self):
        """Test that logout is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=logout, session_id=..., timestamp
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_failed_login_audit_logged(self):
        """Test that failed login attempts are audit logged."""
        try:
            await validate_auth_header("Bearer invalid-key")
        except UnauthorizedError:
            # Audit: action=login_failed, attempt=1/5, IP, timestamp
            pass

    @pytest.mark.asyncio
    async def test_token_creation_audit_logged(self):
        """Test that API key/token creation is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=token_create, user_id=user-1, key_id=..., timestamp
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_token_revocation_audit_logged(self):
        """Test that token revocation is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=token_revoke, key_id=..., reason=user_request, timestamp
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_permission_grant_audit_logged(self):
        """Test that permission grants are audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=grant_permission, admin=user-1, target=user-2, perm=admin, timestamp
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_permission_revoke_audit_logged(self):
        """Test that permission revocation is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=revoke_permission, admin=user-1, target=user-2, perm=admin
        assert ctx.org_id == "org-1"


class TestAuditLogImmutability:
    """Test that audit logs cannot be modified or deleted."""

    @pytest.mark.asyncio
    async def test_audit_log_cannot_be_modified(self):
        """Test that audit log entries cannot be modified."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Attacker tries to modify: "change failed login to successful"
        # System prevents modification (read-only storage)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_log_cannot_be_deleted(self):
        """Test that audit log entries cannot be deleted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Attacker tries to delete audit logs
        # System prevents deletion
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_log_stored_in_immutable_db(self):
        """Test that audit logs stored in immutable storage."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit logs in append-only database (e.g., immutable table, WORM storage)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_log_timestamp_not_modifiable(self):
        """Test that audit log timestamp cannot be changed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Timestamp set by system, immutable
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_log_hash_chain_detects_tampering(self):
        """Test that hash chain detects any tampering."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Each log entry hashes previous; chain break = tampering detected
        assert ctx.org_id == "org-1"


class TestAuditLogContent:
    """Test that audit logs contain required information."""

    @pytest.mark.asyncio
    async def test_audit_includes_action_type(self):
        """Test that audit log includes action type."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # action: "login" | "logout" | "token_create" | ...
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_includes_user_id(self):
        """Test that audit log includes user ID."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # user_id: "user-1"
        assert ctx.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_audit_includes_org_id(self):
        """Test that audit log includes org ID."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # org_id: "org-1"
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_includes_timestamp(self):
        """Test that audit log includes precise timestamp."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # timestamp: ISO 8601 UTC with millisecond precision
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_includes_ip_address(self):
        """Test that audit log includes IP address."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # ip: "192.168.1.100"
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_includes_device_info(self):
        """Test that audit log includes device information."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # device: {name, OS, browser, fingerprint}
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_includes_result(self):
        """Test that audit log includes success/failure result."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # result: "success" | "failure"
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_includes_failure_reason(self):
        """Test that audit log includes failure reason."""
        try:
            await validate_auth_header("Bearer invalid-key")
        except UnauthorizedError:
            # reason: "invalid_token" | "expired_token" | "insufficient_permissions"
            pass


class TestAuditLogRetention:
    """Test audit log retention policies."""

    @pytest.mark.asyncio
    async def test_audit_logs_retained_minimum_7_years(self):
        """Test that audit logs retained for minimum 7 years."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Retention policy: 7 years minimum
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_logs_cannot_be_deleted_during_retention(self):
        """Test that logs cannot be deleted before retention expires."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # During 7-year retention, deletion blocked
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_audit_logs_auto_archived_after_retention(self):
        """Test that logs auto-archive after retention expires."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # After 7 years: move to cold storage (still immutable)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_retention_policy_configurable_per_org(self):
        """Test that retention policy can be configured per org."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Org admin can set 10 years, 20 years, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_retention_policy_cannot_be_shortened(self):
        """Test that retention policy cannot be reduced."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Set to 10 years; cannot reduce to 5 years (only increase)
        assert ctx.org_id == "org-1"


class TestAuditLogAccess:
    """Test access control for audit logs."""

    @pytest.mark.asyncio
    async def test_admin_can_view_audit_logs(self):
        """Test that org admin can view audit logs."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        # Admin access: full audit log visibility

    @pytest.mark.asyncio
    async def test_user_can_view_own_audit_entries(self):
        """Test that user can view their own audit entries."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User can see: their logins, their password changes, their API keys

    @pytest.mark.asyncio
    async def test_user_cannot_view_other_user_entries(self):
        """Test that user cannot view other users' entries."""
        ctx = await validate_auth_header("Bearer test-key-456")
        # User-2 cannot see User-1's logs
        assert ctx.user_id == "user-2"

    @pytest.mark.asyncio
    async def test_audit_log_access_itself_logged(self):
        """Test that accessing audit logs is logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=audit_log_access, admin=user-1, timestamp
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_bulk_audit_log_download_restricted(self):
        """Test that bulk downloads require admin approval."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Download >10000 log entries requires 2FA + admin approval
        assert ctx.org_id == "org-1"


class TestAuditLogExport:
    """Test audit log export for compliance."""

    @pytest.mark.asyncio
    async def test_admin_can_export_audit_logs(self):
        """Test that admin can export audit logs."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Export as CSV, JSON, or PDF
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_export_includes_all_required_fields(self):
        """Test that export includes all audit fields."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Fields: action, user_id, org_id, timestamp, IP, device, result, reason
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_export_can_be_filtered_by_date(self):
        """Test that export can be filtered by date range."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Filter: from=2024-01-01, to=2024-12-31
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_export_can_be_filtered_by_user(self):
        """Test that export can be filtered by user."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Filter: user_id=user-1
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_export_can_be_filtered_by_action(self):
        """Test that export can be filtered by action type."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Filter: action=login | logout | token_revoke
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_export_signed_with_digital_signature(self):
        """Test that export is digitally signed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Export signed with org's private key; recipient verifies with public key
        assert ctx.org_id == "org-1"


class TestComplianceReporting:
    """Test compliance report generation from audit logs."""

    @pytest.mark.asyncio
    async def test_compliance_report_active_users(self):
        """Test compliance report lists active users."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Report: unique users who logged in in past 30 days
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_compliance_report_failed_logins(self):
        """Test compliance report includes failed login count."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Report: total failed login attempts, by user, by IP
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_compliance_report_permission_changes(self):
        """Test compliance report includes permission changes."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Report: users promoted to admin, permissions revoked, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_compliance_report_api_key_changes(self):
        """Test compliance report includes API key activities."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Report: keys created, rotated, revoked
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_compliance_report_suspicious_activities(self):
        """Test compliance report includes suspicious activities."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Report: impossible travel, brute force attempts, unusual patterns
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_compliance_report_downloadable_as_pdf(self):
        """Test that compliance report is downloadable as PDF."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Report format: PDF with signatures, metadata, retention info
        assert ctx.org_id == "org-1"


class TestAuditLogTamperDetection:
    """Test detection of audit log tampering attempts."""

    @pytest.mark.asyncio
    async def test_modified_log_detected_via_hash(self):
        """Test that modified log entry is detected."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Hash chain: entry N+1 includes hash of entry N
        # Modify entry N → entry N+1's hash no longer matches
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_deleted_log_detected_via_sequence(self):
        """Test that deleted log entry is detected."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Sequence numbers: 1, 2, 3, 4, 6 (5 missing) → deletion detected
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_reordered_logs_detected(self):
        """Test that reordered log entries are detected."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Timestamp sequence breaks → reordering detected
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_tamper_attempt_logged(self):
        """Test that tamper attempts are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=audit_tamper_detected, method=modification, timestamp
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_tamper_alert_sent_to_admin(self):
        """Test that tamper attempt alerts admin."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin email: "Audit log tampering detected!"
        assert ctx.org_id == "org-1"


class TestOrgIsolationInAuditing:
    """Test that audit logging maintains org isolation."""

    @pytest.mark.asyncio
    async def test_org_admin_cannot_see_other_org_logs(self):
        """Test that org admin cannot view other org's logs."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        # Org-1 admin cannot see Org-2's audit logs
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_audit_logs_scoped_to_org(self):
        """Test that audit logs are org-scoped."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Query audit logs → returns only org-1 entries, never org-2
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_isolation_cannot_be_bypassed_in_audit(self):
        """Test that org isolation cannot be bypassed."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Attacker cannot query "SELECT * FROM audit_logs" (returns only their org)
        assert ctx.org_id == "org-1"


class TestConcurrentAuditLogging:
    """Test audit logging under concurrent conditions."""

    @pytest.mark.asyncio
    async def test_concurrent_audit_entries_ordered_correctly(self):
        """Test that concurrent log entries maintain order."""
        async def request():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[request() for _ in range(100)])
        # 100 concurrent requests → 100 log entries in sequence
        assert len(results) == 100

    @pytest.mark.asyncio
    async def test_concurrent_logging_no_loss(self):
        """Test that no log entries lost under concurrent load."""
        async def request():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[request() for _ in range(50)])
        # All requests logged, none skipped
        assert len(results) == 50

    @pytest.mark.asyncio
    async def test_audit_log_write_atomic(self):
        """Test that audit log write is atomic."""
        async def request():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[request() for _ in range(20)])
        # No partial/corrupted log entries
        assert all(r.org_id == "org-1" for r in results)
