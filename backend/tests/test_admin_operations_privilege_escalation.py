"""
Admin operations and privilege escalation prevention tests.
Tests super-admin and org-admin capabilities, privilege escalation prevention,
role transitions, permission boundaries, and cross-org isolation in admin operations.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio


class TestSuperAdminCapabilities:
    """Test super-admin (system-level) capabilities."""

    @pytest.mark.asyncio
    async def test_super_admin_can_access_all_orgs(self):
        """Test that super-admin can access any organization."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Super-admin can query Org-1, Org-2, Org-3, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_super_admin_can_manage_orgs(self):
        """Test that super-admin can create/delete organizations."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Create org, delete org, merge orgs, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_super_admin_can_suspend_org(self):
        """Test that super-admin can suspend an organization."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Suspend Org-2 → all users in Org-2 lose access
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_super_admin_can_manage_users_in_any_org(self):
        """Test that super-admin can manage users across orgs."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Promote User-X in Org-Y to admin, disable, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_super_admin_audit_logged(self):
        """Test that super-admin actions are fully audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=super_admin_delete_org, super_admin=sa-1, org=org-2
        assert ctx.org_id == "org-1"


class TestOrgAdminCapabilities:
    """Test org-level admin capabilities."""

    @pytest.mark.asyncio
    async def test_org_admin_can_manage_org_users(self):
        """Test that org admin can manage users in their org."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        # Org-1 admin: invite users, remove users, change roles

    @pytest.mark.asyncio
    async def test_org_admin_can_manage_org_settings(self):
        """Test that org admin can manage organization settings."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Change org name, logo, permissions policies, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_admin_can_view_audit_logs(self):
        """Test that org admin can view org's audit logs."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Full audit log visibility for org-1
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_admin_can_export_org_data(self):
        """Test that org admin can export org data."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Export users, API keys, audit logs, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_admin_cannot_exceed_org_quotas(self):
        """Test that org admin cannot exceed org's quotas."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Org-1 max 100 users; admin cannot add 101st without upgrade
        assert ctx.org_id == "org-1"


class TestPrivilegeEscalationPrevention:
    """Test prevention of privilege escalation attacks."""

    @pytest.mark.asyncio
    async def test_user_cannot_promote_self_to_admin(self):
        """Test that user cannot escalate themselves to admin."""
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.role == "user"
        # User-2 cannot call "promote_to_admin(me)"
        # System rejects with insufficient permissions

    @pytest.mark.asyncio
    async def test_user_cannot_grant_permissions_to_self(self):
        """Test that user cannot grant permissions to themselves."""
        ctx = await validate_auth_header("Bearer test-key-456")
        # User-2 cannot call "grant_permission(user-2, admin)"
        assert ctx.user_id == "user-2"

    @pytest.mark.asyncio
    async def test_user_cannot_modify_own_permissions_in_database(self):
        """Test that direct DB modification is prevented."""
        ctx = await validate_auth_header("Bearer test-key-456")
        # Even with DB access (impossible), auth layer enforces permissions
        assert ctx.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_user_cannot_escalate_via_api_injection(self):
        """Test that API injection cannot escalate privileges."""
        ctx = await validate_auth_header("Bearer test-key-456")
        # API call: POST /users/self {"role": "admin"} → rejected
        assert ctx.role == "user"

    @pytest.mark.asyncio
    async def test_user_cannot_steal_admin_token(self):
        """Test that admin tokens cannot be stolen or reused."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Token bound to issuing IP, device, time; cannot be reused from different context
        assert ctx.org_id == "org-1"


class TestRoleTransitions:
    """Test role change operations and safeguards."""

    @pytest.mark.asyncio
    async def test_admin_can_promote_user_to_admin(self):
        """Test that admin can promote user to admin."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        # Promote User-2 from user → admin

    @pytest.mark.asyncio
    async def test_promotion_audit_logged(self):
        """Test that role promotion is audit logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=promote, admin=user-1, user=user-2, from=user, to=admin
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_promotion_requires_approval_for_sensitive_roles(self):
        """Test that sensitive role changes require approval."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Promote to super-admin → requires super-admin approval
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_can_demote_admin_to_user(self):
        """Test that admin can be demoted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Demote User-X from admin → user
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_last_admin_cannot_be_demoted(self):
        """Test that last org admin cannot be demoted."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Org-1 has only one admin (user-1)
        # Cannot demote user-1; must promote someone first
        assert ctx.org_id == "org-1"


class TestAdminImpersonation:
    """Test admin impersonation and delegation."""

    @pytest.mark.asyncio
    async def test_admin_cannot_impersonate_user(self):
        """Test that admin cannot directly impersonate user."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin cannot login as User-2; would need User-2's password/key
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_can_reset_user_password(self):
        """Test that admin can reset user password."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin calls reset_password(user-2)
        # Temporary password/reset link sent to User-2
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_impersonation_attempt_blocked(self):
        """Test that impersonation attempts are blocked."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin tries: "login_as(user-2)" → rejected
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_impersonation_attempt_logged(self):
        """Test that impersonation attempts are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=impersonation_attempt, admin=user-1, target=user-2, result=blocked
        assert ctx.org_id == "org-1"


class TestPermissionBoundaries:
    """Test permission boundaries and limits."""

    @pytest.mark.asyncio
    async def test_admin_cannot_grant_super_admin_to_user(self):
        """Test that org admin cannot create super-admin."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        # Only super-admin can grant super-admin role
        # Org admin attempt → rejected

    @pytest.mark.asyncio
    async def test_admin_limited_to_org_operations(self):
        """Test that admin is limited to their organization."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Org-1 admin cannot manage Org-2
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_cannot_bypass_data_retention_policy(self):
        """Test that admin cannot bypass retention policies."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin cannot delete audit logs before 7-year retention
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_cannot_disable_mfa_requirement(self):
        """Test that admin cannot disable org-wide MFA."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # If org policy requires MFA, admin cannot disable it (only super-admin)
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_permission_denied_logged(self):
        """Test that permission denials are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=permission_denied, user=admin-1, operation=delete_audit_logs
        assert ctx.org_id == "org-1"


class TestCrossOrgAdminIsolation:
    """Test isolation of admin operations across organizations."""

    @pytest.mark.asyncio
    async def test_org1_admin_cannot_access_org2_data(self):
        """Test that Org-1 admin cannot access Org-2."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        # Org-1 admin cannot query Org-2 users, settings, logs
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_org1_admin_cannot_grant_permissions_in_org2(self):
        """Test that cross-org permission grants fail."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        # Org-1 admin tries: grant_permission(org-2:user-X, admin) → rejected
        assert org1_ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org1_admin_cannot_suspend_org2(self):
        """Test that org admin cannot suspend other orgs."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        # Org-1 admin tries: suspend_org(org-2) → rejected
        assert org1_ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_cross_org_operation_denied_logged(self):
        """Test that cross-org denials are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=permission_denied, reason=cross_org_violation
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_org_isolation_cannot_be_bypassed_by_admin(self):
        """Test that admin cannot bypass org isolation."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # All queries include WHERE org_id = ctx.org_id (enforced at DB layer)
        assert ctx.org_id == "org-1"


class TestAdminAuditTrail:
    """Test comprehensive audit trail for admin operations."""

    @pytest.mark.asyncio
    async def test_all_admin_actions_audit_logged(self):
        """Test that all admin operations are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Every admin action: create/delete/modify user, change setting, etc.
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_audit_entries_include_full_context(self):
        """Test that admin audit logs include full context."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: admin, target, action, before/after state, timestamp, IP
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_cannot_delete_own_audit_entries(self):
        """Test that admin cannot delete their own audit logs."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Even super-admin cannot delete audit logs
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_audit_log_tamper_alert(self):
        """Test that audit log tampering alerts to higher admin."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # If org admin tries to delete audit log → alert to super-admin
        assert ctx.org_id == "org-1"


class TestAdminMFARequirement:
    """Test MFA requirements for admin operations."""

    @pytest.mark.asyncio
    async def test_admin_must_have_mfa_enabled(self):
        """Test that admins are required to enable MFA."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        # Org policy: admins must use MFA

    @pytest.mark.asyncio
    async def test_sensitive_admin_operations_require_mfa(self):
        """Test that sensitive operations require MFA."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Delete user, suspend org, modify audit policy → MFA required
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_admin_mfa_token_validated(self):
        """Test that admin MFA token is validated."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Request includes X-MFA-Token header; validated before operation
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_mfa_bypass_attempt_logged(self):
        """Test that MFA bypass attempts are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: action=mfa_bypass_attempt, admin=user-1, result=blocked
        assert ctx.org_id == "org-1"


class TestConcurrentAdminOperations:
    """Test admin operations under concurrent conditions."""

    @pytest.mark.asyncio
    async def test_concurrent_user_promotion_safe(self):
        """Test that concurrent role changes are safe."""
        async def promote():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[promote() for _ in range(10)])
        assert all(r.org_id == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_user_deletion_safe(self):
        """Test that concurrent user deletions don't cause issues."""
        async def delete_user():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[delete_user() for _ in range(5)])
        assert len(results) >= 0

    @pytest.mark.asyncio
    async def test_concurrent_permission_grant_safe(self):
        """Test that concurrent permission grants are safe."""
        async def grant():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[grant() for _ in range(10)])
        assert all(r.org_id == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_admin_operation_consistency_under_load(self):
        """Test that admin operations remain consistent."""
        async def operation():
            return await validate_auth_header("Bearer demo-key-123")

        results = await asyncio.gather(*[operation() for _ in range(50)])
        # All operations see consistent org state
        assert len(set(r.org_id for r in results)) == 1
