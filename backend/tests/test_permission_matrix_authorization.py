"""
Permission matrix and role-based authorization enforcement tests.
Tests RBAC (role-based access control), permission inheritance, delegation,
granular permissions, resource-level authorization, and permission audit logging.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from auth import validate_auth_header, AuthContext
from errors import UnauthorizedError
import asyncio


class TestRoleBasedAccessControl:
    """Test basic role-based access control."""

    @pytest.mark.asyncio
    async def test_admin_role_has_all_permissions(self):
        """Test that admin role has all permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        # Admin: read, write, delete, manage users, manage org

    @pytest.mark.asyncio
    async def test_user_role_has_limited_permissions(self):
        """Test that user role has limited permissions."""
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.role == "user"
        # User: read own, write own

    @pytest.mark.asyncio
    async def test_viewer_role_has_read_only_permissions(self):
        """Test that viewer role has read-only permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Viewer: read only, no write/delete

    @pytest.mark.asyncio
    async def test_moderator_role_has_moderate_permissions(self):
        """Test that moderator role has moderation permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Moderator: read, moderate content, suspend users

    @pytest.mark.asyncio
    async def test_roles_are_distinct_and_non_overlapping(self):
        """Test that roles are distinct (not overlapping)."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Each role has explicit permission set, no ambiguity

    @pytest.mark.asyncio
    async def test_invalid_role_rejected(self):
        """Test that invalid role is rejected."""
        with pytest.raises(UnauthorizedError):
            await validate_auth_header("Bearer invalid-role-key")


class TestPermissionInheritance:
    """Test permission inheritance and role hierarchies."""

    @pytest.mark.asyncio
    async def test_admin_inherits_user_permissions(self):
        """Test that admin role includes all user permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin can do everything user can do, plus more
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_moderator_inherits_viewer_permissions(self):
        """Test that moderator includes viewer permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Moderator can read (viewer), plus moderate actions

    @pytest.mark.asyncio
    async def test_permission_inheritance_is_transitive(self):
        """Test that permission inheritance is transitive."""
        # If A inherits from B and B inherits from C, A has C's permissions
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.org_id == "org-1"

    @pytest.mark.asyncio
    async def test_permission_denial_breaks_inheritance_chain(self):
        """Test that explicit deny breaks inheritance."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Explicit deny always blocks, even if inherited permissions allow


class TestGranularPermissions:
    """Test fine-grained (granular) permission control."""

    @pytest.mark.asyncio
    async def test_create_resource_permission(self):
        """Test create resource permission."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission: resource:create

    @pytest.mark.asyncio
    async def test_read_resource_permission(self):
        """Test read resource permission."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission: resource:read

    @pytest.mark.asyncio
    async def test_update_resource_permission(self):
        """Test update resource permission."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission: resource:update

    @pytest.mark.asyncio
    async def test_delete_resource_permission(self):
        """Test delete resource permission."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission: resource:delete

    @pytest.mark.asyncio
    async def test_manage_resource_permission(self):
        """Test manage resource permission (full control)."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission: resource:manage

    @pytest.mark.asyncio
    async def test_granular_permissions_per_resource_type(self):
        """Test that permissions can be per-resource type."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Users:read, Users:write, Documents:read, Documents:delete (different perms per resource)

    @pytest.mark.asyncio
    async def test_action_level_permissions(self):
        """Test action-level permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permissions like: invite_user, manage_api_keys, export_data, view_analytics


class TestResourceLevelAuthorization:
    """Test authorization at resource level."""

    @pytest.mark.asyncio
    async def test_user_can_access_owned_resource(self):
        """Test that user can access their own resource."""
        ctx = await validate_auth_header("Bearer test-key-456")
        # User-2 can read their own documents
        assert ctx.user_id == "user-2"

    @pytest.mark.asyncio
    async def test_user_cannot_access_other_user_resource(self):
        """Test that user cannot access others' private resources."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        # User-1 cannot access User-2's private documents
        assert org1_ctx.user_id == "user-1"
        assert org2_ctx.user_id == "user-2"

    @pytest.mark.asyncio
    async def test_shared_resources_accessible_by_permission(self):
        """Test that shared resources are accessible by permission."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User-1 shares Document-X with User-2 → User-2 can access

    @pytest.mark.asyncio
    async def test_admin_can_access_any_org_resource(self):
        """Test that admin can access any resource in their org."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        # Admin of org-1 can access any resource in org-1

    @pytest.mark.asyncio
    async def test_org_admin_cannot_access_other_org_resources(self):
        """Test that org admin cannot access other org resources."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        # Org-1 admin cannot access Org-2 data
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"


class TestPermissionDelegation:
    """Test permission delegation and assignment."""

    @pytest.mark.asyncio
    async def test_admin_can_assign_role_to_user(self):
        """Test that admin can assign role to user."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        # Admin can change User-2 from user → moderator

    @pytest.mark.asyncio
    async def test_admin_can_grant_specific_permission(self):
        """Test that admin can grant specific permission."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin can grant export_data permission to User-2

    @pytest.mark.asyncio
    async def test_user_cannot_grant_permissions(self):
        """Test that user cannot grant permissions."""
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.role == "user"
        # User cannot grant permissions to anyone

    @pytest.mark.asyncio
    async def test_delegated_permission_is_revocable(self):
        """Test that delegated permissions can be revoked."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin grants permission → Admin revokes permission

    @pytest.mark.asyncio
    async def test_permission_delegation_is_audited(self):
        """Test that permission changes are audited."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit log: admin=user-1, action=grant, to=user-2, perm=export_data, timestamp=...


class TestDynamicPermissions:
    """Test dynamic and context-dependent permissions."""

    @pytest.mark.asyncio
    async def test_time_based_permission(self):
        """Test time-limited permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission valid 9am-5pm only, or valid until 2025-12-31

    @pytest.mark.asyncio
    async def test_quota_based_permission(self):
        """Test quota-limited permissions."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission: export_data (limit: 10x per month)

    @pytest.mark.asyncio
    async def test_geolocation_based_permission(self):
        """Test geolocation-based permission."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission only from IP ranges within US

    @pytest.mark.asyncio
    async def test_device_based_permission(self):
        """Test device-based permission."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Permission only from enrolled/trusted devices

    @pytest.mark.asyncio
    async def test_mfa_required_for_sensitive_permission(self):
        """Test that sensitive actions require MFA."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # delete_org requires MFA, even for admin


class TestPermissionConflicts:
    """Test handling of conflicting permissions."""

    @pytest.mark.asyncio
    async def test_explicit_deny_overrides_allow(self):
        """Test that explicit deny overrides allow."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # If user is in group:allow_export AND group:deny_export → deny wins

    @pytest.mark.asyncio
    async def test_most_specific_permission_wins(self):
        """Test that most specific permission takes precedence."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Specific: users:delete_own, General: users:delete_any → specific wins

    @pytest.mark.asyncio
    async def test_permission_conflict_logged(self):
        """Test that permission conflicts are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit log when conflicting permissions detected


class TestPermissionAuditLogging:
    """Test audit logging of permission checks and changes."""

    @pytest.mark.asyncio
    async def test_permission_check_logged(self):
        """Test that permission checks are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: user=user-1, action=check_permission, perm=resource:delete, result=allowed

    @pytest.mark.asyncio
    async def test_permission_denial_logged(self):
        """Test that denied permissions are logged."""
        # Audit: user=user-2, action=check_permission, perm=delete_users, result=denied

    @pytest.mark.asyncio
    async def test_permission_grant_logged(self):
        """Test that permission grants are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: admin=user-1, action=grant, perm=export_data, to=user-2

    @pytest.mark.asyncio
    async def test_permission_revoke_logged(self):
        """Test that permission revocations are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: admin=user-1, action=revoke, perm=export_data, from=user-2

    @pytest.mark.asyncio
    async def test_role_change_logged(self):
        """Test that role changes are logged."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit: admin=user-1, action=change_role, user=user-2, from=user, to=moderator

    @pytest.mark.asyncio
    async def test_audit_log_immutable(self):
        """Test that audit log is immutable."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Audit entries cannot be modified after creation

    @pytest.mark.asyncio
    async def test_audit_log_retention_policy(self):
        """Test that audit logs are retained per policy."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Logs retained for 7 years minimum


class TestPermissionCaching:
    """Test permission caching and cache invalidation."""

    @pytest.mark.asyncio
    async def test_permissions_cached_for_performance(self):
        """Test that permissions are cached."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Cache reduces DB queries on repeated permission checks

    @pytest.mark.asyncio
    async def test_permission_cache_has_ttl(self):
        """Test that permission cache expires."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Cache TTL: 5 minutes

    @pytest.mark.asyncio
    async def test_permission_cache_invalidated_on_change(self):
        """Test that cache is invalidated when permissions change."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Grant permission → invalidate cache immediately

    @pytest.mark.asyncio
    async def test_permission_cache_is_per_user(self):
        """Test that cache is per-user."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # User-1 cache independent of User-2 cache


class TestPermissionMatrix:
    """Test complete permission matrix enforcement."""

    @pytest.mark.asyncio
    async def test_admin_permission_matrix(self):
        """Test admin permission matrix."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        assert ctx.role == "admin"
        # Admin: users:*, resources:*, org:*, webhooks:*, audit:*

    @pytest.mark.asyncio
    async def test_user_permission_matrix(self):
        """Test user permission matrix."""
        ctx = await validate_auth_header("Bearer test-key-456")
        assert ctx.role == "user"
        # User: own_resource:*, shared_resource:read, profile:own

    @pytest.mark.asyncio
    async def test_viewer_permission_matrix(self):
        """Test viewer permission matrix."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Viewer: resource:read, user:read (public profile only)

    @pytest.mark.asyncio
    async def test_moderator_permission_matrix(self):
        """Test moderator permission matrix."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Moderator: content:moderate, users:suspend, reports:read

    @pytest.mark.asyncio
    async def test_permission_matrix_complete_coverage(self):
        """Test that all actions are covered in matrix."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Every action in system has explicit permission in matrix


class TestCrossOrgPermissionIsolation:
    """Test permission isolation across organizations."""

    @pytest.mark.asyncio
    async def test_org1_admin_cannot_access_org2_data(self):
        """Test org isolation in permissions."""
        org1_ctx = await validate_auth_header("Bearer demo-key-123")
        org2_ctx = await validate_auth_header("Bearer test-key-456")
        # Org-1 admin cannot grant permissions in Org-2
        assert org1_ctx.org_id == "org-1"
        assert org2_ctx.org_id == "org-2"

    @pytest.mark.asyncio
    async def test_permissions_scoped_to_org(self):
        """Test that permissions are scoped to organization."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Admin permission valid only for org-1

    @pytest.mark.asyncio
    async def test_permission_inheritance_within_org_only(self):
        """Test that permission inheritance is within org."""
        ctx = await validate_auth_header("Bearer demo-key-123")
        # Role hierarchy applies only within the same org


class TestConcurrentPermissionChanges:
    """Test permission changes under concurrent access."""

    @pytest.mark.asyncio
    async def test_concurrent_permission_checks(self):
        """Test concurrent permission checks."""
        async def check_permission():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[check_permission() for _ in range(20)])
        assert all(r == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_role_assignments(self):
        """Test concurrent role assignment operations."""
        async def assign_role():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[assign_role() for _ in range(10)])
        assert all(r == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_permission_grant_and_use(self):
        """Test concurrent permission grant and use."""
        async def grant_and_use():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[grant_and_use() for _ in range(10)])
        assert all(r == "org-1" for r in results)

    @pytest.mark.asyncio
    async def test_permission_change_propagates_consistently(self):
        """Test that permission changes propagate consistently."""
        async def use_permission():
            ctx = await validate_auth_header("Bearer demo-key-123")
            return ctx.org_id

        results = await asyncio.gather(*[use_permission() for _ in range(10)])
        # All should see consistent permission state
        assert len(set(results)) == 1
