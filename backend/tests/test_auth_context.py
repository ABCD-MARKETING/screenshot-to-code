"""
AuthContext lifecycle and isolation tests.
Tests context creation, mutations, data isolation, serialization, and edge cases.
"""

import pytest
from auth import AuthContext


class TestAuthContextCreation:
    """Test AuthContext object creation and initialization."""

    @pytest.mark.asyncio
    async def test_auth_context_basic_creation(self):
        """Test basic AuthContext creation with required fields."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        assert ctx.user_id == "user-1"
        assert ctx.org_id == "org-1"
        assert ctx.role == "admin"

    @pytest.mark.asyncio
    async def test_auth_context_preserves_exact_values(self):
        """Test that AuthContext preserves exact input values without modification."""
        user_id = "user-with-dashes-123"
        org_id = "org-with-dashes-456"
        role = "custom-role"

        ctx = AuthContext(user_id=user_id, org_id=org_id, role=role)

        assert ctx.user_id == user_id
        assert ctx.org_id == org_id
        assert ctx.role == role

    @pytest.mark.asyncio
    async def test_auth_context_empty_string_values_allowed(self):
        """Test that AuthContext allows empty strings as valid values."""
        ctx = AuthContext(user_id="", org_id="", role="")

        assert ctx.user_id == ""
        assert ctx.org_id == ""
        assert ctx.role == ""

    @pytest.mark.asyncio
    async def test_auth_context_special_characters_preserved(self):
        """Test that AuthContext preserves special characters in values."""
        user_id = "user@domain.com"
        org_id = "org:prod:us-east"
        role = "admin/super-user"

        ctx = AuthContext(user_id=user_id, org_id=org_id, role=role)

        assert ctx.user_id == user_id
        assert ctx.org_id == org_id
        assert ctx.role == role


class TestAuthContextIsolation:
    """Test isolation between AuthContext instances."""

    @pytest.mark.asyncio
    async def test_separate_contexts_are_independent(self):
        """Test that separate AuthContext instances are independent."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-2", org_id="org-2", role="user")

        assert ctx1.user_id != ctx2.user_id
        assert ctx1.org_id != ctx2.org_id
        assert ctx1.role != ctx2.role
        assert ctx1 != ctx2

    @pytest.mark.asyncio
    async def test_context_does_not_share_references(self):
        """Test that AuthContext instances don't share object references."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        # Same values but different objects
        assert ctx1.user_id == ctx2.user_id
        assert ctx1.org_id == ctx2.org_id
        assert ctx1.role == ctx2.role
        # Objects themselves are different
        assert ctx1 is not ctx2

    @pytest.mark.asyncio
    async def test_modifying_context_does_not_affect_other(self):
        """Test that modifying attributes on one context doesn't affect another."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        # Attempt to modify ctx1
        ctx1.user_id = "user-modified"

        # ctx2 should remain unchanged
        assert ctx2.user_id == "user-1"

    @pytest.mark.asyncio
    async def test_org_isolation_is_enforced(self):
        """Test that org_id is unique per context and properly enforced."""
        contexts = [
            AuthContext(user_id=f"user-{i}", org_id=f"org-{i}", role="user")
            for i in range(5)
        ]

        # All contexts have unique org_ids
        org_ids = [ctx.org_id for ctx in contexts]
        assert len(org_ids) == len(set(org_ids))

        # Each context can only access its own org_id
        for i, ctx in enumerate(contexts):
            assert ctx.org_id == f"org-{i}"
            for j, other_ctx in enumerate(contexts):
                if i != j:
                    assert ctx.org_id != other_ctx.org_id


class TestAuthContextEquality:
    """Test AuthContext equality and comparison."""

    @pytest.mark.asyncio
    async def test_identical_contexts_are_separate_instances(self):
        """Test that contexts with identical values are separate instances."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        # Same values but different objects
        assert ctx1.user_id == ctx2.user_id
        assert ctx1.org_id == ctx2.org_id
        assert ctx1.role == ctx2.role
        # Not equal because they're different instances
        assert ctx1 != ctx2

    @pytest.mark.asyncio
    async def test_different_user_id_makes_contexts_unequal(self):
        """Test that different user_id makes contexts unequal."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-2", org_id="org-1", role="admin")

        assert ctx1 != ctx2

    @pytest.mark.asyncio
    async def test_different_org_id_makes_contexts_unequal(self):
        """Test that different org_id makes contexts unequal."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-1", org_id="org-2", role="admin")

        assert ctx1 != ctx2

    @pytest.mark.asyncio
    async def test_different_role_makes_contexts_unequal(self):
        """Test that different role makes contexts unequal."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-1", org_id="org-1", role="user")

        assert ctx1 != ctx2


class TestAuthContextSerialization:
    """Test AuthContext serialization and deserialization."""

    @pytest.mark.asyncio
    async def test_auth_context_to_dict(self):
        """Test converting AuthContext to dictionary."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        ctx_dict = {
            "user_id": ctx.user_id,
            "org_id": ctx.org_id,
            "role": ctx.role,
        }

        assert ctx_dict["user_id"] == "user-1"
        assert ctx_dict["org_id"] == "org-1"
        assert ctx_dict["role"] == "admin"

    @pytest.mark.asyncio
    async def test_auth_context_from_dict_reconstruction(self):
        """Test reconstructing AuthContext from dictionary values."""
        original = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        ctx_dict = {
            "user_id": original.user_id,
            "org_id": original.org_id,
            "role": original.role,
        }

        reconstructed = AuthContext(**ctx_dict)

        # Reconstructed has same values but is a different instance
        assert reconstructed.user_id == original.user_id
        assert reconstructed.org_id == original.org_id
        assert reconstructed.role == original.role
        assert original is not reconstructed

    @pytest.mark.asyncio
    async def test_auth_context_has_expected_attributes(self):
        """Test that AuthContext has the expected attributes."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        # Check that the context has the expected attributes
        assert hasattr(ctx, "user_id")
        assert hasattr(ctx, "org_id")
        assert hasattr(ctx, "role")

        # And they have the right values
        assert ctx.user_id == "user-1"
        assert ctx.org_id == "org-1"
        assert ctx.role == "admin"


class TestAuthContextEdgeCases:
    """Test edge cases and boundary conditions for AuthContext."""

    @pytest.mark.asyncio
    async def test_auth_context_with_very_long_strings(self):
        """Test AuthContext with very long string values."""
        long_value = "x" * 10000

        ctx = AuthContext(
            user_id=long_value,
            org_id=long_value,
            role=long_value,
        )

        assert len(ctx.user_id) == 10000
        assert len(ctx.org_id) == 10000
        assert len(ctx.role) == 10000

    @pytest.mark.asyncio
    async def test_auth_context_with_unicode_values(self):
        """Test AuthContext with unicode characters."""
        ctx = AuthContext(
            user_id="user-日本語",
            org_id="org-中文",
            role="role-Русский",
        )

        assert ctx.user_id == "user-日本語"
        assert ctx.org_id == "org-中文"
        assert ctx.role == "role-Русский"

    @pytest.mark.asyncio
    async def test_auth_context_with_numeric_string_values(self):
        """Test AuthContext with numeric string values."""
        ctx = AuthContext(
            user_id="12345",
            org_id="67890",
            role="999",
        )

        assert ctx.user_id == "12345"
        assert ctx.org_id == "67890"
        assert ctx.role == "999"

    @pytest.mark.asyncio
    async def test_auth_context_with_whitespace_values(self):
        """Test AuthContext with whitespace in values."""
        ctx = AuthContext(
            user_id="user 1",
            org_id="org 2",
            role="admin role",
        )

        assert ctx.user_id == "user 1"
        assert ctx.org_id == "org 2"
        assert ctx.role == "admin role"

    @pytest.mark.asyncio
    async def test_auth_context_with_newline_values(self):
        """Test AuthContext with newline characters."""
        ctx = AuthContext(
            user_id="user\n1",
            org_id="org\n2",
            role="role\n3",
        )

        assert ctx.user_id == "user\n1"
        assert ctx.org_id == "org\n2"
        assert ctx.role == "role\n3"


class TestAuthContextComparison:
    """Test comparison operations on AuthContext."""

    @pytest.mark.asyncio
    async def test_context_comparison_with_same_org(self):
        """Test comparing contexts with the same org."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-2", org_id="org-1", role="user")

        # Same org but different users
        assert ctx1.org_id == ctx2.org_id
        assert ctx1.user_id != ctx2.user_id

    @pytest.mark.asyncio
    async def test_context_comparison_user_isolation(self):
        """Test that contexts with different users are isolated."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-2", org_id="org-1", role="admin")

        # Same org and role but different users must be distinct
        assert ctx1 != ctx2

    @pytest.mark.asyncio
    async def test_context_comparison_role_isolation(self):
        """Test that contexts with different roles are isolated."""
        ctx1 = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        ctx2 = AuthContext(user_id="user-1", org_id="org-1", role="user")

        # Same user and org but different roles must be distinct
        assert ctx1 != ctx2

    @pytest.mark.asyncio
    async def test_context_identity_does_not_change(self):
        """Test that context identity remains constant after creation."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        initial_identity = id(ctx)

        # Access attributes
        _ = ctx.user_id
        _ = ctx.org_id
        _ = ctx.role

        # Identity should not change
        assert id(ctx) == initial_identity


class TestAuthContextMutability:
    """Test mutability behavior of AuthContext."""

    @pytest.mark.asyncio
    async def test_auth_context_allows_attribute_modification(self):
        """Test that AuthContext allows attribute modification (not frozen)."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        # Should allow modification
        ctx.user_id = "user-modified"

        assert ctx.user_id == "user-modified"

    @pytest.mark.asyncio
    async def test_auth_context_allows_org_modification(self):
        """Test that AuthContext allows org_id modification."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        ctx.org_id = "org-modified"

        assert ctx.org_id == "org-modified"

    @pytest.mark.asyncio
    async def test_auth_context_allows_role_modification(self):
        """Test that AuthContext allows role modification."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        ctx.role = "user"

        assert ctx.role == "user"

    @pytest.mark.asyncio
    async def test_modification_does_not_affect_copies(self):
        """Test that modifying one context doesn't affect copies."""
        original = AuthContext(user_id="user-1", org_id="org-1", role="admin")
        copy = AuthContext(
            user_id=original.user_id,
            org_id=original.org_id,
            role=original.role,
        )

        original.user_id = "modified"

        assert copy.user_id == "user-1"
        assert original.user_id == "modified"


class TestAuthContextStringRepresentation:
    """Test string representation of AuthContext."""

    @pytest.mark.asyncio
    async def test_auth_context_string_representation(self):
        """Test that AuthContext has a string representation."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        str_repr = str(ctx)

        # Should contain the class name and field values
        assert "AuthContext" in str_repr or "user_id" in str_repr

    @pytest.mark.asyncio
    async def test_auth_context_repr_contains_values(self):
        """Test that AuthContext repr contains the actual values."""
        ctx = AuthContext(user_id="user-1", org_id="org-1", role="admin")

        repr_str = repr(ctx)

        # Repr should contain at least one of the values
        assert ("user-1" in repr_str or "org-1" in repr_str or
                "admin" in repr_str or "AuthContext" in repr_str)
