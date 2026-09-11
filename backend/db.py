"""Database operations for multi-tenant screenshot-to-code"""

from typing import Optional, List
from datetime import datetime
from prisma import Prisma
from auth import AuthContext

db = Prisma()


async def init_db() -> None:
    """Initialize database connection"""
    await db.connect()


async def close_db() -> None:
    """Close database connection"""
    await db.disconnect()


# ORGANIZATION OPERATIONS
async def get_or_create_org(org_name: str) -> dict:
    """Get or create organization (for API key auth flow)"""
    org = await db.organization.find_first(where={"name": org_name})
    if org:
        return org.model_dump()
    return (await db.organization.create(data={"name": org_name})).model_dump()


async def get_org(org_id: str) -> Optional[dict]:
    """Get organization by ID"""
    org = await db.organization.find_unique(where={"id": org_id})
    return org.model_dump() if org else None


# USER OPERATIONS
async def get_user(user_id: str, org_id: str) -> Optional[dict]:
    """Get user by ID, org-scoped"""
    user = await db.user.find_first(where={"id": user_id, "orgId": org_id})
    return user.model_dump() if user else None


async def get_user_by_email(email: str, org_id: str) -> Optional[dict]:
    """Get user by email, org-scoped"""
    user = await db.user.find_first(where={"email": email, "orgId": org_id})
    return user.model_dump() if user else None


async def create_user(email: str, org_id: str, role: str = "user") -> dict:
    """Create new user in organization"""
    user = await db.user.create(
        data={"email": email, "orgId": org_id, "role": role}
    )
    return user.model_dump()


# PROJECT OPERATIONS
async def create_project(
    auth: AuthContext, name: str, description: Optional[str] = None
) -> dict:
    """Create project in user's org"""
    project = await db.project.create(
        data={"name": name, "description": description, "orgId": auth.org_id}
    )
    return project.model_dump()


async def list_projects(auth: AuthContext) -> List[dict]:
    """List projects in user's org"""
    projects = await db.project.find_many(where={"orgId": auth.org_id})
    return [p.model_dump() for p in projects]


async def get_project(project_id: str, auth: AuthContext) -> Optional[dict]:
    """Get project, org-scoped"""
    project = await db.project.find_first(
        where={"id": project_id, "orgId": auth.org_id}
    )
    return project.model_dump() if project else None


# RENDER OPERATIONS
async def create_render(
    auth: AuthContext,
    project_id: str,
    image_url: str,
    code: str = "",
    status: str = "pending",
) -> dict:
    """Create render (code generation result)"""
    # Verify project belongs to org
    project = await get_project(project_id, auth)
    if not project:
        raise ValueError("Project not found")

    render = await db.render.create(
        data={
            "projectId": project_id,
            "userId": auth.user_id,
            "orgId": auth.org_id,
            "imageUrl": image_url,
            "code": code,
            "status": status,
        }
    )
    return render.model_dump()


async def get_render(render_id: str, auth: AuthContext) -> Optional[dict]:
    """Get render, org-scoped"""
    render = await db.render.find_first(
        where={"id": render_id, "orgId": auth.org_id}
    )
    return render.model_dump() if render else None


async def update_render(
    render_id: str, auth: AuthContext, **updates
) -> Optional[dict]:
    """Update render, org-scoped"""
    render = await get_render(render_id, auth)
    if not render:
        raise ValueError("Render not found")

    updated = await db.render.update(
        where={"id": render_id}, data=updates
    )
    return updated.model_dump()


async def list_renders(auth: AuthContext, project_id: Optional[str] = None) -> List[dict]:
    """List renders in org, optionally filtered by project"""
    where = {"orgId": auth.org_id}
    if project_id:
        where["projectId"] = project_id
    renders = await db.render.find_many(where=where)
    return [r.model_dump() for r in renders]


# API KEY OPERATIONS
async def get_api_key(org_id: str) -> Optional[dict]:
    """Get API key for organization"""
    key = await db.api_key.find_first(where={"orgId": org_id})
    return key.model_dump() if key else None


async def create_api_key(org_id: str, key: str, expires_at: Optional[datetime] = None) -> dict:
    """Create API key for organization"""
    api_key = await db.api_key.create(
        data={"orgId": org_id, "key": key, "expiresAt": expires_at}
    )
    return api_key.model_dump()


async def revoke_api_key(org_id: str) -> bool:
    """Revoke API key for organization"""
    key = await db.api_key.find_first(where={"orgId": org_id})
    if not key:
        return False
    await db.api_key.delete(where={"id": key.id})
    return True
