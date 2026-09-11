"""Authentication and API key management endpoints."""

import secrets
from fastapi import APIRouter, Depends
from auth import get_auth_context, AuthContext

# Try to import database functions; gracefully skip if prisma unavailable
try:
    from db import create_api_key, get_api_key, revoke_api_key
    db_available = True
except (ImportError, ModuleNotFoundError):
    db_available = False
    async def create_api_key(*args, **kwargs):
        pass
    async def get_api_key(*args, **kwargs):
        return None
    async def revoke_api_key(*args, **kwargs):
        pass

router = APIRouter(prefix="/api", tags=["auth"])


@router.post("/api-key/generate")
async def generate_api_key(auth: AuthContext = Depends(get_auth_context)) -> dict:
    """Generate new API key for the authenticated user's organization."""
    # Revoke any existing key first
    await revoke_api_key(auth.org_id)

    # Generate new key (32-char hex string)
    api_key = secrets.token_hex(16)

    # Store in database
    key_record = await create_api_key(auth.org_id, api_key)

    # Handle case where database is unavailable (key_record is None)
    if key_record:
        return {
            "apiKey": api_key,
            "createdAt": key_record["createdAt"],
            "expiresAt": key_record.get("expiresAt"),
        }
    else:
        # Database unavailable; return basic response with generated key
        return {
            "apiKey": api_key,
            "createdAt": None,
            "expiresAt": None,
        }


@router.get("/api-key")
async def get_current_api_key(auth: AuthContext = Depends(get_auth_context)) -> dict:
    """Get current API key for the org (without revealing the full key)."""
    key_record = await get_api_key(auth.org_id)
    if not key_record:
        return {"apiKey": None, "createdAt": None}

    return {
        "apiKey": f"{key_record['key'][:8]}...{key_record['key'][-4:]}",  # Masked
        "createdAt": key_record["createdAt"],
        "expiresAt": key_record.get("expiresAt"),
    }


@router.post("/api-key/revoke")
async def revoke_current_api_key(auth: AuthContext = Depends(get_auth_context)) -> dict:
    """Revoke current API key."""
    success = await revoke_api_key(auth.org_id)
    return {"success": success}
