# Load environment variables first
from dotenv import load_dotenv

load_dotenv()


import os
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from config import IS_DEBUG_ENABLED, IS_PROD

# Try to import database initialization; gracefully skip if prisma unavailable
try:
    from db import init_db, close_db
    db_available = True
except (ImportError, ModuleNotFoundError):
    db_available = False
    async def init_db():
        pass
    async def close_db():
        pass

from routes import (
    auth,
    capabilities,
    screenshot,
    generate_code,
    home,
    evals,
    export,
    design_systems,
    prompt_reports,
    agent_runs,
    eval_sets,
)
from uploaded_assets import configure_uploaded_asset_routes

app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
configure_uploaded_asset_routes(app)


@app.on_event("startup")
async def init_services() -> None:
    """Initialize database and log startup"""
    await init_db()
    debug_status = "ENABLED" if IS_DEBUG_ENABLED else "DISABLED"
    print(f"Backend startup complete. Debug mode is {debug_status}.")


@app.on_event("startup")
async def probe_screenshot_preview_on_startup() -> None:
    """Detect and warm up headless Chromium for screenshot preview tool"""
    from preview_screenshot import probe_screenshot_preview

    await probe_screenshot_preview()


@app.on_event("shutdown")
async def shutdown_services() -> None:
    """Close database connection"""
    await close_db()

# Security headers middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if IS_PROD:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# CORS: lock to frontend origin in prod; allow localhost in dev
_frontend_url = os.environ.get("FRONTEND_URL", "").rstrip("/")
if IS_PROD and _frontend_url:
    _allowed_origins = [_frontend_url]
    _allow_credentials = True
else:
    _allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    _allow_credentials = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

# Add routes
app.include_router(auth.router)
app.include_router(generate_code.router)
app.include_router(screenshot.router)
app.include_router(home.router)
app.include_router(capabilities.router)
app.include_router(evals.router)
app.include_router(export.router)
app.include_router(design_systems.router)
app.include_router(prompt_reports.router)
app.include_router(agent_runs.router)
app.include_router(eval_sets.router)
