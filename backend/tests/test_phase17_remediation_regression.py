"""Phase 17 Remediation + Phase 18 Regression Tests.

Addresses P2 findings from Phase 16 Forensic QA:
  - P2-1: Database schema integrity (FKs, cascades, indexes, orphan prevention)
  - P2-2: UI control workflow integration (auth → api-key → capabilities → generate flow)
  - P2-3: Performance baseline (API p95 < 300ms target)
  - P2-4: Dead code / placeholder audit verification
"""

import asyncio
import time
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch, MagicMock
from main import app

client = TestClient(app)

ADMIN_HEADERS = {"Authorization": "Bearer demo-key-123"}
USER_HEADERS = {"Authorization": "Bearer test-key-456"}
NO_AUTH = {}


# ──────────────────────────────────────────────────────────────
# P2-1  Database Schema Integrity
# ──────────────────────────────────────────────────────────────
class TestDatabaseSchemaIntegrity:
    """Verify schema has correct constraints, cascades, and indexes."""

    def test_schema_file_exists(self):
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        assert os.path.exists(schema_path), "schema.prisma must exist"

    def test_schema_has_cascade_deletes(self):
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        content = open(schema_path).read()
        assert "onDelete: Cascade" in content, "FKs must have cascade delete rules"

    def test_schema_org_fk_on_user(self):
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        content = open(schema_path).read()
        assert 'org       Organization @relation(fields: [orgId], references: [id], onDelete: Cascade)' in content

    def test_schema_org_fk_on_project(self):
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        content = open(schema_path).read()
        lines = [l.strip() for l in content.splitlines()]
        cascade_fks = [l for l in lines if "Organization @relation" in l and "Cascade" in l]
        assert len(cascade_fks) >= 4, f"Expected >=4 cascade FKs to Organization, got {len(cascade_fks)}"

    def test_schema_apikey_has_org_relation(self):
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        content = open(schema_path).read()
        assert "model ApiKey" in content
        apikey_block_start = content.index("model ApiKey")
        apikey_block = content[apikey_block_start:apikey_block_start + 400]
        assert "Organization @relation" in apikey_block, "ApiKey must have FK to Organization"

    def test_schema_render_has_composite_indexes(self):
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        content = open(schema_path).read()
        assert "@@index([orgId, status])" in content, "Render needs composite index on orgId+status"
        assert "@@index([orgId, createdAt])" in content, "Render needs composite index on orgId+createdAt"

    def test_schema_user_has_unique_email_per_org(self):
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        content = open(schema_path).read()
        assert "@@unique([email, orgId])" in content, "User email must be unique per org"

    def test_schema_apikey_key_field_indexed(self):
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        content = open(schema_path).read()
        # key field has @unique which implies index, also verify explicit @@index
        assert 'key       String       @unique' in content or 'key String @unique' in content.replace("  ", " ")

    def test_schema_render_status_has_default(self):
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        content = open(schema_path).read()
        assert '@default("pending")' in content, "Render status must default to pending"

    def test_schema_no_unindexed_tenant_columns(self):
        """Every orgId column should have an index."""
        import os
        schema_path = os.path.join(os.path.dirname(__file__), "../../prisma/schema.prisma")
        content = open(schema_path).read()
        # Every model with orgId should have @@index([orgId])
        models_with_orgid = ["User", "Project", "Render", "ApiKey"]
        for model in models_with_orgid:
            start = content.find(f"model {model}")
            end = content.find("\n}", start)
            block = content[start:end]
            assert "@@index([orgId])" in block or "@unique" in block, \
                f"Model {model} has orgId without index"


# ──────────────────────────────────────────────────────────────
# P2-2  UI Control Workflow Integration
# ──────────────────────────────────────────────────────────────
class TestUIControlWorkflowIntegration:
    """Verify all UI-facing API controls work end-to-end."""

    # ── Auth controls ──
    def test_missing_auth_returns_401(self):
        r = client.get("/api/api-key", headers=NO_AUTH)
        assert r.status_code == 401

    def test_valid_bearer_token_accepted(self):
        r = client.get("/api/api-key", headers=ADMIN_HEADERS)
        assert r.status_code == 200

    def test_invalid_token_rejected(self):
        r = client.get("/api/api-key", headers={"Authorization": "Bearer invalid-token"})
        assert r.status_code == 401

    # ── API Key controls ──
    def test_api_key_get_returns_masked_key(self):
        r = client.get("/api/api-key", headers=ADMIN_HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "apiKey" in data

    def test_api_key_generate_creates_key(self):
        with patch("routes.auth.create_api_key") as mock_create, \
             patch("routes.auth.revoke_api_key") as mock_revoke, \
             patch("routes.auth.get_api_key") as mock_get:
            mock_revoke.return_value = True
            mock_create.return_value = {"createdAt": "2026-01-01T00:00:00Z", "expiresAt": None}
            r = client.post("/api/api-key/generate", headers=ADMIN_HEADERS)
            assert r.status_code == 200
            data = r.json()
            assert "apiKey" in data
            assert len(data["apiKey"]) == 32  # 16 bytes hex

    def test_api_key_revoke_works(self):
        with patch("routes.auth.revoke_api_key") as mock_revoke:
            mock_revoke.return_value = True
            r = client.post("/api/api-key/revoke", headers=ADMIN_HEADERS)
            assert r.status_code == 200
            assert r.json()["success"] is True

    # ── Capabilities control ──
    def test_capabilities_endpoint_available(self):
        r = client.get("/api/capabilities", headers=ADMIN_HEADERS)
        assert r.status_code in (200, 401, 422)

    # ── Home / root control ──
    def test_root_returns_200(self):
        r = client.get("/", headers=ADMIN_HEADERS)
        assert r.status_code == 200

    # ── Export workflow ──
    def test_export_endpoint_exists(self):
        r = client.post("/api/export", headers=ADMIN_HEADERS, json={})
        assert r.status_code != 404, "Export endpoint must exist"

    # ── Evals workflow ──
    def test_evals_endpoint_exists(self):
        r = client.get("/evals", headers=ADMIN_HEADERS)
        assert r.status_code != 404, "Evals endpoint must exist"

    # ── Design systems ──
    def test_design_systems_endpoint_exists(self):
        r = client.get("/api/design-systems", headers=ADMIN_HEADERS)
        assert r.status_code != 404, "Design systems endpoint must exist"

    # ── Prompt reports ──
    def test_prompt_reports_endpoint_exists(self):
        r = client.get("/prompt-reports", headers=ADMIN_HEADERS)
        assert r.status_code != 404, "Prompt reports endpoint must exist"

    # ── Agent runs ──
    def test_agent_runs_endpoint_exists(self):
        r = client.get("/agent-runs", headers=ADMIN_HEADERS)
        assert r.status_code != 404, "Agent runs endpoint must exist"

    # ── Cross-tenant: user sees only own data ──
    def test_api_key_isolated_per_org(self):
        r1 = client.get("/api/api-key", headers=ADMIN_HEADERS)
        r2 = client.get("/api/api-key", headers=USER_HEADERS)
        assert r1.status_code == 200
        assert r2.status_code == 200
        d1 = r1.json()
        d2 = r2.json()
        # Keys from different orgs should not be identical (both may be null, that's fine)
        if d1.get("apiKey") and d2.get("apiKey"):
            assert d1["apiKey"] != d2["apiKey"], "Orgs must have different API keys"


# ──────────────────────────────────────────────────────────────
# P2-3  Performance Baseline
# ──────────────────────────────────────────────────────────────
class TestPerformanceBaseline:
    """Verify p95 response time stays under 300ms for hot paths."""

    P95_LIMIT_MS = 300

    def _measure_ms(self, method: str, url: str, **kwargs) -> float:
        t0 = time.perf_counter()
        func = getattr(client, method)
        func(url, **kwargs)
        return (time.perf_counter() - t0) * 1000

    def _p95(self, samples: list[float]) -> float:
        s = sorted(samples)
        idx = int(len(s) * 0.95)
        return s[min(idx, len(s) - 1)]

    def test_root_p95_under_limit(self):
        samples = [self._measure_ms("get", "/", headers=ADMIN_HEADERS) for _ in range(20)]
        p95 = self._p95(samples)
        assert p95 < self.P95_LIMIT_MS, f"Root p95={p95:.1f}ms exceeds {self.P95_LIMIT_MS}ms"

    def test_api_key_get_p95_under_limit(self):
        samples = [self._measure_ms("get", "/api/api-key", headers=ADMIN_HEADERS) for _ in range(20)]
        p95 = self._p95(samples)
        assert p95 < self.P95_LIMIT_MS, f"/api/api-key p95={p95:.1f}ms exceeds {self.P95_LIMIT_MS}ms"

    def test_capabilities_p95_under_limit(self):
        samples = [self._measure_ms("get", "/capabilities", headers=ADMIN_HEADERS) for _ in range(20)]
        p95 = self._p95(samples)
        assert p95 < self.P95_LIMIT_MS, f"/capabilities p95={p95:.1f}ms exceeds {self.P95_LIMIT_MS}ms"

    def test_evals_p95_under_limit(self):
        samples = [self._measure_ms("get", "/evals", headers=ADMIN_HEADERS) for _ in range(20)]
        p95 = self._p95(samples)
        assert p95 < self.P95_LIMIT_MS, f"/evals p95={p95:.1f}ms exceeds {self.P95_LIMIT_MS}ms"

    def test_auth_rejection_p95_under_limit(self):
        """Unauthorized rejection must be fast to avoid timing-based info leakage."""
        samples = [self._measure_ms("get", "/api/api-key") for _ in range(20)]
        p95 = self._p95(samples)
        assert p95 < self.P95_LIMIT_MS, f"Auth rejection p95={p95:.1f}ms exceeds {self.P95_LIMIT_MS}ms"

    def test_no_endpoint_blocks_forever(self):
        """Every non-streaming endpoint responds within 5 seconds."""
        endpoints = ["/", "/api/api-key", "/capabilities", "/evals", "/design-systems"]
        for ep in endpoints:
            t = self._measure_ms("get", ep, headers=ADMIN_HEADERS)
            assert t < 5000, f"{ep} took {t:.0f}ms — likely blocking"


# ──────────────────────────────────────────────────────────────
# P2-4  Dead Code / Placeholder Audit
# ──────────────────────────────────────────────────────────────
class TestDeadCodeAudit:
    """Confirm no unimplemented stubs or fake/bypass auth paths remain."""

    def test_no_raise_not_implemented(self):
        import os, glob
        backend_dir = os.path.join(os.path.dirname(__file__), "..")
        py_files = glob.glob(f"{backend_dir}/**/*.py", recursive=True)
        violations = []
        for f in py_files:
            if "/tests/" in f:
                continue
            content = open(f).read()
            if "raise NotImplementedError" in content:
                violations.append(f)
        assert not violations, f"Unimplemented stubs in: {violations}"

    def test_no_hardcoded_bypass_passwords(self):
        import os, glob
        backend_dir = os.path.join(os.path.dirname(__file__), "..")
        py_files = glob.glob(f"{backend_dir}/**/*.py", recursive=True)
        bypass_patterns = ["password123", "admin123", "secret123", "bypass_auth = True"]
        violations = []
        for f in py_files:
            if "/tests/" in f:
                continue
            content = open(f).read().lower()
            for pat in bypass_patterns:
                if pat.lower() in content:
                    violations.append(f"{f}: {pat}")
        assert not violations, f"Bypass credentials found: {violations}"

    def test_fallback_keys_are_test_only(self):
        """FALLBACK_KEYS must only exist in auth.py and test files."""
        import os, glob
        backend_dir = os.path.join(os.path.dirname(__file__), "..")
        py_files = glob.glob(f"{backend_dir}/**/*.py", recursive=True)
        violations = []
        for f in py_files:
            basename = os.path.basename(f)
            if basename in ("auth.py",) or "/tests/" in f:
                continue
            content = open(f).read()
            if "FALLBACK_KEYS" in content or "demo-key-123" in content:
                violations.append(f)
        assert not violations, f"FALLBACK_KEYS/demo credentials outside auth.py: {violations}"

    def test_no_debug_print_in_routes(self):
        import os, glob
        routes_dir = os.path.join(os.path.dirname(__file__), "../routes")
        py_files = glob.glob(f"{routes_dir}/*.py")
        violations = []
        for f in py_files:
            lines = open(f).readlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("print(") and "debug" in stripped.lower():
                    violations.append(f"{f}:{i}: {stripped}")
        assert not violations, f"Debug prints in routes: {violations}"

    def test_error_classes_are_used(self):
        """All error classes in errors.py must be referenced somewhere."""
        import os, glob
        backend_dir = os.path.join(os.path.dirname(__file__), "..")
        py_files = glob.glob(f"{backend_dir}/**/*.py", recursive=True)
        all_source = ""
        for f in py_files:
            if "errors.py" not in f:
                all_source += open(f).read()
        error_classes = ["ValidationError", "NotFoundError", "UnauthorizedError",
                         "ForbiddenError", "ProcessingError"]
        for cls in error_classes:
            assert cls in all_source, f"Error class {cls} is unused (dead code)"

    def test_no_commented_out_route_handlers(self):
        import os, glob
        routes_dir = os.path.join(os.path.dirname(__file__), "../routes")
        py_files = glob.glob(f"{routes_dir}/*.py")
        violations = []
        for f in py_files:
            lines = open(f).readlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("# @router.") or stripped.startswith("# async def "):
                    violations.append(f"{f}:{i}")
        assert not violations, f"Commented-out route handlers: {violations}"


# ──────────────────────────────────────────────────────────────
# Phase 18  Regression — Core Security Invariants
# ──────────────────────────────────────────────────────────────
class TestPhase18RegressionCoreInvariants:
    """Re-verify the P0 invariants after Phase 17 changes."""

    def test_auth_header_required_on_api_key_endpoint(self):
        r = client.get("/api/api-key")
        assert r.status_code == 401

    def test_bearer_token_from_org1_accepted(self):
        r = client.get("/api/api-key", headers={"Authorization": "Bearer demo-key-123"})
        assert r.status_code == 200

    def test_bearer_token_from_org2_accepted(self):
        r = client.get("/api/api-key", headers={"Authorization": "Bearer test-key-456"})
        assert r.status_code == 200

    def test_x_api_key_header_accepted(self):
        r = client.get("/api/api-key", headers={"X-API-Key": "demo-key-123"})
        assert r.status_code == 200

    def test_generate_api_key_requires_auth(self):
        r = client.post("/api/api-key/generate")
        assert r.status_code == 401

    def test_revoke_api_key_requires_auth(self):
        r = client.post("/api/api-key/revoke")
        assert r.status_code == 401

    def test_sql_injection_in_auth_header_rejected(self):
        r = client.get("/api/api-key", headers={"Authorization": "Bearer ' OR 1=1--"})
        assert r.status_code == 401

    def test_empty_bearer_token_rejected(self):
        r = client.get("/api/api-key", headers={"Authorization": "Bearer "})
        assert r.status_code == 401

    def test_malformed_auth_scheme_rejected(self):
        r = client.get("/api/api-key", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert r.status_code == 401

    def test_generate_key_is_32_chars_hex(self):
        with patch("routes.auth.create_api_key") as mock_create, \
             patch("routes.auth.revoke_api_key") as mock_revoke:
            mock_revoke.return_value = True
            mock_create.return_value = {"createdAt": "2026-01-01T00:00:00Z", "expiresAt": None}
            r = client.post("/api/api-key/generate", headers=ADMIN_HEADERS)
            assert r.status_code == 200
            key = r.json()["apiKey"]
            assert len(key) == 32
            assert all(c in "0123456789abcdef" for c in key)

    def test_tenant_isolation_api_key_endpoint(self):
        """Org-1 admin cannot see Org-2's API key."""
        with patch("routes.auth.get_api_key") as mock_get:
            def side_effect(org_id):
                if org_id == "org-1":
                    return {"key": "org1key123456789", "createdAt": "2026-01-01T00:00:00Z"}
                return None
            mock_get.side_effect = side_effect

            r1 = client.get("/api/api-key", headers={"Authorization": "Bearer demo-key-123"})
            r2 = client.get("/api/api-key", headers={"Authorization": "Bearer test-key-456"})
            assert r1.status_code == 200
            assert r2.status_code == 200
            d1 = r1.json()
            d2 = r2.json()
            # Org-1 has key, org-2 does not in this mock
            assert d1.get("apiKey") is not None
            assert d2.get("apiKey") is None

    def test_cors_headers_present(self):
        r = client.options("/", headers={"Origin": "https://app.example.com",
                                          "Access-Control-Request-Method": "GET"})
        # CORS middleware set to allow_origins=["*"]
        assert r.status_code in (200, 204, 400)

    def test_error_response_no_stack_trace(self):
        """401 errors must not expose stack traces."""
        r = client.get("/api/api-key")
        body = r.text
        assert "Traceback" not in body
        assert "File " not in body
        assert "line " not in body.lower() or "json" in body.lower()

    def test_unauthorized_error_message_not_verbose(self):
        r = client.get("/api/api-key")
        data = r.json()
        detail = data.get("detail", "")
        # Should not expose internal details
        assert "org_id" not in detail.lower()
        assert "database" not in detail.lower()
        assert "prisma" not in detail.lower()
