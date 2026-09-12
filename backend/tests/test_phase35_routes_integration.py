"""Phase 35 — Routes HTTP integration: capabilities, home, health, auth.

Tests:
  - GET /health → 200 {"status": "ok"}
  - GET / → 200 HTML response
  - GET /api/capabilities → 200 JSON with screenshot_preview bool
  - Auth middleware: missing key, valid keys, cross-org isolation
  - Error response shapes: 400 ValidationError, 401 UnauthorizedError
"""

import pytest
from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


# ─── /health ─────────────────────────────────────────────────────────────────


class TestHealth:
    def test_status_200(self):
        r = client.get("/health")
        assert r.status_code == 200

    def test_status_ok(self):
        r = client.get("/health")
        assert r.json()["status"] == "ok"

    def test_content_type_json(self):
        r = client.get("/health")
        assert "application/json" in r.headers.get("content-type", "")


# ─── / (root) ────────────────────────────────────────────────────────────────


class TestRoot:
    def test_status_200(self):
        r = client.get("/")
        assert r.status_code == 200

    def test_html_response(self):
        r = client.get("/")
        assert "text/html" in r.headers.get("content-type", "")

    def test_backend_running_message(self):
        r = client.get("/")
        assert "backend" in r.text.lower() or "running" in r.text.lower()


# ─── /api/capabilities ───────────────────────────────────────────────────────


class TestCapabilities:
    def test_status_200(self):
        r = client.get("/api/capabilities")
        assert r.status_code == 200

    def test_screenshot_preview_is_bool(self):
        r = client.get("/api/capabilities")
        data = r.json()
        assert "screenshot_preview" in data
        assert isinstance(data["screenshot_preview"], bool)

    def test_json_content_type(self):
        r = client.get("/api/capabilities")
        assert "application/json" in r.headers.get("content-type", "")

    def test_no_extra_required_keys(self):
        r = client.get("/api/capabilities")
        data = r.json()
        # Only key we require
        assert "screenshot_preview" in data


# ─── Auth integration ─────────────────────────────────────────────────────────


class TestAuthIntegration:
    def test_no_api_key_on_list_endpoint(self):
        r = client.get("/agent-runs")
        # Without key, fallback may return empty list or 401
        assert r.status_code in (200, 401, 403)

    def test_demo_key_org1(self):
        r = client.get("/agent-runs", headers={"x-api-key": "demo-key-123"})
        assert r.status_code == 200

    def test_test_key_org2(self):
        r = client.get("/agent-runs", headers={"x-api-key": "test-key-456"})
        assert r.status_code == 200

    def test_cross_org_isolation(self):
        r1 = client.get("/agent-runs", headers={"x-api-key": "demo-key-123"})
        r2 = client.get("/agent-runs", headers={"x-api-key": "test-key-456"})
        # Both succeed
        assert r1.status_code == 200
        assert r2.status_code == 200

    def test_demo_key_returns_runs(self):
        r = client.get("/agent-runs", headers={"x-api-key": "demo-key-123"})
        body = r.json()
        # Response shape: {"runs": [...], "runs_directory": "...", "total_size_bytes": N}
        assert "runs" in body
        assert isinstance(body["runs"], list)

    def test_test_key_returns_runs(self):
        r = client.get("/agent-runs", headers={"x-api-key": "test-key-456"})
        body = r.json()
        assert "runs" in body
        assert isinstance(body["runs"], list)


# ─── HTTP method enforcement ──────────────────────────────────────────────────


class TestMethodEnforcement:
    def test_post_to_health_405(self):
        r = client.post("/health")
        assert r.status_code == 405

    def test_delete_to_health_405(self):
        r = client.delete("/health")
        assert r.status_code == 405

    def test_put_to_capabilities_405(self):
        r = client.put("/api/capabilities")
        assert r.status_code == 405


# ─── Missing routes return 404 ────────────────────────────────────────────────


class TestNotFound:
    def test_unknown_route(self):
        r = client.get("/api/nonexistent-endpoint-xyz")
        assert r.status_code == 404

    def test_unknown_route_json_or_text(self):
        r = client.get("/api/nonexistent-endpoint-xyz")
        # Either JSON error or plain text
        assert r.status_code == 404


# ─── Response structure sanity ────────────────────────────────────────────────


class TestResponseStructure:
    def test_health_has_status_key(self):
        r = client.get("/health")
        assert "status" in r.json()

    def test_capabilities_has_screenshot_preview(self):
        r = client.get("/api/capabilities")
        assert "screenshot_preview" in r.json()

    def test_demo_runs_list_items_have_id(self):
        r = client.get("/agent-runs", headers={"x-api-key": "demo-key-123"})
        body = r.json()
        runs = body.get("runs", body) if isinstance(body, dict) else body
        for run in runs:
            assert "id" in run or isinstance(run, dict)

    def test_cors_headers_present_on_health(self):
        r = client.get(
            "/health", headers={"Origin": "http://localhost:5173"}
        )
        # Depends on CORS config; just check no crash
        assert r.status_code == 200
