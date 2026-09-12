"""Phase 23: Eval sets + eval sessions pipeline tests.

Covers:
  - eval_sets._validate_set_name: valid/invalid names, path-traversal attempts
  - eval_sets.InvalidSetNameError / EvalSetNotFoundError raised correctly
  - eval_sets.EvalSetInfo, EvalSetImage, EvalSetBrief dataclass shapes
  - eval_sessions.default_session_name: returns non-empty string
  - eval_sessions.EvalSession dataclass defaults
  - routes._is_stale_running: old running → stale, completed → not stale, new → not stale
  - Route endpoints via TestClient (no filesystem setup needed for these):
      GET /eval-sets               → 200 list
      GET /eval-sets/{missing}     → 400 or 404
      GET /eval-sessions           → 200 with sessions key
      GET /eval-sessions/active    → 200 (None when none active)
      POST /eval-sessions          → 400/404 for unknown eval set
"""

import pytest
from datetime import datetime, timedelta

from evals.sets import (
    _validate_set_name,
    InvalidSetNameError,
    EvalSetNotFoundError,
    EvalSetInfo,
    EvalSetImage,
    EvalSetBrief,
)
from evals.sessions import default_session_name, EvalSession
from routes.eval_sets import _is_stale_running
from fastapi.testclient import TestClient


# ──────────────────────────────────────────────────────────────
# _validate_set_name
# ──────────────────────────────────────────────────────────────
class TestValidateSetName:
    def test_simple_alpha(self):
        assert _validate_set_name("myevals") == "myevals"

    def test_alphanumeric_with_dash_underscore(self):
        assert _validate_set_name("jun-21-evals") == "jun-21-evals"
        assert _validate_set_name("Landing_Pages") == "Landing_Pages"

    def test_name_with_space(self):
        assert _validate_set_name("Landing Pages v2") == "Landing Pages v2"

    def test_name_with_dots(self):
        assert _validate_set_name("v1.2.3") == "v1.2.3"

    def test_slash_raises(self):
        with pytest.raises(InvalidSetNameError):
            _validate_set_name("../../etc/passwd")

    def test_empty_raises(self):
        with pytest.raises(InvalidSetNameError):
            _validate_set_name("")

    def test_leading_dash_raises(self):
        with pytest.raises(InvalidSetNameError):
            _validate_set_name("-badname")

    def test_leading_space_raises(self):
        with pytest.raises(InvalidSetNameError):
            _validate_set_name(" badname")

    def test_special_chars_raises(self):
        with pytest.raises(InvalidSetNameError):
            _validate_set_name("bad!name")

    def test_single_char_valid(self):
        assert _validate_set_name("a") == "a"


# ──────────────────────────────────────────────────────────────
# EvalSetInfo dataclass shape
# ──────────────────────────────────────────────────────────────
class TestEvalSetInfoShape:
    def test_required_fields(self):
        info = EvalSetInfo(
            name="test",
            display_name="Test Set",
            created_at=None,
            notes="",
            image_count=0,
        )
        assert info.name == "test"
        assert info.kind == "image"

    def test_text_kind(self):
        info = EvalSetInfo(
            name="text-set",
            display_name="Text Set",
            created_at="2026-01-01",
            notes="brief evals",
            image_count=0,
            kind="text",
        )
        assert info.kind == "text"


class TestEvalSetImageShape:
    def test_fields(self):
        img = EvalSetImage(
            filename="test.png",
            sha256="abc123",
            size_bytes=1024,
            mtime=1700000000.0,
            tags=["tag1"],
        )
        assert img.filename == "test.png"
        assert img.sha256 == "abc123"
        assert img.tags == ["tag1"]


class TestEvalSetBriefShape:
    def test_fields(self):
        b = EvalSetBrief(id="brief-1", title="Test Brief", brief="Build X", tests="check Y")
        assert b.id == "brief-1"
        assert b.title == "Test Brief"


# ──────────────────────────────────────────────────────────────
# default_session_name
# ──────────────────────────────────────────────────────────────
class TestDefaultSessionName:
    def test_returns_non_empty_string(self):
        name = default_session_name()
        assert isinstance(name, str)
        assert len(name) > 0

    def test_contains_session_word(self):
        assert "session" in default_session_name().lower()

    def test_contains_current_month(self):
        month = datetime.now().strftime("%b")
        assert month in default_session_name()


# ──────────────────────────────────────────────────────────────
# EvalSession dataclass
# ──────────────────────────────────────────────────────────────
class TestEvalSessionShape:
    def test_fields(self):
        s = EvalSession(
            session_id="sess_abc",
            name="June session",
            eval_set="my-set",
            created_at="2026-06-01T10:00:00",
            is_active=True,
        )
        assert s.session_id == "sess_abc"
        assert s.is_active is True


# ──────────────────────────────────────────────────────────────
# _is_stale_running
# ──────────────────────────────────────────────────────────────
class TestIsStaleRunning:
    def test_completed_never_stale(self):
        old_ts = (datetime.now() - timedelta(hours=10)).isoformat()
        assert _is_stale_running("completed", old_ts) is False

    def test_failed_never_stale(self):
        old_ts = (datetime.now() - timedelta(hours=10)).isoformat()
        assert _is_stale_running("failed", old_ts) is False

    def test_running_old_is_stale(self):
        old_ts = (datetime.now() - timedelta(hours=3)).isoformat()
        assert _is_stale_running("running", old_ts) is True

    def test_running_recent_not_stale(self):
        recent_ts = (datetime.now() - timedelta(minutes=10)).isoformat()
        assert _is_stale_running("running", recent_ts) is False

    def test_running_invalid_timestamp_is_stale(self):
        assert _is_stale_running("running", "not-a-timestamp") is True

    def test_empty_status_not_stale(self):
        old_ts = (datetime.now() - timedelta(hours=5)).isoformat()
        assert _is_stale_running("", old_ts) is False


# ──────────────────────────────────────────────────────────────
# Route endpoints via TestClient
# ──────────────────────────────────────────────────────────────
@pytest.fixture
def client():
    from main import app
    return TestClient(app)


class TestEvalSetsRoutes:
    def test_list_eval_sets_returns_200(self, client):
        r = client.get("/eval-sets")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_missing_eval_set_returns_400_or_404(self, client):
        r = client.get("/eval-sets/../../../../etc/passwd")
        assert r.status_code in (400, 404)

    def test_get_nonexistent_set_returns_400_or_404(self, client):
        r = client.get("/eval-sets/does-not-exist-set-xyz")
        assert r.status_code in (400, 404)

    def test_list_response_items_have_required_keys(self, client):
        r = client.get("/eval-sets")
        items = r.json()
        for item in items:
            assert "name" in item
            assert "image_count" in item


class TestEvalSessionsRoutes:
    def test_list_eval_sessions_returns_200(self, client):
        r = client.get("/eval-sessions")
        assert r.status_code == 200
        data = r.json()
        assert "sessions" in data
        assert isinstance(data["sessions"], list)

    def test_get_active_session_returns_200(self, client):
        r = client.get("/eval-sessions/active")
        assert r.status_code == 200

    def test_create_session_unknown_set_returns_404(self, client):
        r = client.post("/eval-sessions", json={"eval_set": "nonexistent-xyz-set"})
        assert r.status_code == 404

    def test_create_session_invalid_set_name_returns_400(self, client):
        r = client.post("/eval-sessions", json={"eval_set": "../../bad"})
        assert r.status_code == 400

    def test_activate_nonexistent_session_returns_404(self, client):
        r = client.post("/eval-sessions/does-not-exist/activate")
        assert r.status_code == 404

    def test_get_matrix_nonexistent_session_returns_404(self, client):
        r = client.get("/eval-sessions/does-not-exist/matrix")
        assert r.status_code == 404

    def test_model_order_nonexistent_session_returns_404(self, client):
        r = client.put(
            "/eval-sessions/does-not-exist/model-order",
            json={"models": ["gpt-4o"]},
        )
        assert r.status_code == 404

    def test_model_notes_nonexistent_session_returns_404(self, client):
        r = client.put(
            "/eval-sessions/does-not-exist/model-notes",
            json={"model": "gpt-4o", "notes": "test"},
        )
        assert r.status_code == 404
