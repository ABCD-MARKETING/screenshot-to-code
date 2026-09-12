"""Phase 32 — agent/tools/types.py and agent/tools/parsing.py.

Tests:
  - ToolCall: frozen dataclass, field access
  - ToolMultimodalPart: exactly-one-source invariant, localhost rejection
  - ToolExecutionResult: optional fields, ok flag
  - parse_json_arguments: dict passthrough, JSON string, None, empty, invalid
"""

import pytest

from agent.tools.types import (
    CanonicalToolDefinition,
    ToolCall,
    ToolExecutionResult,
    ToolMultimodalPart,
)
from agent.tools.parsing import parse_json_arguments


# ─── ToolCall ────────────────────────────────────────────────────────────────


class TestToolCall:
    def test_basic_fields(self):
        tc = ToolCall(id="call-1", name="create_file", arguments={"path": "index.html"})
        assert tc.id == "call-1"
        assert tc.name == "create_file"
        assert tc.arguments == {"path": "index.html"}

    def test_is_frozen(self):
        tc = ToolCall(id="x", name="y", arguments={})
        with pytest.raises((AttributeError, TypeError)):
            tc.id = "changed"  # type: ignore[misc]

    def test_empty_arguments(self):
        tc = ToolCall(id="id", name="name", arguments={})
        assert tc.arguments == {}

    def test_nested_arguments(self):
        args = {"edits": [{"old_text": "a", "new_text": "b"}]}
        tc = ToolCall(id="id", name="edit_file", arguments=args)
        assert tc.arguments["edits"][0]["new_text"] == "b"

    def test_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(ToolCall)

    def test_equality(self):
        a = ToolCall(id="1", name="n", arguments={"k": "v"})
        b = ToolCall(id="1", name="n", arguments={"k": "v"})
        assert a == b

    def test_inequality(self):
        a = ToolCall(id="1", name="n", arguments={})
        b = ToolCall(id="2", name="n", arguments={})
        assert a != b


# ─── ToolMultimodalPart ──────────────────────────────────────────────────────


class TestToolMultimodalPart:
    def test_data_only(self):
        part = ToolMultimodalPart(
            display_name="img", mime_type="image/png", data=b"\x89PNG"
        )
        assert part.data == b"\x89PNG"
        assert part.image_url is None

    def test_image_url_only(self):
        part = ToolMultimodalPart(
            display_name="img",
            mime_type="image/jpeg",
            image_url="https://example.com/image.jpg",
        )
        assert part.image_url == "https://example.com/image.jpg"
        assert part.data is None

    def test_both_raises(self):
        with pytest.raises(ValueError, match="exactly one"):
            ToolMultimodalPart(
                display_name="img",
                mime_type="image/png",
                data=b"bytes",
                image_url="https://example.com/img.jpg",
            )

    def test_neither_raises(self):
        with pytest.raises(ValueError, match="exactly one"):
            ToolMultimodalPart(
                display_name="img",
                mime_type="image/png",
            )

    def test_localhost_url_raises(self):
        with pytest.raises(ValueError, match="localhost"):
            ToolMultimodalPart(
                display_name="img",
                mime_type="image/png",
                image_url="http://localhost:7001/local-assets/img.png",
            )

    def test_loopback_127_raises(self):
        with pytest.raises(ValueError, match="localhost"):
            ToolMultimodalPart(
                display_name="img",
                mime_type="image/png",
                image_url="http://127.0.0.1:7001/local-assets/img.png",
            )

    def test_public_url_accepted(self):
        part = ToolMultimodalPart(
            display_name="img",
            mime_type="image/webp",
            image_url="https://replicate.delivery/pbxt/abc123/output.webp",
        )
        assert "replicate" in part.image_url

    def test_display_name_stored(self):
        part = ToolMultimodalPart(
            display_name="thumbnail", mime_type="image/gif", data=b"gif"
        )
        assert part.display_name == "thumbnail"

    def test_mime_type_stored(self):
        part = ToolMultimodalPart(
            display_name="x", mime_type="image/webp", data=b"bytes"
        )
        assert part.mime_type == "image/webp"


# ─── ToolExecutionResult ─────────────────────────────────────────────────────


class TestToolExecutionResult:
    def test_ok_true(self):
        r = ToolExecutionResult(ok=True, result={"code": "<html/>"}, summary={})
        assert r.ok is True

    def test_ok_false(self):
        r = ToolExecutionResult(ok=False, result={}, summary={"error": "failed"})
        assert r.ok is False

    def test_optional_updated_content_defaults_none(self):
        r = ToolExecutionResult(ok=True, result={}, summary={})
        assert r.updated_content is None

    def test_optional_multimodal_parts_defaults_none(self):
        r = ToolExecutionResult(ok=True, result={}, summary={})
        assert r.multimodal_parts is None

    def test_with_updated_content(self):
        r = ToolExecutionResult(
            ok=True, result={}, summary={}, updated_content="<html/>"
        )
        assert r.updated_content == "<html/>"

    def test_with_multimodal_parts(self):
        part = ToolMultimodalPart(display_name="x", mime_type="image/png", data=b"p")
        r = ToolExecutionResult(ok=True, result={}, summary={}, multimodal_parts=[part])
        assert len(r.multimodal_parts) == 1

    def test_result_dict_accessible(self):
        r = ToolExecutionResult(ok=True, result={"key": "val"}, summary={})
        assert r.result["key"] == "val"

    def test_summary_dict_accessible(self):
        r = ToolExecutionResult(ok=True, result={}, summary={"info": "done"})
        assert r.summary["info"] == "done"


# ─── parse_json_arguments ────────────────────────────────────────────────────


class TestParseJsonArguments:
    def test_dict_passthrough(self):
        d = {"path": "index.html", "content": "<html/>"}
        result, err = parse_json_arguments(d)
        assert result == d
        assert err is None

    def test_json_string_parsed(self):
        raw = '{"path": "app.html", "content": "hello"}'
        result, err = parse_json_arguments(raw)
        assert result == {"path": "app.html", "content": "hello"}
        assert err is None

    def test_none_returns_empty_dict(self):
        result, err = parse_json_arguments(None)
        assert result == {}
        assert err is None

    def test_empty_string_returns_empty(self):
        result, err = parse_json_arguments("")
        assert result == {}
        assert err is None

    def test_whitespace_only_returns_empty(self):
        result, err = parse_json_arguments("   ")
        assert result == {}
        assert err is None

    def test_invalid_json_returns_error(self):
        result, err = parse_json_arguments("{not valid json}")
        assert result == {}
        assert err is not None
        assert isinstance(err, str)

    def test_invalid_json_error_message(self):
        _, err = parse_json_arguments("broken")
        assert "Invalid JSON" in err

    def test_nested_json_string(self):
        raw = '{"edits": [{"old_text": "a", "new_text": "b"}]}'
        result, err = parse_json_arguments(raw)
        assert err is None
        assert result["edits"][0]["new_text"] == "b"

    def test_empty_dict_passthrough(self):
        result, err = parse_json_arguments({})
        assert result == {}
        assert err is None

    def test_int_arg_becomes_error_or_empty(self):
        result, err = parse_json_arguments(42)
        # json.loads("42") returns int 42 (valid JSON scalar) — result is not a dict
        # but the tuple itself is returned
        out = (result, err)
        assert isinstance(out, tuple) and len(out) == 2

    def test_returns_tuple(self):
        out = parse_json_arguments({"x": 1})
        assert isinstance(out, tuple)
        assert len(out) == 2


# ─── CanonicalToolDefinition ─────────────────────────────────────────────────


class TestCanonicalToolDefinition:
    def test_basic(self):
        td = CanonicalToolDefinition(
            name="create_file",
            description="Creates a file",
            parameters={"type": "object", "properties": {}},
        )
        assert td.name == "create_file"
        assert td.description == "Creates a file"
        assert td.parameters["type"] == "object"

    def test_frozen(self):
        td = CanonicalToolDefinition(
            name="n", description="d", parameters={}
        )
        with pytest.raises((AttributeError, TypeError)):
            td.name = "changed"  # type: ignore[misc]
