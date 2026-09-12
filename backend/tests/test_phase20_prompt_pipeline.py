"""Phase 20: Prompt pipeline tests.

Covers:
  - parse_prompt_content: all input shapes
  - parse_prompt_history: role filtering, type coercion, malformed input
  - derive_prompt_construction_plan: all routing paths
  - build_history_message: user/assistant with/without media
  - _wrap_assistant_file_content: file wrapper logic
  - PromptHistoryMessage / UserTurnInput type invariants
  - SYSTEM_PROMPT content checks
"""

import pytest
from prompts.request_parsing import parse_prompt_content, parse_prompt_history
from prompts.plan import derive_prompt_construction_plan
from prompts.message_builder import build_history_message, _wrap_assistant_file_content
from prompts.system_prompt import SYSTEM_PROMPT
from prompts.prompt_types import UserTurnInput, PromptHistoryMessage


# ──────────────────────────────────────────────────────────────
# parse_prompt_content
# ──────────────────────────────────────────────────────────────
class TestParsePromptContent:
    def test_none_returns_empty(self):
        r = parse_prompt_content(None)
        assert r == {"text": "", "images": [], "videos": []}

    def test_non_dict_returns_empty(self):
        for val in ["string", 42, [], True]:
            r = parse_prompt_content(val)
            assert r["text"] == ""
            assert r["images"] == []
            assert r["videos"] == []

    def test_dict_with_text(self):
        r = parse_prompt_content({"text": "hello"})
        assert r["text"] == "hello"

    def test_dict_with_images(self):
        r = parse_prompt_content({"text": "", "images": ["img1", "img2"]})
        assert r["images"] == ["img1", "img2"]

    def test_dict_with_videos(self):
        r = parse_prompt_content({"text": "", "videos": ["v1"]})
        assert r["videos"] == ["v1"]

    def test_non_string_items_in_images_filtered(self):
        r = parse_prompt_content({"images": ["ok", 42, None, "also_ok"]})
        assert r["images"] == ["ok", "also_ok"]

    def test_non_list_images_returns_empty(self):
        r = parse_prompt_content({"images": "not-a-list"})
        assert r["images"] == []

    def test_full_text_field_parsed(self):
        r = parse_prompt_content({"text": "short", "fullText": "long full text"})
        assert r.get("full_text") == "long full text"

    def test_full_text_whitespace_only_ignored(self):
        r = parse_prompt_content({"text": "x", "fullText": "   "})
        assert "full_text" not in r

    def test_full_text_missing_ok(self):
        r = parse_prompt_content({"text": "x"})
        assert "full_text" not in r

    def test_text_non_string_defaults_empty(self):
        r = parse_prompt_content({"text": 123})
        assert r["text"] == ""

    def test_empty_dict_returns_defaults(self):
        r = parse_prompt_content({})
        assert r == {"text": "", "images": [], "videos": []}

    def test_xss_in_text_preserved_as_is(self):
        r = parse_prompt_content({"text": "<script>alert(1)</script>"})
        assert r["text"] == "<script>alert(1)</script>"


# ──────────────────────────────────────────────────────────────
# parse_prompt_history
# ──────────────────────────────────────────────────────────────
class TestParsePromptHistory:
    def test_none_returns_empty(self):
        assert parse_prompt_history(None) == []

    def test_non_list_returns_empty(self):
        assert parse_prompt_history("bad") == []
        assert parse_prompt_history({}) == []

    def test_valid_user_message(self):
        h = parse_prompt_history([{"role": "user", "text": "hi"}])
        assert len(h) == 1
        assert h[0]["role"] == "user"
        assert h[0]["text"] == "hi"

    def test_valid_assistant_message(self):
        h = parse_prompt_history([{"role": "assistant", "text": "<html/>"}])
        assert len(h) == 1
        assert h[0]["role"] == "assistant"

    def test_invalid_role_filtered(self):
        h = parse_prompt_history([{"role": "system", "text": "nope"}])
        assert h == []

    def test_missing_role_filtered(self):
        h = parse_prompt_history([{"text": "no role"}])
        assert h == []

    def test_non_dict_items_filtered(self):
        h = parse_prompt_history(["not-a-dict", None, 42])
        assert h == []

    def test_mixed_valid_invalid(self):
        raw = [
            {"role": "user", "text": "q1"},
            "garbage",
            {"role": "assistant", "text": "a1"},
            {"role": "bot", "text": "ignored"},
        ]
        h = parse_prompt_history(raw)
        assert len(h) == 2
        assert h[0]["role"] == "user"
        assert h[1]["role"] == "assistant"

    def test_images_parsed_in_history(self):
        h = parse_prompt_history([{"role": "user", "text": "x", "images": ["img1"]}])
        assert h[0]["images"] == ["img1"]

    def test_non_string_images_filtered(self):
        h = parse_prompt_history([{"role": "user", "text": "", "images": ["ok", 42]}])
        assert h[0]["images"] == ["ok"]

    def test_text_non_string_defaults_empty(self):
        h = parse_prompt_history([{"role": "user", "text": 999}])
        assert h[0]["text"] == ""

    def test_videos_parsed(self):
        h = parse_prompt_history([{"role": "user", "text": "", "videos": ["v1"]}])
        assert h[0]["videos"] == ["v1"]

    def test_empty_list_returns_empty(self):
        assert parse_prompt_history([]) == []


# ──────────────────────────────────────────────────────────────
# derive_prompt_construction_plan
# ──────────────────────────────────────────────────────────────
class TestDerivePromptConstructionPlan:
    def _plan(self, **kw):
        defaults = {
            "stack": "html_tailwind",
            "input_mode": "image",
            "generation_type": "create",
            "history": [],
            "file_state": None,
        }
        defaults.update(kw)
        return derive_prompt_construction_plan(**defaults)

    def test_create_returns_create_from_input(self):
        p = self._plan(generation_type="create")
        assert p["construction_strategy"] == "create_from_input"
        assert p["generation_type"] == "create"

    def test_create_preserves_stack(self):
        p = self._plan(generation_type="create", stack="react_tailwind")
        assert p["stack"] == "react_tailwind"

    def test_create_preserves_input_mode(self):
        p = self._plan(generation_type="create", input_mode="video")
        assert p["input_mode"] == "video"

    def test_update_with_history_uses_update_from_history(self):
        history = [{"role": "user", "text": "x", "images": [], "videos": []}]
        p = self._plan(generation_type="update", history=history)
        assert p["construction_strategy"] == "update_from_history"

    def test_update_with_file_state_uses_update_from_file_snapshot(self):
        fs = {"content": "<html>some code</html>", "path": "index.html"}
        p = self._plan(generation_type="update", history=[], file_state=fs)
        assert p["construction_strategy"] == "update_from_file_snapshot"

    def test_update_history_takes_priority_over_file_state(self):
        history = [{"role": "user", "text": "x", "images": [], "videos": []}]
        fs = {"content": "<html/>", "path": "index.html"}
        p = self._plan(generation_type="update", history=history, file_state=fs)
        assert p["construction_strategy"] == "update_from_history"

    def test_update_no_history_no_file_state_raises(self):
        with pytest.raises(ValueError, match="Update requests require"):
            self._plan(generation_type="update", history=[], file_state=None)

    def test_update_empty_file_state_content_raises(self):
        fs = {"content": "   ", "path": "index.html"}
        with pytest.raises(ValueError):
            self._plan(generation_type="update", history=[], file_state=fs)

    def test_plan_returns_all_required_keys(self):
        p = self._plan()
        assert set(p.keys()) == {"generation_type", "input_mode", "stack", "construction_strategy"}


# ──────────────────────────────────────────────────────────────
# build_history_message
# ──────────────────────────────────────────────────────────────
class TestBuildHistoryMessage:
    def _msg(self, **kw) -> PromptHistoryMessage:
        defaults: PromptHistoryMessage = {"role": "user", "text": "hello", "images": [], "videos": []}
        defaults.update(kw)  # type: ignore[typeddict-item]
        return defaults

    def test_user_text_only_returns_string_content(self):
        msg = build_history_message(self._msg(role="user", text="hello", images=[]))
        assert msg["role"] == "user"
        assert msg["content"] == "hello"

    def test_user_with_images_returns_list_content(self):
        msg = build_history_message(self._msg(role="user", text="desc", images=["data:image/png;base64,abc"]))
        assert msg["role"] == "user"
        assert isinstance(msg["content"], list)
        parts = msg["content"]
        image_parts = [p for p in parts if p.get("type") == "image_url"]
        text_parts = [p for p in parts if p.get("type") == "text"]
        assert len(image_parts) == 1
        assert len(text_parts) == 1

    def test_assistant_text_only_wrapped_in_file_tag(self):
        msg = build_history_message(self._msg(role="assistant", text="<html/>", images=[]))
        assert msg["role"] == "assistant"
        content = msg["content"]
        assert isinstance(content, str)
        assert "<file" in content

    def test_assistant_already_wrapped_not_double_wrapped(self):
        wrapped = '<file path="index.html">\n<html/>\n</file>'
        msg = build_history_message(self._msg(role="assistant", text=wrapped, images=[]))
        assert msg["content"].count("<file") == 1

    def test_user_with_videos_treated_as_images(self):
        msg = build_history_message(self._msg(role="user", text="", videos=["v.mp4"], images=[]))
        assert isinstance(msg["content"], list)

    def test_user_with_both_images_and_videos(self):
        msg = build_history_message(self._msg(role="user", text="x", images=["i.png"], videos=["v.mp4"]))
        parts = msg["content"]
        image_parts = [p for p in parts if p.get("type") == "image_url"]
        assert len(image_parts) == 2


# ──────────────────────────────────────────────────────────────
# _wrap_assistant_file_content
# ──────────────────────────────────────────────────────────────
class TestWrapAssistantFileContent:
    def test_wraps_plain_html(self):
        result = _wrap_assistant_file_content("<html>x</html>")
        assert result.startswith('<file path="index.html">')
        assert result.endswith("</file>")

    def test_does_not_double_wrap(self):
        already = '<file path="index.html">\n<html/>\n</file>'
        result = _wrap_assistant_file_content(already)
        assert result.count("<file") == 1

    def test_custom_path(self):
        result = _wrap_assistant_file_content("<div/>", path="app.html")
        assert 'path="app.html"' in result

    def test_strips_leading_trailing_whitespace(self):
        result = _wrap_assistant_file_content("  <html/>  ")
        assert not result.startswith(" ")


# ──────────────────────────────────────────────────────────────
# SYSTEM_PROMPT content checks
# ──────────────────────────────────────────────────────────────
class TestSystemPromptContent:
    def test_system_prompt_is_non_empty_string(self):
        assert isinstance(SYSTEM_PROMPT, str)
        assert len(SYSTEM_PROMPT) > 100

    def test_system_prompt_covers_all_stacks(self):
        stacks = ["html_css", "Tailwind", "Bootstrap", "React", "Ionic", "Vue"]
        for s in stacks:
            assert s in SYSTEM_PROMPT, f"Stack {s} not mentioned in SYSTEM_PROMPT"

    def test_system_prompt_mentions_file_operations(self):
        assert "create_file" in SYSTEM_PROMPT
        assert "edit_file" in SYSTEM_PROMPT

    def test_system_prompt_mentions_screenshot_preview(self):
        assert "screenshot_preview" in SYSTEM_PROMPT

    def test_system_prompt_mentions_index_html(self):
        assert "index.html" in SYSTEM_PROMPT

    def test_system_prompt_no_hardcoded_secrets(self):
        import re
        secret_patterns = [r"sk-[a-zA-Z0-9]{20,}", r"Bearer [a-zA-Z0-9+/]{20,}"]
        for pattern in secret_patterns:
            assert not re.search(pattern, SYSTEM_PROMPT), f"Possible secret in SYSTEM_PROMPT: {pattern}"
