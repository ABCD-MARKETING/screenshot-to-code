"""Phase 21: Agent runner + agent tools tests.

Covers:
  - parse_json_arguments: dict pass-through, JSON string, malformed
  - extract_content_from_args / extract_path_from_args: dict and partial-JSON paths
  - ensure_str: None/int/str coercion
  - AgentFileState: defaults, mutation
  - seed_file_state_from_messages: seeds from assistant message, skips user role
  - AgentToolRuntime.execute: routing dispatch + invalid JSON fast-path
  - AgentToolRuntime._create_file: success, empty content, path defaulting
  - AgentToolRuntime._edit_file: success, old_text not found, no file yet, multi-edit
  - AgentToolRuntime._retrieve_option: option_number, index, out-of-range, empty code
  - summarize_text: truncation, passthrough
  - summarize_tool_input: create_file, edit_file, generate_images, unknown tool
"""

import pytest
from agent.tools.parsing import (
    parse_json_arguments,
    extract_content_from_args,
    extract_path_from_args,
)
from agent.state import ensure_str, AgentFileState, seed_file_state_from_messages
from agent.tools.runtime import AgentToolRuntime
from agent.tools.summaries import summarize_text, summarize_tool_input
from agent.tools.types import ToolCall


# ──────────────────────────────────────────────────────────────
# ensure_str
# ──────────────────────────────────────────────────────────────
class TestEnsureStr:
    def test_none_returns_empty(self):
        assert ensure_str(None) == ""

    def test_str_returns_as_is(self):
        assert ensure_str("hello") == "hello"

    def test_int_converts_to_str(self):
        assert ensure_str(42) == "42"

    def test_empty_str_returns_empty(self):
        assert ensure_str("") == ""

    def test_list_converts_to_str(self):
        result = ensure_str([1, 2])
        assert isinstance(result, str)


# ──────────────────────────────────────────────────────────────
# parse_json_arguments
# ──────────────────────────────────────────────────────────────
class TestParseJsonArguments:
    def test_dict_passthrough(self):
        d = {"key": "val"}
        result, err = parse_json_arguments(d)
        assert result == d
        assert err is None

    def test_json_string_parsed(self):
        result, err = parse_json_arguments('{"a": 1}')
        assert result == {"a": 1}
        assert err is None

    def test_none_returns_empty_dict(self):
        result, err = parse_json_arguments(None)
        assert result == {}
        assert err is None

    def test_empty_string_returns_empty_dict(self):
        result, err = parse_json_arguments("")
        assert result == {}
        assert err is None

    def test_malformed_json_returns_error(self):
        result, err = parse_json_arguments("{bad json}")
        assert result == {}
        assert err is not None
        assert "Invalid JSON" in err

    def test_nested_json_parsed(self):
        result, err = parse_json_arguments('{"edits": [{"old_text": "a"}]}')
        assert result["edits"][0]["old_text"] == "a"
        assert err is None


# ──────────────────────────────────────────────────────────────
# extract_content_from_args / extract_path_from_args
# ──────────────────────────────────────────────────────────────
class TestExtractArgsHelpers:
    def test_extract_content_from_dict(self):
        assert extract_content_from_args({"content": "hello"}) == "hello"

    def test_extract_content_missing_key_returns_none(self):
        assert extract_content_from_args({"other": "x"}) is None

    def test_extract_path_from_dict(self):
        assert extract_path_from_args({"path": "app.html"}) == "app.html"

    def test_extract_path_missing_key_returns_none(self):
        assert extract_path_from_args({"content": "x"}) is None

    def test_extract_content_from_partial_json_string(self):
        raw = '{"content": "partial value"}'
        result = extract_content_from_args(raw)
        assert result == "partial value"

    def test_extract_path_from_partial_json_string(self):
        raw = '{"path": "index.html"}'
        result = extract_path_from_args(raw)
        assert result == "index.html"

    def test_extract_content_from_none_args(self):
        result = extract_content_from_args(None)
        assert result is None or result == ""

    def test_extract_path_from_none_dict_key(self):
        result = extract_path_from_args({"path": None})
        assert result is None


# ──────────────────────────────────────────────────────────────
# AgentFileState
# ──────────────────────────────────────────────────────────────
class TestAgentFileState:
    def test_defaults(self):
        fs = AgentFileState()
        assert fs.path == "index.html"
        assert fs.content == ""

    def test_mutation(self):
        fs = AgentFileState()
        fs.content = "<html/>"
        fs.path = "app.html"
        assert fs.content == "<html/>"
        assert fs.path == "app.html"

    def test_custom_init(self):
        fs = AgentFileState(path="main.html", content="<body/>")
        assert fs.path == "main.html"
        assert fs.content == "<body/>"


# ──────────────────────────────────────────────────────────────
# seed_file_state_from_messages
# ──────────────────────────────────────────────────────────────
class TestSeedFileStateFromMessages:
    def test_seeds_from_assistant_message(self):
        fs = AgentFileState()
        msgs = [{"role": "assistant", "content": "<html><body>hi</body></html>"}]
        seed_file_state_from_messages(fs, msgs)
        assert "html" in fs.content.lower()

    def test_skips_if_content_already_set(self):
        fs = AgentFileState(content="existing")
        msgs = [{"role": "assistant", "content": "<html/>"}]
        seed_file_state_from_messages(fs, msgs)
        assert fs.content == "existing"

    def test_no_messages_leaves_state_empty(self):
        fs = AgentFileState()
        seed_file_state_from_messages(fs, [])
        assert fs.content == ""

    def test_user_messages_not_used(self):
        fs = AgentFileState()
        msgs = [{"role": "user", "content": "<html/>"}]
        seed_file_state_from_messages(fs, msgs)
        assert fs.content == ""

    def test_seeds_path_to_index_html(self):
        fs = AgentFileState(path="")
        msgs = [{"role": "assistant", "content": "<html/>"}]
        seed_file_state_from_messages(fs, msgs)
        assert fs.path == "index.html"


# ──────────────────────────────────────────────────────────────
# AgentToolRuntime helpers
# ──────────────────────────────────────────────────────────────
def _make_runtime(**kw) -> AgentToolRuntime:
    defaults = dict(
        file_state=AgentFileState(),
        should_generate_images=False,
        openai_api_key=None,
        openai_base_url=None,
    )
    defaults.update(kw)
    return AgentToolRuntime(**defaults)


def _tool(name: str, arguments: dict) -> ToolCall:
    return ToolCall(id="t1", name=name, arguments=arguments)


class TestAgentToolRuntimeCreateFile:
    def test_create_file_success(self):
        rt = _make_runtime()
        result = rt._create_file({"path": "index.html", "content": "<html/>"})
        assert result.ok
        assert rt.file_state.content != ""
        assert rt.file_state.path == "index.html"

    def test_create_file_empty_content_fails(self):
        rt = _make_runtime()
        result = rt._create_file({"path": "index.html", "content": ""})
        assert not result.ok
        assert "content" in result.result["error"].lower()

    def test_create_file_defaults_path(self):
        rt = _make_runtime()
        result = rt._create_file({"content": "<html/>"})
        assert result.ok
        assert rt.file_state.path == "index.html"

    def test_create_file_custom_path(self):
        rt = _make_runtime()
        rt._create_file({"path": "app.html", "content": "<div/>"})
        assert rt.file_state.path == "app.html"

    def test_create_file_sets_updated_content(self):
        rt = _make_runtime()
        result = rt._create_file({"content": "<html/>"})
        assert result.updated_content is not None
        assert len(result.updated_content) > 0


class TestAgentToolRuntimeEditFile:
    def _rt_with_content(self, content="<html><body>hello</body></html>"):
        rt = _make_runtime()
        rt._create_file({"content": content})
        return rt

    def test_edit_file_success(self):
        rt = self._rt_with_content()
        result = rt._edit_file({"old_text": "hello", "new_text": "world"})
        assert result.ok
        assert "world" in rt.file_state.content

    def test_edit_file_old_text_not_found_fails(self):
        rt = self._rt_with_content()
        result = rt._edit_file({"old_text": "DOES_NOT_EXIST", "new_text": "x"})
        assert not result.ok
        assert "not found" in result.result["error"].lower()

    def test_edit_file_no_existing_file_fails(self):
        rt = _make_runtime()
        result = rt._edit_file({"old_text": "x", "new_text": "y"})
        assert not result.ok
        assert "create_file" in result.result["error"]

    def test_edit_file_multi_edit_list(self):
        rt = self._rt_with_content("<html><p>one</p><p>two</p></html>")
        result = rt._edit_file({
            "edits": [
                {"old_text": "one", "new_text": "ONE"},
                {"old_text": "two", "new_text": "TWO"},
            ]
        })
        assert result.ok
        assert "ONE" in rt.file_state.content
        assert "TWO" in rt.file_state.content

    def test_edit_file_generates_diff(self):
        rt = self._rt_with_content("<html>old</html>")
        result = rt._edit_file({"old_text": "old", "new_text": "new"})
        assert result.ok
        assert "diff" in result.summary

    def test_edit_file_invalid_edits_type(self):
        rt = self._rt_with_content()
        result = rt._edit_file({"edits": "not-a-list"})
        assert not result.ok


class TestAgentToolRuntimeRetrieveOption:
    def _rt_with_options(self, codes=None):
        if codes is None:
            codes = ["<html>opt1</html>", "<html>opt2</html>"]
        return _make_runtime(option_codes=codes)

    def test_retrieve_by_option_number(self):
        rt = self._rt_with_options()
        result = rt._retrieve_option({"option_number": 1})
        assert result.ok
        assert "opt1" in result.result["code"]

    def test_retrieve_by_index(self):
        rt = self._rt_with_options()
        result = rt._retrieve_option({"index": 1})
        assert result.ok
        assert "opt2" in result.result["code"]

    def test_retrieve_out_of_range(self):
        rt = self._rt_with_options()
        result = rt._retrieve_option({"option_number": 99})
        assert not result.ok
        assert "out of range" in result.result["error"].lower()

    def test_retrieve_missing_option_number(self):
        rt = self._rt_with_options()
        result = rt._retrieve_option({})
        assert not result.ok

    def test_retrieve_empty_code_fails(self):
        rt = self._rt_with_options(codes=["   "])
        result = rt._retrieve_option({"option_number": 1})
        assert not result.ok


class TestAgentToolRuntimeExecuteDispatch:
    def test_unknown_tool_returns_error(self):
        rt = _make_runtime()
        tc = _tool("nonexistent_tool", {})
        import asyncio
        result = asyncio.run(rt.execute(tc))
        assert not result.ok
        assert "Unknown tool" in result.result["error"]

    def test_invalid_json_sentinel_short_circuits(self):
        rt = _make_runtime()
        tc = _tool("create_file", {"INVALID_JSON": '{"broken"'})
        import asyncio
        result = asyncio.run(rt.execute(tc))
        assert not result.ok
        assert "invalid json" in result.result["error"].lower()

    def test_generate_images_disabled_returns_error(self):
        rt = _make_runtime(should_generate_images=False)
        tc = _tool("generate_images", {"prompts": ["a cat"]})
        import asyncio
        result = asyncio.run(rt.execute(tc))
        assert not result.ok
        assert "disabled" in result.result["error"].lower()


# ──────────────────────────────────────────────────────────────
# summarize_text
# ──────────────────────────────────────────────────────────────
class TestSummarizeText:
    def test_short_string_passthrough(self):
        assert summarize_text("hi", 100) == "hi"

    def test_truncates_long_string(self):
        result = summarize_text("x" * 500, 100)
        assert len(result) <= 104
        assert "..." in result

    def test_exact_limit_passthrough(self):
        s = "a" * 100
        assert summarize_text(s, 100) == s

    def test_default_limit(self):
        result = summarize_text("z" * 500)
        assert "..." in result


# ──────────────────────────────────────────────────────────────
# summarize_tool_input
# ──────────────────────────────────────────────────────────────
class TestSummarizeToolInput:
    def _fs(self):
        return AgentFileState()

    def test_create_file_summary(self):
        tc = ToolCall(id="t", name="create_file", arguments={"content": "<html/>", "path": "index.html"})
        summary = summarize_tool_input(tc, self._fs())
        assert "contentLength" in summary

    def test_edit_file_summary_list(self):
        tc = ToolCall(id="t", name="edit_file", arguments={
            "edits": [{"old_text": "old", "new_text": "new"}]
        })
        summary = summarize_tool_input(tc, self._fs())
        assert "edits" in summary

    def test_generate_images_summary(self):
        tc = ToolCall(id="t", name="generate_images", arguments={"prompts": ["a cat", "a dog"]})
        summary = summarize_tool_input(tc, self._fs())
        assert summary["count"] == 2

    def test_unknown_tool_returns_raw_args(self):
        tc = ToolCall(id="t", name="made_up_tool", arguments={"foo": "bar"})
        summary = summarize_tool_input(tc, self._fs())
        assert summary["foo"] == "bar"
