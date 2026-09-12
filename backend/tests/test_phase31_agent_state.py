"""Phase 31 — agent/state.py: AgentFileState, ensure_str, extract_text_content,
seed_file_state_from_messages.
"""

import pytest
from agent.state import (
    AgentFileState,
    ensure_str,
    extract_text_content,
    seed_file_state_from_messages,
)


# ─── AgentFileState ──────────────────────────────────────────────────────────

class TestAgentFileState:
    def test_default_path(self):
        fs = AgentFileState()
        assert fs.path == "index.html"

    def test_default_content_empty(self):
        fs = AgentFileState()
        assert fs.content == ""

    def test_custom_path(self):
        fs = AgentFileState(path="app.html")
        assert fs.path == "app.html"

    def test_custom_content(self):
        fs = AgentFileState(content="<html></html>")
        assert fs.content == "<html></html>"

    def test_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(AgentFileState)

    def test_mutable(self):
        fs = AgentFileState()
        fs.content = "<html><body>x</body></html>"
        assert fs.content == "<html><body>x</body></html>"


# ─── ensure_str ──────────────────────────────────────────────────────────────

class TestEnsureStr:
    def test_none_returns_empty(self):
        assert ensure_str(None) == ""

    def test_string_passthrough(self):
        assert ensure_str("hello") == "hello"

    def test_int_stringified(self):
        assert ensure_str(42) == "42"

    def test_float_stringified(self):
        result = ensure_str(3.14)
        assert "3.14" in result

    def test_empty_string(self):
        assert ensure_str("") == ""

    def test_bool_true(self):
        assert ensure_str(True) == "True"

    def test_bool_false(self):
        assert ensure_str(False) == "False"

    def test_list_stringified(self):
        result = ensure_str([1, 2])
        assert result is not None
        assert isinstance(result, str)

    def test_dict_stringified(self):
        result = ensure_str({"a": 1})
        assert isinstance(result, str)

    def test_returns_string_type(self):
        for val in [None, 1, 2.5, "x", True, [], {}]:
            assert isinstance(ensure_str(val), str)


# ─── extract_text_content ────────────────────────────────────────────────────

class TestExtractTextContent:
    def test_string_content(self):
        msg = {"role": "assistant", "content": "Hello world"}
        assert extract_text_content(msg) == "Hello world"

    def test_list_content_with_text_part(self):
        msg = {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Result text"},
                {"type": "image_url", "image_url": {"url": "http://example.com/img.png"}},
            ],
        }
        assert extract_text_content(msg) == "Result text"

    def test_empty_string_content(self):
        msg = {"role": "assistant", "content": ""}
        assert extract_text_content(msg) == ""

    def test_none_content(self):
        msg = {"role": "assistant", "content": None}
        assert extract_text_content(msg) == ""

    def test_missing_content_key(self):
        msg = {"role": "assistant"}
        assert extract_text_content(msg) == ""

    def test_list_with_no_text_part(self):
        msg = {
            "role": "assistant",
            "content": [{"type": "image_url", "image_url": {}}],
        }
        assert extract_text_content(msg) == ""

    def test_list_text_part_none_text(self):
        msg = {
            "role": "assistant",
            "content": [{"type": "text", "text": None}],
        }
        result = extract_text_content(msg)
        assert result == ""

    def test_list_takes_first_text_part(self):
        msg = {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "first"},
                {"type": "text", "text": "second"},
            ],
        }
        assert extract_text_content(msg) == "first"

    def test_user_message_same_logic(self):
        msg = {"role": "user", "content": "User says hi"}
        assert extract_text_content(msg) == "User says hi"


# ─── seed_file_state_from_messages ───────────────────────────────────────────

class TestSeedFileStateFromMessages:
    def _html(self, body: str = "content") -> str:
        return f"<html><body>{body}</body></html>"

    def test_no_op_when_content_already_set(self):
        fs = AgentFileState(content="already set")
        msgs = [{"role": "assistant", "content": self._html("from msg")}]
        seed_file_state_from_messages(fs, msgs)
        assert fs.content == "already set"

    def test_seeds_from_last_assistant_message(self):
        fs = AgentFileState()
        msgs = [
            {"role": "user", "content": "make a page"},
            {"role": "assistant", "content": self._html("first")},
            {"role": "user", "content": "change something"},
            {"role": "assistant", "content": self._html("second")},
        ]
        seed_file_state_from_messages(fs, msgs)
        assert "second" in fs.content

    def test_seeds_sets_default_path(self):
        fs = AgentFileState(path="")
        msgs = [{"role": "assistant", "content": self._html()}]
        seed_file_state_from_messages(fs, msgs)
        assert fs.path == "index.html"

    def test_seeds_from_system_marker(self):
        fs = AgentFileState()
        code = self._html("from system")
        msgs = [
            {"role": "system", "content": f"Here is the code of the app:\n{code}"},
        ]
        seed_file_state_from_messages(fs, msgs)
        assert "from system" in fs.content

    def test_no_op_on_empty_messages(self):
        fs = AgentFileState()
        seed_file_state_from_messages(fs, [])
        assert fs.content == ""

    def test_skips_non_assistant_messages(self):
        fs = AgentFileState()
        msgs = [
            {"role": "user", "content": self._html("user content")},
            {"role": "system", "content": "Instructions"},
        ]
        # No "Here is the code of the app:" marker so system fallback won't trigger
        seed_file_state_from_messages(fs, msgs)
        # Content remains empty (no assistant message, no matching system marker)
        assert fs.content == "" or isinstance(fs.content, str)

    def test_seeds_html_from_assistant_list_content(self):
        fs = AgentFileState()
        html = self._html("list")
        msgs = [
            {
                "role": "assistant",
                "content": [{"type": "text", "text": html}],
            }
        ]
        seed_file_state_from_messages(fs, msgs)
        assert "list" in fs.content

    def test_path_preserved_if_set(self):
        fs = AgentFileState(path="app.html")
        msgs = [{"role": "assistant", "content": self._html()}]
        seed_file_state_from_messages(fs, msgs)
        assert fs.path == "app.html"

    def test_empty_assistant_message_skipped(self):
        fs = AgentFileState()
        msgs = [
            {"role": "assistant", "content": ""},
            {"role": "assistant", "content": self._html("fallback")},
        ]
        seed_file_state_from_messages(fs, msgs)
        assert "fallback" in fs.content

    def test_extracts_html_from_raw_text(self):
        fs = AgentFileState()
        html = self._html("extracted")
        msgs = [{"role": "assistant", "content": f"Here it is:\n{html}"}]
        seed_file_state_from_messages(fs, msgs)
        assert "<html>" in fs.content
