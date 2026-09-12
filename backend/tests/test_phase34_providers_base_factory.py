"""Phase 34 — agent/providers/base.py and agent/providers/factory.py.

Tests:
  - StreamEvent: dataclass, literal type field, optional tool fields
  - ProviderTurn: assistant_text, tool_calls, assistant_turn optional
  - ExecutedToolCall: tool_call + result
  - create_provider_session: raises for wrong model/missing key
"""

import pytest
from dataclasses import dataclass

from agent.providers.base import (
    ExecutedToolCall,
    ProviderSession,
    ProviderTurn,
    StreamEvent,
    StreamEventType,
)
from agent.tools.types import ToolCall, ToolExecutionResult


# ─── StreamEvent ─────────────────────────────────────────────────────────────


class TestStreamEvent:
    def test_assistant_delta(self):
        e = StreamEvent(type="assistant_delta", text="Hello")
        assert e.type == "assistant_delta"
        assert e.text == "Hello"

    def test_thinking_delta(self):
        e = StreamEvent(type="thinking_delta", text="thinking...")
        assert e.type == "thinking_delta"

    def test_tool_call_delta(self):
        e = StreamEvent(
            type="tool_call_delta",
            tool_call_id="call-1",
            tool_name="create_file",
            tool_arguments={"path": "index.html"},
        )
        assert e.type == "tool_call_delta"
        assert e.tool_call_id == "call-1"
        assert e.tool_name == "create_file"

    def test_text_defaults_empty(self):
        e = StreamEvent(type="assistant_delta")
        assert e.text == ""

    def test_tool_fields_default_none(self):
        e = StreamEvent(type="assistant_delta", text="hi")
        assert e.tool_call_id is None
        assert e.tool_name is None
        assert e.tool_arguments is None

    def test_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(StreamEvent)

    def test_tool_arguments_any_type(self):
        e = StreamEvent(type="tool_call_delta", tool_arguments={"nested": [1, 2]})
        assert e.tool_arguments == {"nested": [1, 2]}

    def test_partial_tool_call(self):
        e = StreamEvent(
            type="tool_call_delta",
            tool_call_id="c1",
            tool_arguments='{"path": "ind',
        )
        assert e.tool_arguments == '{"path": "ind'


# ─── ProviderTurn ────────────────────────────────────────────────────────────


class TestProviderTurn:
    def test_basic(self):
        pt = ProviderTurn(assistant_text="Done.", tool_calls=[])
        assert pt.assistant_text == "Done."
        assert pt.tool_calls == []

    def test_with_tool_calls(self):
        tc = ToolCall(id="c1", name="create_file", arguments={"path": "index.html"})
        pt = ProviderTurn(assistant_text="", tool_calls=[tc])
        assert len(pt.tool_calls) == 1

    def test_assistant_turn_defaults_none(self):
        pt = ProviderTurn(assistant_text="", tool_calls=[])
        assert pt.assistant_turn is None

    def test_assistant_turn_set(self):
        pt = ProviderTurn(assistant_text="", tool_calls=[], assistant_turn={"raw": True})
        assert pt.assistant_turn == {"raw": True}

    def test_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(ProviderTurn)


# ─── ExecutedToolCall ─────────────────────────────────────────────────────────


class TestExecutedToolCall:
    def test_basic(self):
        tc = ToolCall(id="c1", name="create_file", arguments={})
        result = ToolExecutionResult(ok=True, result={}, summary={})
        etc = ExecutedToolCall(tool_call=tc, result=result)
        assert etc.tool_call.name == "create_file"
        assert etc.result.ok is True

    def test_failed_result(self):
        tc = ToolCall(id="c2", name="edit_file", arguments={})
        result = ToolExecutionResult(ok=False, result={}, summary={"error": "oops"})
        etc = ExecutedToolCall(tool_call=tc, result=result)
        assert etc.result.ok is False
        assert etc.result.summary["error"] == "oops"

    def test_is_dataclass(self):
        import dataclasses
        assert dataclasses.is_dataclass(ExecutedToolCall)


# ─── ProviderSession protocol ────────────────────────────────────────────────


class TestProviderSessionProtocol:
    def test_protocol_exists(self):
        # ProviderSession is a Protocol — can't instantiate but class exists
        assert ProviderSession is not None

    def test_protocol_has_stream_turn(self):
        assert hasattr(ProviderSession, "stream_turn")

    def test_protocol_has_append_tool_results(self):
        assert hasattr(ProviderSession, "append_tool_results")

    def test_protocol_has_total_cost_usd(self):
        assert hasattr(ProviderSession, "total_cost_usd")

    def test_protocol_has_close(self):
        assert hasattr(ProviderSession, "close")


# ─── create_provider_session error paths ─────────────────────────────────────


class TestCreateProviderSessionErrors:
    def test_openai_missing_key_raises(self):
        from agent.providers.factory import create_provider_session
        from llm import Llm

        with pytest.raises(Exception, match="OpenAI"):
            create_provider_session(
                model=Llm.GPT_5_4_MINI_LOW,
                prompt_messages=[],
                should_generate_images=False,
                openai_api_key=None,
                openai_base_url=None,
                anthropic_api_key=None,
                gemini_api_key=None,
                replicate_api_key=None,
            )

    def test_anthropic_missing_key_raises(self):
        from agent.providers.factory import create_provider_session
        from llm import Llm

        with pytest.raises(Exception, match="Anthropic"):
            create_provider_session(
                model=Llm.CLAUDE_SONNET_4_6,
                prompt_messages=[],
                should_generate_images=False,
                openai_api_key=None,
                openai_base_url=None,
                anthropic_api_key=None,
                gemini_api_key=None,
                replicate_api_key=None,
            )

    def test_gemini_missing_key_raises(self):
        from agent.providers.factory import create_provider_session
        from llm import Llm, GEMINI_MODELS

        gemini_model = next(iter(GEMINI_MODELS))
        with pytest.raises(Exception, match="Gemini"):
            create_provider_session(
                model=gemini_model,
                prompt_messages=[],
                should_generate_images=False,
                openai_api_key=None,
                openai_base_url=None,
                anthropic_api_key=None,
                gemini_api_key=None,
                replicate_api_key=None,
            )

    def test_unsupported_model_raises(self):
        from agent.providers.factory import create_provider_session
        from llm import Llm
        from unittest.mock import patch

        # Patch the model sets to exclude CLAUDE_SONNET_4_6 → hits ValueError
        with (
            patch("agent.providers.factory.OPENAI_MODELS", set()),
            patch("agent.providers.factory.ANTHROPIC_MODELS", set()),
            patch("agent.providers.factory.GEMINI_MODELS", set()),
        ):
            with pytest.raises((ValueError, Exception)):
                create_provider_session(
                    model=Llm.CLAUDE_SONNET_4_6,
                    prompt_messages=[],
                    should_generate_images=False,
                    openai_api_key="key",
                    openai_base_url=None,
                    anthropic_api_key="key",
                    gemini_api_key="key",
                    replicate_api_key=None,
                )
