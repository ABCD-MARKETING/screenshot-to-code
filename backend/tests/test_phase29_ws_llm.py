"""Phase 29 — WebSocket constants, llm.py model registry.

Tests:
  - ws.constants: APP_ERROR_WEB_SOCKET_CODE value and range
  - llm.Llm enum: members present, unique values
  - llm.MODEL_PROVIDER: every Llm has a provider, valid providers
  - llm.OPENAI_MODELS, ANTHROPIC_MODELS, GEMINI_MODELS: correct partition
  - llm.get_openai_api_name: returns non-empty string for openai models
  - llm.get_openai_reasoning_effort: returns str or None for openai models
  - config env-var overrides (via monkeypatch)
"""

import pytest

from ws.constants import APP_ERROR_WEB_SOCKET_CODE
from llm import (
    Llm,
    MODEL_PROVIDER,
    OPENAI_MODELS,
    ANTHROPIC_MODELS,
    GEMINI_MODELS,
    get_openai_api_name,
    get_openai_reasoning_effort,
)


# ─── ws.constants ───────────────────────────────────────────────────────────


class TestWsConstants:
    def test_error_code_is_int(self):
        assert isinstance(APP_ERROR_WEB_SOCKET_CODE, int)

    def test_error_code_in_custom_range(self):
        # RFC 6455: custom close codes are 4000–4999
        assert 4000 <= APP_ERROR_WEB_SOCKET_CODE <= 4999

    def test_error_code_specific_value(self):
        assert APP_ERROR_WEB_SOCKET_CODE == 4332


# ─── llm.Llm enum ───────────────────────────────────────────────────────────


class TestLlmEnum:
    def test_is_enum(self):
        from enum import Enum
        assert issubclass(Llm, Enum)

    def test_has_members(self):
        assert len(list(Llm)) > 0

    def test_all_values_are_strings(self):
        for m in Llm:
            assert isinstance(m.value, str), f"{m.name} value not str"

    def test_values_unique(self):
        values = [m.value for m in Llm]
        assert len(values) == len(set(values))

    def test_claude_sonnet_present(self):
        assert Llm.CLAUDE_SONNET_4_6 in list(Llm)

    def test_gpt_models_present(self):
        gpt_members = [m for m in Llm if "gpt" in m.value.lower()]
        assert len(gpt_members) > 0

    def test_gemini_models_present(self):
        gemini_members = [m for m in Llm if "gemini" in m.value.lower()]
        assert len(gemini_members) > 0

    def test_claude_models_present(self):
        claude_members = [m for m in Llm if "claude" in m.value.lower()]
        assert len(claude_members) > 0


# ─── MODEL_PROVIDER ─────────────────────────────────────────────────────────


class TestModelProvider:
    def test_every_llm_has_provider(self):
        for m in Llm:
            assert m in MODEL_PROVIDER, f"{m.name} missing from MODEL_PROVIDER"

    def test_valid_providers_only(self):
        valid = {"openai", "anthropic", "gemini"}
        for m, p in MODEL_PROVIDER.items():
            assert p in valid, f"{m.name} has unknown provider '{p}'"

    def test_provider_values_are_strings(self):
        for m, p in MODEL_PROVIDER.items():
            assert isinstance(p, str)

    def test_claude_sonnet_is_anthropic(self):
        assert MODEL_PROVIDER[Llm.CLAUDE_SONNET_4_6] == "anthropic"


# ─── Provider subsets ───────────────────────────────────────────────────────


class TestProviderSubsets:
    def test_openai_models_non_empty(self):
        assert len(OPENAI_MODELS) > 0

    def test_anthropic_models_non_empty(self):
        assert len(ANTHROPIC_MODELS) > 0

    def test_gemini_models_non_empty(self):
        assert len(GEMINI_MODELS) > 0

    def test_sets_are_disjoint(self):
        assert OPENAI_MODELS.isdisjoint(ANTHROPIC_MODELS)
        assert OPENAI_MODELS.isdisjoint(GEMINI_MODELS)
        assert ANTHROPIC_MODELS.isdisjoint(GEMINI_MODELS)

    def test_union_equals_all_llms(self):
        all_llms = set(Llm)
        union = OPENAI_MODELS | ANTHROPIC_MODELS | GEMINI_MODELS
        assert union == all_llms

    def test_all_in_openai_set_have_openai_provider(self):
        for m in OPENAI_MODELS:
            assert MODEL_PROVIDER[m] == "openai"

    def test_all_in_anthropic_set_have_anthropic_provider(self):
        for m in ANTHROPIC_MODELS:
            assert MODEL_PROVIDER[m] == "anthropic"

    def test_all_in_gemini_set_have_gemini_provider(self):
        for m in GEMINI_MODELS:
            assert MODEL_PROVIDER[m] == "gemini"


# ─── get_openai_api_name ─────────────────────────────────────────────────────


class TestGetOpenaiApiName:
    def test_returns_string_for_openai_models(self):
        for m in OPENAI_MODELS:
            name = get_openai_api_name(m)
            assert isinstance(name, str), f"{m.name} → non-string api name"

    def test_name_non_empty_for_openai_models(self):
        for m in OPENAI_MODELS:
            assert get_openai_api_name(m) != "", f"{m.name} → empty api name"

    def test_gpt_mini_api_name(self):
        name = get_openai_api_name(Llm.GPT_5_4_MINI_LOW)
        assert "gpt" in name.lower() or len(name) > 0

    def test_api_names_contain_model_base(self):
        for m in OPENAI_MODELS:
            name = get_openai_api_name(m)
            # All OpenAI API names should contain "gpt"
            assert "gpt" in name.lower(), f"{m.name} api_name='{name}' missing 'gpt'"


# ─── get_openai_reasoning_effort ─────────────────────────────────────────────


class TestGetOpenaiReasoningEffort:
    def test_returns_none_or_string(self):
        for m in OPENAI_MODELS:
            effort = get_openai_reasoning_effort(m)
            assert effort is None or isinstance(effort, str)

    def test_no_thinking_models_return_none_string(self):
        # Models with "(no thinking)" in value return "none" string (not None)
        no_thinking = [m for m in OPENAI_MODELS if "no thinking" in m.value]
        for m in no_thinking:
            effort = get_openai_reasoning_effort(m)
            assert effort == "none", f"{m.name} should have effort='none'"

    def test_effort_values_valid(self):
        valid_efforts = {None, "none", "low", "medium", "high", "xhigh", "max"}
        for m in OPENAI_MODELS:
            effort = get_openai_reasoning_effort(m)
            assert effort in valid_efforts, f"{m.name} has unexpected effort '{effort}'"

    def test_low_effort_model(self):
        low_models = [m for m in OPENAI_MODELS if "low thinking" in m.value]
        assert len(low_models) > 0
        for m in low_models:
            effort = get_openai_reasoning_effort(m)
            assert effort == "low"

    def test_medium_effort_model(self):
        medium_models = [m for m in OPENAI_MODELS if "medium thinking" in m.value]
        assert len(medium_models) > 0
        for m in medium_models:
            effort = get_openai_reasoning_effort(m)
            assert effort == "medium"

    def test_high_effort_model(self):
        # Only models explicitly "(high thinking)" — not xhigh
        high_models = [m for m in OPENAI_MODELS if m.value.endswith("(high thinking)")]
        assert len(high_models) > 0
        for m in high_models:
            effort = get_openai_reasoning_effort(m)
            assert effort == "high"
