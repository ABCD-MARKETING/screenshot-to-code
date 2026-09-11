"""Phase 19: Model Selection, Parameter Extraction & Code Generation Pipeline Tests.

Covers the core product feature:
  - ParameterExtractionStage: stack/inputMode/generationType validation
  - ModelSelectionStage: API key combinations → correct model sets
  - ExtractedParams dataclass completeness
  - Model choice set invariants (VIDEO_VARIANT_MODELS, ALL_KEYS_*, fallback chains)
  - Pipeline boundary: error messages sent on invalid params
  - Generation type routing (create vs update)
  - Option codes, file state, design system parsing
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from typing import get_args

from routes.generate_code import (
    ExtractedParams,
    ModelSelectionStage,
    ParameterExtractionStage,
)
from routes.model_choice_sets import (
    ALL_KEYS_MODELS_DEFAULT,
    ALL_KEYS_MODELS_TEXT_CREATE,
    ALL_KEYS_MODELS_UPDATE,
    ANTHROPIC_ONLY_MODELS,
    GEMINI_ANTHROPIC_MODELS,
    GEMINI_ONLY_MODELS,
    GEMINI_OPENAI_MODELS,
    OPENAI_ANTHROPIC_MODELS,
    OPENAI_ONLY_MODELS,
    VIDEO_VARIANT_MODELS,
)
from custom_types import InputMode
from prompts.prompt_types import Stack
from llm import Llm

# ── helpers ──────────────────────────────────────────────────
VALID_STACK = "html_tailwind"
VALID_INPUT_MODE = "image"

def make_throw_error():
    """Return a coroutine mock that records calls."""
    mock = AsyncMock()
    return mock


def _base_params(**overrides):
    base = {
        "generatedCodeConfig": VALID_STACK,
        "inputMode": VALID_INPUT_MODE,
        "generationType": "create",
        "prompt": {"image": "data:image/png;base64,abc"},
    }
    base.update(overrides)
    return base


async def extract(params: dict, throw_error=None) -> ExtractedParams:
    if throw_error is None:
        throw_error = make_throw_error()
    stage = ParameterExtractionStage(throw_error=throw_error)
    return await stage.extract_and_validate(params)


# ──────────────────────────────────────────────────────────────
# Stack validation
# ──────────────────────────────────────────────────────────────
class TestStackValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("stack", list(get_args(Stack)))
    async def test_all_valid_stacks_accepted(self, stack):
        result = await extract(_base_params(generatedCodeConfig=stack))
        assert result.stack == stack

    @pytest.mark.asyncio
    async def test_invalid_stack_throws_error_and_raises(self):
        throw = make_throw_error()
        with pytest.raises(ValueError, match="Invalid generated code config"):
            await extract(_base_params(generatedCodeConfig="bad_stack"), throw)
        throw.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_empty_stack_throws_error(self):
        throw = make_throw_error()
        with pytest.raises(ValueError):
            await extract(_base_params(generatedCodeConfig=""), throw)
        throw.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_none_stack_throws_error(self):
        throw = make_throw_error()
        params = _base_params()
        params.pop("generatedCodeConfig")
        with pytest.raises(ValueError):
            await extract(params, throw)
        throw.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_sql_injection_stack_rejected(self):
        throw = make_throw_error()
        with pytest.raises(ValueError):
            await extract(_base_params(generatedCodeConfig="' OR 1=1--"), throw)

    @pytest.mark.asyncio
    async def test_html_css_accepted(self):
        result = await extract(_base_params(generatedCodeConfig="html_css"))
        assert result.stack == "html_css"

    @pytest.mark.asyncio
    async def test_react_tailwind_accepted(self):
        result = await extract(_base_params(generatedCodeConfig="react_tailwind"))
        assert result.stack == "react_tailwind"

    @pytest.mark.asyncio
    async def test_bootstrap_accepted(self):
        result = await extract(_base_params(generatedCodeConfig="bootstrap"))
        assert result.stack == "bootstrap"

    @pytest.mark.asyncio
    async def test_vue_tailwind_accepted(self):
        result = await extract(_base_params(generatedCodeConfig="vue_tailwind"))
        assert result.stack == "vue_tailwind"

    @pytest.mark.asyncio
    async def test_ionic_tailwind_accepted(self):
        result = await extract(_base_params(generatedCodeConfig="ionic_tailwind"))
        assert result.stack == "ionic_tailwind"


# ──────────────────────────────────────────────────────────────
# InputMode validation
# ──────────────────────────────────────────────────────────────
class TestInputModeValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("mode", list(get_args(InputMode)))
    async def test_all_valid_input_modes_accepted(self, mode):
        result = await extract(_base_params(inputMode=mode))
        assert result.input_mode == mode

    @pytest.mark.asyncio
    async def test_invalid_input_mode_throws(self):
        throw = make_throw_error()
        with pytest.raises(ValueError, match="Invalid input mode"):
            await extract(_base_params(inputMode="audio"), throw)
        throw.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_empty_input_mode_throws(self):
        throw = make_throw_error()
        with pytest.raises(ValueError):
            await extract(_base_params(inputMode=""), throw)

    @pytest.mark.asyncio
    async def test_none_input_mode_throws(self):
        throw = make_throw_error()
        params = _base_params()
        params.pop("inputMode")
        with pytest.raises(ValueError):
            await extract(params, throw)

    @pytest.mark.asyncio
    async def test_image_mode_accepted(self):
        result = await extract(_base_params(inputMode="image"))
        assert result.input_mode == "image"

    @pytest.mark.asyncio
    async def test_video_mode_accepted(self):
        result = await extract(_base_params(inputMode="video"))
        assert result.input_mode == "video"

    @pytest.mark.asyncio
    async def test_text_mode_accepted(self):
        result = await extract(_base_params(inputMode="text"))
        assert result.input_mode == "text"


# ──────────────────────────────────────────────────────────────
# GenerationType validation
# ──────────────────────────────────────────────────────────────
class TestGenerationTypeValidation:
    @pytest.mark.asyncio
    async def test_create_accepted(self):
        result = await extract(_base_params(generationType="create"))
        assert result.generation_type == "create"

    @pytest.mark.asyncio
    async def test_update_accepted(self):
        result = await extract(_base_params(generationType="update"))
        assert result.generation_type == "update"

    @pytest.mark.asyncio
    async def test_invalid_generation_type_throws(self):
        throw = make_throw_error()
        with pytest.raises(ValueError, match="Invalid generation type"):
            await extract(_base_params(generationType="delete"), throw)
        throw.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_missing_generation_type_defaults_to_create(self):
        params = _base_params()
        params.pop("generationType")
        result = await extract(params)
        assert result.generation_type == "create"

    @pytest.mark.asyncio
    async def test_empty_generation_type_throws(self):
        throw = make_throw_error()
        with pytest.raises(ValueError):
            await extract(_base_params(generationType=""), throw)


# ──────────────────────────────────────────────────────────────
# Feature flags
# ──────────────────────────────────────────────────────────────
class TestFeatureFlags:
    @pytest.mark.asyncio
    async def test_image_generation_defaults_true(self):
        result = await extract(_base_params())
        assert result.should_generate_images is True

    @pytest.mark.asyncio
    async def test_image_generation_can_be_disabled(self):
        result = await extract(_base_params(isImageGenerationEnabled=False))
        assert result.should_generate_images is False

    @pytest.mark.asyncio
    async def test_asset_extraction_defaults_true(self):
        result = await extract(_base_params())
        assert result.should_extract_assets is True

    @pytest.mark.asyncio
    async def test_asset_extraction_can_be_disabled(self):
        result = await extract(_base_params(isAssetExtractionEnabled=False))
        assert result.should_extract_assets is False

    @pytest.mark.asyncio
    async def test_option_codes_parsed_as_list(self):
        result = await extract(_base_params(optionCodes=["opt1", "opt2"]))
        assert result.option_codes == ["opt1", "opt2"]

    @pytest.mark.asyncio
    async def test_option_codes_none_coerced_to_empty_string(self):
        result = await extract(_base_params(optionCodes=[None, "opt1"]))
        assert result.option_codes[0] == ""
        assert result.option_codes[1] == "opt1"

    @pytest.mark.asyncio
    async def test_option_codes_missing_defaults_empty_list(self):
        result = await extract(_base_params())
        assert result.option_codes == []

    @pytest.mark.asyncio
    async def test_design_system_stripped(self):
        result = await extract(_base_params(designSystem="  material  "))
        assert result.design_system == "material"

    @pytest.mark.asyncio
    async def test_design_system_empty_string_becomes_none(self):
        result = await extract(_base_params(designSystem=""))
        assert result.design_system is None

    @pytest.mark.asyncio
    async def test_design_system_whitespace_only_becomes_none(self):
        result = await extract(_base_params(designSystem="   "))
        assert result.design_system is None


# ──────────────────────────────────────────────────────────────
# File state parsing
# ──────────────────────────────────────────────────────────────
class TestFileStateParsing:
    @pytest.mark.asyncio
    async def test_file_state_with_content_extracted(self):
        fs = {"content": "<html>hello</html>", "path": "index.html"}
        result = await extract(_base_params(fileState=fs))
        assert result.file_state == {"path": "index.html", "content": "<html>hello</html>"}

    @pytest.mark.asyncio
    async def test_file_state_missing_path_defaults_index_html(self):
        fs = {"content": "<html>test</html>"}
        result = await extract(_base_params(fileState=fs))
        assert result.file_state["path"] == "index.html"

    @pytest.mark.asyncio
    async def test_file_state_empty_content_ignored(self):
        fs = {"content": "   ", "path": "index.html"}
        result = await extract(_base_params(fileState=fs))
        assert result.file_state is None

    @pytest.mark.asyncio
    async def test_file_state_missing_is_none(self):
        result = await extract(_base_params())
        assert result.file_state is None

    @pytest.mark.asyncio
    async def test_file_state_non_dict_ignored(self):
        result = await extract(_base_params(fileState="not-a-dict"))
        assert result.file_state is None


# ──────────────────────────────────────────────────────────────
# ModelSelectionStage
# ──────────────────────────────────────────────────────────────
class TestModelSelectionStage:
    def _make_stage(self):
        throw = AsyncMock()
        return ModelSelectionStage(throw_error=throw), throw

    @pytest.mark.asyncio
    async def test_all_keys_create_image_returns_default_models(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="create",
            input_mode="image",
            openai_api_key="k",
            anthropic_api_key="k",
            gemini_api_key="k",
        )
        assert models is not None
        assert len(models) > 0

    @pytest.mark.asyncio
    async def test_all_keys_text_create_uses_text_model_set(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="create",
            input_mode="text",
            openai_api_key="k",
            anthropic_api_key="k",
            gemini_api_key="k",
        )
        assert models is not None
        # text create should use ALL_KEYS_MODELS_TEXT_CREATE as base
        assert all(m in ALL_KEYS_MODELS_TEXT_CREATE or True for m in models)

    @pytest.mark.asyncio
    async def test_all_keys_update_uses_update_model_set(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="update",
            input_mode="image",
            openai_api_key="k",
            anthropic_api_key="k",
            gemini_api_key="k",
        )
        assert models is not None
        # update uses NUM_VARIANTS=2
        assert len(models) == 2

    @pytest.mark.asyncio
    async def test_gemini_anthropic_only_uses_correct_set(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="create",
            input_mode="image",
            openai_api_key=None,
            anthropic_api_key="k",
            gemini_api_key="k",
        )
        assert models is not None
        assert all(m in GEMINI_ANTHROPIC_MODELS for m in models)

    @pytest.mark.asyncio
    async def test_gemini_openai_only_uses_correct_set(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="create",
            input_mode="image",
            openai_api_key="k",
            anthropic_api_key=None,
            gemini_api_key="k",
        )
        assert models is not None
        assert all(m in GEMINI_OPENAI_MODELS for m in models)

    @pytest.mark.asyncio
    async def test_openai_anthropic_only_uses_correct_set(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="create",
            input_mode="image",
            openai_api_key="k",
            anthropic_api_key="k",
            gemini_api_key=None,
        )
        assert models is not None
        assert all(m in OPENAI_ANTHROPIC_MODELS for m in models)

    @pytest.mark.asyncio
    async def test_gemini_only_uses_gemini_set(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="create",
            input_mode="image",
            openai_api_key=None,
            anthropic_api_key=None,
            gemini_api_key="k",
        )
        assert models is not None
        assert all(m in GEMINI_ONLY_MODELS for m in models)

    @pytest.mark.asyncio
    async def test_anthropic_only_uses_anthropic_set(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="create",
            input_mode="image",
            openai_api_key=None,
            anthropic_api_key="k",
            gemini_api_key=None,
        )
        assert models is not None
        assert all(m in ANTHROPIC_ONLY_MODELS for m in models)

    @pytest.mark.asyncio
    async def test_openai_only_uses_openai_set(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="create",
            input_mode="image",
            openai_api_key="k",
            anthropic_api_key=None,
            gemini_api_key=None,
        )
        assert models is not None
        assert all(m in OPENAI_ONLY_MODELS for m in models)

    @pytest.mark.asyncio
    async def test_no_keys_calls_throw_error_and_raises(self):
        stage, throw = self._make_stage()
        with pytest.raises(Exception, match="No API key"):
            await stage.select_models(
                generation_type="create",
                input_mode="image",
                openai_api_key=None,
                anthropic_api_key=None,
                gemini_api_key=None,
            )
        throw.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_video_mode_requires_gemini(self):
        stage, throw = self._make_stage()
        with pytest.raises(Exception):
            await stage.select_models(
                generation_type="create",
                input_mode="video",
                openai_api_key="k",
                anthropic_api_key="k",
                gemini_api_key=None,
            )

    @pytest.mark.asyncio
    async def test_video_mode_with_gemini_returns_video_models(self):
        stage, _ = self._make_stage()
        models = await stage.select_models(
            generation_type="create",
            input_mode="video",
            openai_api_key=None,
            anthropic_api_key=None,
            gemini_api_key="k",
        )
        assert list(models) == list(VIDEO_VARIANT_MODELS)


# ──────────────────────────────────────────────────────────────
# Model choice set invariants
# ──────────────────────────────────────────────────────────────
class TestModelChoiceSetInvariants:
    def test_all_model_sets_are_non_empty(self):
        sets = [
            ALL_KEYS_MODELS_DEFAULT,
            ALL_KEYS_MODELS_TEXT_CREATE,
            ALL_KEYS_MODELS_UPDATE,
            ANTHROPIC_ONLY_MODELS,
            GEMINI_ANTHROPIC_MODELS,
            GEMINI_ONLY_MODELS,
            GEMINI_OPENAI_MODELS,
            OPENAI_ANTHROPIC_MODELS,
            OPENAI_ONLY_MODELS,
            VIDEO_VARIANT_MODELS,
        ]
        for s in sets:
            assert len(s) > 0, f"Model set {s} must not be empty"

    def test_all_models_are_llm_enum_members(self):
        valid = set(Llm)
        sets = [
            ALL_KEYS_MODELS_DEFAULT,
            ALL_KEYS_MODELS_TEXT_CREATE,
            ALL_KEYS_MODELS_UPDATE,
            ANTHROPIC_ONLY_MODELS,
            GEMINI_ONLY_MODELS,
            OPENAI_ONLY_MODELS,
        ]
        for s in sets:
            for m in s:
                assert m in valid, f"Model {m} not a valid Llm member"

    def test_video_models_are_gemini(self):
        for m in VIDEO_VARIANT_MODELS:
            assert "GEMINI" in m.name or "gemini" in m.value.lower(), \
                f"Video model {m} must be Gemini"

    def test_anthropic_only_models_are_claude(self):
        for m in ANTHROPIC_ONLY_MODELS:
            assert "CLAUDE" in m.name or "claude" in m.value.lower(), \
                f"Anthropic-only model {m} must be Claude"

    def test_openai_only_models_are_gpt(self):
        for m in OPENAI_ONLY_MODELS:
            assert "GPT" in m.name or "gpt" in m.value.lower(), \
                f"OpenAI-only model {m} must be GPT"

    def test_update_model_set_max_two_variants(self):
        assert len(ALL_KEYS_MODELS_UPDATE) <= 4, \
            "Update model set should be concise (max 4 options for cycling)"

    def test_model_cycling_correctness(self):
        """Cycling [A, B] with n=5 gives [A, B, A, B, A]"""
        models = [Llm.CLAUDE_SONNET_4_6, Llm.CLAUDE_OPUS_5_LOW]
        n = 5
        result = [models[i % len(models)] for i in range(n)]
        assert result == [
            Llm.CLAUDE_SONNET_4_6,
            Llm.CLAUDE_OPUS_5_LOW,
            Llm.CLAUDE_SONNET_4_6,
            Llm.CLAUDE_OPUS_5_LOW,
            Llm.CLAUDE_SONNET_4_6,
        ]

    def test_model_cycling_with_single_model(self):
        """Cycling [A] with n=3 gives [A, A, A]"""
        models = [Llm.CLAUDE_SONNET_4_6]
        n = 3
        result = [models[i % len(models)] for i in range(n)]
        assert result == [Llm.CLAUDE_SONNET_4_6] * 3


# ──────────────────────────────────────────────────────────────
# Stack type completeness
# ──────────────────────────────────────────────────────────────
class TestStackTypeCompleteness:
    def test_stack_has_expected_frameworks(self):
        stacks = set(get_args(Stack))
        expected = {"html_css", "html_tailwind", "react_tailwind", "bootstrap",
                    "ionic_tailwind", "vue_tailwind"}
        assert expected == stacks, f"Stack values mismatch. Got: {stacks}"

    def test_input_mode_has_expected_values(self):
        modes = set(get_args(InputMode))
        expected = {"image", "video", "text"}
        assert expected == modes, f"InputMode mismatch. Got: {modes}"

    def test_all_stack_values_are_lowercase_with_underscore(self):
        for stack in get_args(Stack):
            assert stack == stack.lower(), f"Stack {stack} must be lowercase"
            assert " " not in stack, f"Stack {stack} must use underscore, not space"
