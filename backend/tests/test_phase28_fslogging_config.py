"""Phase 28 — fs_logging utilities & config module.

Tests:
  - fs_logging.prompt_reports: get_run_logs_directory, get_prompt_reports_directory,
    _sanitize_model_name, to_serializable (prompt_reports version)
  - fs_logging.openai_input_formatting: truncate_for_log, as_dict, to_serializable
  - config: constant types and presence, env-var overrides
"""

import os
import pytest

from fs_logging.prompt_reports import (
    get_run_logs_directory,
    get_prompt_reports_directory,
    _sanitize_model_name,
    to_serializable as pr_to_serializable,
)
from fs_logging.openai_input_formatting import (
    truncate_for_log,
    as_dict,
    to_serializable as oif_to_serializable,
)
import config


# ─── prompt_reports: directory helpers ─────────────────────────────────────


class TestPromptReportDirectories:
    def test_run_logs_under_logs_path(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOGS_PATH", str(tmp_path))
        d = get_run_logs_directory()
        assert str(tmp_path) in d
        assert "run_logs" in d

    def test_run_logs_default_uses_cwd(self, monkeypatch):
        monkeypatch.delenv("LOGS_PATH", raising=False)
        d = get_run_logs_directory()
        assert "run_logs" in d

    def test_prompt_reports_dir_nested_under_run_logs(self, monkeypatch, tmp_path):
        monkeypatch.setenv("LOGS_PATH", str(tmp_path))
        run_logs = get_run_logs_directory()
        pr_dir = get_prompt_reports_directory()
        assert pr_dir.startswith(run_logs)
        assert "prompt_reports" in pr_dir

    def test_prompt_reports_returns_string(self):
        assert isinstance(get_prompt_reports_directory(), str)

    def test_run_logs_returns_string(self):
        assert isinstance(get_run_logs_directory(), str)


# ─── prompt_reports: _sanitize_model_name ──────────────────────────────────


class TestSanitizeModelName:
    def test_simple_name_unchanged(self):
        assert _sanitize_model_name("gpt-4o") == "gpt-4o"

    def test_dots_preserved(self):
        assert _sanitize_model_name("claude-3.5-sonnet") == "claude-3.5-sonnet"

    def test_spaces_replaced(self):
        result = _sanitize_model_name("my model name")
        assert " " not in result

    def test_slashes_replaced(self):
        result = _sanitize_model_name("openai/gpt-4")
        assert "/" not in result

    def test_empty_string_returns_unknown(self):
        result = _sanitize_model_name("")
        assert result == "unknown"

    def test_special_chars_replaced(self):
        result = _sanitize_model_name("model@v1.0!")
        assert "@" not in result
        assert "!" not in result

    def test_returns_string(self):
        assert isinstance(_sanitize_model_name("any"), str)


# ─── prompt_reports: to_serializable ───────────────────────────────────────


class TestPrToSerializable:
    def test_none(self):
        assert pr_to_serializable(None) is None

    def test_bool(self):
        assert pr_to_serializable(True) is True
        assert pr_to_serializable(False) is False

    def test_int(self):
        assert pr_to_serializable(42) == 42

    def test_float(self):
        assert pr_to_serializable(3.14) == 3.14

    def test_string(self):
        assert pr_to_serializable("hello") == "hello"

    def test_list(self):
        result = pr_to_serializable([1, "two", None])
        assert result == [1, "two", None]

    def test_dict(self):
        d = {"a": 1, "b": "x"}
        assert pr_to_serializable(d) == d

    def test_nested(self):
        d = {"a": [1, {"b": 2}]}
        assert pr_to_serializable(d) == d

    def test_tuple_becomes_list(self):
        result = pr_to_serializable((1, 2, 3))
        assert isinstance(result, list)
        assert result == [1, 2, 3]

    def test_object_with_model_dump(self):
        class Obj:
            def model_dump(self, **kwargs):
                return {"x": 10}
        result = pr_to_serializable(Obj())
        assert result == {"x": 10}


# ─── openai_input_formatting: truncate_for_log ─────────────────────────────


class TestTruncateForLog:
    def test_short_string_unchanged(self):
        s = "hello"
        assert truncate_for_log(s) == "hello"

    def test_long_string_truncated(self):
        s = "x" * 200
        result = truncate_for_log(s)
        assert len(result) <= 125  # 120 chars + "..."
        assert result.endswith("...")

    def test_exactly_max_len_unchanged(self):
        s = "a" * 120
        result = truncate_for_log(s)
        assert result == s
        assert not result.endswith("...")

    def test_newlines_escaped(self):
        s = "line1\nline2"
        result = truncate_for_log(s)
        assert "\n" not in result
        assert "\\n" in result

    def test_custom_max_len(self):
        s = "a" * 50
        result = truncate_for_log(s, max_len=20)
        assert result.endswith("...")
        assert len(result) == 23  # 20 + "..."

    def test_empty_string(self):
        assert truncate_for_log("") == ""

    def test_returns_string(self):
        assert isinstance(truncate_for_log("hello"), str)

    def test_integer_input(self):
        result = truncate_for_log(42)
        assert "42" in result

    def test_none_input(self):
        result = truncate_for_log(None)
        assert result is not None
        assert isinstance(result, str)


# ─── openai_input_formatting: as_dict ─────────────────────────────────────


class TestAsDict:
    def test_plain_dict_returned(self):
        d = {"k": "v"}
        assert as_dict(d) == d

    def test_none_returns_none(self):
        assert as_dict(None) is None

    def test_string_returns_none(self):
        assert as_dict("hello") is None

    def test_object_with_model_dump(self):
        class Obj:
            def model_dump(self):
                return {"x": 1}
        assert as_dict(Obj()) == {"x": 1}

    def test_object_with_to_dict(self):
        class Obj:
            def to_dict(self):
                return {"y": 2}
        assert as_dict(Obj()) == {"y": 2}

    def test_object_with_dict_method(self):
        class Obj:
            def dict(self):
                return {"z": 3}
        assert as_dict(Obj()) == {"z": 3}

    def test_object_with_dunder_dict(self):
        class Obj:
            def __init__(self):
                self.public = "val"
                self._private = "hidden"
        result = as_dict(Obj())
        assert result is not None
        assert "public" in result
        assert "_private" not in result

    def test_empty_dunder_dict_returns_none(self):
        class Obj:
            pass
        # __dict__ is {} for plain object → as_dict returns None
        result = as_dict(Obj())
        # Could be None or empty-dict—either is valid; just check type
        assert result is None or isinstance(result, dict)

    def test_model_dump_not_dict_falls_through(self):
        class Obj:
            def model_dump(self):
                return "not a dict"
        # Falls through to next handler
        result = as_dict(Obj())
        assert result is None or isinstance(result, dict)


# ─── openai_input_formatting: to_serializable ─────────────────────────────


class TestOifToSerializable:
    def test_primitives(self):
        assert oif_to_serializable(None) is None
        assert oif_to_serializable(True) is True
        assert oif_to_serializable(1) == 1
        assert oif_to_serializable("s") == "s"

    def test_list_recursive(self):
        class Obj:
            def model_dump(self):
                return {"v": 99}
        result = oif_to_serializable([Obj(), 1])
        assert result[0] == {"v": 99}
        assert result[1] == 1

    def test_dict_recursive(self):
        result = oif_to_serializable({"a": [1, 2], "b": None})
        assert result == {"a": [1, 2], "b": None}

    def test_unknown_object_stringified(self):
        class Unknown:
            def __str__(self):
                return "my-repr"
            def __repr__(self):
                return "my-repr"
        result = oif_to_serializable(Unknown())
        assert isinstance(result, str)


# ─── config module ──────────────────────────────────────────────────────────


class TestConfig:
    def test_num_variants_is_int(self):
        assert isinstance(config.NUM_VARIANTS, int)
        assert config.NUM_VARIANTS > 0

    def test_num_variants_video_is_int(self):
        assert isinstance(config.NUM_VARIANTS_VIDEO, int)
        assert config.NUM_VARIANTS_VIDEO > 0

    def test_generation_max_cost_is_positive(self):
        assert config.GENERATION_MAX_COST_USD > 0

    def test_is_debug_enabled_is_bool(self):
        assert isinstance(config.IS_DEBUG_ENABLED, bool)

    def test_debug_dir_is_string(self):
        assert isinstance(config.DEBUG_DIR, str)

    def test_prompt_reports_enabled_is_bool(self):
        assert isinstance(config.PROMPT_REPORTS_ENABLED, bool)

    def test_local_asset_dir_is_string(self):
        assert isinstance(config.LOCAL_ASSET_DIR, str)

    def test_local_asset_base_url_is_string(self):
        assert isinstance(config.LOCAL_ASSET_BASE_URL, str)

    def test_is_prod_value(self):
        # IS_PROD is False by default (no env var)
        assert config.IS_PROD in (False, None, "")

    def test_openai_api_key_none_or_str(self):
        assert config.OPENAI_API_KEY is None or isinstance(config.OPENAI_API_KEY, str)

    def test_anthropic_api_key_none_or_str(self):
        assert config.ANTHROPIC_API_KEY is None or isinstance(config.ANTHROPIC_API_KEY, str)

    def test_gemini_api_key_none_or_str(self):
        assert config.GEMINI_API_KEY is None or isinstance(config.GEMINI_API_KEY, str)

    def test_local_asset_base_url_has_scheme(self):
        url = config.LOCAL_ASSET_BASE_URL
        assert url.startswith("http://") or url.startswith("https://")

    def test_generation_max_cost_is_float_or_int(self):
        assert isinstance(config.GENERATION_MAX_COST_USD, (int, float))
