"""Phase 26 — Video utilities & costs/token tracking.

Tests:
  - video.utils: extract_tag_content, get_video_bytes_and_mime_type
  - costs.pricing: MODEL_PRICING table shape, ModelPricing fields
  - costs.token_usage: TokenUsage arithmetic, cost(), accumulate(),
    total_input_tokens(), cache_hit_rate_percent()
"""

import base64

import pytest

from video.utils import extract_tag_content, get_video_bytes_and_mime_type
from costs.pricing import MODEL_PRICING, ModelPricing
from costs.token_usage import TokenUsage


# ─── extract_tag_content ────────────────────────────────────────────────────


class TestExtractTagContent:
    def test_simple_tag(self):
        result = extract_tag_content("description", "<description>Hello world</description>")
        assert result == "<description>Hello world</description>"

    def test_returns_full_tag_including_delimiters(self):
        result = extract_tag_content("foo", "prefix <foo>bar</foo> suffix")
        assert result == "<foo>bar</foo>"

    def test_tag_not_found_returns_empty(self):
        result = extract_tag_content("missing", "<other>content</other>")
        assert result == ""

    def test_empty_string_input(self):
        result = extract_tag_content("foo", "")
        assert result == ""

    def test_tag_with_no_content(self):
        result = extract_tag_content("tag", "<tag></tag>")
        assert result == "<tag></tag>"

    def test_multiline_content(self):
        text = "<code>\nline1\nline2\n</code>"
        result = extract_tag_content("code", text)
        assert "<code>" in result and "</code>" in result
        assert "line1" in result

    def test_nested_tags_extracts_outer(self):
        text = "<outer><inner>x</inner></outer>"
        result = extract_tag_content("outer", text)
        assert result == "<outer><inner>x</inner></outer>"

    def test_takes_first_occurrence(self):
        text = "<x>first</x> and <x>second</x>"
        result = extract_tag_content("x", text)
        assert "first" in result
        assert "second" not in result

    def test_partial_tag_no_close(self):
        text = "<open>content without close"
        result = extract_tag_content("open", text)
        assert result == ""

    def test_only_closing_tag(self):
        text = "content</close>"
        result = extract_tag_content("close", text)
        assert result == ""

    def test_different_tag_name(self):
        text = "<title>My Title</title>"
        assert extract_tag_content("title", text) == "<title>My Title</title>"
        assert extract_tag_content("body", text) == ""


# ─── get_video_bytes_and_mime_type ─────────────────────────────────────────


class TestGetVideoBytesAndMimeType:
    def _make_data_url(self, mime: str, content: bytes) -> str:
        encoded = base64.b64encode(content).decode()
        return f"data:{mime};base64,{encoded}"

    def test_returns_bytes_and_mime(self):
        raw = b"fake_video_bytes"
        url = self._make_data_url("video/mp4", raw)
        result_bytes, mime = get_video_bytes_and_mime_type(url)
        assert result_bytes == raw
        assert mime == "video/mp4"

    def test_webm_mime(self):
        raw = b"\x1aEDF\xa3"
        url = self._make_data_url("video/webm", raw)
        _, mime = get_video_bytes_and_mime_type(url)
        assert mime == "video/webm"

    def test_mov_mime(self):
        raw = b"mov_bytes"
        url = self._make_data_url("video/quicktime", raw)
        _, mime = get_video_bytes_and_mime_type(url)
        assert mime == "video/quicktime"

    def test_round_trip_large_payload(self):
        raw = b"x" * 10_000
        url = self._make_data_url("video/mp4", raw)
        result_bytes, _ = get_video_bytes_and_mime_type(url)
        assert result_bytes == raw

    def test_binary_data_preserved(self):
        raw = bytes(range(256))
        url = self._make_data_url("video/mp4", raw)
        result_bytes, _ = get_video_bytes_and_mime_type(url)
        assert result_bytes == raw

    def test_empty_video_bytes(self):
        raw = b""
        url = self._make_data_url("video/mp4", raw)
        result_bytes, mime = get_video_bytes_and_mime_type(url)
        assert result_bytes == b""
        assert mime == "video/mp4"


# ─── ModelPricing ───────────────────────────────────────────────────────────


class TestModelPricing:
    def test_default_values_are_zero(self):
        mp = ModelPricing()
        assert mp.input == 0.0
        assert mp.output == 0.0
        assert mp.cache_read == 0.0
        assert mp.cache_write == 0.0

    def test_custom_values(self):
        mp = ModelPricing(input=3.0, output=15.0, cache_read=0.30, cache_write=3.75)
        assert mp.input == 3.0
        assert mp.output == 15.0
        assert mp.cache_read == 0.30
        assert mp.cache_write == 3.75

    def test_model_pricing_table_not_empty(self):
        assert len(MODEL_PRICING) > 0

    def test_all_entries_are_model_pricing(self):
        for key, val in MODEL_PRICING.items():
            assert isinstance(key, str), f"Key not str: {key}"
            assert isinstance(val, ModelPricing), f"Value not ModelPricing: {val}"

    def test_all_prices_non_negative(self):
        for key, mp in MODEL_PRICING.items():
            assert mp.input >= 0, f"{key} has negative input price"
            assert mp.output >= 0, f"{key} has negative output price"
            assert mp.cache_read >= 0, f"{key} has negative cache_read price"
            assert mp.cache_write >= 0, f"{key} has negative cache_write price"

    def test_sonnet_pricing_present(self):
        assert "claude-sonnet-4-6" in MODEL_PRICING

    def test_output_ge_input_for_most_models(self):
        for key, mp in MODEL_PRICING.items():
            if mp.input > 0:
                assert mp.output >= mp.input, f"{key}: output cheaper than input"

    def test_cache_read_le_input(self):
        for key, mp in MODEL_PRICING.items():
            if mp.input > 0 and mp.cache_read > 0:
                assert mp.cache_read <= mp.input, f"{key}: cache_read > input"

    def test_openai_models_present(self):
        openai_models = [k for k in MODEL_PRICING if k.startswith("gpt")]
        assert len(openai_models) > 0

    def test_gemini_models_present(self):
        gemini_models = [k for k in MODEL_PRICING if k.startswith("gemini")]
        assert len(gemini_models) > 0

    def test_anthropic_models_present(self):
        claude_models = [k for k in MODEL_PRICING if k.startswith("claude")]
        assert len(claude_models) > 0


# ─── TokenUsage ─────────────────────────────────────────────────────────────


class TestTokenUsage:
    def test_defaults_zero(self):
        u = TokenUsage()
        assert u.input == 0
        assert u.output == 0
        assert u.cache_read == 0
        assert u.cache_write == 0
        assert u.total == 0

    def test_construct_with_values(self):
        u = TokenUsage(input=100, output=50, cache_read=20, cache_write=10, total=180)
        assert u.input == 100
        assert u.output == 50

    def test_cost_basic(self):
        mp = ModelPricing(input=3.0, output=15.0, cache_read=0.30, cache_write=3.75)
        u = TokenUsage(input=1_000_000, output=0)
        assert abs(u.cost(mp) - 3.0) < 1e-6

    def test_cost_output_only(self):
        mp = ModelPricing(input=3.0, output=15.0)
        u = TokenUsage(output=1_000_000)
        assert abs(u.cost(mp) - 15.0) < 1e-6

    def test_cost_all_fields(self):
        mp = ModelPricing(input=3.0, output=15.0, cache_read=0.30, cache_write=3.75)
        u = TokenUsage(input=1_000_000, output=1_000_000, cache_read=1_000_000, cache_write=1_000_000)
        expected = (3.0 + 15.0 + 0.30 + 3.75)  # per 1M tokens each
        assert abs(u.cost(mp) - expected) < 1e-6

    def test_cost_zero_usage(self):
        mp = ModelPricing(input=3.0, output=15.0)
        u = TokenUsage()
        assert u.cost(mp) == 0.0

    def test_cost_zero_pricing(self):
        mp = ModelPricing()
        u = TokenUsage(input=1000, output=500)
        assert u.cost(mp) == 0.0

    def test_accumulate(self):
        a = TokenUsage(input=100, output=50, cache_read=20, cache_write=10, total=180)
        b = TokenUsage(input=200, output=100, cache_read=40, cache_write=20, total=360)
        a.accumulate(b)
        assert a.input == 300
        assert a.output == 150
        assert a.cache_read == 60
        assert a.cache_write == 30
        assert a.total == 540

    def test_accumulate_with_zero(self):
        a = TokenUsage(input=100, output=50)
        b = TokenUsage()
        a.accumulate(b)
        assert a.input == 100
        assert a.output == 50

    def test_accumulate_multiple_times(self):
        a = TokenUsage(input=10)
        for _ in range(5):
            a.accumulate(TokenUsage(input=10))
        assert a.input == 60

    def test_total_input_tokens_no_cache(self):
        u = TokenUsage(input=500, cache_read=0, cache_write=0)
        assert u.total_input_tokens() == 500

    def test_total_input_tokens_with_cache(self):
        u = TokenUsage(input=500, cache_read=200, cache_write=100)
        assert u.total_input_tokens() == 800

    def test_cache_hit_rate_zero_when_no_input(self):
        u = TokenUsage()
        assert u.cache_hit_rate_percent() == 0.0

    def test_cache_hit_rate_full_cache(self):
        u = TokenUsage(input=0, cache_read=1000)
        assert abs(u.cache_hit_rate_percent() - 100.0) < 1e-6

    def test_cache_hit_rate_half(self):
        u = TokenUsage(input=500, cache_read=500)
        assert abs(u.cache_hit_rate_percent() - 50.0) < 1e-6

    def test_cache_hit_rate_with_write(self):
        u = TokenUsage(input=400, cache_read=400, cache_write=200)
        # total_input = 1000, cache_read = 400 → 40%
        assert abs(u.cache_hit_rate_percent() - 40.0) < 1e-6

    def test_cache_hit_rate_no_cache(self):
        u = TokenUsage(input=1000)
        assert u.cache_hit_rate_percent() == 0.0

    def test_cost_fractional_tokens(self):
        mp = ModelPricing(input=1.0, output=2.0)
        u = TokenUsage(input=500_000, output=250_000)
        expected = (500_000 * 1.0 + 250_000 * 2.0) / 1_000_000
        assert abs(u.cost(mp) - expected) < 1e-9

    def test_cost_uses_actual_model_pricing(self):
        mp = MODEL_PRICING["claude-sonnet-4-6"]
        u = TokenUsage(input=1_000, output=1_000)
        cost = u.cost(mp)
        assert cost > 0
