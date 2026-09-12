"""Phase 33 — agent/tools/local_assets.py and agent/tools/summaries.py.

Tests:
  - is_local_host_url: loopback hostnames, non-local
  - local_asset_url_to_bytes: path traversal blocked, real file, external blocked
  - guess_image_mime: common extensions
  - summarize_text: truncation, passthrough
  - summarize_tool_input: create_file, edit_file, generate_images, remove_backgrounds, unknown
"""

import os
import tempfile
import pytest

from agent.tools.local_assets import (
    is_local_host_url,
    guess_image_mime,
    local_asset_url_to_bytes,
)
from agent.tools.summaries import summarize_text, summarize_tool_input
from agent.state import AgentFileState
from agent.tools.types import ToolCall


# ─── is_local_host_url ───────────────────────────────────────────────────────


class TestIsLocalHostUrl:
    def test_localhost(self):
        assert is_local_host_url("http://localhost:7001/img.png") is True

    def test_127(self):
        assert is_local_host_url("http://127.0.0.1:7001/img.png") is True

    def test_ipv6_loopback(self):
        assert is_local_host_url("http://[::1]:7001/img.png") is True

    def test_external_url(self):
        assert is_local_host_url("https://example.com/img.png") is False

    def test_replicate_url(self):
        assert is_local_host_url("https://replicate.delivery/pbxt/abc/out.png") is False

    def test_empty_string(self):
        assert is_local_host_url("") is False

    def test_no_scheme(self):
        assert is_local_host_url("localhost/path") is False

    def test_https_localhost(self):
        assert is_local_host_url("https://localhost/path") is True


# ─── guess_image_mime ────────────────────────────────────────────────────────


class TestGuessImageMime:
    def test_png(self):
        assert guess_image_mime("http://x.com/image.png") == "image/png"

    def test_jpeg(self):
        mime = guess_image_mime("http://x.com/photo.jpg")
        assert "jpeg" in mime or "jpg" in mime

    def test_webp(self):
        mime = guess_image_mime("http://x.com/out.webp")
        assert "webp" in mime

    def test_gif(self):
        mime = guess_image_mime("http://x.com/anim.gif")
        assert "gif" in mime

    def test_unknown_defaults_png(self):
        mime = guess_image_mime("http://x.com/file.xyz123")
        assert mime == "image/png"

    def test_no_extension(self):
        mime = guess_image_mime("http://x.com/file")
        assert mime == "image/png"


# ─── local_asset_url_to_bytes ────────────────────────────────────────────────


class TestLocalAssetUrlToBytes:
    def test_external_url_returns_none(self):
        result = local_asset_url_to_bytes("https://example.com/image.png")
        assert result is None

    def test_path_traversal_blocked(self):
        result = local_asset_url_to_bytes(
            "http://localhost:7001/local-assets/../../secret.txt"
        )
        assert result is None

    def test_non_local_asset_path_returns_none(self):
        result = local_asset_url_to_bytes("http://localhost:7001/other/image.png")
        assert result is None

    def test_real_file_returned(self, tmp_path, monkeypatch):
        img_content = b"\x89PNG\r\n\x1a\n"
        img_file = tmp_path / "test.png"
        img_file.write_bytes(img_content)

        monkeypatch.setattr(
            "agent.tools.local_assets.LOCAL_ASSET_DIR", str(tmp_path)
        )
        result = local_asset_url_to_bytes(
            f"http://localhost:7001/local-assets/test.png"
        )
        assert result is not None
        data, mime = result
        assert data == img_content
        assert "png" in mime

    def test_missing_file_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "agent.tools.local_assets.LOCAL_ASSET_DIR", str(tmp_path)
        )
        result = local_asset_url_to_bytes(
            "http://localhost:7001/local-assets/nonexistent.png"
        )
        assert result is None

    def test_data_url_returns_none(self):
        result = local_asset_url_to_bytes("data:image/png;base64,abc123")
        assert result is None


# ─── summarize_text ──────────────────────────────────────────────────────────


class TestSummarizeText:
    def test_short_unchanged(self):
        assert summarize_text("hello") == "hello"

    def test_long_truncated(self):
        s = "x" * 300
        result = summarize_text(s)
        assert len(result) <= 243  # 240 + "..."
        assert result.endswith("...")

    def test_exactly_limit_unchanged(self):
        s = "a" * 240
        result = summarize_text(s)
        assert result == s
        assert not result.endswith("...")

    def test_empty_unchanged(self):
        assert summarize_text("") == ""

    def test_custom_limit(self):
        s = "x" * 100
        result = summarize_text(s, limit=10)
        assert result.endswith("...")
        assert len(result) == 13

    def test_returns_string(self):
        assert isinstance(summarize_text("hello"), str)


# ─── summarize_tool_input ────────────────────────────────────────────────────


class TestSummarizeToolInput:
    def _fs(self):
        return AgentFileState(path="index.html", content="")

    def test_create_file(self):
        tc = ToolCall(
            id="1",
            name="create_file",
            arguments={"path": "app.html", "content": "<html/>" * 50},
        )
        summary = summarize_tool_input(tc, self._fs())
        assert "path" in summary
        assert "contentLength" in summary
        assert summary["contentLength"] > 0

    def test_create_file_default_path(self):
        tc = ToolCall(
            id="1",
            name="create_file",
            arguments={"content": "<html/>"},
        )
        summary = summarize_tool_input(tc, self._fs())
        assert summary["path"] == "index.html"

    def test_edit_file(self):
        tc = ToolCall(
            id="2",
            name="edit_file",
            arguments={
                "path": "app.html",
                "old_text": "old",
                "new_text": "new",
            },
        )
        summary = summarize_tool_input(tc, self._fs())
        assert "edits" in summary
        assert isinstance(summary["edits"], list)

    def test_edit_file_edits_list(self):
        tc = ToolCall(
            id="3",
            name="edit_file",
            arguments={
                "edits": [{"old_text": "a", "new_text": "b", "count": 1}],
            },
        )
        summary = summarize_tool_input(tc, self._fs())
        assert len(summary["edits"]) == 1

    def test_generate_images(self):
        tc = ToolCall(
            id="4",
            name="generate_images",
            arguments={"prompts": ["a cat", "a dog"]},
        )
        summary = summarize_tool_input(tc, self._fs())
        assert summary["count"] == 2
        assert len(summary["prompts"]) == 2

    def test_remove_backgrounds(self):
        tc = ToolCall(
            id="5",
            name="remove_backgrounds",
            arguments={
                "image_urls": [
                    "https://example.com/a.png",
                    "https://example.com/b.png",
                ]
            },
        )
        summary = summarize_tool_input(tc, self._fs())
        assert isinstance(summary, dict)

    def test_unknown_tool_returns_dict(self):
        tc = ToolCall(
            id="6",
            name="unknown_tool",
            arguments={"foo": "bar"},
        )
        summary = summarize_tool_input(tc, self._fs())
        assert isinstance(summary, dict)
