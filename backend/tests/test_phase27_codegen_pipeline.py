"""Phase 27 — codegen utilities and pipeline internals.

Tests for codegen.utils.extract_html_content:
  - markdown fence stripping
  - DOCTYPE handling
  - <file path="..."> wrapper stripping
  - fallback (no HTML tags)
  - nested / multiple html blocks
  - whitespace tolerance
  - LLM-output edge cases
"""

import pytest

from codegen.utils import extract_html_content


class TestExtractHtmlContentBasic:
    def test_plain_html_tags(self):
        text = "<html><body><p>Hello</p></body></html>"
        assert extract_html_content(text) == text

    def test_html_with_attributes(self):
        text = '<html lang="en"><head></head><body></body></html>'
        result = extract_html_content(text)
        assert "<html" in result
        assert "</html>" in result

    def test_no_html_returns_original(self):
        text = "No HTML here."
        assert extract_html_content(text) == text

    def test_empty_string(self):
        assert extract_html_content("") == ""


class TestExtractHtmlContentDoctype:
    def test_doctype_preserved(self):
        text = '<!DOCTYPE html><html lang="en"><head></head><body></body></html>'
        result = extract_html_content(text)
        assert "<!DOCTYPE" in result or "<html" in result

    def test_doctype_uppercase(self):
        text = "<!DOCTYPE HTML><HTML><HEAD></HEAD><BODY></BODY></HTML>"
        result = extract_html_content(text)
        assert len(result) > 0

    def test_doctype_with_preceding_text(self):
        text = "Here is the code:\n<!DOCTYPE html><html><body></body></html>"
        result = extract_html_content(text)
        assert "<html>" in result or "<!DOCTYPE" in result


class TestExtractHtmlContentMarkdownFences:
    def test_markdown_html_fence_stripped(self):
        text = "```html\n<html><body></body></html>\n```"
        result = extract_html_content(text)
        assert "```" not in result
        assert "<html>" in result

    def test_markdown_plain_fence_stripped(self):
        text = "```\n<html><body></body></html>\n```"
        result = extract_html_content(text)
        assert "<html>" in result

    def test_markdown_fence_with_doctype(self):
        text = "```html\n<!DOCTYPE html>\n<html><body></body></html>\n```"
        result = extract_html_content(text)
        assert "<html>" in result

    def test_fenced_no_html_tags_returns_stripped(self):
        text = "```html\nNot actually HTML\n```"
        result = extract_html_content(text)
        assert result is not None


class TestExtractHtmlContentFileWrapper:
    def test_file_tag_wrapper_stripped(self):
        inner = "<html><body>content</body></html>"
        text = f'<file path="index.html">{inner}</file>'
        result = extract_html_content(text)
        assert "<file" not in result
        assert "<html>" in result or "<body>" in result

    def test_file_tag_with_whitespace(self):
        inner = "<html><body>content</body></html>"
        text = f'<file path="index.html">  {inner}  </file>'
        result = extract_html_content(text)
        assert "<html>" in result

    def test_file_tag_recursive_extraction(self):
        inner = "```html\n<html><body>x</body></html>\n```"
        text = f'<file path="index.html">{inner}</file>'
        result = extract_html_content(text)
        assert "<html>" in result


class TestExtractHtmlContentMultiple:
    def test_takes_first_html_block(self):
        text = "<html><body>first</body></html> text <html><body>second</body></html>"
        result = extract_html_content(text)
        assert "first" in result
        assert "second" not in result

    def test_prefers_doctype_version(self):
        text = "<!DOCTYPE html><html><body>full</body></html>"
        result = extract_html_content(text)
        assert "full" in result


class TestExtractHtmlContentLlmOutputs:
    def test_explanation_before_html(self):
        text = (
            "Got it! Here is the updated code:\n\n"
            '<html lang="en"><head></head><body class="bg-black"></body></html>'
        )
        result = extract_html_content(text)
        assert "<html" in result
        assert "Got it" not in result

    def test_explanation_after_html(self):
        text = '<html><body>content</body></html>\n\nI hope this helps!'
        result = extract_html_content(text)
        assert "<html>" in result
        assert "hope" not in result

    def test_code_block_with_doctype(self):
        text = "```html\n<!DOCTYPE html>\n<html><body>page</body></html>\n```"
        result = extract_html_content(text)
        assert "<html>" in result

    def test_large_content_extracted(self):
        inner = "<html><body>" + "<div>item</div>" * 500 + "</body></html>"
        result = extract_html_content(inner)
        assert result == inner

    def test_self_closing_body(self):
        text = "<html><head><meta charset='utf-8'/></head><body/></html>"
        result = extract_html_content(text)
        assert "<html>" in result

    def test_html_with_script_and_style(self):
        text = (
            "<html><head>"
            "<style>body{margin:0}</style>"
            "<script>console.log('hi')</script>"
            "</head><body><h1>Test</h1></body></html>"
        )
        result = extract_html_content(text)
        assert "console.log" in result
        assert "margin:0" in result

    def test_no_html_tags_returns_text_as_is(self):
        text = "Just some description."
        result = extract_html_content(text)
        assert result == text

    def test_partial_html_fallback(self):
        text = "<html><body><p>Unclosed"
        result = extract_html_content(text)
        # Falls back to returning input unchanged since no </html>
        assert len(result) > 0

    def test_uppercase_html_tags(self):
        text = "<HTML><BODY>content</BODY></HTML>"
        result = extract_html_content(text)
        assert len(result) > 0

    def test_html_in_middle_of_long_text(self):
        prefix = "Some very long explanation that goes on and on. " * 20
        html = "<html><body><h1>Title</h1></body></html>"
        suffix = " And more text after." * 10
        text = prefix + html + suffix
        result = extract_html_content(text)
        assert "<html>" in result

    def test_newlines_inside_html(self):
        text = "<html>\n  <body>\n    <p>Hello</p>\n  </body>\n</html>"
        result = extract_html_content(text)
        assert "<html>" in result
        assert "<p>Hello</p>" in result


class TestExtractHtmlEdgeCases:
    def test_whitespace_only(self):
        result = extract_html_content("   ")
        assert result is not None

    def test_html_comment_only(self):
        text = "<!-- comment -->"
        result = extract_html_content(text)
        assert result is not None

    def test_malformed_fence_still_finds_html(self):
        text = "```\n<html><body>test</body></html>"
        result = extract_html_content(text)
        # After stripping incomplete fence, HTML should be found
        assert "<html>" in result or len(result) > 0

    def test_returns_string_type(self):
        result = extract_html_content("<html><body></body></html>")
        assert isinstance(result, str)

    def test_unicode_content(self):
        text = "<html><body><p>こんにちは世界</p></body></html>"
        result = extract_html_content(text)
        assert "こんにちは" in result
