"""Phase 22: Export + Design Systems CRUD tests.

Covers:
  - Export utility functions: is_skippable_asset_url, extension_from_mime_type,
    extension_from_url, is_fetchable_asset_reference, parse_srcset,
    extract_css_urls, collect_asset_candidates, resolve_fetch_url,
    is_private_ip, decode_data_url
  - Export HTTP endpoint: POST /api/export returns a ZIP
  - Design Systems CRUD: list, create, update, delete via TestClient
  - Design systems error cases: 404, blank name, missing
"""

import base64
import json
import os
import tempfile
import zipfile
from io import BytesIO

import pytest
from fastapi.testclient import TestClient

from routes.export import (
    is_skippable_asset_url,
    extension_from_mime_type,
    extension_from_url,
    is_fetchable_asset_reference,
    parse_srcset,
    extract_css_urls,
    collect_asset_candidates,
    resolve_fetch_url,
    is_private_ip,
    decode_data_url,
    create_project_zip,
    ExportedAsset,
)
from bs4 import BeautifulSoup


# ──────────────────────────────────────────────────────────────
# is_skippable_asset_url
# ──────────────────────────────────────────────────────────────
class TestIsSkippableAssetUrl:
    def test_empty_string(self):
        assert is_skippable_asset_url("") is True

    def test_hash_fragment(self):
        assert is_skippable_asset_url("#section") is True

    def test_javascript_protocol(self):
        assert is_skippable_asset_url("javascript:void(0)") is True

    def test_mailto_protocol(self):
        assert is_skippable_asset_url("mailto:x@y.com") is True

    def test_tel_protocol(self):
        assert is_skippable_asset_url("tel:+15555555555") is True

    def test_https_url_not_skippable(self):
        assert is_skippable_asset_url("https://example.com/img.png") is False

    def test_relative_url_not_skippable(self):
        assert is_skippable_asset_url("images/logo.png") is False

    def test_whitespace_only(self):
        assert is_skippable_asset_url("   ") is True


# ──────────────────────────────────────────────────────────────
# extension_from_mime_type
# ──────────────────────────────────────────────────────────────
class TestExtensionFromMimeType:
    def test_image_jpeg(self):
        assert extension_from_mime_type("image/jpeg") == "jpg"

    def test_image_png(self):
        assert extension_from_mime_type("image/png") == "png"

    def test_image_gif(self):
        assert extension_from_mime_type("image/gif") == "gif"

    def test_image_webp(self):
        assert extension_from_mime_type("image/webp") == "webp"

    def test_image_svg(self):
        assert extension_from_mime_type("image/svg+xml") == "svg"

    def test_unknown_defaults_bin(self):
        assert extension_from_mime_type("application/octet-stream") == "bin"

    def test_mime_with_charset_stripped(self):
        assert extension_from_mime_type("image/png; charset=utf-8") == "png"

    def test_case_insensitive(self):
        assert extension_from_mime_type("IMAGE/PNG") == "png"


# ──────────────────────────────────────────────────────────────
# extension_from_url
# ──────────────────────────────────────────────────────────────
class TestExtensionFromUrl:
    def test_png_url(self):
        assert extension_from_url("https://cdn.example.com/img.png") == "png"

    def test_jpg_url(self):
        assert extension_from_url("https://cdn.example.com/photo.jpg") == "jpg"

    def test_data_url_png(self):
        assert extension_from_url("data:image/png;base64,abc123") == "png"

    def test_data_url_jpeg(self):
        assert extension_from_url("data:image/jpeg;base64,abc") == "jpg"

    def test_no_extension_returns_bin(self):
        assert extension_from_url("https://cdn.example.com/file") == "bin"

    def test_svg_extension(self):
        assert extension_from_url("https://cdn.example.com/icon.svg") == "svg"


# ──────────────────────────────────────────────────────────────
# is_fetchable_asset_reference
# ──────────────────────────────────────────────────────────────
class TestIsFetchableAssetReference:
    def test_https_url_fetchable(self):
        assert is_fetchable_asset_reference("https://example.com/img.png") is True

    def test_data_image_url_fetchable(self):
        assert is_fetchable_asset_reference("data:image/png;base64,abc") is True

    def test_javascript_not_fetchable(self):
        assert is_fetchable_asset_reference("javascript:void(0)") is False

    def test_blob_url_not_fetchable(self):
        assert is_fetchable_asset_reference("blob:http://localhost/xyz") is False

    def test_empty_not_fetchable(self):
        assert is_fetchable_asset_reference("") is False

    def test_data_non_image_not_fetchable(self):
        assert is_fetchable_asset_reference("data:text/plain;base64,abc") is False


# ──────────────────────────────────────────────────────────────
# parse_srcset
# ──────────────────────────────────────────────────────────────
class TestParseSrcset:
    def test_single_url(self):
        assert parse_srcset("img.png") == ["img.png"]

    def test_multiple_with_descriptors(self):
        result = parse_srcset("small.png 1x, large.png 2x")
        assert result == ["small.png", "large.png"]

    def test_empty_string(self):
        assert parse_srcset("") == []

    def test_url_with_width(self):
        result = parse_srcset("img-480.jpg 480w, img-800.jpg 800w")
        assert result == ["img-480.jpg", "img-800.jpg"]


# ──────────────────────────────────────────────────────────────
# extract_css_urls
# ──────────────────────────────────────────────────────────────
class TestExtractCssUrls:
    def test_single_url(self):
        css = "background: url('bg.png');"
        result = extract_css_urls(css)
        assert "bg.png" in result

    def test_double_quoted_url(self):
        css = 'background-image: url("logo.png");'
        result = extract_css_urls(css)
        assert "logo.png" in result

    def test_unquoted_url(self):
        css = "background: url(icon.svg);"
        result = extract_css_urls(css)
        assert "icon.svg" in result

    def test_multiple_urls(self):
        css = "bg: url('a.png'); border: url('b.png');"
        result = extract_css_urls(css)
        assert len(result) == 2

    def test_no_urls(self):
        assert extract_css_urls("color: red;") == []


# ──────────────────────────────────────────────────────────────
# collect_asset_candidates
# ──────────────────────────────────────────────────────────────
class TestCollectAssetCandidates:
    def _soup(self, html: str) -> BeautifulSoup:
        return BeautifulSoup(html, "html.parser")

    def test_img_src_found(self):
        soup = self._soup('<img src="https://example.com/img.png">')
        candidates = collect_asset_candidates(soup)
        urls = [c.url for c in candidates]
        assert "https://example.com/img.png" in urls

    def test_css_url_found(self):
        soup = self._soup('<style>body { background: url("bg.jpg"); }</style>')
        candidates = collect_asset_candidates(soup)
        urls = [c.url for c in candidates]
        assert "bg.jpg" in urls

    def test_javascript_href_not_collected(self):
        soup = self._soup('<a href="javascript:void(0)">click</a>')
        candidates = collect_asset_candidates(soup)
        urls = [c.url for c in candidates]
        assert "javascript:void(0)" not in urls

    def test_empty_html_returns_empty(self):
        soup = self._soup("<html><body></body></html>")
        candidates = collect_asset_candidates(soup)
        assert candidates == []


# ──────────────────────────────────────────────────────────────
# resolve_fetch_url
# ──────────────────────────────────────────────────────────────
class TestResolveFetchUrl:
    def test_absolute_https(self):
        result = resolve_fetch_url("https://cdn.example.com/img.png", None)
        assert result == "https://cdn.example.com/img.png"

    def test_protocol_relative_with_base(self):
        result = resolve_fetch_url("//cdn.example.com/img.png", "https://example.com")
        assert result == "https://cdn.example.com/img.png"

    def test_relative_with_base(self):
        result = resolve_fetch_url("images/logo.png", "https://example.com")
        assert result == "https://example.com/images/logo.png"

    def test_relative_without_base_returns_none(self):
        result = resolve_fetch_url("images/logo.png", None)
        assert result is None

    def test_data_url_returned_as_is(self):
        url = "data:image/png;base64,abc"
        assert resolve_fetch_url(url, None) == url


# ──────────────────────────────────────────────────────────────
# is_private_ip
# ──────────────────────────────────────────────────────────────
class TestIsPrivateIp:
    def test_localhost_is_private(self):
        assert is_private_ip("127.0.0.1") is True

    def test_rfc1918_is_private(self):
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True

    def test_public_ip_not_private(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False


# ──────────────────────────────────────────────────────────────
# decode_data_url
# ──────────────────────────────────────────────────────────────
class TestDecodeDataUrl:
    def test_valid_base64_png(self):
        payload = base64.b64encode(b"\x89PNG").decode()
        data_url = f"data:image/png;base64,{payload}"
        result = decode_data_url(data_url)
        assert result is not None
        content, ext = result
        assert ext == "png"
        assert content == b"\x89PNG"

    def test_invalid_non_image_mime(self):
        data_url = "data:text/plain;base64,aGVsbG8="
        assert decode_data_url(data_url) is None

    def test_malformed_no_comma(self):
        assert decode_data_url("data:image/png;base64") is None


# ──────────────────────────────────────────────────────────────
# create_project_zip
# ──────────────────────────────────────────────────────────────
class TestCreateProjectZip:
    def test_creates_valid_zip_with_index_html(self):
        html = "<html><body>hello</body></html>"
        assets: list[ExportedAsset] = []
        content = create_project_zip(html, assets)
        with zipfile.ZipFile(BytesIO(content)) as zf:
            assert "index.html" in zf.namelist()
            assert zf.read("index.html").decode() == html

    def test_includes_assets_in_zip(self):
        html = "<html/>"
        assets = [ExportedAsset(path="assets/image-1.png", content=b"\x89PNG")]
        content = create_project_zip(html, assets)
        with zipfile.ZipFile(BytesIO(content)) as zf:
            assert "assets/image-1.png" in zf.namelist()


# ──────────────────────────────────────────────────────────────
# Export HTTP endpoint
# ──────────────────────────────────────────────────────────────
class TestExportEndpoint:
    @pytest.fixture
    def client(self):
        from main import app
        return TestClient(app)

    def test_export_simple_html_returns_zip(self, client):
        r = client.post("/api/export", json={"code": "<html><body>hello</body></html>"})
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/zip"
        with zipfile.ZipFile(BytesIO(r.content)) as zf:
            assert "index.html" in zf.namelist()

    def test_export_contains_html_content(self, client):
        html = "<html><body>test content</body></html>"
        r = client.post("/api/export", json={"code": html})
        with zipfile.ZipFile(BytesIO(r.content)) as zf:
            content = zf.read("index.html").decode()
            assert "test content" in content


# ──────────────────────────────────────────────────────────────
# Design Systems CRUD
# ──────────────────────────────────────────────────────────────
class TestDesignSystemsCrud:
    @pytest.fixture
    def client(self, tmp_path):
        os.environ["SCREENSHOT_TO_CODE_DATA_DIR"] = str(tmp_path)
        from main import app
        with TestClient(app) as c:
            yield c
        del os.environ["SCREENSHOT_TO_CODE_DATA_DIR"]

    def test_list_empty(self, client):
        r = client.get("/api/design-systems")
        assert r.status_code == 200
        assert r.json() == []

    def test_create_design_system(self, client):
        r = client.post("/api/design-systems", json={"name": "MyDS", "content": ":root{}"})
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "MyDS"
        assert "id" in data

    def test_create_then_list(self, client):
        client.post("/api/design-systems", json={"name": "DS1", "content": "a"})
        r = client.get("/api/design-systems")
        assert len(r.json()) == 1

    def test_update_design_system_name(self, client):
        created = client.post("/api/design-systems", json={"name": "Old", "content": "x"}).json()
        r = client.patch(f"/api/design-systems/{created['id']}", json={"name": "New"})
        assert r.status_code == 200
        assert r.json()["name"] == "New"

    def test_update_preserves_unset_fields(self, client):
        created = client.post("/api/design-systems", json={"name": "DS", "content": "original"}).json()
        client.patch(f"/api/design-systems/{created['id']}", json={"name": "Renamed"})
        r = client.get("/api/design-systems")
        item = r.json()[0]
        assert item["content"] == "original"

    def test_delete_design_system(self, client):
        created = client.post("/api/design-systems", json={"name": "ToDelete", "content": ""}).json()
        r = client.delete(f"/api/design-systems/{created['id']}")
        assert r.status_code == 204
        remaining = client.get("/api/design-systems").json()
        assert all(item["id"] != created["id"] for item in remaining)

    def test_delete_nonexistent_returns_404(self, client):
        r = client.delete("/api/design-systems/does-not-exist")
        assert r.status_code == 404

    def test_update_nonexistent_returns_404(self, client):
        r = client.patch("/api/design-systems/does-not-exist", json={"name": "x"})
        assert r.status_code == 404

    def test_create_blank_name_returns_400(self, client):
        r = client.post("/api/design-systems", json={"name": "   ", "content": ""})
        assert r.status_code == 400

    def test_create_multiple_returns_all(self, client):
        for i in range(3):
            client.post("/api/design-systems", json={"name": f"DS{i}", "content": str(i)})
        items = client.get("/api/design-systems").json()
        assert len(items) == 3
