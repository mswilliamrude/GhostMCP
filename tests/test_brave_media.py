"""Tests for Brave Search API media engines (images, videos, news)."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.engines.brave_media import BraveMediaEngine, ImageResult, VideoResult, NewsResult
from src.engines.base import SearchEngineError


# ---------------------------------------------------------------------------
# Sample API responses — Images
# ---------------------------------------------------------------------------

SAMPLE_IMAGE_RESPONSE = {
    "query": {"original": "sunset beach"},
    "results": [
        {
            "title": "Beautiful Sunset at the Beach",
            "url": "https://example.com/sunset-gallery",
            "properties": {
                "url": "https://cdn.example.com/images/sunset-large.jpg",
                "width": 1920,
                "height": 1080,
            },
            "thumbnail": {
                "src": "https://cdn.example.com/thumbs/sunset-sm.jpg",
            },
            "source": "example.com",
        },
        {
            "title": "Tropical Beach Sunset Wallpaper",
            "url": "https://wallpapers.io/tropical-sunset",
            "properties": {
                "url": "https://wallpapers.io/cdn/tropical-4k.png",
                "width": 3840,
                "height": 2160,
            },
            "thumbnail": {
                "src": "https://wallpapers.io/cdn/tropical-thumb.png",
            },
            "source": "wallpapers.io",
        },
        {
            "title": "",
            "url": "https://no-title.example.com/img",
            "properties": {
                "url": "https://no-title.example.com/img/full.jpg",
            },
            "thumbnail": {"src": ""},
            "source": "no-title.example.com",
        },
    ],
}

EMPTY_IMAGE_RESPONSE = {
    "query": {"original": "xyzzy_nothing"},
    "results": [],
}

IMAGE_RESPONSE_NO_URL = {
    "query": {"original": "test"},
    "results": [
        {"title": "No URL", "url": "", "properties": {"url": ""}, "thumbnail": {"src": ""}, "source": ""},
        {"title": "Valid", "url": "https://valid.com/page", "properties": {"url": "https://valid.com/img.jpg"}, "thumbnail": {"src": "https://valid.com/thumb.jpg"}, "source": "valid.com"},
    ],
}


# ---------------------------------------------------------------------------
# Sample API responses — Videos
# ---------------------------------------------------------------------------

SAMPLE_VIDEO_RESPONSE = {
    "query": {"original": "python tutorial"},
    "results": [
        {
            "title": "Python Tutorial for Beginners",
            "url": "https://www.youtube.com/watch?v=abc123",
            "thumbnail": {
                "src": "https://i.ytimg.com/vi/abc123/maxresdefault.jpg",
            },
            "video": {
                "duration": "12:34",
            },
            "age": "6 months ago",
            "meta_url": {
                "hostname": "www.youtube.com",
            },
            "description": "Learn Python from scratch with this comprehensive tutorial.",
        },
        {
            "title": "Advanced Python Concepts",
            "url": "https://vimeo.com/987654",
            "thumbnail": {
                "src": "https://vimeo.com/thumbs/987654.jpg",
            },
            "video": {
                "duration": "45:00",
            },
            "age": "1 year ago",
            "meta_url": {
                "hostname": "vimeo.com",
            },
            "description": "Deep dive into Python internals.",
        },
        {
            "title": "",
            "url": "https://example.com/video/no-title",
            "thumbnail": {"src": ""},
            "video": {},
            "age": "",
            "meta_url": {"hostname": "example.com"},
            "description": "",
        },
    ],
}

EMPTY_VIDEO_RESPONSE = {
    "query": {"original": "xyzzy_nothing"},
    "results": [],
}


# ---------------------------------------------------------------------------
# Sample API responses — News
# ---------------------------------------------------------------------------

SAMPLE_NEWS_RESPONSE = {
    "query": {"original": "cybersecurity breach"},
    "results": [
        {
            "title": "Major Data Breach Exposes 10M Records",
            "url": "https://techcrunch.com/2026/01/15/data-breach-millions",
            "description": "A major healthcare provider disclosed a breach affecting 10 million patients.",
            "age": "3 hours ago",
            "meta_url": {
                "hostname": "techcrunch.com",
            },
            "thumbnail": {
                "src": "https://techcrunch.com/img/breach-thumb.jpg",
            },
        },
        {
            "title": "New Ransomware Strain Targets Critical Infrastructure",
            "url": "https://www.wired.com/story/ransomware-infrastructure-2026",
            "description": "Security researchers discovered a new ransomware variant targeting power grids.",
            "age": "1 day ago",
            "meta_url": {
                "hostname": "www.wired.com",
            },
            "thumbnail": {
                "src": "https://www.wired.com/thumbs/ransomware.jpg",
            },
        },
        {
            "title": "",
            "url": "https://news.example.com/no-title",
            "description": "",
            "age": "",
            "meta_url": {"hostname": "news.example.com"},
            "thumbnail": {"src": ""},
        },
    ],
}

EMPTY_NEWS_RESPONSE = {
    "query": {"original": "xyzzy_nothing"},
    "results": [],
}


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------

class TestBraveMediaInit:

    def test_not_available_without_key(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_BRAVE_KEY", None)
            eng = BraveMediaEngine()
            assert not eng.available

    def test_available_with_key(self):
        eng = BraveMediaEngine(api_key="test-key")
        assert eng.available

    def test_reads_env_var(self):
        with patch.dict(os.environ, {"GHOST_BRAVE_KEY": "env-key"}):
            eng = BraveMediaEngine()
            assert eng.api_key == "env-key"
            assert eng.available

    def test_explicit_key_overrides_env(self):
        with patch.dict(os.environ, {"GHOST_BRAVE_KEY": "env-key"}):
            eng = BraveMediaEngine(api_key="explicit-key")
            assert eng.api_key == "explicit-key"


# ---------------------------------------------------------------------------
# Missing key tests
# ---------------------------------------------------------------------------

class TestMissingKey:

    @pytest.mark.asyncio
    async def test_images_no_key_raises(self):
        eng = BraveMediaEngine(api_key="")
        with pytest.raises(SearchEngineError) as exc_info:
            await eng.search_images("test")
        assert "GHOST_BRAVE_KEY not set" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_videos_no_key_raises(self):
        eng = BraveMediaEngine(api_key="")
        with pytest.raises(SearchEngineError) as exc_info:
            await eng.search_videos("test")
        assert "GHOST_BRAVE_KEY not set" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_news_no_key_raises(self):
        eng = BraveMediaEngine(api_key="")
        with pytest.raises(SearchEngineError) as exc_info:
            await eng.search_news("test")
        assert "GHOST_BRAVE_KEY not set" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Image search tests
# ---------------------------------------------------------------------------

class TestImageSearch:

    @pytest.mark.asyncio
    async def test_successful_search(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_IMAGE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_images("sunset beach", num_results=10)

        assert len(results) == 3
        assert all(isinstance(r, ImageResult) for r in results)

    @pytest.mark.asyncio
    async def test_image_fields_parsed(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_IMAGE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_images("sunset beach")

        r = results[0]
        assert r.title == "Beautiful Sunset at the Beach"
        assert r.url == "https://example.com/sunset-gallery"
        assert r.image_url == "https://cdn.example.com/images/sunset-large.jpg"
        assert r.thumbnail_url == "https://cdn.example.com/thumbs/sunset-sm.jpg"
        assert r.source == "example.com"
        assert r.width == 1920
        assert r.height == 1080

    @pytest.mark.asyncio
    async def test_empty_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = EMPTY_IMAGE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_images("xyzzy_nothing")

        assert results == []

    @pytest.mark.asyncio
    async def test_skips_empty_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = IMAGE_RESPONSE_NO_URL
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_images("test")

        assert len(results) == 1
        assert results[0].url == "https://valid.com/page"

    @pytest.mark.asyncio
    async def test_empty_title_uses_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_IMAGE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_images("test", num_results=10)

        # Third result has empty title — should fall back to URL
        assert results[2].title == "https://no-title.example.com/img"

    @pytest.mark.asyncio
    async def test_num_results_capped(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_IMAGE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_images("test", num_results=2)

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_401_invalid_key(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        eng = BraveMediaEngine(api_key="bad-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search_images("test")
        assert "Invalid GHOST_BRAVE_KEY" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_429_rate_limited(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search_images("test")
        assert "rate limit" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Video search tests
# ---------------------------------------------------------------------------

class TestVideoSearch:

    @pytest.mark.asyncio
    async def test_successful_search(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_VIDEO_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_videos("python tutorial", num_results=10)

        assert len(results) == 3
        assert all(isinstance(r, VideoResult) for r in results)

    @pytest.mark.asyncio
    async def test_video_fields_parsed(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_VIDEO_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_videos("python tutorial")

        r = results[0]
        assert r.title == "Python Tutorial for Beginners"
        assert r.url == "https://www.youtube.com/watch?v=abc123"
        assert r.thumbnail_url == "https://i.ytimg.com/vi/abc123/maxresdefault.jpg"
        assert r.source == "www.youtube.com"
        assert r.duration == "12:34"
        assert r.published == "6 months ago"
        assert "Learn Python" in r.description

    @pytest.mark.asyncio
    async def test_empty_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = EMPTY_VIDEO_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_videos("xyzzy_nothing")

        assert results == []

    @pytest.mark.asyncio
    async def test_empty_title_uses_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_VIDEO_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_videos("test", num_results=10)

        # Third result has empty title — should fall back to URL
        assert results[2].title == "https://example.com/video/no-title"

    @pytest.mark.asyncio
    async def test_num_results_capped(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_VIDEO_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_videos("test", num_results=1)

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_403_access_denied(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        eng = BraveMediaEngine(api_key="limited-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search_videos("test")
        assert "access denied" in str(exc_info.value)


# ---------------------------------------------------------------------------
# News search tests
# ---------------------------------------------------------------------------

class TestNewsSearch:

    @pytest.mark.asyncio
    async def test_successful_search(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NEWS_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_news("cybersecurity breach", num_results=10)

        assert len(results) == 3
        assert all(isinstance(r, NewsResult) for r in results)

    @pytest.mark.asyncio
    async def test_news_fields_parsed(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NEWS_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_news("cybersecurity breach")

        r = results[0]
        assert r.title == "Major Data Breach Exposes 10M Records"
        assert r.url == "https://techcrunch.com/2026/01/15/data-breach-millions"
        assert r.source == "techcrunch.com"
        assert r.published == "3 hours ago"
        assert "healthcare provider" in r.description
        assert r.thumbnail_url == "https://techcrunch.com/img/breach-thumb.jpg"

    @pytest.mark.asyncio
    async def test_empty_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = EMPTY_NEWS_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_news("xyzzy_nothing")

        assert results == []

    @pytest.mark.asyncio
    async def test_empty_title_uses_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NEWS_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_news("test", num_results=10)

        # Third result has empty title — should fall back to URL
        assert results[2].title == "https://news.example.com/no-title"

    @pytest.mark.asyncio
    async def test_num_results_capped(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NEWS_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search_news("test", num_results=2)

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx as _httpx

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.TimeoutException("")):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search_news("test")
        assert "timed out" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_connect_error(self):
        import httpx as _httpx

        eng = BraveMediaEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.ConnectError("")):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search_news("test")
        assert "Connection failed" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Response parsing unit tests
# ---------------------------------------------------------------------------

class TestImageParsing:

    def test_parse_standard_response(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_image_response(SAMPLE_IMAGE_RESPONSE, 10)
        assert len(results) == 3
        assert all(isinstance(r, ImageResult) for r in results)

    def test_parse_empty_response(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_image_response(EMPTY_IMAGE_RESPONSE, 10)
        assert results == []

    def test_parse_missing_results_key(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_image_response({"query": {}}, 10)
        assert results == []

    def test_parse_respects_num_results(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_image_response(SAMPLE_IMAGE_RESPONSE, 1)
        assert len(results) == 1

    def test_dimensions_default_zero(self):
        eng = BraveMediaEngine(api_key="test")
        response = {
            "results": [
                {
                    "title": "No dims",
                    "url": "https://example.com/page",
                    "properties": {"url": "https://example.com/img.jpg"},
                    "thumbnail": {"src": ""},
                    "source": "example.com",
                }
            ]
        }
        results = eng._parse_image_response(response, 10)
        assert results[0].width == 0
        assert results[0].height == 0


class TestVideoParsing:

    def test_parse_standard_response(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_video_response(SAMPLE_VIDEO_RESPONSE, 10)
        assert len(results) == 3
        assert all(isinstance(r, VideoResult) for r in results)

    def test_parse_empty_response(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_video_response(EMPTY_VIDEO_RESPONSE, 10)
        assert results == []

    def test_parse_missing_results_key(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_video_response({"query": {}}, 10)
        assert results == []

    def test_parse_respects_num_results(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_video_response(SAMPLE_VIDEO_RESPONSE, 1)
        assert len(results) == 1


class TestNewsParsing:

    def test_parse_standard_response(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_news_response(SAMPLE_NEWS_RESPONSE, 10)
        assert len(results) == 3
        assert all(isinstance(r, NewsResult) for r in results)

    def test_parse_empty_response(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_news_response(EMPTY_NEWS_RESPONSE, 10)
        assert results == []

    def test_parse_missing_results_key(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_news_response({"query": {}}, 10)
        assert results == []

    def test_parse_respects_num_results(self):
        eng = BraveMediaEngine(api_key="test")
        results = eng._parse_news_response(SAMPLE_NEWS_RESPONSE, 1)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Integration tests (require live API key)
# ---------------------------------------------------------------------------

class TestIntegration:

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_image_search(self):
        """Integration test — requires GHOST_BRAVE_KEY set."""
        key = os.environ.get("GHOST_BRAVE_KEY", "")
        if not key:
            pytest.skip("GHOST_BRAVE_KEY not set")

        eng = BraveMediaEngine(api_key=key)
        results = await eng.search_images("python programming", num_results=5)

        assert len(results) > 0
        assert all(isinstance(r, ImageResult) for r in results)
        assert all(r.url.startswith("http") for r in results)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_video_search(self):
        """Integration test — requires GHOST_BRAVE_KEY set."""
        key = os.environ.get("GHOST_BRAVE_KEY", "")
        if not key:
            pytest.skip("GHOST_BRAVE_KEY not set")

        eng = BraveMediaEngine(api_key=key)
        results = await eng.search_videos("python tutorial", num_results=5)

        assert len(results) > 0
        assert all(isinstance(r, VideoResult) for r in results)
        assert all(r.url.startswith("http") for r in results)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_news_search(self):
        """Integration test — requires GHOST_BRAVE_KEY set."""
        key = os.environ.get("GHOST_BRAVE_KEY", "")
        if not key:
            pytest.skip("GHOST_BRAVE_KEY not set")

        eng = BraveMediaEngine(api_key=key)
        results = await eng.search_news("technology", num_results=5)

        assert len(results) > 0
        assert all(isinstance(r, NewsResult) for r in results)
        assert all(r.url.startswith("http") for r in results)
