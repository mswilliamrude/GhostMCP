"""Tests for SearXNG metasearch engine."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.engines.searxng import SearXNGEngine
from src.engines.base import SearchResult, SearchEngineError


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_SEARXNG_RESPONSE = {
    "query": "Python asyncio",
    "results": [
        {
            "title": "Async IO in Python: A Complete Walkthrough",
            "url": "https://realpython.com/async-io-python/",
            "content": "This tutorial will give you a firm grasp of async IO in Python.",
            "engine": "google",
            "score": 1.0,
        },
        {
            "title": "Python asyncio documentation",
            "url": "https://docs.python.org/3/library/asyncio.html",
            "content": "asyncio is a library to write concurrent code using the async/await syntax.",
            "engine": "duckduckgo",
            "score": 0.9,
        },
        {
            "title": "Wikipedia: Asyncio",
            "url": "https://en.wikipedia.org/wiki/Asyncio",
            "content": "asyncio is a Python library for asynchronous programming.",
            "engine": "wikipedia",
            "score": 0.8,
        },
    ],
    "suggestions": ["python async await", "python concurrency"],
    "answers": [],
    "infoboxes": [],
}

EMPTY_SEARXNG_RESPONSE = {
    "query": "xyzzy_nonexistent_query_2026",
    "results": [],
    "suggestions": [],
    "answers": [],
    "infoboxes": [],
}

SEARXNG_RESPONSE_NO_URL = {
    "query": "test",
    "results": [
        {"title": "No URL Entry", "url": "", "content": "Should be skipped.", "engine": "test"},
        {"title": "Valid Entry", "url": "https://valid.com", "content": "Kept.", "engine": "google"},
    ],
}

SEARXNG_CONFIG_RESPONSE = {
    "engines": {
        "google": {"name": "Google", "categories": ["general"], "enabled": True},
        "duckduckgo": {"name": "DuckDuckGo", "categories": ["general"], "enabled": True},
        "wikipedia": {"name": "Wikipedia", "categories": ["general"], "enabled": True},
        "github": {"name": "GitHub", "categories": ["it"], "enabled": True},
    }
}


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------

class TestSearXNGEngineInit:

    def test_name(self):
        eng = SearXNGEngine()
        assert eng.name == "searxng"

    def test_min_delay(self):
        eng = SearXNGEngine()
        assert eng.min_delay == 1.0

    def test_not_available_without_url(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_SEARXNG_URL", None)
            eng = SearXNGEngine()
            assert not eng.available

    def test_available_with_url(self):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        assert eng.available

    def test_reads_env_var(self):
        with patch.dict(os.environ, {"GHOST_SEARXNG_URL": "http://searx.local:8080"}):
            eng = SearXNGEngine()
            assert eng.instance_url == "http://searx.local:8080"
            assert eng.available

    def test_explicit_url_overrides_env(self):
        with patch.dict(os.environ, {"GHOST_SEARXNG_URL": "http://env-url.local"}):
            eng = SearXNGEngine(instance_url="http://explicit-url.local")
            assert eng.instance_url == "http://explicit-url.local"

    def test_strips_trailing_slash(self):
        eng = SearXNGEngine(instance_url="http://localhost:8888/")
        assert eng.instance_url == "http://localhost:8888"


# ---------------------------------------------------------------------------
# Search tests with mocked HTTP
# ---------------------------------------------------------------------------

class TestSearXNGSearch:

    @pytest.mark.asyncio
    async def test_search_no_url_raises_error(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_SEARXNG_URL", None)
            eng = SearXNGEngine()
            with pytest.raises(SearchEngineError) as exc:
                await eng.search("test query")
            assert "GHOST_SEARXNG_URL not set" in str(exc.value)

    @pytest.mark.asyncio
    async def test_search_success(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")

        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_SEARXNG_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            # Skip rate limiting for test
            eng._rate_limit = AsyncMock()

            results = await eng.search("Python asyncio", num_results=10)

        assert len(results) == 3
        assert results[0].title == "Async IO in Python: A Complete Walkthrough"
        assert results[0].url == "https://realpython.com/async-io-python/"
        assert "searxng:google" in results[0].source_engine
        assert results[1].source_engine == "searxng:duckduckgo"
        assert results[2].source_engine == "searxng:wikipedia"

    @pytest.mark.asyncio
    async def test_search_empty_results(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=200, json_data=EMPTY_SEARXNG_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            results = await eng.search("xyzzy_nonexistent", num_results=10)

        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_search_skips_empty_urls(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=200, json_data=SEARXNG_RESPONSE_NO_URL)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            results = await eng.search("test", num_results=10)

        assert len(results) == 1
        assert results[0].title == "Valid Entry"

    @pytest.mark.asyncio
    async def test_search_respects_num_results(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_SEARXNG_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            results = await eng.search("Python asyncio", num_results=2)

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_search_rate_limit_error(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=429)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            with pytest.raises(SearchEngineError) as exc:
                await eng.search("test")

        assert "rate limit" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_search_403_blocked(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=403)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            with pytest.raises(SearchEngineError) as exc:
                await eng.search("test")

        assert "blocked" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_search_404_not_found(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=404)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            with pytest.raises(SearchEngineError) as exc:
                await eng.search("test")

        assert "not found" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Query parameter tests
# ---------------------------------------------------------------------------

class TestSearXNGQueryParams:

    @pytest.mark.asyncio
    async def test_search_with_categories(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_SEARXNG_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            await eng.search("test", categories="science,it")

            # Verify categories were passed
            call_args = mock_instance.get.call_args
            assert call_args[1]["params"]["categories"] == "science,it"

    @pytest.mark.asyncio
    async def test_search_with_engines(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_SEARXNG_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            await eng.search("test", engines="google,duckduckgo")

            call_args = mock_instance.get.call_args
            assert call_args[1]["params"]["engines"] == "google,duckduckgo"

    @pytest.mark.asyncio
    async def test_search_with_time_range(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_SEARXNG_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            await eng.search("test", time_range="week")

            call_args = mock_instance.get.call_args
            assert call_args[1]["params"]["time_range"] == "week"

    @pytest.mark.asyncio
    async def test_search_with_language(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_SEARXNG_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            await eng.search("test", language="de")

            call_args = mock_instance.get.call_args
            assert call_args[1]["params"]["language"] == "de"

    @pytest.mark.asyncio
    async def test_search_json_format_always_set(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        eng._rate_limit = AsyncMock()

        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_SEARXNG_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            await eng.search("test")

            call_args = mock_instance.get.call_args
            assert call_args[1]["params"]["format"] == "json"


# ---------------------------------------------------------------------------
# Response parsing tests
# ---------------------------------------------------------------------------

class TestSearXNGResponseParsing:

    def test_parse_response_basic(self):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        results = eng._parse_response(SAMPLE_SEARXNG_RESPONSE, num_results=10)

        assert len(results) == 3
        assert all(isinstance(r, SearchResult) for r in results)

    def test_parse_response_with_limit(self):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        results = eng._parse_response(SAMPLE_SEARXNG_RESPONSE, num_results=2)

        assert len(results) == 2

    def test_parse_response_empty(self):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        results = eng._parse_response(EMPTY_SEARXNG_RESPONSE, num_results=10)

        assert len(results) == 0

    def test_parse_response_skips_empty_urls(self):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        results = eng._parse_response(SEARXNG_RESPONSE_NO_URL, num_results=10)

        assert len(results) == 1
        assert results[0].url == "https://valid.com"

    def test_parse_response_source_engine_format(self):
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        results = eng._parse_response(SAMPLE_SEARXNG_RESPONSE, num_results=10)

        # Should be "searxng:engine_name"
        assert results[0].source_engine == "searxng:google"
        assert results[1].source_engine == "searxng:duckduckgo"
        assert results[2].source_engine == "searxng:wikipedia"

    def test_parse_response_fallback_title(self):
        """If title is empty, URL should be used as title."""
        response = {
            "results": [
                {"title": "", "url": "https://example.com/page", "content": "Test", "engine": "test"}
            ]
        }
        eng = SearXNGEngine(instance_url="http://localhost:8888")
        results = eng._parse_response(response, num_results=10)

        assert results[0].title == "https://example.com/page"


# ---------------------------------------------------------------------------
# Get engines endpoint test
# ---------------------------------------------------------------------------

class TestSearXNGGetEngines:

    @pytest.mark.asyncio
    async def test_get_engines_success(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")

        mock_resp = mock_httpx_response(status_code=200, json_data=SEARXNG_CONFIG_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            engines = await eng.get_engines()

        assert "google" in engines
        assert "duckduckgo" in engines
        assert engines["google"]["enabled"] is True

    @pytest.mark.asyncio
    async def test_get_engines_no_url_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_SEARXNG_URL", None)
            eng = SearXNGEngine()
            with pytest.raises(SearchEngineError):
                await eng.get_engines()

    @pytest.mark.asyncio
    async def test_get_engines_failure_returns_empty(self, mock_httpx_response):
        eng = SearXNGEngine(instance_url="http://localhost:8888")

        mock_resp = mock_httpx_response(status_code=500)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            engines = await eng.get_engines()

        assert engines == {}


# ---------------------------------------------------------------------------
# Integration test (requires live SearXNG instance)
# ---------------------------------------------------------------------------

class TestSearXNGIntegration:

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_search(self):
        """Test against a live SearXNG instance.

        Run with: pytest -m integration
        Requires: GHOST_SEARXNG_URL environment variable
        """
        url = os.environ.get("GHOST_SEARXNG_URL")
        if not url:
            pytest.skip("GHOST_SEARXNG_URL not set")

        eng = SearXNGEngine(instance_url=url)
        results = await eng.search("Python programming", num_results=5)

        assert len(results) >= 1
        assert all(r.url.startswith("http") for r in results)
        assert all(r.title for r in results)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_search_with_filters(self):
        """Test filtered search against live instance."""
        url = os.environ.get("GHOST_SEARXNG_URL")
        if not url:
            pytest.skip("GHOST_SEARXNG_URL not set")

        eng = SearXNGEngine(instance_url=url)
        results = await eng.search(
            "machine learning",
            categories="science",
            time_range="month",
            num_results=5,
        )

        # May return fewer results with filters
        assert isinstance(results, list)
