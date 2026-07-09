"""Tests for Brave Search API engine."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.engines.brave import BraveEngine
from ghostmcp.engines.base import SearchResult, SearchEngineError


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_BRAVE_RESPONSE = {
    "query": {"original": "Python asyncio best practices"},
    "web": {
        "results": [
            {
                "title": "Async IO in Python: A Complete Walkthrough",
                "url": "https://realpython.com/async-io-python/",
                "description": "This tutorial will give you a firm grasp of async IO in Python.",
                "age": "2 years ago",
                "language": "en",
            },
            {
                "title": "Python asyncio documentation",
                "url": "https://docs.python.org/3/library/asyncio.html",
                "description": "asyncio is a library to write concurrent code using the async/await syntax.",
                "age": "3 months ago",
                "language": "en",
            },
            {
                "title": "",
                "url": "https://no-title.example.com/page",
                "description": "A result with empty title.",
            },
        ]
    },
}

EMPTY_BRAVE_RESPONSE = {
    "query": {"original": "xyzzy_nonexistent_query_2026"},
    "web": {"results": []},
}

BRAVE_RESPONSE_NO_URL = {
    "query": {"original": "test"},
    "web": {
        "results": [
            {"title": "No URL Entry", "url": "", "description": "Should be skipped."},
            {"title": "Valid Entry", "url": "https://valid.com", "description": "Kept."},
        ]
    },
}


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------

class TestBraveEngineInit:

    def test_name(self):
        eng = BraveEngine()
        assert eng.name == "brave"

    def test_min_delay(self):
        eng = BraveEngine()
        assert eng.min_delay == 1.0

    def test_not_available_without_key(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_BRAVE_KEY", None)
            eng = BraveEngine()
            assert not eng.available

    def test_available_with_key(self):
        eng = BraveEngine(api_key="test-key")
        assert eng.available

    def test_reads_env_var(self):
        with patch.dict(os.environ, {"GHOST_BRAVE_KEY": "env-key"}):
            eng = BraveEngine()
            assert eng.api_key == "env-key"
            assert eng.available

    def test_explicit_key_overrides_env(self):
        with patch.dict(os.environ, {"GHOST_BRAVE_KEY": "env-key"}):
            eng = BraveEngine(api_key="explicit-key")
            assert eng.api_key == "explicit-key"


# ---------------------------------------------------------------------------
# Search tests
# ---------------------------------------------------------------------------

class TestBraveSearch:

    @pytest.mark.asyncio
    async def test_no_key_raises(self):
        eng = BraveEngine(api_key="")
        with pytest.raises(SearchEngineError) as exc_info:
            await eng.search("test query")
        assert "GHOST_BRAVE_KEY not set" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_successful_search(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_BRAVE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("Python asyncio", num_results=5)

        assert len(results) == 3
        assert results[0].title == "Async IO in Python: A Complete Walkthrough"
        assert results[0].url == "https://realpython.com/async-io-python/"
        assert results[0].source_engine == "brave"

    @pytest.mark.asyncio
    async def test_empty_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = EMPTY_BRAVE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("xyzzy_nothing")

        assert results == []

    @pytest.mark.asyncio
    async def test_skips_empty_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = BRAVE_RESPONSE_NO_URL
        mock_resp.raise_for_status = MagicMock()

        eng = BraveEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("test")

        assert len(results) == 1
        assert results[0].url == "https://valid.com"

    @pytest.mark.asyncio
    async def test_empty_title_uses_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_BRAVE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("test", num_results=10)

        # Third result has empty title — should fall back to URL
        assert results[2].title == "https://no-title.example.com/page"

    @pytest.mark.asyncio
    async def test_401_invalid_key(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        eng = BraveEngine(api_key="bad-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "Invalid GHOST_BRAVE_KEY" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_403_access_denied(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        eng = BraveEngine(api_key="limited-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "access denied" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_429_rate_limited(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        eng = BraveEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "rate limit" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx as _httpx

        eng = BraveEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.TimeoutException("")):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "timed out" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_connect_error(self):
        import httpx as _httpx

        eng = BraveEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.ConnectError("")):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "Connection failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_num_results_capped(self):
        """Verify results are capped at num_results."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_BRAVE_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BraveEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("test", num_results=2)

        assert len(results) == 2


# ---------------------------------------------------------------------------
# Response parsing tests
# ---------------------------------------------------------------------------

class TestBraveParseResponse:

    def test_parse_standard_response(self):
        eng = BraveEngine(api_key="test")
        results = eng._parse_response(SAMPLE_BRAVE_RESPONSE, 10)
        assert len(results) == 3
        assert all(isinstance(r, SearchResult) for r in results)

    def test_parse_empty_response(self):
        eng = BraveEngine(api_key="test")
        results = eng._parse_response(EMPTY_BRAVE_RESPONSE, 10)
        assert results == []

    def test_parse_missing_web_key(self):
        eng = BraveEngine(api_key="test")
        results = eng._parse_response({"query": {}}, 10)
        assert results == []

    def test_parse_respects_num_results(self):
        eng = BraveEngine(api_key="test")
        results = eng._parse_response(SAMPLE_BRAVE_RESPONSE, 1)
        assert len(results) == 1

    def test_source_engine_set(self):
        eng = BraveEngine(api_key="test")
        results = eng._parse_response(SAMPLE_BRAVE_RESPONSE, 10)
        for r in results:
            assert r.source_engine == "brave"
