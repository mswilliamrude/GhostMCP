"""Tests for Bing Search API engine."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.engines.bing import BingEngine
from ghostmcp.engines.base import SearchResult, SearchEngineError


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_BING_RESPONSE = {
    "webPages": {
        "totalEstimatedMatches": 42000000,
        "value": [
            {
                "name": "Python Official Website",
                "url": "https://www.python.org/",
                "snippet": "The official home of the Python Programming Language.",
                "dateLastCrawled": "2026-01-10T00:00:00.0000000Z",
            },
            {
                "name": "Python Tutorial - W3Schools",
                "url": "https://www.w3schools.com/python/",
                "snippet": "Well organized and easy to understand Web building tutorials.",
                "dateLastCrawled": "2026-01-09T00:00:00.0000000Z",
            },
            {
                "name": "",
                "url": "https://no-title.example.com/python",
                "snippet": "A result with an empty title.",
            },
        ],
    },
    "_type": "SearchResponse",
    "queryContext": {"originalQuery": "python programming"},
}

EMPTY_BING_RESPONSE = {
    "webPages": {
        "totalEstimatedMatches": 0,
        "value": [],
    },
    "_type": "SearchResponse",
    "queryContext": {"originalQuery": "xyzzy_nonexistent_2026"},
}

BING_RESPONSE_NO_URL = {
    "webPages": {
        "value": [
            {"name": "No URL Entry", "url": "", "snippet": "Should be skipped."},
            {"name": "Valid Entry", "url": "https://valid.com", "snippet": "Kept."},
        ]
    },
}

BING_RESPONSE_NO_WEBPAGES = {
    "_type": "SearchResponse",
    "queryContext": {"originalQuery": "nothing"},
}


# ---------------------------------------------------------------------------
# Initialization tests
# ---------------------------------------------------------------------------

class TestBingEngineInit:

    def test_name(self):
        eng = BingEngine()
        assert eng.name == "bing"

    def test_min_delay(self):
        eng = BingEngine()
        assert eng.min_delay == 1.0

    def test_not_available_without_key(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_BING_KEY", None)
            eng = BingEngine()
            assert not eng.available

    def test_available_with_key(self):
        eng = BingEngine(api_key="test-key")
        assert eng.available

    def test_reads_env_var(self):
        with patch.dict(os.environ, {"GHOST_BING_KEY": "env-key"}):
            eng = BingEngine()
            assert eng.api_key == "env-key"
            assert eng.available

    def test_explicit_key_overrides_env(self):
        with patch.dict(os.environ, {"GHOST_BING_KEY": "env-key"}):
            eng = BingEngine(api_key="explicit-key")
            assert eng.api_key == "explicit-key"


# ---------------------------------------------------------------------------
# Availability tests
# ---------------------------------------------------------------------------

class TestBingAvailability:

    def test_available_true_with_key(self):
        eng = BingEngine(api_key="some-key")
        assert eng.available is True

    def test_available_false_empty_string(self):
        eng = BingEngine(api_key="")
        assert eng.available is False

    def test_available_false_no_env(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_BING_KEY", None)
            eng = BingEngine()
            assert eng.available is False

    def test_available_true_from_env(self):
        with patch.dict(os.environ, {"GHOST_BING_KEY": "from-env"}):
            eng = BingEngine()
            assert eng.available is True


# ---------------------------------------------------------------------------
# Search tests
# ---------------------------------------------------------------------------

class TestBingSearch:

    @pytest.mark.asyncio
    async def test_no_key_raises(self):
        eng = BingEngine(api_key="")
        with pytest.raises(SearchEngineError) as exc_info:
            await eng.search("test query")
        assert "GHOST_BING_KEY not set" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_successful_search(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_BING_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("python programming", num_results=10)

        assert len(results) == 3
        assert results[0].title == "Python Official Website"
        assert results[0].url == "https://www.python.org/"
        assert results[0].source_engine == "bing"

    @pytest.mark.asyncio
    async def test_snippet_parsed(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_BING_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("python programming")

        assert "official home" in results[0].snippet

    @pytest.mark.asyncio
    async def test_empty_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = EMPTY_BING_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("xyzzy_nothing")

        assert results == []

    @pytest.mark.asyncio
    async def test_skips_empty_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = BING_RESPONSE_NO_URL
        mock_resp.raise_for_status = MagicMock()

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("test")

        assert len(results) == 1
        assert results[0].url == "https://valid.com"

    @pytest.mark.asyncio
    async def test_empty_title_uses_url(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_BING_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("test", num_results=10)

        # Third result has empty title — should fall back to URL
        assert results[2].title == "https://no-title.example.com/python"

    @pytest.mark.asyncio
    async def test_num_results_capped(self):
        """Verify results are capped at num_results."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_BING_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("test", num_results=2)

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_missing_webpages_key(self):
        """Handle response without webPages key gracefully."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = BING_RESPONSE_NO_WEBPAGES
        mock_resp.raise_for_status = MagicMock()

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("nothing")

        assert results == []


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------

class TestBingErrors:

    @pytest.mark.asyncio
    async def test_401_invalid_key(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        eng = BingEngine(api_key="bad-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "Invalid GHOST_BING_KEY" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_403_access_denied(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        eng = BingEngine(api_key="limited-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "access denied" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_429_rate_limited(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "rate limit" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx as _httpx

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.TimeoutException("")):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "timed out" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_connect_error(self):
        import httpx as _httpx

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.ConnectError("")):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "Connection failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_generic_request_error(self):
        import httpx as _httpx

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.RequestError("network issue")):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "Request failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_http_status_error(self):
        import httpx as _httpx

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.raise_for_status.side_effect = _httpx.HTTPStatusError(
            "500 Internal Server Error",
            request=MagicMock(),
            response=mock_resp,
        )

        eng = BingEngine(api_key="test-key")
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError) as exc_info:
                await eng.search("test")
        assert "API HTTP 500" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Response parsing tests
# ---------------------------------------------------------------------------

class TestBingParseResponse:

    def test_parse_standard_response(self):
        eng = BingEngine(api_key="test")
        results = eng._parse_response(SAMPLE_BING_RESPONSE, 10)
        assert len(results) == 3
        assert all(isinstance(r, SearchResult) for r in results)

    def test_parse_empty_response(self):
        eng = BingEngine(api_key="test")
        results = eng._parse_response(EMPTY_BING_RESPONSE, 10)
        assert results == []

    def test_parse_missing_webpages_key(self):
        eng = BingEngine(api_key="test")
        results = eng._parse_response({"_type": "SearchResponse"}, 10)
        assert results == []

    def test_parse_respects_num_results(self):
        eng = BingEngine(api_key="test")
        results = eng._parse_response(SAMPLE_BING_RESPONSE, 1)
        assert len(results) == 1

    def test_source_engine_set(self):
        eng = BingEngine(api_key="test")
        results = eng._parse_response(SAMPLE_BING_RESPONSE, 10)
        for r in results:
            assert r.source_engine == "bing"


# ---------------------------------------------------------------------------
# Integration tests (require live API key)
# ---------------------------------------------------------------------------

class TestIntegration:

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_search(self):
        """Integration test — requires GHOST_BING_KEY set."""
        key = os.environ.get("GHOST_BING_KEY", "")
        if not key:
            pytest.skip("GHOST_BING_KEY not set")

        eng = BingEngine(api_key=key)
        results = await eng.search("python programming language", num_results=5)

        assert len(results) > 0
        assert all(isinstance(r, SearchResult) for r in results)
        assert all(r.url.startswith("http") for r in results)
        assert all(r.source_engine == "bing" for r in results)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_freshness_filter(self):
        """Integration test — verify freshness filter works."""
        key = os.environ.get("GHOST_BING_KEY", "")
        if not key:
            pytest.skip("GHOST_BING_KEY not set")

        eng = BingEngine(api_key=key)
        results = await eng.search("latest news", num_results=5, freshness="Week")

        assert len(results) > 0
        assert all(isinstance(r, SearchResult) for r in results)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_market_parameter(self):
        """Integration test — verify market parameter is accepted."""
        key = os.environ.get("GHOST_BING_KEY", "")
        if not key:
            pytest.skip("GHOST_BING_KEY not set")

        eng = BingEngine(api_key=key)
        results = await eng.search("weather", num_results=3, market="en-GB")

        assert len(results) > 0
        assert all(isinstance(r, SearchResult) for r in results)
