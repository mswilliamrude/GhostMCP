"""Tests for Serper API engine — response parsing, key detection, mocked HTTP."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.engines.serper import SerperEngine
from src.engines.base import SearchEngineError

from tests.conftest import (
    SAMPLE_SERPER_RESPONSE,
    EMPTY_SERPER_RESPONSE,
    SERPER_RESPONSE_NO_LINK,
)


class TestSerperEngineInit:
    """Tests for SerperEngine initialization."""

    def test_default_no_key(self):
        with patch.dict(os.environ, {}, clear=True):
            eng = SerperEngine()
            assert eng.api_key == ""

    def test_key_from_env(self):
        with patch.dict(os.environ, {"SERPER_API_KEY": "test-key-123"}):
            eng = SerperEngine()
            assert eng.api_key == "test-key-123"

    def test_key_from_argument(self):
        eng = SerperEngine(api_key="explicit-key")
        assert eng.api_key == "explicit-key"

    def test_argument_overrides_env(self):
        with patch.dict(os.environ, {"SERPER_API_KEY": "env-key"}):
            eng = SerperEngine(api_key="arg-key")
            assert eng.api_key == "arg-key"

    def test_name(self):
        eng = SerperEngine(api_key="k")
        assert eng.name == "serper"

    def test_min_delay(self):
        eng = SerperEngine(api_key="k")
        assert eng.min_delay == 0.5

    def test_api_url(self):
        assert SerperEngine.API_URL == "https://google.serper.dev/search"


class TestSerperAvailable:
    """Tests for the available property."""

    def test_available_with_key(self):
        eng = SerperEngine(api_key="some-key")
        assert eng.available is True

    def test_not_available_without_key(self):
        with patch.dict(os.environ, {}, clear=True):
            eng = SerperEngine()
            assert eng.available is False

    def test_not_available_empty_key(self):
        eng = SerperEngine(api_key="")
        assert eng.available is False


class TestSerperParseResponse:
    """Tests for _parse_response() — pure logic, no network."""

    def setup_method(self):
        self.engine = SerperEngine(api_key="test")

    def test_parses_organic_results(self):
        results = self.engine._parse_response(SAMPLE_SERPER_RESPONSE, num_results=10)
        assert len(results) == 3

    def test_extracts_title(self):
        results = self.engine._parse_response(SAMPLE_SERPER_RESPONSE, num_results=10)
        assert results[0].title == "First Serper Result"
        assert results[1].title == "Second Serper Result"

    def test_extracts_url(self):
        results = self.engine._parse_response(SAMPLE_SERPER_RESPONSE, num_results=10)
        assert results[0].url == "https://example.com/serper1"
        assert results[1].url == "https://example.org/serper2"

    def test_extracts_snippet(self):
        results = self.engine._parse_response(SAMPLE_SERPER_RESPONSE, num_results=10)
        assert "serper API result one" in results[0].snippet

    def test_source_engine(self):
        results = self.engine._parse_response(SAMPLE_SERPER_RESPONSE, num_results=10)
        for r in results:
            assert r.source_engine == "serper"

    def test_respects_num_results(self):
        results = self.engine._parse_response(SAMPLE_SERPER_RESPONSE, num_results=1)
        assert len(results) == 1

    def test_empty_response(self):
        results = self.engine._parse_response(EMPTY_SERPER_RESPONSE, num_results=10)
        assert results == []

    def test_skips_entries_without_link(self):
        results = self.engine._parse_response(SERPER_RESPONSE_NO_LINK, num_results=10)
        assert len(results) == 1
        assert results[0].url == "https://valid.com"

    def test_empty_title_uses_link(self):
        results = self.engine._parse_response(SAMPLE_SERPER_RESPONSE, num_results=10)
        # Third entry has empty title, should use link
        assert results[2].title == "https://no-title.com/page"


class TestSerperSearch:
    """Tests for search() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_search_no_key_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            eng = SerperEngine()
            eng.min_delay = 0
            with pytest.raises(SearchEngineError, match="SERPER_API_KEY"):
                await eng.search("test")

    @pytest.mark.asyncio
    async def test_search_success(self):
        eng = SerperEngine(api_key="test-key")
        eng.min_delay = 0
        eng._last_request = 0

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_SERPER_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            results = await eng.search("test query", num_results=5)

        assert len(results) == 3
        assert results[0].title == "First Serper Result"

    @pytest.mark.asyncio
    async def test_search_401_invalid_key(self):
        eng = SerperEngine(api_key="bad-key")
        eng.min_delay = 0
        eng._last_request = 0

        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError, match="Invalid SERPER_API_KEY"):
                await eng.search("test")

    @pytest.mark.asyncio
    async def test_search_429_rate_limit(self):
        eng = SerperEngine(api_key="key")
        eng.min_delay = 0
        eng._last_request = 0

        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError, match="rate limit"):
                await eng.search("test")

    @pytest.mark.asyncio
    async def test_search_sends_correct_headers(self):
        eng = SerperEngine(api_key="my-key-abc")
        eng.min_delay = 0
        eng._last_request = 0

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = EMPTY_SERPER_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp) as mock_post:
            await eng.search("query")
            call_kwargs = mock_post.call_args
            headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
            assert headers["X-API-KEY"] == "my-key-abc"
            assert headers["Content-Type"] == "application/json"

    @pytest.mark.asyncio
    async def test_search_connection_error(self):
        import httpx
        eng = SerperEngine(api_key="key")
        eng.min_delay = 0
        eng._last_request = 0

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, side_effect=httpx.ConnectError("refused")):
            with pytest.raises(SearchEngineError, match="Request failed"):
                await eng.search("test")
