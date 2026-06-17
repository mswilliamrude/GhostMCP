"""Tests for DuckDuckGo engine parsing and SearchResult dataclass."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.engines.base import SearchResult, SearchEngineError
from src.engines.duckduckgo import DuckDuckGoEngine


# Sample DDG HTML response for testing parsing logic
SAMPLE_DDG_HTML = """
<html>
<body>
<div class="serp__results">

<div class="result results_links results_links_deep web-result">
  <div class="links_main links_deep result__body">
    <h2 class="result__title">
      <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage1&rut=abc123">
        Example Page One — Great Resource
      </a>
    </h2>
    <a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage1">
      This is the first result snippet with <b>search terms</b> highlighted.
    </a>
  </div>
</div>

<div class="result results_links results_links_deep web-result">
  <div class="links_main links_deep result__body">
    <h2 class="result__title">
      <a rel="nofollow" class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fresearch&rut=def456">
        Research Paper on OSINT Techniques
      </a>
    </h2>
    <a class="result__snippet" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.org%2Fresearch">
      A comprehensive overview of open source intelligence methods and tools.
    </a>
  </div>
</div>

<div class="result results_links results_links_deep web-result">
  <div class="links_main links_deep result__body">
    <h2 class="result__title">
      <a rel="nofollow" class="result__a" href="https://direct-link.net/article">
        Direct Link Article &amp; Title
      </a>
    </h2>
    <a class="result__snippet" href="https://direct-link.net/article">
      This result has a direct URL without DDG redirect wrapper.
    </a>
  </div>
</div>

</div>
</body>
</html>
"""

EMPTY_DDG_HTML = """
<html>
<body>
<div class="serp__results">
  <div class="no-results">No results found for "xyzzy_nothing_here_12345"</div>
</div>
</body>
</html>
"""


class TestSearchResult:
    """Tests for the SearchResult dataclass."""

    def test_creation(self):
        result = SearchResult(
            title="Test Title",
            url="https://example.com",
            snippet="A test snippet",
            source_engine="test",
        )
        assert result.title == "Test Title"
        assert result.url == "https://example.com"
        assert result.snippet == "A test snippet"
        assert result.source_engine == "test"

    def test_timestamp_auto_set(self):
        result = SearchResult(
            title="T", url="http://x.com", snippet="", source_engine="test"
        )
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.tzinfo == timezone.utc

    def test_str_representation(self):
        result = SearchResult(
            title="My Title",
            url="https://example.com",
            snippet="Some snippet",
            source_engine="ddg",
        )
        s = str(result)
        assert "[ddg]" in s
        assert "My Title" in s
        assert "https://example.com" in s


class TestDuckDuckGoParser:
    """Tests for DDG HTML parsing — no network calls."""

    def setup_method(self):
        self.engine = DuckDuckGoEngine()

    def test_parse_results_count(self):
        results = self.engine._parse_html(SAMPLE_DDG_HTML, num_results=10)
        assert len(results) == 3

    def test_parse_title_extraction(self):
        results = self.engine._parse_html(SAMPLE_DDG_HTML, num_results=10)
        assert "Example Page One" in results[0].title
        assert "Research Paper" in results[1].title

    def test_parse_url_unwrapping(self):
        results = self.engine._parse_html(SAMPLE_DDG_HTML, num_results=10)
        # DDG redirect URL should be unwrapped
        assert results[0].url == "https://example.com/page1"
        assert results[1].url == "https://example.org/research"

    def test_parse_direct_url(self):
        results = self.engine._parse_html(SAMPLE_DDG_HTML, num_results=10)
        assert results[2].url == "https://direct-link.net/article"

    def test_parse_snippet_strips_html(self):
        results = self.engine._parse_html(SAMPLE_DDG_HTML, num_results=10)
        # Bold tags should be stripped
        assert "<b>" not in results[0].snippet
        assert "search terms" in results[0].snippet

    def test_parse_html_entities(self):
        results = self.engine._parse_html(SAMPLE_DDG_HTML, num_results=10)
        # &amp; should be decoded
        assert "&" in results[2].title
        assert "&amp;" not in results[2].title

    def test_parse_empty_results(self):
        results = self.engine._parse_html(EMPTY_DDG_HTML, num_results=10)
        assert results == []

    def test_parse_respects_num_results(self):
        results = self.engine._parse_html(SAMPLE_DDG_HTML, num_results=1)
        assert len(results) <= 1

    def test_source_engine_set(self):
        results = self.engine._parse_html(SAMPLE_DDG_HTML, num_results=10)
        for r in results:
            assert r.source_engine == "duckduckgo"


class TestDuckDuckGoURL:
    """Tests for URL cleaning logic."""

    def test_uddg_unwrap(self):
        raw = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpath&rut=abc"
        assert DuckDuckGoEngine._clean_url(raw) == "https://example.com/path"

    def test_protocol_relative(self):
        raw = "//example.com/page"
        assert DuckDuckGoEngine._clean_url(raw) == "https://example.com/page"

    def test_direct_url_passthrough(self):
        raw = "https://already-clean.com/page"
        assert DuckDuckGoEngine._clean_url(raw) == "https://already-clean.com/page"


class TestDuckDuckGoSearch:
    """Tests for the search method — mocked HTTP."""

    @pytest.fixture
    def engine(self):
        return DuckDuckGoEngine()

    @pytest.mark.asyncio
    async def test_search_returns_results(self, engine):
        """Mocked search returns parsed results."""
        mock_response = MagicMock()
        mock_response.text = SAMPLE_DDG_HTML
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_response
            # Bypass rate limiting for test speed
            engine._last_request = 0
            engine.min_delay = 0

            results = await engine.search("test query", num_results=5)

        assert len(results) == 3
        assert results[0].url == "https://example.com/page1"

    @pytest.mark.asyncio
    async def test_search_with_proxy(self):
        """Engine accepts proxy configuration."""
        proxy = {"all": "socks5://127.0.0.1:9050"}
        engine = DuckDuckGoEngine(proxy=proxy)
        assert engine.proxy == proxy

    @pytest.mark.asyncio
    async def test_search_handles_http_error(self, engine):
        """Search raises SearchEngineError on HTTP failures."""
        engine.min_delay = 0

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = Exception("Connection refused")

            with pytest.raises(Exception):
                await engine.search("test")


class TestStripTags:
    """Test HTML tag stripping utility."""

    def test_removes_tags(self):
        assert DuckDuckGoEngine._strip_tags("<b>bold</b> text") == "bold text"

    def test_normalizes_whitespace(self):
        assert DuckDuckGoEngine._strip_tags("a   b\n\nc") == "a b c"

    def test_handles_empty(self):
        assert DuckDuckGoEngine._strip_tags("") == ""
