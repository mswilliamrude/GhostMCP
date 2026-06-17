"""Tests for DuckDuckGo engine parsing and SearchResult dataclass."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.engines.base import SearchResult, SearchEngineError
from src.engines.duckduckgo import DuckDuckGoEngine


# Sample DDG Lite HTML response for testing parsing logic
# DDG Lite uses table-based layout with result-link and result-snippet classes
SAMPLE_DDG_HTML = """
<html>
<body>
<table>
  <tr>
    <td valign="top">1.&nbsp;</td>
    <td>
      <a rel="nofollow" href="https://example.com/page1" class='result-link'>Example Page One &#x2014; Great Resource</a>
    </td>
  </tr>
  <tr>
    <td>&nbsp;&nbsp;&nbsp;</td>
    <td class='result-snippet'>
      This is the first result snippet with <b>search terms</b> highlighted.
    </td>
  </tr>

  <tr>
    <td valign="top">2.&nbsp;</td>
    <td>
      <a rel="nofollow" href="https://example.org/research" class='result-link'>Research Paper on OSINT Techniques</a>
    </td>
  </tr>
  <tr>
    <td>&nbsp;&nbsp;&nbsp;</td>
    <td class='result-snippet'>
      A comprehensive overview of open source intelligence methods and tools.
    </td>
  </tr>

  <tr>
    <td valign="top">3.&nbsp;</td>
    <td>
      <a rel="nofollow" href="https://direct-link.net/article" class='result-link'>Direct Link Article &amp; Title</a>
    </td>
  </tr>
  <tr>
    <td>&nbsp;&nbsp;&nbsp;</td>
    <td class='result-snippet'>
      This result has a direct URL without DDG redirect wrapper.
    </td>
  </tr>
</table>
</body>
</html>
"""

EMPTY_DDG_HTML = """
<html>
<body>
<table>
  <tr>
    <td>No results found for "xyzzy_nothing_here_12345"</td>
  </tr>
</table>
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
    """Tests for DDG Lite HTML parsing — no network calls."""

    def setup_method(self):
        self.engine = DuckDuckGoEngine()

    def test_parse_results_count(self):
        results = self.engine._parse_lite_html(SAMPLE_DDG_HTML, num_results=10)
        assert len(results) == 3

    def test_parse_title_extraction(self):
        results = self.engine._parse_lite_html(SAMPLE_DDG_HTML, num_results=10)
        assert "Example Page One" in results[0].title
        assert "Research Paper" in results[1].title

    def test_parse_url_direct(self):
        results = self.engine._parse_lite_html(SAMPLE_DDG_HTML, num_results=10)
        # DDG Lite provides direct URLs (no redirect wrapper)
        assert results[0].url == "https://example.com/page1"
        assert results[1].url == "https://example.org/research"

    def test_parse_direct_url(self):
        results = self.engine._parse_lite_html(SAMPLE_DDG_HTML, num_results=10)
        assert results[2].url == "https://direct-link.net/article"

    def test_parse_snippet_strips_html(self):
        results = self.engine._parse_lite_html(SAMPLE_DDG_HTML, num_results=10)
        # Bold tags should be stripped
        assert "<b>" not in results[0].snippet
        assert "search terms" in results[0].snippet

    def test_parse_html_entities(self):
        results = self.engine._parse_lite_html(SAMPLE_DDG_HTML, num_results=10)
        # &amp; should be decoded
        assert "&" in results[2].title
        assert "&amp;" not in results[2].title

    def test_parse_empty_results(self):
        results = self.engine._parse_lite_html(EMPTY_DDG_HTML, num_results=10)
        assert results == []

    def test_parse_respects_num_results(self):
        results = self.engine._parse_lite_html(SAMPLE_DDG_HTML, num_results=1)
        assert len(results) <= 1

    def test_source_engine_set(self):
        results = self.engine._parse_lite_html(SAMPLE_DDG_HTML, num_results=10)
        for r in results:
            assert r.source_engine == "duckduckgo"


class TestDuckDuckGoURL:
    """Tests for URL handling — DDG Lite gives direct URLs."""

    def test_direct_urls_in_results(self):
        """DDG Lite provides direct URLs, no unwrapping needed."""
        engine = DuckDuckGoEngine()
        results = engine._parse_lite_html(SAMPLE_DDG_HTML, num_results=10)
        # All URLs should be direct https:// links
        for r in results:
            assert r.url.startswith("https://")
            assert "duckduckgo.com" not in r.url

    def test_ddg_internal_links_filtered(self):
        """Links to duckduckgo.com itself should be filtered out."""
        html = """
        <tr>
          <td><a rel="nofollow" href="https://duckduckgo.com/about" class='result-link'>About DDG</a></td>
        </tr>
        <tr><td class='result-snippet'>Internal link.</td></tr>
        <tr>
          <td><a rel="nofollow" href="https://real-site.com/page" class='result-link'>Real Result</a></td>
        </tr>
        <tr><td class='result-snippet'>External link.</td></tr>
        """
        engine = DuckDuckGoEngine()
        results = engine._parse_lite_html(html, num_results=10)
        assert len(results) == 1
        assert results[0].url == "https://real-site.com/page"


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
    async def test_search_uses_lite_endpoint(self, engine):
        """Engine posts to lite.duckduckgo.com, not html endpoint."""
        assert "lite.duckduckgo.com" in engine.BASE_URL

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
