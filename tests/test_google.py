"""Tests for Google engine parser with sample HTML and mocked HTTP."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from ghostmcp.engines.google import GoogleEngine
from ghostmcp.engines.base import SearchEngineError, RateLimitError

from tests.conftest import (
    SAMPLE_GOOGLE_HTML,
    CAPTCHA_GOOGLE_HTML,
    CONSENT_GOOGLE_HTML,
    EMPTY_GOOGLE_HTML,
)


class TestGoogleEngineInit:
    """Tests for GoogleEngine initialization."""

    def test_default_creation(self):
        eng = GoogleEngine()
        assert eng.name == "google"
        assert eng.min_delay == 5.0
        assert eng.proxy is None
        assert eng.paranoia == "cautious"

    def test_with_proxy(self):
        proxy = {"all": "socks5://127.0.0.1:9050"}
        eng = GoogleEngine(proxy=proxy)
        assert eng.proxy == proxy

    def test_with_paranoia(self):
        eng = GoogleEngine(paranoia="ghost")
        assert eng.paranoia == "ghost"

    def test_base_url(self):
        assert GoogleEngine.BASE_URL == "https://www.google.com/search"


class TestGoogleParser:
    """Tests for _parse_serp() HTML parsing — no network."""

    def setup_method(self):
        self.engine = GoogleEngine()
        self.engine.min_delay = 0

    def test_parse_extracts_results(self):
        results = self.engine._parse_serp(SAMPLE_GOOGLE_HTML, num_results=10)
        assert len(results) >= 1

    def test_parse_extracts_titles(self):
        results = self.engine._parse_serp(SAMPLE_GOOGLE_HTML, num_results=10)
        titles = [r.title for r in results]
        assert any("First Result Title" in t for t in titles)

    def test_parse_extracts_urls(self):
        results = self.engine._parse_serp(SAMPLE_GOOGLE_HTML, num_results=10)
        urls = [r.url for r in results]
        assert any("example.com/result1" in u for u in urls)

    def test_parse_source_engine(self):
        results = self.engine._parse_serp(SAMPLE_GOOGLE_HTML, num_results=10)
        for r in results:
            assert r.source_engine == "google"

    def test_parse_respects_num_results(self):
        results = self.engine._parse_serp(SAMPLE_GOOGLE_HTML, num_results=1)
        assert len(results) <= 1

    def test_parse_empty_html(self):
        results = self.engine._parse_serp(EMPTY_GOOGLE_HTML, num_results=10)
        assert results == []

    def test_parse_captcha_raises(self):
        with pytest.raises(SearchEngineError, match="CAPTCHA"):
            self.engine._parse_serp(CAPTCHA_GOOGLE_HTML, num_results=10)

    def test_parse_consent_page_raises(self):
        with pytest.raises(SearchEngineError, match="consent"):
            self.engine._parse_serp(CONSENT_GOOGLE_HTML, num_results=10)


class TestGoogleCaptchaDetection:
    """Tests for _is_captcha static method."""

    def test_detects_unusual_traffic(self):
        assert GoogleEngine._is_captcha("We detected unusual traffic from your network")

    def test_detects_captcha_keyword(self):
        assert GoogleEngine._is_captcha("<div>captcha required</div>")

    def test_detects_recaptcha(self):
        assert GoogleEngine._is_captcha('<script src="recaptcha"></script>')

    def test_detects_sorry_page(self):
        assert GoogleEngine._is_captcha("redirect to /sorry/ page")

    def test_normal_html_not_captcha(self):
        assert not GoogleEngine._is_captcha("<html><body>Normal results</body></html>")

    def test_case_insensitive(self):
        assert GoogleEngine._is_captcha("UNUSUAL TRAFFIC detected")


class TestGoogleConsentDetection:
    """Tests for _is_consent_page static method."""

    def test_detects_consent_google_url(self):
        assert GoogleEngine._is_consent_page("redirect to consent.google.com")

    def test_detects_before_continue_text(self):
        assert GoogleEngine._is_consent_page("Before you continue to Google Search")

    def test_detects_cxqnmb_id(self):
        assert GoogleEngine._is_consent_page('<div id="CXQnmb">content</div>')

    def test_normal_html_not_consent(self):
        assert not GoogleEngine._is_consent_page("<html><body>Results</body></html>")


class TestGoogleCleanText:
    """Tests for _clean_text static method."""

    def test_strips_tags(self):
        assert GoogleEngine._clean_text("<b>bold</b> text") == "bold text"

    def test_decodes_entities(self):
        assert GoogleEngine._clean_text("a &amp; b") == "a & b"

    def test_normalizes_whitespace(self):
        assert GoogleEngine._clean_text("a   b\n\nc") == "a b c"

    def test_handles_empty(self):
        assert GoogleEngine._clean_text("") == ""

    def test_nested_tags(self):
        assert GoogleEngine._clean_text("<div><span>text</span></div>") == "text"


class TestGoogleSearch:
    """Tests for search() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_search_returns_results(self):
        eng = GoogleEngine()
        eng.min_delay = 0
        eng._last_request = 0

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = SAMPLE_GOOGLE_HTML

        with patch.object(eng, "_fetch", new_callable=AsyncMock, return_value=SAMPLE_GOOGLE_HTML):
            results = await eng.search("test query", num_results=5)

        assert isinstance(results, list)
        assert all(r.source_engine == "google" for r in results)

    @pytest.mark.asyncio
    async def test_search_rate_limit_429(self):
        eng = GoogleEngine()
        eng.min_delay = 0
        eng._last_request = 0

        with patch.object(eng, "_fetch", new_callable=AsyncMock, side_effect=RateLimitError("google", "429")):
            with pytest.raises(RateLimitError):
                await eng.search("test")

    @pytest.mark.asyncio
    async def test_fetch_httpx_429_raises_ratelimit(self):
        eng = GoogleEngine()
        eng.min_delay = 0

        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(RateLimitError):
                await eng._fetch_httpx("http://test.com", {})

    @pytest.mark.asyncio
    async def test_fetch_httpx_500_raises_engine_error(self):
        eng = GoogleEngine()
        eng.min_delay = 0

        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(SearchEngineError):
                await eng._fetch_httpx("http://test.com", {})

    @pytest.mark.asyncio
    async def test_fetch_httpx_success(self):
        eng = GoogleEngine()
        eng.min_delay = 0

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "<html>results</html>"

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            html = await eng._fetch_httpx("http://test.com", {})

        assert html == "<html>results</html>"
