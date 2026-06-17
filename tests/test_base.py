"""Tests for SearchResult dataclass, exceptions, and rate limiter."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from src.engines.base import SearchResult, SearchEngineError, RateLimitError, SearchEngine


class TestSearchResult:
    """Tests for SearchResult dataclass."""

    def test_basic_creation(self):
        r = SearchResult(
            title="Title", url="https://x.com", snippet="snip", source_engine="test"
        )
        assert r.title == "Title"
        assert r.url == "https://x.com"
        assert r.snippet == "snip"
        assert r.source_engine == "test"

    def test_timestamp_default_is_utc_now(self):
        r = SearchResult(title="T", url="http://x.com", snippet="", source_engine="e")
        assert isinstance(r.timestamp, datetime)
        assert r.timestamp.tzinfo == timezone.utc
        # Timestamp should be very recent
        delta = datetime.now(timezone.utc) - r.timestamp
        assert delta.total_seconds() < 2

    def test_custom_timestamp(self):
        custom_ts = datetime(2024, 1, 1, tzinfo=timezone.utc)
        r = SearchResult(
            title="T", url="http://x.com", snippet="", source_engine="e",
            timestamp=custom_ts
        )
        assert r.timestamp == custom_ts

    def test_str_format(self):
        r = SearchResult(
            title="My Title", url="https://site.com/page",
            snippet="Some snippet text", source_engine="google"
        )
        s = str(r)
        assert "[google]" in s
        assert "My Title" in s
        assert "https://site.com/page" in s
        assert "Some snippet text" in s

    def test_str_with_empty_snippet(self):
        r = SearchResult(title="T", url="http://x.com", snippet="", source_engine="e")
        s = str(r)
        assert "[e]" in s


class TestSearchEngineError:
    """Tests for SearchEngineError."""

    def test_stores_engine_name(self):
        err = SearchEngineError("google", "something broke")
        assert err.engine == "google"

    def test_message_format(self):
        err = SearchEngineError("serper", "API key invalid")
        assert "[serper]" in str(err)
        assert "API key invalid" in str(err)

    def test_inherits_from_exception(self):
        assert issubclass(SearchEngineError, Exception)


class TestRateLimitError:
    """Tests for RateLimitError."""

    def test_inherits_from_search_engine_error(self):
        assert issubclass(RateLimitError, SearchEngineError)

    def test_creation(self):
        err = RateLimitError("google", "429 Too Many Requests")
        assert err.engine == "google"
        assert "429" in str(err)


class TestSearchEngineABC:
    """Tests for the SearchEngine abstract base class."""

    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            SearchEngine()

    def test_subclass_with_search_method(self):
        class FakeEngine(SearchEngine):
            name = "fake"
            min_delay = 0.0

            async def search(self, query: str, num_results: int = 10):
                return []

        eng = FakeEngine()
        assert eng.name == "fake"
        assert eng.proxy is None
        assert eng._last_request == 0.0

    def test_subclass_with_proxy(self):
        class FakeEngine(SearchEngine):
            name = "fake"

            async def search(self, query, num_results=10):
                return []

        proxy = {"all": "socks5://127.0.0.1:9050"}
        eng = FakeEngine(proxy=proxy)
        assert eng.proxy == proxy


class TestRateLimiter:
    """Tests for the _rate_limit() async method."""

    @pytest.mark.asyncio
    async def test_first_call_no_delay(self):
        """First call should not wait (no previous request)."""

        class FakeEngine(SearchEngine):
            name = "fake"
            min_delay = 1.0

            async def search(self, query, num_results=10):
                return []

        eng = FakeEngine()
        eng._last_request = 0.0

        # First call should complete quickly (time starts at 0, loop time > 0)
        start = asyncio.get_event_loop().time()
        await eng._rate_limit()
        elapsed = asyncio.get_event_loop().time() - start
        # Should not wait because loop.time() is already > 0 and _last_request is 0
        assert elapsed < 1.0

    @pytest.mark.asyncio
    async def test_enforces_min_delay(self):
        """Rapid consecutive calls should enforce the minimum delay."""

        class FakeEngine(SearchEngine):
            name = "fake"
            min_delay = 0.1  # 100ms for fast test

            async def search(self, query, num_results=10):
                return []

        eng = FakeEngine()

        # First call sets _last_request
        await eng._rate_limit()

        # Second call should wait ~0.1s
        start = asyncio.get_event_loop().time()
        await eng._rate_limit()
        elapsed = asyncio.get_event_loop().time() - start

        # Should have waited at least min_delay (minus some tolerance)
        assert elapsed >= 0.08

    @pytest.mark.asyncio
    async def test_no_delay_after_enough_time(self):
        """No delay needed if enough time has passed since last request."""

        class FakeEngine(SearchEngine):
            name = "fake"
            min_delay = 0.05

            async def search(self, query, num_results=10):
                return []

        eng = FakeEngine()

        await eng._rate_limit()
        # Wait longer than min_delay
        await asyncio.sleep(0.1)

        start = asyncio.get_event_loop().time()
        await eng._rate_limit()
        elapsed = asyncio.get_event_loop().time() - start

        # Should not have waited
        assert elapsed < 0.05
