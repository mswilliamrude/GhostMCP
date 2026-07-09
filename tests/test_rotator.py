"""Tests for the engine rotator — round-robin rotation, rate limiting, backoff."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest

from ghostmcp.engines.base import SearchEngine, SearchResult, SearchEngineError, RateLimitError
from ghostmcp.engines.rotator import EngineRotator, EngineState


# ---------------------------------------------------------------------------
# Mock engine helpers
# ---------------------------------------------------------------------------

class MockEngine(SearchEngine):
    """Mock search engine for testing."""

    def __init__(self, name: str = "mock", results: list[SearchResult] | None = None,
                 error: Exception | None = None):
        self.name = name
        self.min_delay = 0.0  # No delay in tests
        self._results = results or []
        self._error = error
        self._call_count = 0
        super().__init__(proxy=None)

    async def _rate_limit(self) -> None:
        """Skip rate limiting in tests."""
        pass

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        self._call_count += 1
        if self._error:
            raise self._error
        return self._results[:num_results]


def _make_results(engine_name: str, count: int = 3) -> list[SearchResult]:
    """Create dummy search results."""
    return [
        SearchResult(
            title=f"Result {i} from {engine_name}",
            url=f"https://example.com/{engine_name}/{i}",
            snippet=f"Snippet {i}",
            source_engine=engine_name,
        )
        for i in range(1, count + 1)
    ]


# ---------------------------------------------------------------------------
# TestEngineState — availability checks
# ---------------------------------------------------------------------------

class TestEngineState:
    """Test EngineState availability logic."""

    def test_available_by_default(self):
        """Fresh engine should be available."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine)
        state = rotator._engines[0]
        assert rotator._is_available(state) is True

    def test_unavailable_during_cooldown(self):
        """Engine in cooldown should be unavailable."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine)
        state = rotator._engines[0]

        # Set cooldown to future
        state.cooldown_until = time.monotonic() + 100.0
        assert rotator._is_available(state) is False

    def test_available_after_cooldown_expires(self):
        """Engine should become available after cooldown expires."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine)
        state = rotator._engines[0]

        # Set cooldown to past
        state.cooldown_until = time.monotonic() - 1.0
        assert rotator._is_available(state) is True

    def test_unavailable_at_window_limit(self):
        """Engine at window limit should be unavailable."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, max_per_window=5)
        state = rotator._engines[0]

        state.requests_in_window = 5
        state.window_start = time.monotonic()  # Window just started
        assert rotator._is_available(state) is False

    def test_window_reset_after_expiry(self):
        """Window counter should reset when window duration expires."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, max_per_window=5)
        state = rotator._engines[0]

        state.requests_in_window = 5
        # Set window start far in the past (expired)
        state.window_start = time.monotonic() - state.window_duration - 1
        assert rotator._is_available(state) is True
        # Counter should have been reset
        assert state.requests_in_window == 0

    def test_unavailable_after_max_consecutive_failures(self):
        """Engine disabled after max_consecutive_failures."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, base_cooldown=10.0)
        state = rotator._engines[0]

        state.consecutive_failures = state.max_consecutive_failures  # 3
        state.cooldown_until = time.monotonic() + 5.0  # Still in cooldown
        assert rotator._is_available(state) is False

    def test_reenabled_after_extended_cooldown(self):
        """Engine re-enabled after extended cooldown expires."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, base_cooldown=10.0)
        state = rotator._engines[0]

        state.consecutive_failures = 3
        # Set cooldown far in the past so extended cooldown also expired
        # Extended = base(10) * failures(3) * 5 = 150s
        state.cooldown_until = time.monotonic() - 200.0
        assert rotator._is_available(state) is True
        # Failures should have been reset
        assert state.consecutive_failures == 0


# ---------------------------------------------------------------------------
# TestEngineRotator — rotation and search behavior
# ---------------------------------------------------------------------------

class TestEngineRotator:
    """Test EngineRotator selection, rotation, and search."""

    @pytest.mark.asyncio
    async def test_api_preferred_over_scraper(self):
        """API engines should be selected before scrapers."""
        rotator = EngineRotator()
        api_engine = MockEngine("serper", results=_make_results("serper"))
        scraper_engine = MockEngine("google", results=_make_results("google"))

        rotator.register(api_engine, is_api=True)
        rotator.register(scraper_engine, is_api=False)

        state = await rotator.select_engine()
        assert state is not None
        assert state.name == "serper"
        assert state.is_api is True

    @pytest.mark.asyncio
    async def test_scraper_selected_when_no_api_available(self):
        """Scrapers should be selected when all API engines are unavailable."""
        rotator = EngineRotator()
        api_engine = MockEngine("serper", results=_make_results("serper"))
        scraper_engine = MockEngine("google", results=_make_results("google"))

        rotator.register(api_engine, is_api=True)
        rotator.register(scraper_engine, is_api=False)

        # Disable API engine
        rotator._engines[0].cooldown_until = time.monotonic() + 100.0

        state = await rotator.select_engine()
        assert state is not None
        assert state.name == "google"

    @pytest.mark.asyncio
    async def test_round_robin_rotation(self):
        """Multiple API engines should rotate in round-robin order."""
        rotator = EngineRotator()
        engine1 = MockEngine("serper", results=_make_results("serper"))
        engine2 = MockEngine("brave", results=_make_results("brave"))

        rotator.register(engine1, is_api=True)
        rotator.register(engine2, is_api=True)

        selected_names = []
        for _ in range(4):
            state = await rotator.select_engine()
            assert state is not None
            selected_names.append(state.name)

        # Should alternate between engines
        assert selected_names[0] == "serper"
        assert selected_names[1] == "brave"
        assert selected_names[2] == "serper"
        assert selected_names[3] == "brave"

    @pytest.mark.asyncio
    async def test_cooldown_on_failure(self):
        """Engine should enter cooldown after failure."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, base_cooldown=60.0)
        state = rotator._engines[0]

        rotator.record_failure(state)

        # Should be in cooldown
        assert state.cooldown_until > time.monotonic()
        assert state.consecutive_failures == 1
        assert rotator._is_available(state) is False

    @pytest.mark.asyncio
    async def test_exponential_backoff(self):
        """Cooldown should double with each consecutive failure."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, base_cooldown=10.0)
        state = rotator._engines[0]

        # First failure: 10 * 2^0 = 10s
        rotator.record_failure(state)
        cooldown_1 = state.cooldown_until - time.monotonic()

        # Wait out cooldown for next failure
        state.cooldown_until = time.monotonic() - 1

        # Second failure: 10 * 2^1 = 20s
        rotator.record_failure(state)
        cooldown_2 = state.cooldown_until - time.monotonic()

        # Wait out cooldown for next failure
        state.cooldown_until = time.monotonic() - 1

        # Third failure: 10 * 2^2 = 40s
        rotator.record_failure(state)
        cooldown_3 = state.cooldown_until - time.monotonic()

        # Each should roughly double (allow small timing tolerance)
        assert cooldown_1 < cooldown_2
        assert cooldown_2 < cooldown_3
        assert abs(cooldown_2 - cooldown_1 * 2) < 1.0
        assert abs(cooldown_3 - cooldown_2 * 2) < 1.0

    @pytest.mark.asyncio
    async def test_captcha_double_penalty(self):
        """CAPTCHA detection should double the cooldown."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, base_cooldown=30.0)
        state = rotator._engines[0]

        # Normal failure: 30s
        rotator.record_failure(state, is_captcha=False)
        normal_cooldown = state.cooldown_until - time.monotonic()
        state.cooldown_until = time.monotonic() - 1
        state.consecutive_failures = 0

        # CAPTCHA failure: should be ~60s (double)
        rotator.record_failure(state, is_captcha=True)
        captcha_cooldown = state.cooldown_until - time.monotonic()

        assert captcha_cooldown > normal_cooldown * 1.8  # Allow tolerance
        assert state.last_captcha_time > 0

    @pytest.mark.asyncio
    async def test_window_reset(self):
        """Request counter should reset when window expires."""
        rotator = EngineRotator()
        engine = MockEngine("test", results=_make_results("test"))
        rotator.register(engine, max_per_window=5)
        state = rotator._engines[0]

        # Fill up the window
        state.requests_in_window = 5
        state.window_start = time.monotonic()

        assert rotator._is_available(state) is False

        # Expire the window
        state.window_start = time.monotonic() - state.window_duration - 1

        assert rotator._is_available(state) is True
        assert state.requests_in_window == 0

    @pytest.mark.asyncio
    async def test_disabled_after_max_failures(self):
        """Engine should be disabled after max_consecutive_failures."""
        rotator = EngineRotator()
        engine = MockEngine("test", error=SearchEngineError("test", "always fails"))
        rotator.register(engine, base_cooldown=10.0)
        state = rotator._engines[0]

        # Record max failures
        for _ in range(state.max_consecutive_failures):
            state.cooldown_until = time.monotonic() - 1  # Clear cooldown between
            rotator.record_failure(state)

        # Now it's disabled (consecutive_failures >= max)
        assert state.consecutive_failures >= state.max_consecutive_failures
        assert rotator._is_available(state) is False

    @pytest.mark.asyncio
    async def test_search_rotates_on_failure(self):
        """Search should try next engine when one fails."""
        rotator = EngineRotator()

        failing_engine = MockEngine("serper", error=SearchEngineError("serper", "API error"))
        working_engine = MockEngine("brave", results=_make_results("brave"))

        rotator.register(failing_engine, is_api=True)
        rotator.register(working_engine, is_api=True)

        results, engine_used = await rotator.search("test query")
        assert len(results) == 3
        assert engine_used == "brave"
        assert failing_engine._call_count == 1
        assert working_engine._call_count == 1

    @pytest.mark.asyncio
    async def test_search_handles_rate_limit(self):
        """Search should handle RateLimitError and try next engine."""
        rotator = EngineRotator()

        rate_limited = MockEngine("serper", error=RateLimitError("serper", "Rate limited"))
        working = MockEngine("brave", results=_make_results("brave"))

        rotator.register(rate_limited, is_api=True)
        rotator.register(working, is_api=True)

        results, engine_used = await rotator.search("test query")
        assert len(results) == 3
        assert engine_used == "brave"

        # Rate-limited engine should be in cooldown now
        state = rotator._engines[0]
        assert state.consecutive_failures == 1
        assert state.cooldown_until > time.monotonic()

    @pytest.mark.asyncio
    async def test_all_engines_unavailable(self):
        """Should return empty results gracefully when all engines are unavailable."""
        rotator = EngineRotator()

        engine1 = MockEngine("serper", error=SearchEngineError("serper", "fail"))
        engine2 = MockEngine("brave", error=SearchEngineError("brave", "fail"))

        rotator.register(engine1, is_api=True, base_cooldown=60.0)
        rotator.register(engine2, is_api=True, base_cooldown=60.0)

        results, error_msg = await rotator.search("test query")
        assert results == []
        assert error_msg is not None
        assert len(error_msg) > 0

    @pytest.mark.asyncio
    async def test_no_engines_registered(self):
        """Should handle gracefully when no engines are registered."""
        rotator = EngineRotator()
        results, error_msg = await rotator.search("test query")
        assert results == []
        assert "No engines available" in error_msg

    @pytest.mark.asyncio
    async def test_success_resets_failures(self):
        """Successful search should reset consecutive_failures counter."""
        rotator = EngineRotator()
        engine = MockEngine("test", results=_make_results("test"))
        rotator.register(engine, is_api=True)
        state = rotator._engines[0]

        # Simulate previous failures
        state.consecutive_failures = 2
        state.total_failures = 2

        # Successful search
        results, engine_used = await rotator.search("test")
        assert len(results) == 3
        assert state.consecutive_failures == 0
        assert state.total_successes == 1

    @pytest.mark.asyncio
    async def test_empty_results_tries_next(self):
        """Engine returning empty results should try next engine."""
        rotator = EngineRotator()

        empty_engine = MockEngine("serper", results=[])
        full_engine = MockEngine("brave", results=_make_results("brave"))

        rotator.register(empty_engine, is_api=True)
        rotator.register(full_engine, is_api=True)

        results, engine_used = await rotator.search("test query")
        assert len(results) == 3
        assert engine_used == "brave"

    @pytest.mark.asyncio
    async def test_get_status(self):
        """get_status should return complete engine information."""
        rotator = EngineRotator()
        engine1 = MockEngine("serper")
        engine2 = MockEngine("google")

        rotator.register(engine1, is_api=True, max_per_window=40)
        rotator.register(engine2, is_api=False, max_per_window=10)

        status = rotator.get_status()

        assert "serper" in status
        assert "google" in status

        assert status["serper"]["is_api"] is True
        assert status["serper"]["max_per_window"] == 40
        assert status["serper"]["available"] is True
        assert status["serper"]["requests_in_window"] == 0
        assert status["serper"]["consecutive_failures"] == 0
        assert status["serper"]["total"] == 0
        assert status["serper"]["successes"] == 0
        assert status["serper"]["failures"] == 0

        assert status["google"]["is_api"] is False
        assert status["google"]["max_per_window"] == 10

    @pytest.mark.asyncio
    async def test_get_status_shows_cooldown(self):
        """get_status should show cooldown remaining."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, base_cooldown=60.0)
        state = rotator._engines[0]

        # Put engine in cooldown
        state.cooldown_until = time.monotonic() + 30.0

        status = rotator.get_status()
        assert status["test"]["cooldown_remaining"] > 25.0
        assert status["test"]["available"] is False

    @pytest.mark.asyncio
    async def test_cooldown_capped_at_10_minutes(self):
        """Cooldown should never exceed 600 seconds."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, base_cooldown=100.0)
        state = rotator._engines[0]

        # 10 failures: 100 * 2^9 = 51200, but capped at 600
        for i in range(10):
            state.cooldown_until = time.monotonic() - 1
            rotator.record_failure(state)

        cooldown_remaining = state.cooldown_until - time.monotonic()
        # Should be at most 600s (plus small tolerance for CAPTCHA doubling)
        assert cooldown_remaining <= 601.0

    @pytest.mark.asyncio
    async def test_max_attempts_limits_retries(self):
        """Search should respect max_attempts parameter."""
        rotator = EngineRotator()

        # Register 5 engines all returning empty
        for i in range(5):
            rotator.register(
                MockEngine(f"engine{i}", results=[]),
                is_api=True,
            )

        results, error = await rotator.search("test", max_attempts=2)
        assert results == []
        # Should have only tried at most 2 engines
        tried = sum(1 for s in rotator._engines if s.total_requests > 0)
        assert tried <= 2

    @pytest.mark.asyncio
    async def test_record_success_increments_stats(self):
        """record_success should update all relevant counters."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine)
        state = rotator._engines[0]

        rotator.record_success(state)
        assert state.requests_in_window == 1
        assert state.total_requests == 1
        assert state.total_successes == 1
        assert state.total_failures == 0
        assert state.consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_record_failure_increments_stats(self):
        """record_failure should update all relevant counters."""
        rotator = EngineRotator()
        engine = MockEngine("test")
        rotator.register(engine, base_cooldown=30.0)
        state = rotator._engines[0]

        rotator.record_failure(state)
        assert state.requests_in_window == 1
        assert state.total_requests == 1
        assert state.total_failures == 1
        assert state.total_successes == 0
        assert state.consecutive_failures == 1
        assert state.cooldown_until > time.monotonic()
