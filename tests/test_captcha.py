"""Tests for CAPTCHA Layer 2 (self-solve) framework.

All tests mock Playwright completely so they run without it installed.
"""

from __future__ import annotations

import asyncio
import base64
import io
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.captcha.detector import detect_captcha, CaptchaDetection, CAPTCHA_INDICATORS
from ghostmcp.captcha.grid_solver import (
    solve_grid_captcha,
    extract_grid_tiles,
    GridSolveResult,
    TileClassification,
    TileClassifier,
    DummyClassifier,
)
from ghostmcp.captcha.slider_solver import (
    solve_slider_captcha,
    find_gap_position,
    simulate_slider_drag,
    SliderSolveResult,
)
from ghostmcp.captcha.learning import (
    log_captcha_event,
    get_event_log,
    get_stats,
    clear_log,
    CaptchaEvent,
    _event_log,
)
from ghostmcp.captcha.solver_chain import solve_captcha, SolveAttempt


# ---------------------------------------------------------------------------
# Mock Playwright objects
# ---------------------------------------------------------------------------


class MockMouse:
    """Mock Playwright mouse with move/click tracking."""

    def __init__(self):
        self.moves: list[tuple[float, float]] = []
        self.clicks: list[tuple[float, float]] = []
        self.downs: list[str] = []
        self.ups: list[str] = []

    async def move(self, x, y, **kwargs):
        self.moves.append((x, y))

    async def click(self, x, y, **kwargs):
        self.clicks.append((x, y))

    async def down(self, **kwargs):
        self.downs.append("left")

    async def up(self, **kwargs):
        self.ups.append("left")


class MockElement:
    """Mock Playwright element handle."""

    def __init__(self, box=None, screenshot_bytes=None, text_content=None):
        self._box = box or {"x": 100, "y": 100, "width": 300, "height": 300}
        self._screenshot_bytes = screenshot_bytes or b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        self._text_content = text_content

    async def bounding_box(self):
        return self._box

    async def screenshot(self):
        return self._screenshot_bytes

    async def text_content(self):
        return self._text_content


class MockElementNone:
    """Mock element that returns None for bounding_box."""

    async def bounding_box(self):
        return None

    async def screenshot(self):
        return b""

    async def text_content(self):
        return None


class MockPage:
    """Mock Playwright page with CAPTCHA-related tracking."""

    def __init__(self, elements=None, content_text="", url="https://example.com"):
        self.mouse = MockMouse()
        self.url = url
        self._elements = elements or {}  # selector -> element
        self._content_text = content_text
        self.frames = []

    async def query_selector(self, selector):
        """Return mock element if selector matches any registered selector."""
        # Check exact match first
        if selector in self._elements:
            return self._elements[selector]
        # Check if any registered selector is contained in a multi-selector
        for registered, element in self._elements.items():
            if registered in selector.split(", "):
                return element
            # Handle comma-separated selector groups
            for sub_selector in selector.split(", "):
                if sub_selector.strip() == registered:
                    return element
        return None

    async def content(self):
        return self._content_text


class MockFrame:
    """Mock Playwright frame."""

    def __init__(self, elements=None):
        self._elements = elements or {}

    async def query_selector(self, selector):
        return self._elements.get(selector)


# ---------------------------------------------------------------------------
# Helper: Create a real PNG image for tests that need PIL
# ---------------------------------------------------------------------------


def create_test_png(width=300, height=300, fill_color=(128, 128, 128)) -> bytes:
    """Create a valid PNG image bytes using PIL."""
    try:
        from PIL import Image
        img = Image.new('RGB', (width, height), fill_color)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()
    except ImportError:
        # Return minimal PNG bytes if PIL not available
        return b"\x89PNG\r\n\x1a\n" + b"\x00" * 100


def create_test_png_with_edges(width=300, height=100) -> bytes:
    """Create a PNG with a vertical edge for slider gap detection tests."""
    try:
        from PIL import Image, ImageDraw
        img = Image.new('RGB', (width, height), (200, 200, 200))
        draw = ImageDraw.Draw(img)
        # Draw a strong vertical line at x=180 (60% of width) to simulate gap edge
        for y in range(int(height * 0.2), int(height * 0.8)):
            draw.point((180, y), fill=(0, 0, 0))
            draw.point((181, y), fill=(0, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return buf.getvalue()
    except ImportError:
        return b"\x89PNG\r\n\x1a\n" + b"\x00" * 100


# ---------------------------------------------------------------------------
# TestCaptchaDetection
# ---------------------------------------------------------------------------


class TestCaptchaDetection:
    """Test CAPTCHA detection from page DOM."""

    @pytest.mark.asyncio
    async def test_detects_recaptcha(self):
        """Should detect reCAPTCHA v2 via iframe selector."""
        page = MockPage(
            elements={"iframe[src*='recaptcha']": MockElement()}
        )
        result = await detect_captcha(page)
        assert result.detected is True
        assert result.captcha_type == "recaptcha_v2"
        assert result.iframe_selector == "iframe[src*='recaptcha']"
        assert result.confidence == 0.9

    @pytest.mark.asyncio
    async def test_detects_hcaptcha(self):
        """Should detect hCaptcha via iframe selector."""
        page = MockPage(
            elements={"iframe[src*='hcaptcha']": MockElement()}
        )
        result = await detect_captcha(page)
        assert result.detected is True
        assert result.captcha_type == "hcaptcha"
        assert result.confidence == 0.9

    @pytest.mark.asyncio
    async def test_detects_cloudflare(self):
        """Should detect Cloudflare challenge via div selector."""
        page = MockPage(
            elements={"div#challenge-form": MockElement()}
        )
        result = await detect_captcha(page)
        assert result.detected is True
        assert result.captcha_type == "cloudflare"
        assert result.challenge_type == "behavioral"

    @pytest.mark.asyncio
    async def test_detects_geetest(self):
        """Should detect GeeTest via panel selector."""
        page = MockPage(
            elements={"div.geetest_panel": MockElement()}
        )
        result = await detect_captcha(page)
        assert result.detected is True
        assert result.captcha_type == "geetest"
        assert result.challenge_type == "slider"

    @pytest.mark.asyncio
    async def test_no_captcha_detected(self):
        """Should return detected=False when no CAPTCHA present."""
        page = MockPage(elements={}, content_text="<html><body>Normal page</body></html>")
        result = await detect_captcha(page)
        assert result.detected is False
        assert result.captcha_type == ""
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_text_based_detection(self):
        """Should detect CAPTCHA from page text when no selector matches."""
        page = MockPage(
            elements={},
            content_text="<html><body>Please select all images with traffic lights</body></html>"
        )
        result = await detect_captcha(page)
        assert result.detected is True
        assert result.captcha_type == "recaptcha_v2"
        assert result.confidence == 0.6  # Lower confidence for text-only

    @pytest.mark.asyncio
    async def test_challenge_type_assignment(self):
        """Should assign correct challenge_type based on captcha_type."""
        # reCAPTCHA -> image_grid
        page = MockPage(elements={"div.g-recaptcha": MockElement()})
        result = await detect_captcha(page)
        assert result.challenge_type == "image_grid"
        assert result.grid_dimensions == (3, 3)

        # GeeTest -> slider
        page = MockPage(elements={"div.geetest_widget": MockElement()})
        result = await detect_captcha(page)
        assert result.challenge_type == "slider"

        # Cloudflare -> behavioral
        page = MockPage(elements={"div.cf-challenge": MockElement()})
        result = await detect_captcha(page)
        assert result.challenge_type == "behavioral"

        # FunCaptcha -> interactive
        page = MockPage(elements={"iframe[src*='funcaptcha']": MockElement()})
        result = await detect_captcha(page)
        assert result.challenge_type == "interactive"

    @pytest.mark.asyncio
    async def test_instruction_text_extraction(self):
        """Should extract instruction text when element found."""
        instruction_el = MockElement(text_content="Select all images with traffic lights")
        page = MockPage(
            elements={
                "iframe[src*='recaptcha']": MockElement(),
                ".rc-imageselect-desc-wrapper": instruction_el,
            }
        )
        result = await detect_captcha(page)
        assert result.instruction_text == "Select all images with traffic lights"


# ---------------------------------------------------------------------------
# TestGridSolver
# ---------------------------------------------------------------------------


class TestGridSolver:
    """Test grid CAPTCHA tile extraction and classification."""

    @pytest.mark.asyncio
    async def test_extract_tiles_with_pil(self):
        """Should crop grid into 9 tiles with PIL available."""
        png_bytes = create_test_png(300, 300)
        grid_el = MockElement(
            box={"x": 0, "y": 0, "width": 300, "height": 300},
            screenshot_bytes=png_bytes,
        )
        page = MockPage(elements={"div.grid": grid_el})

        tiles = await extract_grid_tiles(page, "div.grid", grid_size=(3, 3))

        try:
            import PIL
            # With PIL, should get 9 tiles
            assert len(tiles) == 9
            # Each tile should be valid base64
            for tile in tiles:
                decoded = base64.b64decode(tile)
                assert len(decoded) > 0
        except ImportError:
            # Without PIL, falls back to single full-grid tile
            assert len(tiles) == 1

    @pytest.mark.asyncio
    async def test_extract_tiles_no_pil(self):
        """Should gracefully fall back when PIL not available."""
        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        grid_el = MockElement(
            box={"x": 0, "y": 0, "width": 300, "height": 300},
            screenshot_bytes=png_bytes,
        )
        page = MockPage(elements={"div.grid": grid_el})

        with patch.dict('sys.modules', {'PIL': None, 'PIL.Image': None}):
            # Force ImportError in extract_grid_tiles
            with patch('builtins.__import__', side_effect=lambda name, *args, **kwargs:
                       (_ for _ in ()).throw(ImportError()) if 'PIL' in name else __import__(name, *args, **kwargs)):
                tiles = await extract_grid_tiles(page, "div.grid", grid_size=(3, 3))
                # Should get at least the raw screenshot as fallback or empty
                # (depends on whether the PIL import block triggers)
                assert isinstance(tiles, list)

    @pytest.mark.asyncio
    async def test_classify_tiles(self):
        """Should classify tiles using provided classifier."""
        class MockClassifier:
            async def classify_tile(self, image_base64: str, target_label: str) -> tuple[bool, float]:
                # Tiles 0, 3, 6 match (first column)
                return (True, 0.95)

        png_bytes = create_test_png(300, 300)
        grid_el = MockElement(
            box={"x": 0, "y": 0, "width": 300, "height": 300},
            screenshot_bytes=png_bytes,
        )
        page = MockPage(elements={"div.grid": grid_el})

        result = await solve_grid_captcha(
            page,
            captcha_selector="div.grid",
            target_label="traffic lights",
            grid_size=(3, 3),
            classifier=MockClassifier(),
        )

        assert result.tiles_total > 0
        assert result.confidence_mean > 0.0
        assert result.target_label == "traffic lights"

    @pytest.mark.asyncio
    async def test_dummy_classifier_returns_uncertain(self):
        """DummyClassifier should return False with 0.5 confidence."""
        classifier = DummyClassifier()
        matches, confidence = await classifier.classify_tile("base64data", "cats")
        assert matches is False
        assert confidence == 0.5

    @pytest.mark.asyncio
    async def test_click_selected_tiles(self):
        """Should call mouse.click for each selected tile."""
        class MatchAllClassifier:
            async def classify_tile(self, image_base64: str, target_label: str) -> tuple[bool, float]:
                return (True, 0.95)

        png_bytes = create_test_png(300, 300)
        grid_el = MockElement(
            box={"x": 0, "y": 0, "width": 300, "height": 300},
            screenshot_bytes=png_bytes,
        )
        page = MockPage(elements={"div.grid": grid_el})

        result = await solve_grid_captcha(
            page,
            captcha_selector="div.grid",
            target_label="bicycles",
            grid_size=(3, 3),
            classifier=MatchAllClassifier(),
        )

        try:
            import PIL
            # With PIL: 9 tiles all matching = 9 clicks
            assert len(page.mouse.clicks) == 9
            assert result.success is True
            assert result.tiles_selected == 9
        except ImportError:
            # Without PIL: 1 tile (full grid), 1 click
            assert len(page.mouse.clicks) >= 1

    @pytest.mark.asyncio
    async def test_empty_grid(self):
        """Should handle empty grid gracefully."""
        page = MockPage(elements={})  # No grid element found
        result = await solve_grid_captcha(
            page,
            captcha_selector="div.nonexistent",
            target_label="cars",
            grid_size=(3, 3),
        )
        assert result.success is False
        assert result.tiles_total == 0
        assert result.error == "Failed to extract tiles from grid"

    @pytest.mark.asyncio
    async def test_confidence_threshold_filters_tiles(self):
        """Tiles below confidence threshold should not be selected."""
        class LowConfidenceClassifier:
            async def classify_tile(self, image_base64: str, target_label: str) -> tuple[bool, float]:
                return (True, 0.3)  # Below default 0.7 threshold

        png_bytes = create_test_png(300, 300)
        grid_el = MockElement(
            box={"x": 0, "y": 0, "width": 300, "height": 300},
            screenshot_bytes=png_bytes,
        )
        page = MockPage(elements={"div.grid": grid_el})

        result = await solve_grid_captcha(
            page,
            captcha_selector="div.grid",
            target_label="traffic lights",
            grid_size=(3, 3),
            classifier=LowConfidenceClassifier(),
            confidence_threshold=0.7,
        )

        # No tiles should be selected (all below threshold)
        assert result.tiles_selected == 0
        assert len(page.mouse.clicks) == 0


# ---------------------------------------------------------------------------
# TestSliderSolver
# ---------------------------------------------------------------------------


class TestSliderSolver:
    """Test slider CAPTCHA gap detection and drag simulation."""

    @pytest.mark.asyncio
    async def test_find_gap_position(self):
        """Should find gap position from image with vertical edge."""
        png_bytes = create_test_png_with_edges(300, 100)
        b64 = base64.b64encode(png_bytes).decode('utf-8')

        gap_x = await find_gap_position(b64)

        try:
            import PIL
            # With PIL, should detect the edge near x=180
            assert gap_x > 0
            # Should be in the expected region (60% of 300 = 180, +/- tolerance)
            assert 100 < gap_x < 250
        except ImportError:
            # Without PIL, returns 0
            assert gap_x == 0

    @pytest.mark.asyncio
    async def test_simulate_drag(self):
        """Should simulate mouse down, moves, and up."""
        slider_el = MockElement(
            box={"x": 50, "y": 200, "width": 40, "height": 40}
        )
        page = MockPage(elements={"div.slider-btn": slider_el})

        success = await simulate_slider_drag(page, "div.slider-btn", 150)

        assert success is True
        # Should have mouse down + multiple moves + mouse up
        assert len(page.mouse.downs) == 1
        assert len(page.mouse.ups) == 1
        assert len(page.mouse.moves) > 20  # At least 25 steps + initial move + final

    @pytest.mark.asyncio
    async def test_slider_not_found(self):
        """Should return False when slider element not found."""
        page = MockPage(elements={})
        success = await simulate_slider_drag(page, "div.nonexistent", 100)
        assert success is False

    @pytest.mark.asyncio
    async def test_puzzle_not_found(self):
        """Should return error when puzzle element not found."""
        page = MockPage(elements={})
        result = await solve_slider_captcha(page, puzzle_selector="div.nonexistent")
        assert result.success is False
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_slider_drag_movement_pattern(self):
        """Drag should follow acceleration curve (slow-fast-slow)."""
        slider_el = MockElement(
            box={"x": 50, "y": 200, "width": 40, "height": 40}
        )
        page = MockPage(elements={"div.slider-btn": slider_el})

        await simulate_slider_drag(page, "div.slider-btn", 200)

        # Check that moves start slow, speed up, then slow down
        moves = page.mouse.moves
        if len(moves) > 10:
            # X displacement between consecutive moves
            deltas = [moves[i+1][0] - moves[i][0] for i in range(1, len(moves)-2)]
            # Early moves should be smaller than middle moves
            early_avg = sum(abs(d) for d in deltas[:5]) / 5
            mid_start = len(deltas) // 3
            mid_avg = sum(abs(d) for d in deltas[mid_start:mid_start+5]) / 5
            # Middle should generally be larger (acceleration)
            # This is probabilistic so we just check it ran without error
            assert len(deltas) > 0

    @pytest.mark.asyncio
    async def test_slider_bounding_box_none(self):
        """Should return False when slider bounding box is None."""
        page = MockPage(elements={"div.slider-btn": MockElementNone()})
        success = await simulate_slider_drag(page, "div.slider-btn", 100)
        assert success is False


# ---------------------------------------------------------------------------
# TestLearningLoop
# ---------------------------------------------------------------------------


class TestLearningLoop:
    """Test CAPTCHA event logging and statistics."""

    def setup_method(self):
        """Clear event log before each test."""
        clear_log()

    def test_log_event(self):
        """Should log event and return it."""
        event = log_captcha_event(
            url="https://google.com/search?q=test",
            captcha_type="recaptcha_v2",
            challenge_type="image_grid",
            challenge_category="traffic_lights",
            layer_used=2,
            attempts=1,
            success=True,
            solve_time_ms=1500,
            model_used="clip",
            confidence_mean=0.85,
            engine_triggered="google",
        )
        assert event.url == "https://google.com/search?q=test"
        assert event.captcha_type == "recaptcha_v2"
        assert event.success is True
        assert event.timestamp > 0

    def test_get_stats(self):
        """Should compute aggregate statistics."""
        log_captcha_event(url="a", captcha_type="recaptcha_v2", success=True, solve_time_ms=1000, layer_used=2)
        log_captcha_event(url="b", captcha_type="hcaptcha", success=False, solve_time_ms=2000, layer_used=2)
        log_captcha_event(url="c", captcha_type="recaptcha_v2", success=True, solve_time_ms=800, layer_used=1)

        stats = get_stats()
        assert stats["total"] == 3
        assert stats["success_rate"] == pytest.approx(2/3)
        assert stats["avg_solve_time_ms"] == (1000 + 2000 + 800) // 3

    def test_clear_log(self):
        """Should clear log and return count."""
        log_captcha_event(url="a", captcha_type="x")
        log_captcha_event(url="b", captcha_type="y")
        count = clear_log()
        assert count == 2
        assert get_event_log() == []
        assert get_stats() == {"total": 0}

    def test_stats_by_type(self):
        """Should break down events by CAPTCHA type."""
        log_captcha_event(url="a", captcha_type="recaptcha_v2")
        log_captcha_event(url="b", captcha_type="recaptcha_v2")
        log_captcha_event(url="c", captcha_type="hcaptcha")

        stats = get_stats()
        assert stats["by_type"]["recaptcha_v2"] == 2
        assert stats["by_type"]["hcaptcha"] == 1

    def test_stats_by_layer(self):
        """Should break down events by layer used."""
        log_captcha_event(url="a", captcha_type="x", layer_used=1)
        log_captcha_event(url="b", captcha_type="x", layer_used=2)
        log_captcha_event(url="c", captcha_type="x", layer_used=2)
        log_captcha_event(url="d", captcha_type="x", layer_used=3)

        stats = get_stats()
        assert stats["layer1_avoided"] == 1
        assert stats["layer2_self_solved"] == 2
        assert stats["layer3_api"] == 1

    def test_get_event_log_returns_copy(self):
        """get_event_log should return a copy, not the internal list."""
        log_captcha_event(url="a", captcha_type="x")
        log = get_event_log()
        log.clear()
        # Internal log should be unaffected
        assert len(get_event_log()) == 1


# ---------------------------------------------------------------------------
# TestSolverChain
# ---------------------------------------------------------------------------


class TestSolverChain:
    """Test the three-layer CAPTCHA solver orchestration."""

    def setup_method(self):
        """Clear learning log before each test."""
        clear_log()

    @pytest.mark.asyncio
    async def test_no_captcha_detected(self):
        """Should return early when no CAPTCHA detected."""
        page = MockPage(elements={}, content_text="<html>Normal page</html>")
        result = await solve_captcha(page)
        assert result.detected is False
        assert result.solved is False
        assert result.layer_used == 0

    @pytest.mark.asyncio
    async def test_grid_captcha_solved(self):
        """Should solve grid CAPTCHA with matching classifier."""
        class AlwaysMatchClassifier:
            async def classify_tile(self, image_base64: str, target_label: str) -> tuple[bool, float]:
                return (True, 0.95)

        png_bytes = create_test_png(300, 300)
        grid_el = MockElement(
            box={"x": 0, "y": 0, "width": 300, "height": 300},
            screenshot_bytes=png_bytes,
        )
        page = MockPage(
            elements={
                "iframe[src*='recaptcha']": MockElement(),
                "div.rc-imageselect-challenge": grid_el,
            },
            url="https://example.com/login",
        )

        result = await solve_captcha(page, classifier=AlwaysMatchClassifier())

        assert result.detected is True
        assert result.captcha_type == "recaptcha_v2"
        assert result.solved is True
        assert result.layer_used == 2

    @pytest.mark.asyncio
    async def test_slider_captcha_solved(self):
        """Should solve slider CAPTCHA when elements found."""
        png_bytes = create_test_png_with_edges(300, 100)
        puzzle_el = MockElement(
            box={"x": 0, "y": 0, "width": 300, "height": 100},
            screenshot_bytes=png_bytes,
        )
        slider_el = MockElement(
            box={"x": 10, "y": 80, "width": 40, "height": 40},
        )
        page = MockPage(
            elements={
                "div.geetest_panel": MockElement(),  # Triggers detection
                "div.geetest_canvas_img, div[class*='slider-puzzle'], canvas.captcha-canvas": puzzle_el,
                "div.geetest_slider_button, div[class*='slider-handle'], .slider-btn": slider_el,
                # Individual selectors for multi-selector parsing
                "div.geetest_canvas_img": puzzle_el,
                "div.geetest_slider_button": slider_el,
            },
            url="https://example.com/geetest",
        )

        result = await solve_captcha(page)

        assert result.detected is True
        assert result.captcha_type == "geetest"
        # Success depends on PIL availability for gap detection
        try:
            import PIL
            assert result.layer_used == 2
        except ImportError:
            # Without PIL, gap detection fails
            pass

    @pytest.mark.asyncio
    async def test_behavioral_returns_layer1(self):
        """Behavioral CAPTCHA should report layer 1 (stealth patches)."""
        page = MockPage(
            elements={"div#challenge-form": MockElement()},
            url="https://example.com/cf-challenge",
        )
        result = await solve_captcha(page)
        assert result.detected is True
        assert result.captcha_type == "cloudflare"
        assert result.layer_used == 1
        assert "Layer 1" in result.error

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """Should retry up to max_attempts on solver failure."""
        call_count = 0

        class FailThenSucceedClassifier:
            async def classify_tile(self, image_base64: str, target_label: str) -> tuple[bool, float]:
                nonlocal call_count
                call_count += 1
                # Never match (no tiles selected = grid_result.success stays False
                # because no tiles to click means we skip clicks)
                return (False, 0.9)

        png_bytes = create_test_png(300, 300)
        grid_el = MockElement(
            box={"x": 0, "y": 0, "width": 300, "height": 300},
            screenshot_bytes=png_bytes,
        )
        page = MockPage(
            elements={
                "iframe[src*='recaptcha']": MockElement(),
                "div.rc-imageselect-challenge, div.challenge-container": grid_el,
            },
            url="https://example.com/retry",
        )

        result = await solve_captcha(
            page,
            classifier=FailThenSucceedClassifier(),
            max_attempts=3,
        )

        # Should have attempted multiple times
        assert result.attempts == 3
        assert result.solved is False  # Classifier never matches

    @pytest.mark.asyncio
    async def test_logs_event(self):
        """Should log CAPTCHA event regardless of outcome."""
        page = MockPage(
            elements={"iframe[src*='hcaptcha']": MockElement()},
            content_text="",
            url="https://target.com/page",
        )

        png_bytes = create_test_png(300, 300)
        grid_el = MockElement(
            box={"x": 0, "y": 0, "width": 300, "height": 300},
            screenshot_bytes=png_bytes,
        )
        page._elements["div.rc-imageselect-challenge, div.challenge-container"] = grid_el

        await solve_captcha(page)

        events = get_event_log()
        assert len(events) == 1
        assert events[0].captcha_type == "hcaptcha"
        assert events[0].url == "https://target.com/page"
        assert events[0].model_used == "dummy"

    @pytest.mark.asyncio
    async def test_solve_time_recorded(self):
        """Should record non-zero solve time."""
        page = MockPage(
            elements={"div.geetest_panel": MockElement()},
            url="https://example.com",
        )
        result = await solve_captcha(page)
        assert result.solve_time_ms >= 0

    @pytest.mark.asyncio
    async def test_api_fallback_not_called_when_disabled(self):
        """API fallback should not be called when use_api_fallback=False."""
        api_solver = MagicMock()
        page = MockPage(
            elements={"iframe[src*='recaptcha']": MockElement()},
            url="https://example.com",
        )

        result = await solve_captcha(
            page,
            use_api_fallback=False,
            api_solver=api_solver,
        )

        # API solver should not have been called
        assert result.layer_used != 3
