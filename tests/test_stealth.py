"""Tests for stealth browser patches and behavioral simulation.

All tests mock Playwright completely so they run without it installed.
"""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.stealth.browser_stealth import (
    STEALTH_SCRIPTS,
    apply_stealth,
    get_stealth_context_options,
)
from src.stealth.behavioral import (
    human_click,
    human_move_to,
    human_scroll,
    human_type,
    random_delay,
)


# ---------------------------------------------------------------------------
# Mock Playwright objects
# ---------------------------------------------------------------------------


class MockMouse:
    """Mock Playwright mouse with move tracking."""

    def __init__(self):
        self.moves: list[tuple[float, float]] = []
        self.downs: list[str] = []
        self.ups: list[str] = []

    async def move(self, x, y, **kwargs):
        self.moves.append((x, y))

    async def down(self, **kwargs):
        self.downs.append(kwargs.get("button", "left"))

    async def up(self, **kwargs):
        self.ups.append(kwargs.get("button", "left"))


class MockElement:
    """Mock Playwright element handle."""

    def __init__(self, box=None):
        self._box = box or {"x": 100, "y": 100, "width": 200, "height": 50}

    async def bounding_box(self):
        return self._box


class MockElementNoBox(MockElement):
    """Mock element that returns None for bounding_box."""

    async def bounding_box(self):
        return None


class MockPage:
    """Mock Playwright page with tracking for all interactions."""

    def __init__(self, element=None):
        self.mouse = MockMouse()
        self.init_scripts: list[str] = []
        self.typed: list[tuple[str, str]] = []  # (selector, char)
        self.evaluations: list[str] = []
        self.clicks: list[dict] = []
        self._element = element

    async def add_init_script(self, script):
        self.init_scripts.append(script)

    async def evaluate(self, expr):
        self.evaluations.append(expr)
        return {"x": 500, "y": 500}

    async def query_selector(self, selector):
        return self._element

    async def click(self, selector, **kwargs):
        self.clicks.append({"selector": selector, **kwargs})

    async def type(self, selector, text, **kwargs):
        self.typed.append((selector, text))


# ---------------------------------------------------------------------------
# TestStealthScripts
# ---------------------------------------------------------------------------


class TestStealthScripts:
    """Verify STEALTH_SCRIPTS list structure and content."""

    def test_scripts_is_nonempty_list(self):
        """STEALTH_SCRIPTS should be a non-empty list."""
        assert isinstance(STEALTH_SCRIPTS, list)
        assert len(STEALTH_SCRIPTS) > 0

    def test_all_scripts_are_strings(self):
        """Each stealth script should be a string."""
        for i, script in enumerate(STEALTH_SCRIPTS):
            assert isinstance(script, str), f"Script at index {i} is not a string"

    def test_all_scripts_are_nonempty(self):
        """Each stealth script should contain actual JS code."""
        for i, script in enumerate(STEALTH_SCRIPTS):
            assert len(script.strip()) > 0, f"Script at index {i} is empty"

    def test_webdriver_patch_present(self):
        """Should include a script that patches navigator.webdriver."""
        combined = "\n".join(STEALTH_SCRIPTS)
        assert "webdriver" in combined

    def test_chrome_runtime_patch_present(self):
        """Should include a script that adds chrome.runtime."""
        combined = "\n".join(STEALTH_SCRIPTS)
        assert "chrome.runtime" in combined

    def test_plugins_patch_present(self):
        """Should include a script that patches navigator.plugins."""
        combined = "\n".join(STEALTH_SCRIPTS)
        assert "plugins" in combined

    def test_webgl_patch_present(self):
        """Should include a script that patches WebGL parameters."""
        combined = "\n".join(STEALTH_SCRIPTS)
        assert "WebGLRenderingContext" in combined

    def test_script_count(self):
        """Should have 10 stealth scripts."""
        assert len(STEALTH_SCRIPTS) == 10


# ---------------------------------------------------------------------------
# TestStealthContextOptions
# ---------------------------------------------------------------------------


class TestStealthContextOptions:
    """Verify get_stealth_context_options returns expected structure."""

    def test_returns_dict(self):
        """Should return a dictionary."""
        opts = get_stealth_context_options()
        assert isinstance(opts, dict)

    def test_user_agent_present(self):
        """Should include a realistic user agent string."""
        opts = get_stealth_context_options()
        assert "user_agent" in opts
        assert "Mozilla" in opts["user_agent"]
        assert "Chrome" in opts["user_agent"]

    def test_viewport_present(self):
        """Should include viewport dimensions."""
        opts = get_stealth_context_options()
        assert "viewport" in opts
        assert opts["viewport"]["width"] == 1920
        assert opts["viewport"]["height"] == 1080

    def test_locale_present(self):
        """Should include locale setting."""
        opts = get_stealth_context_options()
        assert opts["locale"] == "en-US"

    def test_timezone_present(self):
        """Should include timezone setting."""
        opts = get_stealth_context_options()
        assert "timezone_id" in opts
        assert isinstance(opts["timezone_id"], str)

    def test_screen_present(self):
        """Should include screen dimensions."""
        opts = get_stealth_context_options()
        assert "screen" in opts
        assert opts["screen"]["width"] == 1920
        assert opts["screen"]["height"] == 1080

    def test_not_mobile(self):
        """Should not be configured as mobile device."""
        opts = get_stealth_context_options()
        assert opts["is_mobile"] is False
        assert opts["has_touch"] is False

    def test_device_scale_factor(self):
        """Should have standard device scale factor."""
        opts = get_stealth_context_options()
        assert opts["device_scale_factor"] == 1

    def test_color_scheme(self):
        """Should specify a color scheme."""
        opts = get_stealth_context_options()
        assert opts["color_scheme"] == "light"

    def test_permissions(self):
        """Should include permissions list."""
        opts = get_stealth_context_options()
        assert "permissions" in opts
        assert isinstance(opts["permissions"], list)


# ---------------------------------------------------------------------------
# TestApplyStealth
# ---------------------------------------------------------------------------


class TestApplyStealth:
    """Test apply_stealth function."""

    @pytest.mark.asyncio
    async def test_applies_all_scripts(self):
        """Should inject all stealth scripts into the page."""
        page = MockPage()
        await apply_stealth(page)
        assert len(page.init_scripts) == len(STEALTH_SCRIPTS)

    @pytest.mark.asyncio
    async def test_scripts_match(self):
        """Injected scripts should match STEALTH_SCRIPTS exactly."""
        page = MockPage()
        await apply_stealth(page)
        for i, script in enumerate(STEALTH_SCRIPTS):
            assert page.init_scripts[i] == script


# ---------------------------------------------------------------------------
# TestBehavioralHelpers — random_delay
# ---------------------------------------------------------------------------


class TestRandomDelay:
    """Test random_delay timing bounds."""

    @pytest.mark.asyncio
    async def test_random_delay_within_bounds(self):
        """Delay should fall within min/max millisecond bounds."""
        start = time.monotonic()
        await random_delay(min_ms=100, max_ms=500)
        elapsed = time.monotonic() - start
        # Allow small tolerance for asyncio overhead
        assert elapsed >= 0.09, f"Delay too short: {elapsed:.3f}s"
        assert elapsed <= 0.6, f"Delay too long: {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_random_delay_default_bounds(self):
        """Default bounds (500-2000ms) should produce delays in range."""
        start = time.monotonic()
        await random_delay()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.4, f"Delay too short: {elapsed:.3f}s"
        assert elapsed <= 2.5, f"Delay too long: {elapsed:.3f}s"


# ---------------------------------------------------------------------------
# TestBehavioralHelpers — human_move_to
# ---------------------------------------------------------------------------


class TestHumanMoveTo:
    """Test Bezier curve mouse movement."""

    @pytest.mark.asyncio
    async def test_generates_multiple_moves(self):
        """Should call page.mouse.move multiple times (not just once)."""
        page = MockPage()
        await human_move_to(page, 300, 400)
        # Should have many intermediate moves plus the final one
        assert len(page.mouse.moves) > 5

    @pytest.mark.asyncio
    async def test_ends_at_target(self):
        """Final mouse position should be the exact target coordinates."""
        page = MockPage()
        await human_move_to(page, 300, 400)
        last_move = page.mouse.moves[-1]
        assert last_move == (300, 400)

    @pytest.mark.asyncio
    async def test_custom_steps(self):
        """Should respect explicit step count."""
        page = MockPage()
        await human_move_to(page, 300, 400, steps=15)
        # 15 intermediate moves + 1 final exact move
        assert len(page.mouse.moves) == 16

    @pytest.mark.asyncio
    async def test_stores_position(self):
        """Should store final position via page.evaluate for next call."""
        page = MockPage()
        await human_move_to(page, 250, 350)
        # Last evaluate should store the position
        last_eval = page.evaluations[-1]
        assert "250" in last_eval
        assert "350" in last_eval

    @pytest.mark.asyncio
    async def test_intermediate_points_vary(self):
        """Intermediate moves should not be collinear (Bezier + jitter)."""
        page = MockPage()
        await human_move_to(page, 500, 500, steps=20)
        # Check that not all intermediate points are on a straight line
        # from (500,500) to (500,500) — the jitter should make them vary
        xs = [m[0] for m in page.mouse.moves[:-1]]  # exclude final exact
        ys = [m[1] for m in page.mouse.moves[:-1]]
        # With jitter, x and y values should not all be identical
        assert len(set(round(x, 2) for x in xs)) > 1
        assert len(set(round(y, 2) for y in ys)) > 1


# ---------------------------------------------------------------------------
# TestBehavioralHelpers — human_click
# ---------------------------------------------------------------------------


class TestHumanClick:
    """Test human-like click simulation."""

    @pytest.mark.asyncio
    async def test_click_finds_element(self):
        """Should locate element and use its bounding box."""
        element = MockElement({"x": 100, "y": 200, "width": 300, "height": 60})
        page = MockPage(element=element)
        await human_click(page, "#button")
        # Should have moved mouse (multiple moves from Bezier)
        assert len(page.mouse.moves) > 5
        # Should have mouse down + up
        assert len(page.mouse.downs) == 1
        assert len(page.mouse.ups) == 1

    @pytest.mark.asyncio
    async def test_click_target_within_element(self):
        """Click target should be within the element's bounding box."""
        box = {"x": 100, "y": 200, "width": 300, "height": 60}
        element = MockElement(box)
        page = MockPage(element=element)
        await human_click(page, "#button")
        # The final exact move before mouse.down should be within box
        # (last move from human_move_to is the exact target)
        final_x, final_y = page.mouse.moves[-1]
        # The target is randomized within 20-80% of the box
        assert box["x"] <= final_x <= box["x"] + box["width"]
        assert box["y"] <= final_y <= box["y"] + box["height"]

    @pytest.mark.asyncio
    async def test_click_missing_element_raises(self):
        """Should raise ValueError when element not found."""
        page = MockPage(element=None)  # query_selector returns None
        with pytest.raises(ValueError, match="Element not found"):
            await human_click(page, "#nonexistent")

    @pytest.mark.asyncio
    async def test_click_no_bounding_box_raises(self):
        """Should raise ValueError when element has no bounding box."""
        element = MockElementNoBox()
        page = MockPage(element=element)
        with pytest.raises(ValueError, match="has no bounding box"):
            await human_click(page, "#hidden")

    @pytest.mark.asyncio
    async def test_click_button_type(self):
        """Should pass button parameter to mouse.down/up."""
        element = MockElement()
        page = MockPage(element=element)
        await human_click(page, "#button", button="right")
        assert page.mouse.downs == ["right"]
        assert page.mouse.ups == ["right"]


# ---------------------------------------------------------------------------
# TestBehavioralHelpers — human_type
# ---------------------------------------------------------------------------


class TestHumanType:
    """Test human-like typing simulation."""

    @pytest.mark.asyncio
    async def test_types_each_character(self):
        """Should type each character individually."""
        page = MockPage(element=MockElement())
        await human_type(page, "#input", "hello")
        # Should have typed 5 characters
        chars_typed = [char for _, char in page.typed]
        assert chars_typed == ["h", "e", "l", "l", "o"]

    @pytest.mark.asyncio
    async def test_types_to_correct_selector(self):
        """All type calls should target the correct selector."""
        page = MockPage(element=MockElement())
        await human_type(page, "#email", "ab")
        selectors = [sel for sel, _ in page.typed]
        assert all(s == "#email" for s in selectors)

    @pytest.mark.asyncio
    async def test_clear_first_default(self):
        """Should click to select-all before typing by default."""
        page = MockPage(element=MockElement())
        await human_type(page, "#input", "x")
        # Should have clicked with click_count=3 (select all)
        assert len(page.clicks) == 1
        assert page.clicks[0]["click_count"] == 3

    @pytest.mark.asyncio
    async def test_no_clear_when_disabled(self):
        """Should not clear when clear_first=False."""
        page = MockPage(element=MockElement())
        await human_type(page, "#input", "x", clear_first=False)
        assert len(page.clicks) == 0

    @pytest.mark.asyncio
    async def test_empty_string(self):
        """Should handle empty string without error."""
        page = MockPage(element=MockElement())
        await human_type(page, "#input", "")
        assert len(page.typed) == 0


# ---------------------------------------------------------------------------
# TestBehavioralHelpers — human_scroll
# ---------------------------------------------------------------------------


class TestHumanScroll:
    """Test human-like scroll simulation."""

    @pytest.mark.asyncio
    async def test_scroll_down_direction(self):
        """Scroll down should produce positive scrollBy values."""
        page = MockPage()
        await human_scroll(page, direction="down", amount=300)
        # All scroll evaluations should contain positive values
        scroll_evals = [e for e in page.evaluations if "scrollBy" in e]
        assert len(scroll_evals) > 0
        for expr in scroll_evals:
            # Extract the scroll value from "window.scrollBy(0, N)"
            val_str = expr.split(",")[1].strip().rstrip(")")
            assert int(val_str) > 0

    @pytest.mark.asyncio
    async def test_scroll_up_direction(self):
        """Scroll up should produce negative scrollBy values."""
        page = MockPage()
        await human_scroll(page, direction="up", amount=300)
        scroll_evals = [e for e in page.evaluations if "scrollBy" in e]
        assert len(scroll_evals) > 0
        for expr in scroll_evals:
            val_str = expr.split(",")[1].strip().rstrip(")")
            assert int(val_str) < 0

    @pytest.mark.asyncio
    async def test_smooth_scroll_multiple_chunks(self):
        """Smooth scroll should produce multiple small scrollBy calls."""
        page = MockPage()
        await human_scroll(page, direction="down", amount=500, smooth=True)
        scroll_evals = [e for e in page.evaluations if "scrollBy" in e]
        # Should have multiple chunks, not just one big scroll
        assert len(scroll_evals) > 3

    @pytest.mark.asyncio
    async def test_non_smooth_single_scroll(self):
        """Non-smooth scroll should produce exactly one scrollBy call."""
        page = MockPage()
        await human_scroll(page, direction="down", amount=500, smooth=False)
        scroll_evals = [e for e in page.evaluations if "scrollBy" in e]
        assert len(scroll_evals) == 1

    @pytest.mark.asyncio
    async def test_non_smooth_uses_exact_amount(self):
        """Non-smooth scroll should use the exact amount specified."""
        page = MockPage()
        await human_scroll(page, direction="down", amount=777, smooth=False)
        scroll_evals = [e for e in page.evaluations if "scrollBy" in e]
        assert len(scroll_evals) == 1
        # Should contain the negated value for "up" or exact for "down"
        assert "777" in scroll_evals[0]

    @pytest.mark.asyncio
    async def test_non_smooth_up_uses_negative(self):
        """Non-smooth scroll up should negate the amount."""
        page = MockPage()
        await human_scroll(page, direction="up", amount=400, smooth=False)
        scroll_evals = [e for e in page.evaluations if "scrollBy" in e]
        assert "-400" in scroll_evals[0]

    @pytest.mark.asyncio
    async def test_default_amount_nonzero(self):
        """When amount=0, should pick a random non-zero amount."""
        page = MockPage()
        await human_scroll(page, direction="down", amount=0)
        scroll_evals = [e for e in page.evaluations if "scrollBy" in e]
        assert len(scroll_evals) > 0


# ---------------------------------------------------------------------------
# TestImports — verify __init__.py re-exports
# ---------------------------------------------------------------------------


class TestModuleImports:
    """Verify that the stealth package exports work."""

    def test_import_from_package(self):
        """Should be able to import all public names from src.stealth."""
        from src.stealth import (
            STEALTH_SCRIPTS,
            apply_stealth,
            get_stealth_context_options,
            human_click,
            human_move_to,
            human_scroll,
            human_type,
            random_delay,
        )

        # Verify they're the real functions, not None
        assert callable(apply_stealth)
        assert callable(get_stealth_context_options)
        assert callable(human_move_to)
        assert callable(human_click)
        assert callable(human_type)
        assert callable(human_scroll)
        assert callable(random_delay)
        assert isinstance(STEALTH_SCRIPTS, list)
