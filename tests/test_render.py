"""Tests for ghost_render module — headless browser rendering.

All tests mock Playwright completely so they run without it installed.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

from ghostmcp.recon.render import RenderReport, render_page


# ---------------------------------------------------------------------------
# RenderReport dataclass tests
# ---------------------------------------------------------------------------

class TestRenderReport:
    """Test RenderReport dataclass creation and defaults."""

    def test_defaults(self):
        """RenderReport should have sensible defaults."""
        report = RenderReport(url="https://example.com")
        assert report.url == "https://example.com"
        assert report.title == ""
        assert report.rendered_html == ""
        assert report.console_log == []
        assert report.console_errors == []
        assert report.js_errors == []
        assert report.status_code == 0
        assert report.final_url == ""
        assert report.load_time_ms == 0
        assert report.screenshot_path is None
        assert report.error is None

    def test_with_values(self):
        """RenderReport should accept all values."""
        report = RenderReport(
            url="https://test.com",
            title="Test Page",
            rendered_html="<html><body>Hello</body></html>",
            console_log=["[log] loaded"],
            console_errors=["[error] oops"],
            js_errors=["ReferenceError: x is not defined"],
            status_code=200,
            final_url="https://test.com/final",
            load_time_ms=1500,
            screenshot_path="/tmp/test.png",
            error=None,
        )
        assert report.title == "Test Page"
        assert report.status_code == 200
        assert len(report.console_log) == 1
        assert len(report.js_errors) == 1
        assert report.screenshot_path == "/tmp/test.png"

    def test_mutable_defaults_isolation(self):
        """Each instance should have independent mutable defaults."""
        r1 = RenderReport(url="http://a.com")
        r2 = RenderReport(url="http://b.com")
        r1.console_log.append("msg")
        assert r2.console_log == []
        assert r1.console_log == ["msg"]


# ---------------------------------------------------------------------------
# render_page — playwright not installed
# ---------------------------------------------------------------------------

class TestRenderPageNoPlaywright:
    """Test graceful handling when playwright is not installed."""

    @pytest.mark.asyncio
    async def test_import_error(self):
        """Should return report with error when playwright not installed."""
        with patch.dict("sys.modules", {"playwright": None, "playwright.async_api": None}):
            # Force ImportError by patching the import inside render_page
            with patch("builtins.__import__", side_effect=_import_blocker):
                report = await render_page("https://example.com")
                assert report.error is not None
                assert "Playwright not installed" in report.error
                assert report.url == "https://example.com"


def _import_blocker(name, *args, **kwargs):
    """Block playwright imports to simulate missing package."""
    if "playwright" in name:
        raise ImportError("No module named 'playwright'")
    return original_import(name, *args, **kwargs)


import builtins
original_import = builtins.__import__


# ---------------------------------------------------------------------------
# render_page — full flow with mocked playwright
# ---------------------------------------------------------------------------

def _make_mock_playwright():
    """Create a full mock of playwright async API."""
    # Mock page
    mock_page = AsyncMock()
    mock_page.goto = AsyncMock()
    mock_page.wait_for_timeout = AsyncMock()
    mock_page.evaluate = AsyncMock(return_value="eval_result")
    mock_page.content = AsyncMock(return_value="<html><body>Rendered</body></html>")
    mock_page.title = AsyncMock(return_value="Test Title")
    mock_page.screenshot = AsyncMock()

    # Track on() callbacks
    mock_page._event_handlers = {}

    def on_handler(event, callback):
        mock_page._event_handlers[event] = callback

    mock_page.on = MagicMock(side_effect=on_handler)

    # Mock response from goto
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.url = "https://example.com/final"
    mock_page.goto.return_value = mock_response

    # Mock context
    mock_context = AsyncMock()
    mock_context.new_page = AsyncMock(return_value=mock_page)

    # Mock browser
    mock_browser = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    mock_browser.close = AsyncMock()

    # Mock playwright instance
    mock_pw = AsyncMock()
    mock_pw.chromium = AsyncMock()
    mock_pw.chromium.launch = AsyncMock(return_value=mock_browser)

    return mock_pw, mock_browser, mock_context, mock_page


class TestRenderPageMocked:
    """Test render_page with fully mocked playwright."""

    @pytest.mark.asyncio
    async def test_basic_render(self):
        """Should render page and return report with title, HTML, status."""
        mock_pw, mock_browser, mock_context, mock_page = _make_mock_playwright()

        mock_async_playwright = AsyncMock()
        mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
        mock_async_playwright.__aexit__ = AsyncMock(return_value=False)

        import sys
        mock_playwright_module = MagicMock()
        mock_playwright_module.async_api.async_playwright = MagicMock(return_value=mock_async_playwright)

        with patch.dict(sys.modules, {
            "playwright": mock_playwright_module,
            "playwright.async_api": mock_playwright_module.async_api,
        }):
            report = await render_page("https://example.com", wait_ms=1000)

        assert report.url == "https://example.com"
        assert report.title == "Test Title"
        assert report.rendered_html == "<html><body>Rendered</body></html>"
        assert report.status_code == 200
        assert report.final_url == "https://example.com/final"
        assert report.error is None

    @pytest.mark.asyncio
    async def test_console_capture(self):
        """Should capture console.log and console.error messages."""
        mock_pw, mock_browser, mock_context, mock_page = _make_mock_playwright()

        mock_async_playwright = AsyncMock()
        mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
        mock_async_playwright.__aexit__ = AsyncMock(return_value=False)

        import sys
        mock_playwright_module = MagicMock()
        mock_playwright_module.async_api.async_playwright = MagicMock(return_value=mock_async_playwright)

        with patch.dict(sys.modules, {
            "playwright": mock_playwright_module,
            "playwright.async_api": mock_playwright_module.async_api,
        }):
            report = await render_page("https://example.com", wait_ms=0)

        # Simulate console events via the captured handlers
        assert "console" in mock_page._event_handlers
        console_cb = mock_page._event_handlers["console"]

        # Simulate log message
        log_msg = MagicMock()
        log_msg.type = "log"
        log_msg.text = "Hello from console"
        console_cb(log_msg)

        # Simulate error message
        err_msg = MagicMock()
        err_msg.type = "error"
        err_msg.text = "Something broke"
        console_cb(err_msg)

        # Simulate warning message
        warn_msg = MagicMock()
        warn_msg.type = "warning"
        warn_msg.text = "Deprecation notice"
        console_cb(warn_msg)

        assert "[log] Hello from console" in report.console_log
        assert "[error] Something broke" in report.console_errors
        assert "[warning] Deprecation notice" in report.console_errors

    @pytest.mark.asyncio
    async def test_js_error_capture(self):
        """Should capture uncaught JS errors via pageerror event."""
        mock_pw, mock_browser, mock_context, mock_page = _make_mock_playwright()

        mock_async_playwright = AsyncMock()
        mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
        mock_async_playwright.__aexit__ = AsyncMock(return_value=False)

        import sys
        mock_playwright_module = MagicMock()
        mock_playwright_module.async_api.async_playwright = MagicMock(return_value=mock_async_playwright)

        with patch.dict(sys.modules, {
            "playwright": mock_playwright_module,
            "playwright.async_api": mock_playwright_module.async_api,
        }):
            report = await render_page("https://example.com", wait_ms=0)

        # Simulate JS error
        assert "pageerror" in mock_page._event_handlers
        pageerror_cb = mock_page._event_handlers["pageerror"]
        pageerror_cb(Exception("ReferenceError: x is not defined"))

        assert any("ReferenceError" in e for e in report.js_errors)

    @pytest.mark.asyncio
    async def test_custom_js_execution(self):
        """Should execute custom JS and capture result."""
        mock_pw, mock_browser, mock_context, mock_page = _make_mock_playwright()
        mock_page.evaluate = AsyncMock(return_value=42)

        mock_async_playwright = AsyncMock()
        mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
        mock_async_playwright.__aexit__ = AsyncMock(return_value=False)

        import sys
        mock_playwright_module = MagicMock()
        mock_playwright_module.async_api.async_playwright = MagicMock(return_value=mock_async_playwright)

        with patch.dict(sys.modules, {
            "playwright": mock_playwright_module,
            "playwright.async_api": mock_playwright_module.async_api,
        }):
            report = await render_page(
                "https://example.com",
                wait_ms=0,
                execute_js="return document.querySelectorAll('div').length",
            )

        mock_page.evaluate.assert_called_once_with("return document.querySelectorAll('div').length")
        assert "[execute] Result: 42" in report.console_log

    @pytest.mark.asyncio
    async def test_custom_js_error(self):
        """Should capture errors from custom JS execution."""
        mock_pw, mock_browser, mock_context, mock_page = _make_mock_playwright()
        mock_page.evaluate = AsyncMock(side_effect=Exception("SyntaxError: unexpected token"))

        mock_async_playwright = AsyncMock()
        mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
        mock_async_playwright.__aexit__ = AsyncMock(return_value=False)

        import sys
        mock_playwright_module = MagicMock()
        mock_playwright_module.async_api.async_playwright = MagicMock(return_value=mock_async_playwright)

        with patch.dict(sys.modules, {
            "playwright": mock_playwright_module,
            "playwright.async_api": mock_playwright_module.async_api,
        }):
            report = await render_page(
                "https://example.com",
                wait_ms=0,
                execute_js="invalid((",
            )

        assert any("SyntaxError" in e for e in report.js_errors)

    @pytest.mark.asyncio
    async def test_screenshot_capture(self):
        """Should take screenshot when flag is set."""
        mock_pw, mock_browser, mock_context, mock_page = _make_mock_playwright()

        mock_async_playwright = AsyncMock()
        mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
        mock_async_playwright.__aexit__ = AsyncMock(return_value=False)

        import sys
        mock_playwright_module = MagicMock()
        mock_playwright_module.async_api.async_playwright = MagicMock(return_value=mock_async_playwright)

        with patch.dict(sys.modules, {
            "playwright": mock_playwright_module,
            "playwright.async_api": mock_playwright_module.async_api,
        }):
            report = await render_page(
                "https://example.com",
                wait_ms=0,
                capture_screenshot=True,
                screenshot_path="/tmp/test_shot.png",
            )

        mock_page.screenshot.assert_called_once_with(path="/tmp/test_shot.png", full_page=True)
        assert report.screenshot_path == "/tmp/test_shot.png"

    @pytest.mark.asyncio
    async def test_no_screenshot_by_default(self):
        """Should not take screenshot by default."""
        mock_pw, mock_browser, mock_context, mock_page = _make_mock_playwright()

        mock_async_playwright = AsyncMock()
        mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
        mock_async_playwright.__aexit__ = AsyncMock(return_value=False)

        import sys
        mock_playwright_module = MagicMock()
        mock_playwright_module.async_api.async_playwright = MagicMock(return_value=mock_async_playwright)

        with patch.dict(sys.modules, {
            "playwright": mock_playwright_module,
            "playwright.async_api": mock_playwright_module.async_api,
        }):
            report = await render_page("https://example.com", wait_ms=0)

        mock_page.screenshot.assert_not_called()
        assert report.screenshot_path is None

    @pytest.mark.asyncio
    async def test_browser_exception(self):
        """Should handle browser launch errors gracefully."""
        mock_pw = AsyncMock()
        mock_pw.chromium = AsyncMock()
        mock_pw.chromium.launch = AsyncMock(side_effect=Exception("Failed to launch browser"))

        mock_async_playwright = AsyncMock()
        mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
        mock_async_playwright.__aexit__ = AsyncMock(return_value=False)

        import sys
        mock_playwright_module = MagicMock()
        mock_playwright_module.async_api.async_playwright = MagicMock(return_value=mock_async_playwright)

        with patch.dict(sys.modules, {
            "playwright": mock_playwright_module,
            "playwright.async_api": mock_playwright_module.async_api,
        }):
            report = await render_page("https://example.com")

        assert report.error is not None
        assert "Failed to launch browser" in report.error

    @pytest.mark.asyncio
    async def test_navigation_timeout(self):
        """Should handle navigation timeout."""
        mock_pw, mock_browser, mock_context, mock_page = _make_mock_playwright()
        mock_page.goto = AsyncMock(side_effect=Exception("TimeoutError: Navigation timeout"))

        mock_async_playwright = AsyncMock()
        mock_async_playwright.__aenter__ = AsyncMock(return_value=mock_pw)
        mock_async_playwright.__aexit__ = AsyncMock(return_value=False)

        import sys
        mock_playwright_module = MagicMock()
        mock_playwright_module.async_api.async_playwright = MagicMock(return_value=mock_async_playwright)

        with patch.dict(sys.modules, {
            "playwright": mock_playwright_module,
            "playwright.async_api": mock_playwright_module.async_api,
        }):
            report = await render_page("https://example.com", timeout_ms=1000)

        assert report.error is not None
        assert "TimeoutError" in report.error


# ---------------------------------------------------------------------------
# ghost_render MCP tool — extract modes
# ---------------------------------------------------------------------------

class TestGhostRenderTool:
    """Test the ghost_render MCP tool formatting logic."""

    @pytest.mark.asyncio
    async def test_extract_all(self):
        """extract='all' should include DOM, console, and errors."""
        mock_report = RenderReport(
            url="https://test.com",
            title="My Page",
            rendered_html="<html><body>Content</body></html>",
            console_log=["[log] Loaded"],
            console_errors=["[error] Oops"],
            js_errors=["TypeError: null is not an object"],
            status_code=200,
            final_url="https://test.com",
            load_time_ms=500,
        )

        with patch("src.mcp.render_page", new_callable=AsyncMock, return_value=mock_report):
            from ghostmcp.mcp import ghost_render
            result = await ghost_render(url="https://test.com", extract="all")

        assert "=== Rendered Page: My Page ===" in result
        assert "Status: 200" in result
        assert "<html><body>Content</body></html>" in result
        assert "=== Console Output ===" in result
        assert "[log] Loaded" in result
        assert "** [error] Oops" in result
        assert "=== JavaScript Errors ===" in result
        assert "TypeError: null is not an object" in result

    @pytest.mark.asyncio
    async def test_extract_dom_only(self):
        """extract='dom' should only include rendered HTML."""
        mock_report = RenderReport(
            url="https://test.com",
            title="DOM Only",
            rendered_html="<div>Hello</div>",
            console_log=["[log] ignored"],
            js_errors=["also ignored"],
            status_code=200,
            final_url="https://test.com",
            load_time_ms=100,
        )

        with patch("src.mcp.render_page", new_callable=AsyncMock, return_value=mock_report):
            from ghostmcp.mcp import ghost_render
            result = await ghost_render(url="https://test.com", extract="dom")

        assert "=== Rendered Page: DOM Only ===" in result
        assert "<div>Hello</div>" in result
        assert "=== Console Output ===" not in result
        assert "=== JavaScript Errors ===" not in result

    @pytest.mark.asyncio
    async def test_extract_console_only(self):
        """extract='console' should only include console output."""
        mock_report = RenderReport(
            url="https://test.com",
            title="Console Only",
            rendered_html="<div>Ignored</div>",
            console_log=["[log] message one"],
            console_errors=["[error] bad thing"],
            js_errors=[],
            status_code=200,
            final_url="https://test.com",
            load_time_ms=100,
        )

        with patch("src.mcp.render_page", new_callable=AsyncMock, return_value=mock_report):
            from ghostmcp.mcp import ghost_render
            result = await ghost_render(url="https://test.com", extract="console")

        assert "=== Console Output ===" in result
        assert "[log] message one" in result
        assert "** [error] bad thing" in result
        assert "=== Rendered Page:" not in result
        assert "<div>Ignored</div>" not in result

    @pytest.mark.asyncio
    async def test_extract_errors_only(self):
        """extract='errors' should only include JS errors."""
        mock_report = RenderReport(
            url="https://test.com",
            title="Errors Only",
            rendered_html="<div>Ignored</div>",
            console_log=["[log] ignored"],
            console_errors=[],
            js_errors=["ReferenceError: foo is not defined"],
            status_code=200,
            final_url="https://test.com",
            load_time_ms=100,
        )

        with patch("src.mcp.render_page", new_callable=AsyncMock, return_value=mock_report):
            from ghostmcp.mcp import ghost_render
            result = await ghost_render(url="https://test.com", extract="errors")

        assert "=== JavaScript Errors ===" in result
        assert "ReferenceError: foo is not defined" in result
        assert "=== Rendered Page:" not in result
        assert "=== Console Output ===" not in result

    @pytest.mark.asyncio
    async def test_extract_errors_no_errors(self):
        """extract='errors' with no JS errors should say so."""
        mock_report = RenderReport(
            url="https://test.com",
            title="Clean",
            rendered_html="<div>Clean</div>",
            console_log=[],
            console_errors=[],
            js_errors=[],
            status_code=200,
            final_url="https://test.com",
            load_time_ms=100,
        )

        with patch("src.mcp.render_page", new_callable=AsyncMock, return_value=mock_report):
            from ghostmcp.mcp import ghost_render
            result = await ghost_render(url="https://test.com", extract="errors")

        assert "No JavaScript errors detected." in result

    @pytest.mark.asyncio
    async def test_render_error_passthrough(self):
        """Should return error message when render fails."""
        mock_report = RenderReport(
            url="https://test.com",
            error="TimeoutError: page did not load",
        )

        with patch("src.mcp.render_page", new_callable=AsyncMock, return_value=mock_report):
            from ghostmcp.mcp import ghost_render
            result = await ghost_render(url="https://test.com")

        assert "Render error: TimeoutError: page did not load" in result

    @pytest.mark.asyncio
    async def test_html_truncation(self):
        """Should truncate HTML over 30KB."""
        big_html = "x" * 50000
        mock_report = RenderReport(
            url="https://test.com",
            title="Big Page",
            rendered_html=big_html,
            status_code=200,
            final_url="https://test.com",
            load_time_ms=100,
        )

        with patch("src.mcp.render_page", new_callable=AsyncMock, return_value=mock_report):
            from ghostmcp.mcp import ghost_render
            result = await ghost_render(url="https://test.com", extract="dom")

        assert "[... truncated at 30KB ...]" in result
        # Verify it's not the full 50KB
        assert len(result) < 40000

    @pytest.mark.asyncio
    async def test_screenshot_message(self):
        """Should include screenshot path when screenshot is taken."""
        mock_report = RenderReport(
            url="https://test.com",
            title="Screenshot Test",
            rendered_html="<div>Content</div>",
            status_code=200,
            final_url="https://test.com",
            load_time_ms=100,
            screenshot_path="/tmp/ghostmcp_screenshot.png",
        )

        with patch("src.mcp.render_page", new_callable=AsyncMock, return_value=mock_report):
            from ghostmcp.mcp import ghost_render
            result = await ghost_render(url="https://test.com", screenshot=True)

        assert "Screenshot saved: /tmp/ghostmcp_screenshot.png" in result
