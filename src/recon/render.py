"""Headless browser rendering + JavaScript console capture via Playwright."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RenderReport:
    """Result of rendering a page with headless browser."""
    url: str
    title: str = ""
    rendered_html: str = ""
    console_log: list[str] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    js_errors: list[str] = field(default_factory=list)
    status_code: int = 0
    final_url: str = ""          # After redirects
    load_time_ms: int = 0
    screenshot_path: str | None = None
    error: str | None = None


async def render_page(
    url: str,
    wait_ms: int = 5000,
    execute_js: str | None = None,
    capture_screenshot: bool = False,
    screenshot_path: str = "/tmp/ghostmcp_screenshot.png",
    timeout_ms: int = 30000,
) -> RenderReport:
    """Render a page with headless Chromium and capture console output.

    Args:
        url: URL to load.
        wait_ms: Milliseconds to wait after page load for JS execution.
        execute_js: Optional JavaScript to run after page loads.
        capture_screenshot: Whether to take a screenshot.
        screenshot_path: Where to save the screenshot.
        timeout_ms: Total timeout for the operation.

    Returns:
        RenderReport with rendered DOM, console output, and JS errors.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return RenderReport(url=url, error="Playwright not installed. Install with: pip install playwright && playwright install chromium")

    report = RenderReport(url=url)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ]
            )

            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1920, "height": 1080},
            )

            page = await context.new_page()

            # Capture console messages
            page.on("console", lambda msg: (
                report.console_errors.append(f"[{msg.type}] {msg.text}")
                if msg.type in ("error", "warning")
                else report.console_log.append(f"[{msg.type}] {msg.text}")
            ))

            # Capture JS errors (uncaught exceptions)
            page.on("pageerror", lambda err: report.js_errors.append(str(err)))

            # Navigate
            import time
            start = time.monotonic()

            response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

            if response:
                report.status_code = response.status
                report.final_url = response.url

            # Wait for JS to execute
            if wait_ms > 0:
                await page.wait_for_timeout(wait_ms)

            report.load_time_ms = int((time.monotonic() - start) * 1000)

            # Execute custom JS if provided
            if execute_js:
                try:
                    result = await page.evaluate(execute_js)
                    report.console_log.append(f"[execute] Result: {result}")
                except Exception as e:
                    report.js_errors.append(f"[execute] {e}")

            # Get rendered HTML
            report.rendered_html = await page.content()
            report.title = await page.title()

            # Screenshot
            if capture_screenshot:
                await page.screenshot(path=screenshot_path, full_page=True)
                report.screenshot_path = screenshot_path

            await browser.close()

    except Exception as e:
        report.error = f"{type(e).__name__}: {e}"

    return report
