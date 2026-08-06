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
    device_info: dict | None = None   # Effective emulation (name, viewport, DPR, mobile, touch)


async def render_page(
    url: str,
    wait_ms: int = 5000,
    execute_js: str | None = None,
    capture_screenshot: bool = False,
    screenshot_path: str = "/tmp/ghostmcp_screenshot.png",
    timeout_ms: int = 30000,
    route_handler=None,
    ignore_https_errors: bool = True,
    device: str | None = None,
) -> RenderReport:
    """Render a page with headless Chromium and capture console output.

    Args:
        url: URL to load.
        wait_ms: Milliseconds to wait after page load for JS execution.
        execute_js: Optional JavaScript to run after page loads.
        capture_screenshot: Whether to take a screenshot.
        screenshot_path: Where to save the screenshot.
        timeout_ms: Total timeout for the operation.
        route_handler: Optional async callable(route, request) installed via
            page.route("**/*", ...). Used to proxy same-origin requests through
            a connectivity bridge so a multi-file SPA actually loads and runs
            (instead of the data: URL trick which breaks relative URLs,
            /api calls and localStorage). When None, the browser navigates and
            fetches normally.
        device: Optional Playwright device-registry name (e.g. "Pixel 7",
            "iPhone 14 Pro Max", "iPad Pro 11"). When set, emulates that device
            exactly — viewport, device-scale-factor, mobile user-agent, and
            touch — for realistic mobile/tablet visual review. Overrides the
            default desktop 1920x1080 (and any stealth UA/viewport). Unknown
            names are reported as an error listing available devices.

    Returns:
        RenderReport with rendered DOM, console output, and JS errors.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return RenderReport(url=url, error="Playwright not installed. Install with: pip install playwright && playwright install chromium")

    report = RenderReport(url=url)

    try:
        # Import stealth module (optional — degrades gracefully)
        try:
            from ..stealth import apply_stealth, get_stealth_context_options
            _has_stealth = True
        except ImportError:
            _has_stealth = False

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

            # Use stealth context options if available, else fallback
            if _has_stealth:
                ctx_options = get_stealth_context_options()
            else:
                ctx_options = {
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "viewport": {"width": 1920, "height": 1080},
                }

            # Device emulation: when a device name is given, Playwright's device
            # registry supplies the exact viewport, device_scale_factor, mobile
            # user_agent, is_mobile and has_touch. These OVERRIDE the desktop
            # defaults / stealth UA above so mobile/tablet visual review is
            # pixel-accurate (e.g. a Pixel 7 renders at 412x915 @ DPR 2.625).
            if device:
                device_profile = p.devices.get(device)
                if device_profile is None:
                    available = ", ".join(sorted(p.devices.keys()))
                    return RenderReport(
                        url=url,
                        error=(
                            f"Unknown device '{device}'. Available devices: {available}"
                        ),
                    )
                # Drop any desktop 'screen' from stealth/defaults — it would
                # contradict the device's mobile viewport. Device profile wins
                # on every overlapping key (UA, viewport, is_mobile, has_touch).
                ctx_options.pop("screen", None)
                ctx_options = {**ctx_options, **device_profile}
                report.device_info = {
                    "device": device,
                    "viewport": device_profile.get("viewport"),
                    "device_scale_factor": device_profile.get("device_scale_factor"),
                    "is_mobile": device_profile.get("is_mobile"),
                    "has_touch": device_profile.get("has_touch"),
                    "user_agent": device_profile.get("user_agent"),
                }

            # Accept self-signed / expired / name-mismatch certs when asked. This
            # is a security tool — rendering internal apps behind bad certs is a
            # legitimate need; validation shouldn't block DOM inspection.
            if ignore_https_errors:
                ctx_options["ignore_https_errors"] = True

            context = await browser.new_context(**ctx_options)
            page = await context.new_page()

            # Apply stealth patches before navigation
            if _has_stealth:
                await apply_stealth(page)

            # Capture console messages
            page.on("console", lambda msg: (
                report.console_errors.append(f"[{msg.type}] {msg.text}")
                if msg.type in ("error", "warning")
                else report.console_log.append(f"[{msg.type}] {msg.text}")
            ))

            # Capture JS errors (uncaught exceptions)
            page.on("pageerror", lambda err: report.js_errors.append(str(err)))

            # Install request router (e.g. proxy same-origin requests through a
            # connectivity bridge) so a real navigation works for isolated SPAs.
            if route_handler is not None:
                await page.route("**/*", route_handler)

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
