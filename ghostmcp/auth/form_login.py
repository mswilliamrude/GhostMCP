"""Form-based authentication via Playwright headless browser.

Fills login forms, submits, captures resulting cookies/tokens.
Used for web applications with standard username/password forms.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FormLoginResult:
    """Result of a form-based login attempt."""
    success: bool = False
    cookies: dict = field(default_factory=dict)
    error: str = ""
    final_url: str = ""        # URL after login (redirect target)
    session_storage: dict = field(default_factory=dict)


async def form_login(
    url: str,
    username: str,
    password: str,
    username_selector: str = "input[name='username'], input[name='email'], input[type='email'], #username, #email",
    password_selector: str = "input[name='password'], input[type='password'], #password",
    submit_selector: str = "button[type='submit'], input[type='submit'], button:has-text('Log in'), button:has-text('Sign in')",
    wait_after_ms: int = 3000,
    success_indicator: str = "",   # CSS selector that appears on successful login
    failure_indicator: str = "",   # CSS selector that appears on failed login
) -> FormLoginResult:
    """Log into a web application via form submission.

    Uses Playwright with stealth patches to fill and submit a login form,
    then captures the resulting cookies and session tokens.

    Args:
        url: Login page URL
        username: Username/email to enter
        password: Password to enter
        username_selector: CSS selector for username field (tries multiple)
        password_selector: CSS selector for password field
        submit_selector: CSS selector for submit button
        wait_after_ms: Time to wait after submission for redirect/JS
        success_indicator: CSS selector proving login succeeded
        failure_indicator: CSS selector proving login failed

    Returns:
        FormLoginResult with captured cookies on success
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return FormLoginResult(error="Playwright not installed. Install with: pip install playwright && playwright install chromium")

    try:
        from ..stealth import apply_stealth, get_stealth_context_options
        has_stealth = True
    except ImportError:
        has_stealth = False

    result = FormLoginResult()

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox"]
            )

            if has_stealth:
                ctx_options = get_stealth_context_options()
            else:
                ctx_options = {
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "viewport": {"width": 1920, "height": 1080},
                }
            context = await browser.new_context(**ctx_options)
            page = await context.new_page()

            if has_stealth:
                await apply_stealth(page)

            # Navigate to login page
            await page.goto(url, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(1000)

            # Find and fill username field
            username_el = None
            for selector in username_selector.split(", "):
                try:
                    username_el = await page.query_selector(selector.strip())
                    if username_el:
                        break
                except Exception:
                    continue

            if not username_el:
                result.error = f"Username field not found with selectors: {username_selector}"
                await browser.close()
                return result

            # Find and fill password field
            password_el = None
            for selector in password_selector.split(", "):
                try:
                    password_el = await page.query_selector(selector.strip())
                    if password_el:
                        break
                except Exception:
                    continue

            if not password_el:
                result.error = f"Password field not found with selectors: {password_selector}"
                await browser.close()
                return result

            # Type credentials (with human-like timing)
            await username_el.click()
            await page.wait_for_timeout(200)
            await username_el.fill(username)
            await page.wait_for_timeout(300)

            await password_el.click()
            await page.wait_for_timeout(200)
            await password_el.fill(password)
            await page.wait_for_timeout(500)

            # Submit
            submit_el = None
            for selector in submit_selector.split(", "):
                try:
                    submit_el = await page.query_selector(selector.strip())
                    if submit_el:
                        break
                except Exception:
                    continue

            if submit_el:
                await submit_el.click()
            else:
                # Try pressing Enter on password field
                await password_el.press("Enter")

            # Wait for navigation/response
            await page.wait_for_timeout(wait_after_ms)

            result.final_url = page.url

            # Check success/failure indicators
            if failure_indicator:
                fail_el = await page.query_selector(failure_indicator)
                if fail_el:
                    result.error = "Login failed (failure indicator found)"
                    await browser.close()
                    return result

            if success_indicator:
                success_el = await page.query_selector(success_indicator)
                if not success_el:
                    result.error = "Login may have failed (success indicator not found)"
                    await browser.close()
                    return result

            # Capture cookies
            cookies_list = await context.cookies()
            result.cookies = {c["name"]: c["value"] for c in cookies_list}

            # Capture localStorage/sessionStorage tokens
            try:
                storage = await page.evaluate("""() => {
                    const data = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        if (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth') || key.toLowerCase().includes('session')) {
                            data[key] = localStorage.getItem(key);
                        }
                    }
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        if (key.toLowerCase().includes('token') || key.toLowerCase().includes('auth') || key.toLowerCase().includes('session')) {
                            data['session:' + key] = sessionStorage.getItem(key);
                        }
                    }
                    return data;
                }""")
                result.session_storage = storage
            except Exception:
                result.session_storage = {}

            result.success = bool(result.cookies)
            await browser.close()

    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"

    return result
