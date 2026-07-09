"""CAPTCHA detection in web pages.

Identifies when a CAPTCHA is present, what type it is, and extracts
the challenge element for solving.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CaptchaDetection:
    """Result of scanning a page for CAPTCHAs."""
    detected: bool = False
    captcha_type: str = ""     # "recaptcha_v2", "hcaptcha", "cloudflare", "geetest", "funcaptcha", "text", "unknown"
    challenge_type: str = ""   # "image_grid", "slider", "text", "behavioral", "unknown"
    instruction_text: str = "" # "Select all images with traffic lights"
    iframe_selector: str = ""  # CSS selector for the CAPTCHA iframe/container
    grid_dimensions: tuple = (0, 0)  # (rows, cols) for grid CAPTCHAs
    confidence: float = 0.0    # 0-1 detection confidence


# Detection patterns for each CAPTCHA type
CAPTCHA_INDICATORS = {
    "recaptcha_v2": {
        "selectors": [
            "iframe[src*='recaptcha']",
            "div.g-recaptcha",
            "#recaptcha",
            "iframe[title*='reCAPTCHA']",
        ],
        "text_patterns": [
            "select all images",
            "click verify once there are none left",
            "verify you are human",
        ],
    },
    "hcaptcha": {
        "selectors": [
            "iframe[src*='hcaptcha']",
            "div.h-captcha",
            "#hcaptcha",
        ],
        "text_patterns": [
            "please click each image containing",
            "select all images matching",
        ],
    },
    "cloudflare": {
        "selectors": [
            "div#challenge-form",
            "div.cf-challenge",
            "iframe[src*='challenges.cloudflare.com']",
            "div#turnstile-wrapper",
        ],
        "text_patterns": [
            "checking your browser",
            "verify you are human",
            "just a moment",
        ],
    },
    "geetest": {
        "selectors": [
            "div.geetest_panel",
            "div.geetest_widget",
            "div[class*='geetest']",
        ],
        "text_patterns": [
            "slide to verify",
            "drag the slider",
        ],
    },
    "funcaptcha": {
        "selectors": [
            "iframe[src*='funcaptcha']",
            "iframe[src*='arkoselabs']",
            "div#FunCaptcha",
        ],
        "text_patterns": [
            "verify you are a human",
        ],
    },
}


async def detect_captcha(page) -> CaptchaDetection:
    """Scan a Playwright page for CAPTCHA presence.

    Checks DOM selectors and page text for known CAPTCHA indicators.
    Does NOT solve — just identifies type and location.

    Args:
        page: Playwright page object (already navigated)

    Returns:
        CaptchaDetection with type, selector, and confidence
    """
    detection = CaptchaDetection()

    # Check each CAPTCHA type's selectors
    for captcha_type, indicators in CAPTCHA_INDICATORS.items():
        for selector in indicators["selectors"]:
            try:
                element = await page.query_selector(selector)
                if element:
                    detection.detected = True
                    detection.captcha_type = captcha_type
                    detection.iframe_selector = selector
                    detection.confidence = 0.9
                    break
            except Exception:
                continue
        if detection.detected:
            break

    # If no selector match, check page text
    if not detection.detected:
        try:
            page_text = (await page.content()).lower()
            for captcha_type, indicators in CAPTCHA_INDICATORS.items():
                for pattern in indicators["text_patterns"]:
                    if pattern in page_text:
                        detection.detected = True
                        detection.captcha_type = captcha_type
                        detection.confidence = 0.6  # Lower confidence for text-only match
                        break
                if detection.detected:
                    break
        except Exception:
            pass

    # Determine challenge type
    if detection.detected:
        if detection.captcha_type in ("recaptcha_v2", "hcaptcha"):
            detection.challenge_type = "image_grid"
            detection.grid_dimensions = (3, 3)  # Default, refined during solving
        elif detection.captcha_type == "geetest":
            detection.challenge_type = "slider"
        elif detection.captcha_type == "cloudflare":
            detection.challenge_type = "behavioral"
        elif detection.captcha_type == "funcaptcha":
            detection.challenge_type = "interactive"

        # Try to extract instruction text
        try:
            instruction_el = await page.query_selector(
                ".rc-imageselect-desc-wrapper, .prompt-text, .challenge-text, "
                "[class*='instruction'], [class*='prompt']"
            )
            if instruction_el:
                detection.instruction_text = (await instruction_el.text_content() or "").strip()
        except Exception:
            pass

    return detection
