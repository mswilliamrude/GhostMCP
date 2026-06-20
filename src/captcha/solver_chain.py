"""Three-layer CAPTCHA solver chain.

Layer 1: Avoidance (handled by engine rotator + stealth, before this code runs)
Layer 2: Self-solve (this code) — CLIP/Qwen-VL for grids, edge detection for sliders
Layer 3: API fallback (external service, last resort)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

from .detector import detect_captcha, CaptchaDetection
from .grid_solver import solve_grid_captcha, GridSolveResult, TileClassifier, DummyClassifier
from .slider_solver import solve_slider_captcha, SliderSolveResult
from .learning import log_captcha_event


@dataclass
class SolveAttempt:
    """Result of the full solver chain."""
    detected: bool = False
    captcha_type: str = ""
    solved: bool = False
    layer_used: int = 0      # 0=not attempted, 1=avoided, 2=self-solved, 3=API
    attempts: int = 0
    error: str = ""
    solve_time_ms: int = 0


async def solve_captcha(
    page,
    classifier: Optional[TileClassifier] = None,
    max_attempts: int = 3,
    use_api_fallback: bool = False,
    api_solver=None,
) -> SolveAttempt:
    """Attempt to solve any detected CAPTCHA on the current page.

    Orchestrates the full solving pipeline:
    1. Detect CAPTCHA type
    2. Route to appropriate solver (grid, slider, etc.)
    3. Retry on failure
    4. Fall back to API if configured
    5. Log the encounter for learning

    Args:
        page: Playwright page with potential CAPTCHA
        classifier: TileClassifier for grid CAPTCHAs (None = dummy)
        max_attempts: Maximum solve attempts before giving up
        use_api_fallback: Whether to try Layer 3 API if self-solve fails
        api_solver: API solver instance (for Layer 3)

    Returns:
        SolveAttempt with results
    """
    import time
    start = time.monotonic()

    result = SolveAttempt()

    # Step 1: Detect
    detection = await detect_captcha(page)
    result.detected = detection.detected
    result.captcha_type = detection.captcha_type

    if not detection.detected:
        return result

    # Step 2: Route to solver based on challenge type
    for attempt in range(max_attempts):
        result.attempts = attempt + 1

        if detection.challenge_type == "image_grid":
            # Use dedicated grid container selectors — iframe_selector points at the
            # CAPTCHA wrapper, not the image grid itself
            grid_selector = "div.rc-imageselect-challenge, div.challenge-container, div.task-image-container"
            grid_result = await solve_grid_captcha(
                page,
                captcha_selector=grid_selector,
                target_label=detection.instruction_text or "the target",
                grid_size=detection.grid_dimensions if detection.grid_dimensions != (0, 0) else (3, 3),
                classifier=classifier,
            )
            if grid_result.success:
                result.solved = True
                result.layer_used = 2
                break

        elif detection.challenge_type == "slider":
            slider_result = await solve_slider_captcha(page)
            if slider_result.success:
                result.solved = True
                result.layer_used = 2
                break

        elif detection.challenge_type == "behavioral":
            # Behavioral CAPTCHAs (Cloudflare Turnstile, reCAPTCHA v3)
            # Can't be "solved" — they pass/fail based on browser fingerprint
            # Our stealth patches are the solution (Layer 1)
            result.error = "Behavioral CAPTCHA — relies on stealth patches (Layer 1)"
            result.layer_used = 1
            break

        else:
            result.error = f"Unknown challenge type: {detection.challenge_type}"
            break

        # Brief wait between attempts
        if attempt < max_attempts - 1:
            await asyncio.sleep(1.0)

    # Step 3: API fallback if self-solve failed
    if not result.solved and use_api_fallback and api_solver:
        # TODO: implement API solver integration
        result.layer_used = 3
        result.error = "API fallback not yet implemented"

    result.solve_time_ms = int((time.monotonic() - start) * 1000)

    # Step 4: Log for learning
    log_captcha_event(
        url=page.url if hasattr(page, 'url') else "",
        captcha_type=detection.captcha_type,
        challenge_type=detection.challenge_type,
        challenge_category=detection.instruction_text,
        layer_used=result.layer_used,
        attempts=result.attempts,
        success=result.solved,
        solve_time_ms=result.solve_time_ms,
        model_used="dummy" if isinstance(classifier, (DummyClassifier, type(None))) else "vlm",
    )

    return result
