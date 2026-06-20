"""Slider CAPTCHA solver — finds gap position and simulates human drag.

For GeeTest-style slider CAPTCHAs:
1. Screenshot the puzzle image
2. Find the gap position via edge detection or template matching
3. Calculate drag distance
4. Simulate human-like drag with Bézier acceleration curve
"""

from __future__ import annotations

import asyncio
import base64
import math
import random
from dataclasses import dataclass


@dataclass
class SliderSolveResult:
    """Result of attempting to solve a slider CAPTCHA."""
    success: bool = False
    gap_position_x: int = 0    # Detected gap X coordinate
    drag_distance: int = 0     # Pixels to drag
    solve_time_ms: int = 0
    error: str = ""


async def find_gap_position(puzzle_screenshot_b64: str) -> int:
    """Find the gap position in a slider puzzle image using edge detection.

    Uses PIL + simple edge detection to find the puzzle piece gap.
    Falls back to a heuristic if PIL/OpenCV not available.

    Args:
        puzzle_screenshot_b64: Base64-encoded PNG of the puzzle area

    Returns:
        X pixel position of the gap (0 if detection fails)
    """
    try:
        from PIL import Image, ImageFilter
        import io

        # Decode image
        img_bytes = base64.b64decode(puzzle_screenshot_b64)
        img = Image.open(io.BytesIO(img_bytes)).convert('L')  # Grayscale

        # Apply edge detection
        edges = img.filter(ImageFilter.FIND_EDGES)

        # Find the column with the highest edge density (gap boundary)
        width, height = edges.size
        col_scores = []

        # Scan from left 20% to right 80% (gap won't be at the very edges)
        start_col = int(width * 0.2)
        end_col = int(width * 0.8)

        for col in range(start_col, end_col):
            score = 0
            for row in range(int(height * 0.2), int(height * 0.8)):
                pixel = edges.getpixel((col, row))
                if pixel > 50:  # Edge threshold
                    score += 1
            col_scores.append((col, score))

        if not col_scores:
            return 0

        # Find the column with peak edge density
        # The gap creates a vertical edge that should have high score
        col_scores.sort(key=lambda x: x[1], reverse=True)

        # Take the highest-scoring column that's not too close to existing high scores
        # (avoid detecting the puzzle piece edges vs the gap edges)
        gap_x = col_scores[0][0]

        return gap_x

    except ImportError:
        # No PIL available — return 0 (will trigger fallback)
        return 0
    except Exception:
        return 0


async def simulate_slider_drag(page, slider_selector: str, distance: int) -> bool:
    """Simulate a human-like slider drag.

    Uses acceleration + deceleration curve with jitter to mimic
    real human drag behavior (fast in middle, slow at start/end).

    Args:
        page: Playwright page
        slider_selector: CSS selector for the draggable element
        distance: Pixels to drag horizontally

    Returns:
        True if drag completed successfully
    """
    try:
        slider = await page.query_selector(slider_selector)
        if not slider:
            return False

        box = await slider.bounding_box()
        if not box:
            return False

        # Start position (center of slider handle)
        start_x = box["x"] + box["width"] / 2
        start_y = box["y"] + box["height"] / 2

        # Generate human-like movement path
        # Acceleration curve: slow start, fast middle, slow end with slight overshoot
        steps = random.randint(25, 40)

        await page.mouse.move(start_x, start_y)
        await asyncio.sleep(random.uniform(0.1, 0.3))
        await page.mouse.down()
        await asyncio.sleep(random.uniform(0.05, 0.15))

        # Move along path with acceleration/deceleration
        for i in range(steps):
            t = i / steps

            # Ease-in-out cubic curve
            if t < 0.5:
                progress = 4 * t * t * t
            else:
                progress = 1 - pow(-2 * t + 2, 3) / 2

            # Add slight overshoot near the end
            if t > 0.85:
                overshoot = random.uniform(-3, 5)
            else:
                overshoot = 0

            current_x = start_x + distance * progress + overshoot
            # Slight Y jitter (humans don't drag perfectly horizontal)
            current_y = start_y + random.gauss(0, 1.5)

            await page.mouse.move(current_x, current_y)

            # Variable delay (faster in middle)
            speed = 1.0 - 0.6 * math.sin(math.pi * t)
            delay = random.uniform(0.01, 0.03) * speed
            await asyncio.sleep(delay)

        # Final position
        await page.mouse.move(start_x + distance, start_y)
        await asyncio.sleep(random.uniform(0.05, 0.2))
        await page.mouse.up()

        return True

    except Exception:
        return False


async def solve_slider_captcha(
    page,
    puzzle_selector: str = "div.geetest_canvas_img, div[class*='slider-puzzle'], canvas.captcha-canvas",
    slider_selector: str = "div.geetest_slider_button, div[class*='slider-handle'], .slider-btn",
) -> SliderSolveResult:
    """Solve a slider CAPTCHA end-to-end.

    1. Screenshots the puzzle area
    2. Detects gap position via edge detection
    3. Simulates human-like drag to the gap

    Args:
        page: Playwright page with slider CAPTCHA visible
        puzzle_selector: CSS selector for the puzzle image area
        slider_selector: CSS selector for the draggable slider handle

    Returns:
        SliderSolveResult with details
    """
    import time
    start = time.monotonic()
    result = SliderSolveResult()

    try:
        # Find puzzle element
        puzzle_el = await page.query_selector(puzzle_selector)
        if not puzzle_el:
            result.error = f"Puzzle element not found: {puzzle_selector}"
            return result

        # Screenshot puzzle
        screenshot_bytes = await puzzle_el.screenshot()
        screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')

        # Detect gap position
        gap_x = await find_gap_position(screenshot_b64)
        if gap_x == 0:
            result.error = "Could not detect gap position"
            return result

        result.gap_position_x = gap_x

        # Calculate drag distance
        # Gap position is absolute in the image; slider starts at left edge
        # Subtract slider starting position (usually ~40-60px from left)
        puzzle_box = await puzzle_el.bounding_box()
        slider_el = await page.query_selector(slider_selector)

        if not slider_el:
            result.error = f"Slider handle not found: {slider_selector}"
            return result

        slider_box = await slider_el.bounding_box()

        # Drag distance = gap position - slider current position (relative to puzzle)
        slider_offset = slider_box["x"] - puzzle_box["x"]
        drag_distance = gap_x - int(slider_offset) - int(slider_box["width"] / 2)

        result.drag_distance = max(0, drag_distance)

        # Simulate drag
        success = await simulate_slider_drag(page, slider_selector, result.drag_distance)
        result.success = success

    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"

    result.solve_time_ms = int((time.monotonic() - start) * 1000)
    return result
