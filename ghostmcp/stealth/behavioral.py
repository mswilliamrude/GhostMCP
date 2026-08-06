"""Behavioral simulation for human-like browser interaction.

Provides helpers for realistic mouse movement, typing, scrolling,
and timing that defeat behavioral analysis in anti-bot systems.

Used by ghost_render and ghost_auth_session for authenticated interactions.
"""

from __future__ import annotations

import asyncio
import math
import random


async def human_move_to(page, x: float, y: float, steps: int = 0) -> None:
    """Move mouse to (x, y) following a Bezier curve with micro-jitter.

    Instead of instant teleportation or straight lines (bot-like),
    generates a natural curved path with slight randomness.
    """
    if steps == 0:
        # Calculate steps based on distance
        current = await page.evaluate(
            "() => ({x: window._mouseX || 0, y: window._mouseY || 0})"
        )
        cx, cy = current.get("x", 0), current.get("y", 0)
        distance = math.sqrt((x - cx) ** 2 + (y - cy) ** 2)
        steps = max(10, min(50, int(distance / 15)))

    # Get current position
    current = await page.evaluate(
        "() => ({x: window._mouseX || 0, y: window._mouseY || 0})"
    )
    cx, cy = current.get("x", 0), current.get("y", 0)

    # Control points offset perpendicular to the path for natural curve
    mid_x = (cx + x) / 2 + random.uniform(-50, 50)
    mid_y = (cy + y) / 2 + random.uniform(-30, 30)

    for i in range(steps):
        t = i / steps
        # Quadratic Bezier: B(t) = (1-t)^2*P0 + 2(1-t)t*P1 + t^2*P2
        bx = (1 - t) ** 2 * cx + 2 * (1 - t) * t * mid_x + t ** 2 * x
        by = (1 - t) ** 2 * cy + 2 * (1 - t) * t * mid_y + t ** 2 * y

        # Add micro-jitter (1-3 pixels, human hand tremor)
        jitter_x = random.gauss(0, 1.5)
        jitter_y = random.gauss(0, 1.0)

        await page.mouse.move(bx + jitter_x, by + jitter_y)

        # Variable delay between moves (faster in middle, slower at edges)
        speed_factor = 1.0 - 0.5 * math.sin(math.pi * t)  # Slower at start/end
        delay = random.uniform(0.005, 0.02) * speed_factor
        await asyncio.sleep(delay)

    # Final position (exact, no jitter)
    await page.mouse.move(x, y)
    # Store position for next movement
    await page.evaluate(
        f"() => {{ window._mouseX = {x}; window._mouseY = {y}; }}"
    )


async def human_click(page, selector: str, button: str = "left") -> None:
    """Click an element with human-like mouse movement and timing.

    1. Finds the element's bounding box
    2. Picks a random point within the element (not dead center)
    3. Moves to it via Bezier curve
    4. Brief pause (100-300ms, human reaction time)
    5. Mouse down, short hold (50-150ms), mouse up
    """
    element = await page.query_selector(selector)
    if not element:
        raise ValueError(f"Element not found: {selector}")

    box = await element.bounding_box()
    if not box:
        raise ValueError(f"Element has no bounding box: {selector}")

    # Random point within element (not center -- humans don't click dead center)
    target_x = box["x"] + box["width"] * random.uniform(0.2, 0.8)
    target_y = box["y"] + box["height"] * random.uniform(0.2, 0.8)

    # Move to target with natural curve
    await human_move_to(page, target_x, target_y)

    # Human reaction pause before clicking
    await asyncio.sleep(random.uniform(0.1, 0.3))

    # Click with brief hold (humans don't click instantly)
    await page.mouse.down(button=button)
    await asyncio.sleep(random.uniform(0.05, 0.15))
    await page.mouse.up(button=button)


async def human_type(
    page, selector: str, text: str, clear_first: bool = True
) -> None:
    """Type text into an element with human-like keystroke timing.

    Features:
    - Variable inter-key delay (50-200ms, faster for common patterns)
    - Occasional brief pauses (thinking pauses mid-word)
    - Slight speed-up for common letter combinations
    """
    if clear_first:
        await page.click(selector, click_count=3)  # Select all
        await asyncio.sleep(random.uniform(0.05, 0.1))

    for i, char in enumerate(text):
        # Base delay varies by character
        if char == " ":
            delay = random.uniform(0.08, 0.2)  # Slightly longer for spaces
        elif char in ".,!?":
            delay = random.uniform(0.1, 0.25)  # Longer for punctuation
        elif (
            i > 0
            and text[i - 1 : i + 1].lower()
            in ("th", "he", "in", "er", "an", "on", "en", "at", "es", "or")
        ):
            delay = random.uniform(0.03, 0.08)  # Faster for common bigrams
        else:
            delay = random.uniform(0.05, 0.15)  # Normal character

        # Occasional thinking pause (1 in 20 characters)
        if random.random() < 0.05 and i > 3:
            await asyncio.sleep(random.uniform(0.3, 0.8))

        await page.type(selector, char, delay=0)
        await asyncio.sleep(delay)


async def human_scroll(
    page, direction: str = "down", amount: int = 0, smooth: bool = True
) -> None:
    """Scroll the page with human-like behavior.

    Features:
    - Variable scroll speed (not constant)
    - Momentum effect (fast start, gradual slow)
    - Small random pauses (reading behavior)
    """
    if amount == 0:
        amount = random.randint(300, 800)

    if direction == "up":
        amount = -amount

    if not smooth:
        await page.evaluate(f"window.scrollBy(0, {amount})")
        return

    # Smooth scroll in chunks with variable speed
    total = abs(amount)
    scrolled = 0
    sign = 1 if amount > 0 else -1

    while scrolled < total:
        # Scroll faster at start, slower at end (momentum)
        progress = scrolled / total
        chunk = random.randint(30, 100) * (1.5 - progress)
        chunk = min(chunk, total - scrolled)

        # Round to at least 1px in the scroll direction. int() truncation on a
        # sub-1 final remainder would otherwise emit a useless scrollBy(0, 0).
        step = max(1, int(round(chunk)))
        await page.evaluate(f"window.scrollBy(0, {step * sign})")
        scrolled += step

        # Variable delay (faster during momentum, slower as stopping)
        delay = random.uniform(0.01, 0.04) * (0.5 + progress)
        await asyncio.sleep(delay)

    # Occasional reading pause after scroll
    if random.random() < 0.3:
        await asyncio.sleep(random.uniform(0.5, 1.5))


async def random_delay(min_ms: int = 500, max_ms: int = 2000) -> None:
    """Wait a random duration, simulating human think time.

    Uses a log-normal distribution (most delays are short,
    occasional longer ones -- matches real human behavior).
    """
    # Log-normal gives natural-looking delays
    mean = (min_ms + max_ms) / 2 / 1000
    sigma = 0.3
    delay = random.lognormvariate(math.log(mean), sigma)
    delay = max(min_ms / 1000, min(max_ms / 1000, delay))
    await asyncio.sleep(delay)
