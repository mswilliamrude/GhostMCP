"""Grid CAPTCHA solver — extracts tiles and classifies via pluggable VLM backend.

Pipeline:
1. Screenshot the CAPTCHA grid
2. Crop into individual tiles
3. Classify each tile via VLM (CLIP fast path or Qwen-VL for ambiguous)
4. Map selections back to click coordinates
5. Click and submit
"""

from __future__ import annotations

import asyncio
import base64
import math
from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable


@dataclass
class TileClassification:
    """Result of classifying a single grid tile."""
    tile_index: int      # 0-indexed position in grid (row-major)
    row: int
    col: int
    matches: bool        # Does this tile match the target?
    confidence: float    # 0-1
    label: str = ""      # What the model thinks this is


@dataclass
class GridSolveResult:
    """Result of attempting to solve a grid CAPTCHA."""
    success: bool = False
    tiles_total: int = 0
    tiles_selected: int = 0
    tiles_classified: list[TileClassification] = field(default_factory=list)
    target_label: str = ""      # What we're looking for ("traffic lights")
    confidence_mean: float = 0.0
    solve_time_ms: int = 0
    error: str = ""


@runtime_checkable
class TileClassifier(Protocol):
    """Interface for tile classification backends (CLIP, Qwen-VL, API, etc.)."""

    async def classify_tile(self, image_base64: str, target_label: str) -> tuple[bool, float]:
        """Classify whether a tile image matches the target label.

        Args:
            image_base64: Base64-encoded PNG of the tile
            target_label: What to look for ("traffic light", "bicycle", etc.)

        Returns:
            Tuple of (matches: bool, confidence: float 0-1)
        """
        ...


class DummyClassifier:
    """Placeholder classifier that always returns uncertain.

    Used when no VLM backend is configured. Returns confidence 0.5
    for all tiles, which will trigger Layer 3 API fallback.
    """

    async def classify_tile(self, image_base64: str, target_label: str) -> tuple[bool, float]:
        return (False, 0.5)


async def extract_grid_tiles(page, captcha_selector: str, grid_size: tuple[int, int] = (3, 3)) -> list[str]:
    """Screenshot the CAPTCHA grid and crop into individual tiles.

    Args:
        page: Playwright page with CAPTCHA visible
        captcha_selector: CSS selector for the grid element
        grid_size: (rows, cols) of the grid

    Returns:
        List of base64-encoded PNG images, one per tile (row-major order)
    """
    tiles = []

    try:
        # Find the grid element
        grid_element = await page.query_selector(captcha_selector)
        if not grid_element:
            # Try within iframe
            frames = page.frames
            for frame in frames:
                grid_element = await frame.query_selector(captcha_selector)
                if grid_element:
                    break

        if not grid_element:
            return tiles

        # Screenshot the grid
        screenshot_bytes = await grid_element.screenshot()

        # Use PIL to crop into tiles if available
        try:
            from PIL import Image
            import io

            img = Image.open(io.BytesIO(screenshot_bytes))
            width, height = img.size
            rows, cols = grid_size

            tile_w = width // cols
            tile_h = height // rows

            for row in range(rows):
                for col in range(cols):
                    left = col * tile_w
                    top = row * tile_h
                    right = left + tile_w
                    bottom = top + tile_h

                    tile = img.crop((left, top, right, bottom))

                    # Convert to base64 PNG
                    buf = io.BytesIO()
                    tile.save(buf, format='PNG')
                    tile_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
                    tiles.append(tile_b64)

        except ImportError:
            # No PIL — return the full grid as a single "tile"
            tile_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            tiles.append(tile_b64)

    except Exception:
        pass

    return tiles


async def solve_grid_captcha(
    page,
    captcha_selector: str,
    target_label: str,
    grid_size: tuple[int, int] = (3, 3),
    classifier: Optional[TileClassifier] = None,
    confidence_threshold: float = 0.7,
) -> GridSolveResult:
    """Solve a grid CAPTCHA by classifying tiles and clicking matches.

    Args:
        page: Playwright page with CAPTCHA visible
        captcha_selector: CSS selector for the grid container
        target_label: What to select ("traffic lights", "bicycles", etc.)
        grid_size: Grid dimensions (rows, cols)
        classifier: TileClassifier backend (CLIP, Qwen-VL, etc.)
        confidence_threshold: Minimum confidence to select a tile

    Returns:
        GridSolveResult with classification details
    """
    import time
    start = time.monotonic()

    if classifier is None:
        classifier = DummyClassifier()

    result = GridSolveResult(target_label=target_label)

    # Extract tiles
    tiles = await extract_grid_tiles(page, captcha_selector, grid_size)
    result.tiles_total = len(tiles)

    if not tiles:
        result.error = "Failed to extract tiles from grid"
        return result

    # Classify each tile
    rows, cols = grid_size
    classifications = []

    for idx, tile_b64 in enumerate(tiles):
        row = idx // cols
        col = idx % cols

        matches, confidence = await classifier.classify_tile(tile_b64, target_label)

        classification = TileClassification(
            tile_index=idx,
            row=row,
            col=col,
            matches=matches and confidence >= confidence_threshold,
            confidence=confidence,
        )
        classifications.append(classification)

    result.tiles_classified = classifications

    # Select tiles above threshold
    selected = [c for c in classifications if c.matches]
    result.tiles_selected = len(selected)

    if classifications:
        result.confidence_mean = sum(c.confidence for c in classifications) / len(classifications)

    # Click selected tiles (implementation depends on grid element structure)
    # This is the part that interacts with the actual page
    try:
        grid_element = await page.query_selector(captcha_selector)
        if grid_element:
            box = await grid_element.bounding_box()
            if box and selected:
                tile_w = box["width"] / cols
                tile_h = box["height"] / rows

                for tile in selected:
                    # Click center of the tile
                    click_x = box["x"] + (tile.col + 0.5) * tile_w
                    click_y = box["y"] + (tile.row + 0.5) * tile_h
                    await page.mouse.click(click_x, click_y)
                    await asyncio.sleep(0.3)  # Brief pause between clicks

                result.success = True
    except Exception as e:
        result.error = f"Click failed: {e}"

    result.solve_time_ms = int((time.monotonic() - start) * 1000)
    return result
