"""CAPTCHA encounter learning loop.

Logs every CAPTCHA encounter (type, outcome, timing) for adaptive improvement.
Uses Unimind knowledge storage when available, falls back to local log.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class CaptchaEvent:
    """A single CAPTCHA encounter for learning."""
    timestamp: float
    url: str
    captcha_type: str         # "recaptcha_v2", "hcaptcha", "cloudflare", etc.
    challenge_type: str       # "image_grid", "slider", "behavioral", etc.
    challenge_category: str   # "traffic_lights", "bicycles", etc. (for grid)
    layer_used: int           # 1=avoided, 2=self-solved, 3=API
    attempts: int
    success: bool
    solve_time_ms: int
    model_used: str           # "clip", "qwen-vl", "api:capsolver", "stealth_bypass"
    confidence_mean: float    # Average tile confidence (for grid)
    engine_triggered: str     # Which search engine triggered this CAPTCHA


# In-memory event log (persists for session duration)
_event_log: list[CaptchaEvent] = []


def log_captcha_event(
    url: str,
    captcha_type: str,
    challenge_type: str = "",
    challenge_category: str = "",
    layer_used: int = 1,
    attempts: int = 1,
    success: bool = True,
    solve_time_ms: int = 0,
    model_used: str = "",
    confidence_mean: float = 0.0,
    engine_triggered: str = "",
) -> CaptchaEvent:
    """Log a CAPTCHA encounter. Stored in memory + optionally to Unimind.

    Args:
        All fields of CaptchaEvent

    Returns:
        The logged event
    """
    event = CaptchaEvent(
        timestamp=time.time(),
        url=url,
        captcha_type=captcha_type,
        challenge_type=challenge_type,
        challenge_category=challenge_category,
        layer_used=layer_used,
        attempts=attempts,
        success=success,
        solve_time_ms=solve_time_ms,
        model_used=model_used,
        confidence_mean=confidence_mean,
        engine_triggered=engine_triggered,
    )
    _event_log.append(event)
    return event


def get_event_log() -> list[CaptchaEvent]:
    """Get all logged events for this session."""
    return list(_event_log)


def get_stats() -> dict:
    """Get aggregate statistics from the event log."""
    if not _event_log:
        return {"total": 0}

    total = len(_event_log)
    by_type = {}
    by_layer = {1: 0, 2: 0, 3: 0}
    successes = sum(1 for e in _event_log if e.success)
    total_solve_time = sum(e.solve_time_ms for e in _event_log)

    for event in _event_log:
        by_type[event.captcha_type] = by_type.get(event.captcha_type, 0) + 1
        by_layer[event.layer_used] = by_layer.get(event.layer_used, 0) + 1

    return {
        "total": total,
        "success_rate": successes / total if total > 0 else 0,
        "by_type": by_type,
        "by_layer": by_layer,
        "avg_solve_time_ms": total_solve_time // total if total > 0 else 0,
        "layer1_avoided": by_layer.get(1, 0),
        "layer2_self_solved": by_layer.get(2, 0),
        "layer3_api": by_layer.get(3, 0),
    }


def clear_log() -> int:
    """Clear the event log. Returns number of events cleared."""
    global _event_log
    count = len(_event_log)
    _event_log = []
    return count
