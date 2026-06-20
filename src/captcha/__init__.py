"""CAPTCHA Layer 2 — self-solve framework.

Detection, tile extraction, solver interface, and learning loop.
VLM inference backends are pluggable via TileClassifier protocol.
"""

from .detector import detect_captcha, CaptchaDetection, CAPTCHA_INDICATORS
from .grid_solver import (
    solve_grid_captcha,
    extract_grid_tiles,
    GridSolveResult,
    TileClassification,
    TileClassifier,
    DummyClassifier,
)
from .slider_solver import (
    solve_slider_captcha,
    find_gap_position,
    simulate_slider_drag,
    SliderSolveResult,
)
from .learning import (
    log_captcha_event,
    get_event_log,
    get_stats,
    clear_log,
    CaptchaEvent,
)
from .solver_chain import solve_captcha, SolveAttempt
from .clip_classifier import CLIPClassifier, is_loaded as clip_is_loaded, get_model_info as clip_model_info

__all__ = [
    "detect_captcha",
    "CaptchaDetection",
    "CAPTCHA_INDICATORS",
    "solve_grid_captcha",
    "extract_grid_tiles",
    "GridSolveResult",
    "TileClassification",
    "TileClassifier",
    "DummyClassifier",
    "CLIPClassifier",
    "clip_is_loaded",
    "clip_model_info",
    "solve_slider_captcha",
    "find_gap_position",
    "simulate_slider_drag",
    "SliderSolveResult",
    "solve_captcha",
    "SolveAttempt",
    "log_captcha_event",
    "get_event_log",
    "get_stats",
    "clear_log",
    "CaptchaEvent",
]
