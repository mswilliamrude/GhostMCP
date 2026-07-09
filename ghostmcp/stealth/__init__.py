"""Stealth browser patches and behavioral simulation for CAPTCHA avoidance."""

from .browser_stealth import apply_stealth, get_stealth_context_options, STEALTH_SCRIPTS
from .behavioral import human_move_to, human_click, human_type, human_scroll, random_delay
