"""GhostMCP dorking module — Google dork query builder and templates."""

from .builder import build_dork, from_template
from .templates import TEMPLATES

__all__ = ["build_dork", "from_template", "TEMPLATES"]
