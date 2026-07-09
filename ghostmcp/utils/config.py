"""Configuration and paranoia level definitions."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ParanoiaLevel(Enum):
    """Operational security levels for GhostMCP.

    casual   — Direct connection. Fast. No anonymity.
    cautious — Rotating headers, delays between requests.
    ghost    — All traffic through Tor. Slower but anonymous.
    midnight — Tor + identity rotation + max delays. Paranoid mode.
    """

    CASUAL = "casual"
    CAUTIOUS = "cautious"
    GHOST = "ghost"
    MIDNIGHT = "midnight"


@dataclass
class Config:
    """GhostMCP runtime configuration.

    Loads from environment variables with sensible defaults.
    Env vars are prefixed with GHOST_.
    """

    paranoia_level: ParanoiaLevel = ParanoiaLevel.CASUAL
    max_results: int = 10
    request_timeout: float = 30.0
    tor_proxy: str = "socks5://127.0.0.1:9050"
    tor_control_port: int = 9051
    min_delay: float = 2.0  # seconds between requests
    output_format: str = "text"  # text, json
    engines: list[str] = field(default_factory=lambda: ["duckduckgo"])

    @classmethod
    def from_env(cls) -> Config:
        """Load configuration from environment variables.

        Supported env vars:
            GHOST_PARANOIA   — casual, cautious, ghost, midnight
            GHOST_MAX_RESULTS — integer
            GHOST_TIMEOUT    — float seconds
            GHOST_TOR_PROXY  — socks5 URL
            GHOST_MIN_DELAY  — float seconds
            GHOST_OUTPUT     — text, json
            GHOST_ENGINES    — comma-separated engine names
        """
        paranoia_str = os.environ.get("GHOST_PARANOIA", "casual").lower()
        try:
            paranoia = ParanoiaLevel(paranoia_str)
        except ValueError:
            paranoia = ParanoiaLevel.CASUAL

        engines_str = os.environ.get("GHOST_ENGINES", "duckduckgo")
        engines = [e.strip() for e in engines_str.split(",") if e.strip()]

        return cls(
            paranoia_level=paranoia,
            max_results=int(os.environ.get("GHOST_MAX_RESULTS", "10")),
            request_timeout=float(os.environ.get("GHOST_TIMEOUT", "30.0")),
            tor_proxy=os.environ.get("GHOST_TOR_PROXY", "socks5://127.0.0.1:9050"),
            tor_control_port=int(os.environ.get("GHOST_TOR_CONTROL", "9051")),
            min_delay=float(os.environ.get("GHOST_MIN_DELAY", "2.0")),
            output_format=os.environ.get("GHOST_OUTPUT", "text"),
            engines=engines,
        )

    @classmethod
    def load(cls, yaml_path: Optional[str] = None) -> Config:
        """Load config from YAML file, falling back to env vars.

        Args:
            yaml_path: Path to YAML config file. If None or file missing,
                      falls back to environment variable configuration.
        """
        if yaml_path and os.path.exists(yaml_path):
            try:
                import yaml  # Optional dependency

                with open(yaml_path) as f:
                    data = yaml.safe_load(f) or {}

                paranoia_str = data.get("paranoia_level", "casual")
                try:
                    paranoia = ParanoiaLevel(paranoia_str)
                except ValueError:
                    paranoia = ParanoiaLevel.CASUAL

                return cls(
                    paranoia_level=paranoia,
                    max_results=data.get("max_results", 10),
                    request_timeout=data.get("timeout", 30.0),
                    tor_proxy=data.get("tor_proxy", "socks5://127.0.0.1:9050"),
                    tor_control_port=data.get("tor_control_port", 9051),
                    min_delay=data.get("min_delay", 2.0),
                    output_format=data.get("output", "text"),
                    engines=data.get("engines", ["duckduckgo"]),
                )
            except ImportError:
                pass  # No PyYAML installed, fall through to env vars

        return cls.from_env()
