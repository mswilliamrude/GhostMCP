"""GhostMCP CLI — lightweight OSINT search from the terminal."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import timezone

from .engines.duckduckgo import DuckDuckGoEngine
from .proxy.manager import ProxyManager
from .proxy.fingerprint import get_headers
from .utils.config import Config, ParanoiaLevel


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for GhostMCP CLI."""
    parser = argparse.ArgumentParser(
        prog="ghost",
        description="GhostMCP — anonymous OSINT search tool",
    )
    subparsers = parser.add_subparsers(dest="command")

    # search command
    search_parser = subparsers.add_parser("search", help="Search the web anonymously")
    search_parser.add_argument("query", help="Search query string")
    search_parser.add_argument(
        "--paranoia", "-p",
        choices=["casual", "cautious", "ghost", "midnight"],
        default=None,
        help="Paranoia level (default: from config/env)",
    )
    search_parser.add_argument(
        "--num", "-n",
        type=int,
        default=None,
        help="Number of results (default: 10)",
    )
    search_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )

    # status command
    subparsers.add_parser("status", help="Check proxy/Tor connectivity")

    return parser


async def cmd_search(args: argparse.Namespace, config: Config) -> int:
    """Execute search command."""
    paranoia = ParanoiaLevel(args.paranoia) if args.paranoia else config.paranoia_level
    num_results = args.num or config.max_results

    # Set up proxy
    proxy_mgr = ProxyManager()
    proxy = proxy_mgr.get_proxy(paranoia)

    # Get stealth headers
    headers = get_headers(paranoia)

    # Create engine
    engine = DuckDuckGoEngine(proxy=proxy)

    if not args.json_output:
        level_str = paranoia.value.upper()
        print(f"\n  [{level_str}] Searching: {args.query}\n")

    try:
        results = await engine.search(args.query, num_results=num_results)
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)
        return 1

    if not results:
        print("  No results found.")
        return 0

    if args.json_output:
        output = [
            {
                "title": r.title,
                "url": r.url,
                "snippet": r.snippet,
                "engine": r.source_engine,
                "timestamp": r.timestamp.isoformat(),
            }
            for r in results
        ]
        print(json.dumps(output, indent=2))
    else:
        for i, r in enumerate(results, 1):
            print(f"  {i}. {r.title}")
            print(f"     {r.url}")
            if r.snippet:
                # Wrap snippet at ~70 chars
                snippet = r.snippet[:140] + "..." if len(r.snippet) > 140 else r.snippet
                print(f"     {snippet}")
            print()

    return 0


async def cmd_status(config: Config) -> int:
    """Check proxy connectivity status."""
    proxy_mgr = ProxyManager()

    print("\n  GhostMCP Status")
    print(f"  {'─' * 40}")
    print(f"  Paranoia level: {config.paranoia_level.value}")
    print(f"  Tor proxy:      {config.tor_proxy}")

    print("\n  Checking Tor connectivity...", end=" ", flush=True)
    tor_ok = await proxy_mgr.check_tor_health()
    print("OK" if tor_ok else "UNAVAILABLE")

    if not tor_ok and config.paranoia_level in (ParanoiaLevel.GHOST, ParanoiaLevel.MIDNIGHT):
        print("\n  WARNING: Tor is required for ghost/midnight mode but unavailable.")
        print("  Install Tor: sudo apt install tor && sudo systemctl start tor")
        return 1

    print()
    return 0


def main() -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    config = Config.from_env()

    if args.command == "search":
        rc = asyncio.run(cmd_search(args, config))
    elif args.command == "status":
        rc = asyncio.run(cmd_status(config))
    else:
        parser.print_help()
        rc = 0

    sys.exit(rc)


if __name__ == "__main__":
    main()
