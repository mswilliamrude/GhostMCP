"""GhostMCP CLI — lightweight OSINT search from the terminal."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import timezone

from .engines.duckduckgo import DuckDuckGoEngine
from .engines.google import GoogleEngine
from .engines.serper import SerperEngine
from .dorking.builder import build_dork, from_template
from .dorking.templates import get_template_names
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
        "--engine", "-e",
        choices=["auto", "google", "serper", "duckduckgo"],
        default="auto",
        help="Search engine to use (default: auto)",
    )
    search_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON",
    )

    # dork command
    dork_parser = subparsers.add_parser("dork", help="Build and execute Google dork queries")
    dork_parser.add_argument("query", nargs="?", default="", help="Base query terms")
    dork_parser.add_argument(
        "--template", "-t",
        help="Use a predefined dork template",
    )
    dork_parser.add_argument(
        "--domain", "-d",
        help="Target domain (site: operator)",
    )
    dork_parser.add_argument(
        "--site", "-s",
        help="Alias for --domain",
    )
    dork_parser.add_argument(
        "--filetype", "-f",
        help="File extension to search for",
    )
    dork_parser.add_argument(
        "--inurl",
        help="String that must appear in URL",
    )
    dork_parser.add_argument(
        "--intitle",
        help="String that must appear in page title",
    )
    dork_parser.add_argument(
        "--intext",
        help="String that must appear in page body",
    )
    dork_parser.add_argument(
        "--exclude", "-x",
        help="Comma-separated terms to exclude",
    )
    dork_parser.add_argument(
        "--no-execute",
        action="store_true",
        help="Only build the dork query, don't search",
    )
    dork_parser.add_argument(
        "--num", "-n",
        type=int,
        default=10,
        help="Number of results (default: 10)",
    )
    dork_parser.add_argument(
        "--paranoia", "-p",
        choices=["casual", "cautious", "ghost", "midnight"],
        default=None,
        help="Paranoia level",
    )
    dork_parser.add_argument(
        "--list-templates",
        action="store_true",
        help="List available dork templates",
    )
    dork_parser.add_argument(
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

    # Engine selection
    engine_name = args.engine if hasattr(args, "engine") else "auto"

    if engine_name == "serper":
        engine = SerperEngine(proxy=proxy)
    elif engine_name == "google":
        engine = GoogleEngine(proxy=proxy, paranoia=paranoia.value)
    elif engine_name == "duckduckgo":
        engine = DuckDuckGoEngine(proxy=proxy)
    else:
        # Auto: try serper -> google -> duckduckgo
        serper = SerperEngine(proxy=proxy)
        if serper.available:
            engine = serper
        else:
            engine = DuckDuckGoEngine(proxy=proxy)

    if not args.json_output:
        level_str = paranoia.value.upper()
        print(f"\n  [{level_str}] Searching: {args.query} (engine: {engine.name})\n")

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


async def cmd_dork(args: argparse.Namespace, config: Config) -> int:
    """Execute dork command — build and optionally run dork queries."""
    # List templates
    if args.list_templates:
        templates = get_template_names()
        print("\n  Available dork templates:")
        print(f"  {'─' * 40}")
        for name in templates:
            print(f"    {name}")
        print(f"\n  Usage: ghost dork --template <name> --domain example.com\n")
        return 0

    domain = args.domain or args.site

    # Build the dork
    if args.template:
        try:
            kwargs = {}
            if domain:
                kwargs["domain"] = domain
            dork_query = from_template(args.template, **kwargs)
        except ValueError as e:
            print(f"  Error: {e}", file=sys.stderr)
            return 1
    else:
        if not args.query and not domain:
            print("  Error: provide a query or use --template", file=sys.stderr)
            return 1

        exclude_list = [e.strip() for e in args.exclude.split(",")] if args.exclude else None
        dork_query = build_dork(
            query=args.query,
            site=domain,
            filetype=args.filetype,
            inurl=args.inurl,
            intitle=args.intitle,
            intext=args.intext,
            exclude=exclude_list,
        )

    print(f"\n  Dork: {dork_query}\n")

    if args.no_execute:
        return 0

    # Execute the dork query
    paranoia = ParanoiaLevel(args.paranoia) if args.paranoia else config.paranoia_level
    proxy_mgr = ProxyManager()
    proxy = proxy_mgr.get_proxy(paranoia)

    # Use serper if available, else duckduckgo (google gets captcha'd with dorks)
    serper = SerperEngine(proxy=proxy)
    if serper.available:
        engine = serper
    else:
        engine = DuckDuckGoEngine(proxy=proxy)

    print(f"  Executing via {engine.name}...\n")

    try:
        results = await engine.search(dork_query, num_results=args.num)
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
    elif args.command == "dork":
        rc = asyncio.run(cmd_dork(args, config))
    elif args.command == "status":
        rc = asyncio.run(cmd_status(config))
    else:
        parser.print_help()
        rc = 0

    sys.exit(rc)


if __name__ == "__main__":
    main()
