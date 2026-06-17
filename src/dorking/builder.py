"""Google dork query builder — construct advanced search operators."""

from __future__ import annotations

from typing import Optional

from .templates import TEMPLATES


def build_dork(
    query: str,
    site: Optional[str] = None,
    filetype: Optional[str] = None,
    inurl: Optional[str] = None,
    intitle: Optional[str] = None,
    intext: Optional[str] = None,
    exclude: Optional[list[str]] = None,
) -> str:
    """Build a Google dork query from components.

    Combines search operators into proper Google dorking syntax.
    Operators are prepended to the base query.

    Args:
        query: Base search query text.
        site: Limit results to a specific domain (e.g. "example.com").
        filetype: Restrict to file extension (e.g. "pdf", "env").
        inurl: Require string to appear in URL.
        intitle: Require string to appear in page title.
        intext: Require string to appear in page body text.
        exclude: List of terms/domains to exclude (prefixed with -).

    Returns:
        Formatted Google dork query string.

    Examples:
        >>> build_dork("passwords", site="example.com", filetype="txt")
        'site:example.com filetype:txt passwords'

        >>> build_dork("config", site="corp.io", exclude=["github.com"])
        'site:corp.io -github.com config'
    """
    parts: list[str] = []

    if site:
        parts.append(f"site:{site}")

    if filetype:
        # Strip leading dot if user passes ".env" instead of "env"
        ft = filetype.lstrip(".")
        parts.append(f"filetype:{ft}")

    if inurl:
        parts.append(f'inurl:"{inurl}"')

    if intitle:
        parts.append(f'intitle:"{intitle}"')

    if intext:
        parts.append(f'intext:"{intext}"')

    if exclude:
        for term in exclude:
            if term.startswith("-"):
                parts.append(term)
            else:
                parts.append(f"-{term}")

    # Base query goes last
    if query:
        parts.append(query)

    return " ".join(parts)


def from_template(template_name: str, **kwargs: str) -> str:
    """Build a dork query from a predefined template.

    Templates use Python format string syntax with named placeholders.
    Common placeholders: {domain}, {keyword}, {ext}

    Args:
        template_name: Name of the template (from templates.py).
        **kwargs: Template placeholder values (domain, keyword, ext, etc.).

    Returns:
        Formatted dork query string.

    Raises:
        ValueError: If template_name not found or required placeholders missing.

    Examples:
        >>> from_template("exposed_configs", domain="example.com")
        'site:example.com (filetype:env OR ...) -github.com'

        >>> from_template("login_pages", domain="target.org")
        'site:target.org (inurl:login OR inurl:admin ...)'
    """
    if template_name not in TEMPLATES:
        available = ", ".join(sorted(TEMPLATES.keys()))
        raise ValueError(
            f"Unknown template '{template_name}'. "
            f"Available: {available}"
        )

    template = TEMPLATES[template_name]

    try:
        return template.format(**kwargs)
    except KeyError as e:
        raise ValueError(
            f"Template '{template_name}' requires placeholder {e}. "
            f"Provide it as a keyword argument."
        )
