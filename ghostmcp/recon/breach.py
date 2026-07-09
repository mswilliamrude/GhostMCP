"""Breach data search module — two-layer legal model for breach intelligence.

Layer 1 (metadata_only — default): HIBP breach metadata — which breaches,
    dates, data classes exposed.  No PII returned.
Layer 2 (full — opt-in): Snusbase / DeHashed / LeakCheck — actual breach
    records including PII fields.  Requires explicit mode="full".
"""

from __future__ import annotations

import asyncio
import base64
import os
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus

import httpx

TIMEOUT = 15.0

# HIBP rate limit: 10 requests per minute (6 s between requests)
HIBP_RATE_INTERVAL = 6.0

# ── API endpoints ────────────────────────────────────────────────────────

HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount"
SNUSBASE_API = "https://api.snusbase.com/data/search"
DEHASHED_API = "https://api.dehashed.com/search"
LEAKCHECK_API = "https://leakcheck.io/api/public"

# ── Data classes critical to severity classification ─────────────────────

_CRITICAL_CLASSES = {
    "credit cards", "credit card cvvs", "bank account numbers",
    "financial data", "payment histories", "credit status information",
    "partial credit card data",
}
_PASSWORD_CLASSES = {
    "passwords", "password hints", "password strengths",
    "hashed passwords", "security questions and answers",
}
_HIGH_CLASSES = {
    "social security numbers", "national ids",
    "phone numbers", "government issued ids",
}
_MEDIUM_CLASSES = {
    "physical addresses", "dates of birth", "genders",
    "employers", "job titles", "names",
}


def _classify_severity(data_classes: list[str]) -> str:
    """Classify breach severity based on exposed data classes."""
    lower = {dc.lower() for dc in data_classes}

    has_passwords = bool(lower & _PASSWORD_CLASSES)
    has_financial = bool(lower & _CRITICAL_CLASSES)
    has_high = bool(lower & _HIGH_CLASSES)
    has_medium = bool(lower & _MEDIUM_CLASSES)

    if has_passwords and has_financial:
        return "critical"
    if has_passwords or has_high:
        return "high"
    if has_medium and not has_passwords:
        return "medium"
    return "low"


# ── Result dataclasses ───────────────────────────────────────────────────


@dataclass
class BreachRecord:
    """A single breach record from any provider."""

    source: str                              # which breach DB (hibp, snusbase, dehashed, leakcheck)
    breach_name: str
    date: str                                # breach date (YYYY-MM-DD or partial)
    data_classes: list[str] = field(default_factory=list)
    record_count: int | None = None
    details: dict | None = None              # actual PII from full mode
    severity: str = "low"                    # low / medium / high / critical


@dataclass
class BreachSearchResult:
    """Aggregated result across all breach providers."""

    query: str
    query_type: str = "email"                # email / phone / username / name / ip
    mode: str = "metadata_only"              # metadata_only / full
    total_breaches: int = 0
    records: list[BreachRecord] = field(default_factory=list)
    providers_checked: list[str] = field(default_factory=list)
    providers_failed: dict[str, str] = field(default_factory=dict)
    search_urls: dict[str, str] = field(default_factory=dict)
    error: str | None = None


# ── Search URL generation ────────────────────────────────────────────────


def _build_search_urls(query: str) -> dict[str, str]:
    """Generate manual follow-up URLs for breach investigation."""
    encoded = quote_plus(query)
    return {
        "haveibeenpwned": f"https://haveibeenpwned.com/account/{quote(query)}",
        "dehashed": f"https://dehashed.com/search?query={encoded}",
        "snusbase": "https://snusbase.com",
        "leakcheck": "https://leakcheck.io",
    }


# ── Layer 1: HIBP (metadata only) ───────────────────────────────────────


async def _query_hibp(
    client: httpx.AsyncClient,
    email: str,
    result: BreachSearchResult,
) -> None:
    """Query Have I Been Pwned for breach metadata.

    HIBP only supports email lookups.  Returns breach metadata (names,
    dates, data classes) — no actual PII.
    """
    api_key = os.environ.get("GHOST_HIBP_KEY", "")
    if not api_key:
        result.providers_failed["hibp"] = "GHOST_HIBP_KEY not configured"
        return

    url = f"{HIBP_API}/{quote(email)}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": "GhostMCP-OSINT",
    }

    try:
        resp = await client.get(url, headers=headers, params={"truncateResponse": "false"})

        if resp.status_code == 200:
            breaches = resp.json()
            for b in breaches:
                data_classes = b.get("DataClasses", [])
                record = BreachRecord(
                    source="hibp",
                    breach_name=b.get("Name", b.get("Title", "Unknown")),
                    date=b.get("BreachDate", ""),
                    data_classes=data_classes,
                    record_count=b.get("PwnCount"),
                    details=None,
                    severity=_classify_severity(data_classes),
                )
                result.records.append(record)

        elif resp.status_code == 404:
            pass  # email not found in any breach — not an error
        elif resp.status_code == 401:
            result.providers_failed["hibp"] = "Invalid API key"
        elif resp.status_code == 429:
            result.providers_failed["hibp"] = "Rate limited — try again later"
        else:
            result.providers_failed["hibp"] = f"HTTP {resp.status_code}"

    except httpx.TimeoutException:
        result.providers_failed["hibp"] = "Request timed out"
    except httpx.ConnectError as exc:
        result.providers_failed["hibp"] = f"Connection error: {exc}"
    except Exception as exc:
        result.providers_failed["hibp"] = f"Unexpected error: {exc}"


# ── Layer 2: Snusbase ────────────────────────────────────────────────────


async def _query_snusbase(
    client: httpx.AsyncClient,
    query: str,
    query_type: str,
    result: BreachSearchResult,
) -> None:
    """Query Snusbase for full breach records (Layer 2 — PII)."""
    api_key = os.environ.get("GHOST_SNUSBASE_KEY", "")
    if not api_key:
        result.providers_failed["snusbase"] = "GHOST_SNUSBASE_KEY not configured"
        return

    headers = {
        "Auth": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "terms": [query],
        "types": [query_type],
        "wildcard": False,
    }

    try:
        resp = await client.post(SNUSBASE_API, json=payload, headers=headers)

        if resp.status_code == 200:
            data = resp.json()
            results_dict = data.get("results", {})

            for breach_name, records in results_dict.items():
                for rec in records:
                    # Extract available PII fields
                    details: dict = {}
                    for pii_field in ("email", "password", "hash", "salt",
                                      "name", "username", "phone", "ip",
                                      "address", "lastip", "uid"):
                        val = rec.get(pii_field)
                        if val:
                            details[pii_field] = val

                    # Determine data classes from available fields
                    data_classes = _data_classes_from_details(details)

                    record = BreachRecord(
                        source="snusbase",
                        breach_name=breach_name,
                        date="",  # Snusbase doesn't return breach dates per record
                        data_classes=data_classes,
                        record_count=None,
                        details=details,
                        severity=_classify_severity(data_classes),
                    )
                    result.records.append(record)

        elif resp.status_code == 401:
            result.providers_failed["snusbase"] = "Invalid API key"
        else:
            result.providers_failed["snusbase"] = f"HTTP {resp.status_code}"

    except httpx.TimeoutException:
        result.providers_failed["snusbase"] = "Request timed out"
    except httpx.ConnectError as exc:
        result.providers_failed["snusbase"] = f"Connection error: {exc}"
    except Exception as exc:
        result.providers_failed["snusbase"] = f"Unexpected error: {exc}"


# ── Layer 2: DeHashed ────────────────────────────────────────────────────

# Map our query_type to DeHashed field names
_DEHASHED_FIELD_MAP = {
    "email": "email",
    "username": "username",
    "name": "name",
    "phone": "phone",
    "ip": "ip_address",
    "password": "password",
    "hash": "hashed_password",
}


async def _query_dehashed(
    client: httpx.AsyncClient,
    query: str,
    query_type: str,
    result: BreachSearchResult,
) -> None:
    """Query DeHashed for full breach records (Layer 2 — PII)."""
    dh_email = os.environ.get("GHOST_DEHASHED_EMAIL", "")
    dh_key = os.environ.get("GHOST_DEHASHED_KEY", "")
    if not dh_email or not dh_key:
        result.providers_failed["dehashed"] = (
            "GHOST_DEHASHED_EMAIL and/or GHOST_DEHASHED_KEY not configured"
        )
        return

    dh_field = _DEHASHED_FIELD_MAP.get(query_type, "email")
    search_query = f"{dh_field}:{query}"

    # DeHashed uses HTTP Basic auth
    auth_string = base64.b64encode(f"{dh_email}:{dh_key}".encode()).decode()
    headers = {
        "Accept": "application/json",
        "Authorization": f"Basic {auth_string}",
    }

    try:
        resp = await client.get(
            DEHASHED_API,
            params={"query": search_query},
            headers=headers,
        )

        if resp.status_code == 200:
            data = resp.json()
            entries = data.get("entries") or []

            for entry in entries:
                details: dict = {}
                for pii_field in ("email", "ip_address", "username", "password",
                                  "hashed_password", "name", "vin", "address",
                                  "phone"):
                    val = entry.get(pii_field)
                    if val:
                        details[pii_field] = val

                data_classes = _data_classes_from_details(details)
                db_name = entry.get("database_name", "Unknown")

                record = BreachRecord(
                    source="dehashed",
                    breach_name=db_name,
                    date="",  # DeHashed doesn't always include breach date
                    data_classes=data_classes,
                    record_count=None,
                    details=details,
                    severity=_classify_severity(data_classes),
                )
                result.records.append(record)

        elif resp.status_code == 401:
            result.providers_failed["dehashed"] = "Invalid credentials"
        elif resp.status_code == 402:
            result.providers_failed["dehashed"] = "Insufficient balance"
        else:
            result.providers_failed["dehashed"] = f"HTTP {resp.status_code}"

    except httpx.TimeoutException:
        result.providers_failed["dehashed"] = "Request timed out"
    except httpx.ConnectError as exc:
        result.providers_failed["dehashed"] = f"Connection error: {exc}"
    except Exception as exc:
        result.providers_failed["dehashed"] = f"Unexpected error: {exc}"


# ── Layer 2: LeakCheck ───────────────────────────────────────────────────


async def _query_leakcheck(
    client: httpx.AsyncClient,
    query: str,
    query_type: str,
    result: BreachSearchResult,
) -> None:
    """Query LeakCheck for breach exposure (Layer 2)."""
    api_key = os.environ.get("GHOST_LEAKCHECK_KEY", "")
    if not api_key:
        result.providers_failed["leakcheck"] = "GHOST_LEAKCHECK_KEY not configured"
        return

    # LeakCheck only supports email, phone, username
    if query_type not in ("email", "phone", "username"):
        result.providers_failed["leakcheck"] = (
            f"LeakCheck does not support query_type={query_type!r}"
        )
        return

    params = {
        "key": api_key,
        "check": query,
        "type": query_type,
    }

    try:
        resp = await client.get(LEAKCHECK_API, params=params)

        if resp.status_code == 200:
            data = resp.json()

            if data.get("success") and data.get("found"):
                exposed_fields = data.get("fields", [])
                sources = data.get("sources", [])

                for src in sources:
                    src_name = src.get("name", "Unknown")
                    src_date = src.get("date", "")

                    record = BreachRecord(
                        source="leakcheck",
                        breach_name=src_name,
                        date=src_date,
                        data_classes=exposed_fields,
                        record_count=None,
                        details=None,
                        severity=_classify_severity(exposed_fields),
                    )
                    result.records.append(record)

        elif resp.status_code == 401:
            result.providers_failed["leakcheck"] = "Invalid API key"
        elif resp.status_code == 429:
            result.providers_failed["leakcheck"] = "Rate limited"
        else:
            result.providers_failed["leakcheck"] = f"HTTP {resp.status_code}"

    except httpx.TimeoutException:
        result.providers_failed["leakcheck"] = "Request timed out"
    except httpx.ConnectError as exc:
        result.providers_failed["leakcheck"] = f"Connection error: {exc}"
    except Exception as exc:
        result.providers_failed["leakcheck"] = f"Unexpected error: {exc}"


# ── Helpers ──────────────────────────────────────────────────────────────


def _data_classes_from_details(details: dict) -> list[str]:
    """Infer HIBP-style data class labels from raw PII field names."""
    field_to_class = {
        "email": "Email addresses",
        "password": "Passwords",
        "hash": "Password hashes",
        "hashed_password": "Password hashes",
        "salt": "Password salts",
        "name": "Names",
        "username": "Usernames",
        "phone": "Phone numbers",
        "ip": "IP addresses",
        "ip_address": "IP addresses",
        "address": "Physical addresses",
        "vin": "Vehicle identification numbers",
        "uid": "User IDs",
        "lastip": "IP addresses",
    }
    classes: list[str] = []
    seen: set[str] = set()
    for fld in details:
        label = field_to_class.get(fld, "")
        if label and label not in seen:
            classes.append(label)
            seen.add(label)
    return classes


# ── Main entry point ─────────────────────────────────────────────────────


async def breach_search(
    query: str,
    query_type: str = "email",
    mode: str = "metadata_only",
) -> BreachSearchResult:
    """Search breach databases for exposure.

    Args:
        query: The value to search for (email, phone, username, etc.).
        query_type: Type of query — "email", "phone", "username",
                    "name", "ip".
        mode: "metadata_only" (default) — HIBP metadata only, no PII.
              "full" — also queries Snusbase, DeHashed, LeakCheck for
              actual breach records.  Requires appropriate API keys.

    Returns:
        BreachSearchResult with all available intelligence.
    """
    result = BreachSearchResult(
        query=query,
        query_type=query_type,
        mode=mode,
    )

    # Validate mode
    if mode not in ("metadata_only", "full"):
        result.error = f"Invalid mode {mode!r} — must be 'metadata_only' or 'full'"
        return result

    # Validate query_type
    valid_types = {"email", "phone", "username", "name", "ip"}
    if query_type not in valid_types:
        result.error = (
            f"Invalid query_type {query_type!r} — "
            f"must be one of {', '.join(sorted(valid_types))}"
        )
        return result

    result.search_urls = _build_search_urls(query)

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:

        # ── Layer 1: HIBP (metadata only, email queries only) ────────
        if query_type == "email":
            result.providers_checked.append("hibp")
            await _query_hibp(client, query, result)

        # ── Layer 2: Full breach record providers (opt-in) ───────────
        if mode == "full":
            tasks = []

            result.providers_checked.append("snusbase")
            tasks.append(_query_snusbase(client, query, query_type, result))

            result.providers_checked.append("dehashed")
            tasks.append(_query_dehashed(client, query, query_type, result))

            if query_type in ("email", "phone", "username"):
                result.providers_checked.append("leakcheck")
                tasks.append(_query_leakcheck(client, query, query_type, result))

            await asyncio.gather(*tasks)

    # Deduplicate by (source, breach_name) — keep first occurrence
    seen: set[tuple[str, str]] = set()
    unique: list[BreachRecord] = []
    for rec in result.records:
        key = (rec.source, rec.breach_name.lower())
        if key not in seen:
            seen.add(key)
            unique.append(rec)
    result.records = unique
    result.total_breaches = len(result.records)

    return result
