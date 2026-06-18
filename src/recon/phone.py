"""Phone number intelligence module — offline validation + carrier/CNAM lookups."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus

import httpx

# Optional dependency — degrades gracefully if missing
try:
    import phonenumbers
    from phonenumbers import (
        carrier as pn_carrier,
        geocoder as pn_geocoder,
        timezone as pn_timezone,
    )

    _HAS_PHONENUMBERS = True
except ImportError:
    _HAS_PHONENUMBERS = False

TIMEOUT = 10.0

# API endpoints
VERIPHONE_URL = "https://api.veriphone.io/v2/verify"
OPENCNAM_URL = "https://api.opencnam.com/v3/phone"


@dataclass
class PhoneReport:
    """Complete phone intelligence report."""

    number: str
    formatted: dict = field(default_factory=dict)  # e164, national, international
    valid: bool | None = None
    country_code: str = ""
    country: str = ""
    region: str = ""
    carrier_type: str = "unknown"  # mobile, landline, voip, unknown
    carrier_name: str = ""
    timezone: str = ""
    veriphone: dict | None = None  # API response if key is set
    cnam_name: str | None = None  # Caller ID name from CNAM lookup
    search_urls: dict = field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Offline analysis (phonenumbers library)
# ---------------------------------------------------------------------------


def _offline_analysis(number: str, default_region: str) -> PhoneReport:
    """Parse and analyze a phone number using Google's libphonenumber.

    This is entirely offline — no network calls.  Returns a partially
    populated PhoneReport.
    """
    report = PhoneReport(number=number)

    if not _HAS_PHONENUMBERS:
        report.error = (
            "phonenumbers library not installed — "
            "run: pip install phonenumbers"
        )
        return report

    try:
        parsed = phonenumbers.parse(number, default_region)
    except phonenumbers.NumberParseException as exc:
        report.valid = False
        report.error = f"Parse error: {exc}"
        return report

    # Validity
    report.valid = phonenumbers.is_valid_number(parsed)

    # Formatting variants
    report.formatted = {
        "e164": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164
        ),
        "national": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        "international": phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
    }

    # Country
    report.country_code = str(parsed.country_code)
    region_code = phonenumbers.region_code_for_number(parsed) or ""
    report.country = region_code
    report.region = pn_geocoder.description_for_number(parsed, "en") or ""

    # Carrier
    report.carrier_name = pn_carrier.name_for_number(parsed, "en") or ""
    number_type = phonenumbers.number_type(parsed)
    type_map = {
        phonenumbers.PhoneNumberType.MOBILE: "mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "landline",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "mobile",
        phonenumbers.PhoneNumberType.VOIP: "voip",
        phonenumbers.PhoneNumberType.TOLL_FREE: "landline",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "landline",
        phonenumbers.PhoneNumberType.PAGER: "landline",
    }
    report.carrier_type = type_map.get(number_type, "unknown")

    # Timezone
    tz_list = pn_timezone.time_zones_for_number(parsed)
    report.timezone = tz_list[0] if tz_list else ""

    return report


# ---------------------------------------------------------------------------
# Veriphone API (free, 1000 req/mo)
# ---------------------------------------------------------------------------


async def _query_veriphone(
    client: httpx.AsyncClient,
    e164: str,
    report: PhoneReport,
) -> None:
    """Online carrier verification via Veriphone."""
    key = os.environ.get("GHOST_VERIPHONE_KEY", "")
    if not key:
        return

    try:
        resp = await client.get(
            VERIPHONE_URL,
            params={"phone": e164, "key": key},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            report.veriphone = {
                "phone_valid": data.get("phone_valid"),
                "phone_type": data.get("phone_type", ""),
                "phone_region": data.get("phone_region", ""),
                "country": data.get("country", ""),
                "country_code": data.get("country_code", ""),
                "international_number": data.get("international_number", ""),
                "local_number": data.get("local_number", ""),
                "carrier": data.get("carrier", ""),
            }
            # Supplement carrier info from API if offline was empty
            if not report.carrier_name and data.get("carrier"):
                report.carrier_name = data["carrier"]
            if report.carrier_type == "unknown" and data.get("phone_type"):
                report.carrier_type = data["phone_type"].lower()
        else:
            report.veriphone = {"error": f"HTTP {resp.status_code}"}
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        report.veriphone = {"error": str(exc)}


# ---------------------------------------------------------------------------
# Twilio CNAM lookup ($0.06/lookup)
# ---------------------------------------------------------------------------


async def _query_twilio_cnam(
    client: httpx.AsyncClient,
    e164: str,
    report: PhoneReport,
) -> None:
    """Caller Name (CNAM) lookup via Twilio."""
    sid = os.environ.get("GHOST_TWILIO_SID", "")
    token = os.environ.get("GHOST_TWILIO_TOKEN", "")
    if not sid or not token:
        return

    # Twilio Lookup v2: phone number with CNAM add-on
    url = (
        f"https://lookups.twilio.com/v2/PhoneNumbers/{quote(e164)}"
        f"?Fields=caller_name"
    )

    try:
        resp = await client.get(url, auth=(sid, token), timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            caller_name_info = data.get("caller_name") or {}
            name = caller_name_info.get("caller_name", "")
            if name:
                report.cnam_name = name
        # Don't overwrite if already set by OpenCNAM
    except (httpx.TimeoutException, httpx.ConnectError):
        pass


# ---------------------------------------------------------------------------
# OpenCNAM lookup (15 free/mo)
# ---------------------------------------------------------------------------


async def _query_opencnam(
    client: httpx.AsyncClient,
    e164: str,
    report: PhoneReport,
) -> None:
    """Caller Name (CNAM) lookup via OpenCNAM (cheaper alternative)."""
    sid = os.environ.get("GHOST_OPENCNAM_SID", "")
    token = os.environ.get("GHOST_OPENCNAM_TOKEN", "")
    if not sid or not token:
        return

    # Skip if Twilio already resolved CNAM
    if report.cnam_name:
        return

    try:
        resp = await client.get(
            OPENCNAM_URL,
            params={
                "phone_number": e164,
                "account_sid": sid,
                "auth_token": token,
                "format": "json",
            },
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            name = data.get("name", "")
            if name and name.lower() != "unavailable":
                report.cnam_name = name
    except (httpx.TimeoutException, httpx.ConnectError):
        pass


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------


def _generate_search_urls(report: PhoneReport) -> dict[str, list[dict[str, str]]]:
    """Build reverse-phone search URLs for manual investigation."""
    e164 = report.formatted.get("e164", report.number)
    # Strip leading '+' for URL paths — most sites use bare digits
    digits = e164.lstrip("+").replace("-", "").replace(" ", "")
    national = report.formatted.get("national", digits)

    urls: dict[str, list[dict[str, str]]] = {"reverse_phone": []}

    urls["reverse_phone"] = [
        {
            "name": "USPhonebook",
            "url": f"https://www.usphonebook.com/{digits}",
        },
        {
            "name": "ThatsThem",
            "url": f"https://thatsthem.com/phone/{digits}",
        },
        {
            "name": "Spokeo",
            "url": f"https://www.spokeo.com/phone/{quote(national)}",
        },
        {
            "name": "WhoCallsMe",
            "url": f"https://whocallsme.com/Phone-Number.aspx/{digits}",
        },
        {
            "name": "CallerID Test",
            "url": f"https://calleridtest.com/results/?dn={digits}",
        },
        {
            "name": "NumLookup",
            "url": f"https://www.numlookup.com/phone/{digits}",
        },
    ]

    return urls


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def phone_lookup(number: str, country: str = "US") -> PhoneReport:
    """Full phone number intelligence lookup.

    Always runs offline analysis via phonenumbers (instant).
    Conditionally runs Veriphone, Twilio CNAM, and OpenCNAM if
    their respective API keys are configured.
    Always generates reverse-phone search URLs.

    Args:
        number: Phone number in any common format.
        country: Default country code for parsing (ISO 3166-1 alpha-2).

    Returns:
        PhoneReport with all available intelligence.
    """
    # Offline analysis runs synchronously (pure CPU, no I/O)
    report = await asyncio.to_thread(_offline_analysis, number, country)

    # If offline parse failed completely, still generate URLs with raw input
    e164 = report.formatted.get("e164", number)

    # Online lookups — run in parallel
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        tasks = []
        tasks.append(_query_veriphone(client, e164, report))
        tasks.append(_query_twilio_cnam(client, e164, report))
        tasks.append(_query_opencnam(client, e164, report))
        await asyncio.gather(*tasks)

    # Search URLs — always generated
    report.search_urls = _generate_search_urls(report)

    return report
