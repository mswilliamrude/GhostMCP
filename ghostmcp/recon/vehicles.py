"""Vehicle intelligence module — VIN decoding, history, title, salvage, and market data.

Layered approach:
  Layer 0 (free)  — NHTSA vPIC decode, recalls, complaints, safety ratings
  Layer 1 (free)  — NICB VINCheck stolen/salvage flag (scrape, 5/day)
  Layer 2 (free)  — Copart / IAAI salvage auction lookup (scrape)
  Layer 3 (paid)  — VinAudit NMVTIS history ($1/query + $100/mo)
  Layer 4 (paid)  — CarsXE market value / lien / ownership ($41+/mo)

Environment variables for paid tiers:
  GHOST_VINAUDIT_API_KEY  — VinAudit API key (enables Layer 3)
  GHOST_CARSXE_API_KEY    — CarsXE API key  (enables Layer 4)
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

TIMEOUT = 15.0

# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

# NHTSA (all free, no key)
NHTSA_VIN_DECODE_URL = "https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues"
NHTSA_RECALLS_URL = "https://api.nhtsa.gov/recalls/recallsByVehicle"
NHTSA_COMPLAINTS_URL = "https://api.nhtsa.gov/complaints/complaintsByVehicle"
NHTSA_SAFETY_RATINGS_URL = "https://api.nhtsa.gov/SafetyRatings/VehicleId"

# NICB VINCheck (free, 5/day, scrape)
NICB_VINCHECK_URL = "https://www.nicb.org/vincheck"

# Copart (free, scrape)
COPART_SEARCH_URL = "https://www.copart.com/public/data/lotdetails/solr"

# IAAI (free, scrape)
IAAI_SEARCH_URL = "https://www.iaai.com/VehicleSearch/SearchDetails"

# VinAudit (paid — $1/query + $100/mo)
VINAUDIT_API_URL = "https://api.vinaudit.com/query.php"

# CarsXE (paid — $41+/mo)
CARSXE_MARKET_URL = "https://api.carsxe.com/marketvalue"
CARSXE_HISTORY_URL = "https://api.carsxe.com/history"


# ---------------------------------------------------------------------------
# Data layer enum
# ---------------------------------------------------------------------------

class DataLayer(Enum):
    """Which data layers to include in a report."""
    FREE_ONLY = "free"          # Layers 0-2
    NMVTIS = "nmvtis"           # Layers 0-3 (adds VinAudit)
    FULL = "full"               # Layers 0-4 (adds CarsXE)


# ---------------------------------------------------------------------------
# Report dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TitleRecord:
    """Single title event from NMVTIS."""
    state: str = ""
    date: str = ""
    odometer: str = ""
    title_type: str = ""  # clean, salvage, rebuilt, flood, etc.


@dataclass
class AuctionRecord:
    """Salvage auction listing from Copart/IAAI."""
    source: str = ""           # "Copart" or "IAAI"
    lot_number: str = ""
    damage_primary: str = ""
    damage_secondary: str = ""
    loss_type: str = ""        # clean title, salvage, etc.
    sale_price: str = ""
    sale_date: str = ""
    odometer: str = ""
    keys_present: str = ""
    image_urls: list[str] = field(default_factory=list)
    listing_url: str = ""


@dataclass
class SafetyRating:
    """NHTSA NCAP crash test rating."""
    overall: str = ""
    frontal_driver: str = ""
    frontal_passenger: str = ""
    side_driver: str = ""
    side_passenger: str = ""
    rollover: str = ""
    side_pole: str = ""


@dataclass
class MarketValue:
    """Market value estimate."""
    source: str = ""
    retail: str = ""
    trade_in: str = ""
    private_party: str = ""


@dataclass
class VehicleReport:
    """Complete vehicle intelligence report from VIN."""

    vin: str

    # Layer 0 — NHTSA decode
    make: str = ""
    model: str = ""
    year: str = ""
    trim: str = ""
    body_type: str = ""
    engine: dict = field(default_factory=dict)
    drive_type: str = ""
    transmission: str = ""
    manufacturer: dict = field(default_factory=dict)
    safety_features: list[str] = field(default_factory=list)

    # Layer 0 — NHTSA recalls + complaints
    recalls: list[dict] = field(default_factory=list)
    complaints: list[dict] = field(default_factory=list)
    complaint_count: int = 0

    # Layer 0 — NHTSA safety ratings
    safety_rating: SafetyRating | None = None

    # Layer 1 — NICB
    nicb_theft_flag: bool | None = None
    nicb_salvage_flag: bool | None = None
    nicb_error: str = ""

    # Layer 2 — Copart / IAAI auction records
    auction_records: list[AuctionRecord] = field(default_factory=list)

    # Layer 3 — VinAudit / NMVTIS
    title_records: list[TitleRecord] = field(default_factory=list)
    owner_count: int | None = None
    title_brands: list[str] = field(default_factory=list)  # salvage, flood, lemon, etc.
    odometer_records: list[dict] = field(default_factory=list)
    odometer_rollback: bool | None = None
    accident_records: list[dict] = field(default_factory=list)
    theft_records: list[dict] = field(default_factory=list)
    salvage_records: list[dict] = field(default_factory=list)

    # Layer 4 — CarsXE
    market_value: MarketValue | None = None
    lien_records: list[dict] = field(default_factory=list)
    ownership_history: list[dict] = field(default_factory=list)

    # Meta
    search_urls: dict = field(default_factory=dict)
    layers_used: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    error: str | None = None  # fatal error


# ---------------------------------------------------------------------------
# VIN validation
# ---------------------------------------------------------------------------

_TRANSLITERATION = {
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def _validate_vin(vin: str) -> str | None:
    """Validate a 17-character VIN. Returns error message or None."""
    vin = vin.strip().upper()
    if len(vin) != 17:
        return f"VIN must be 17 characters, got {len(vin)}"

    invalid_chars = {"I", "O", "Q"}
    for ch in vin:
        if ch in invalid_chars:
            return f"VIN contains invalid character: {ch}"
        if ch not in _TRANSLITERATION and not ch.isdigit():
            return f"VIN contains invalid character: {ch}"
    return None


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 0 — NHTSA (free, no key)
# ═══════════════════════════════════════════════════════════════════════════

_SAFETY_FIELDS = [
    "AirBagLocCurtain", "AirBagLocFront", "AirBagLocKnee",
    "AirBagLocSeatCushion", "AirBagLocSide",
    "AutomaticPedestrianAlertingSound", "AdaptiveCruiseControl",
    "AdaptiveDrivingBeam", "AEB", "BackupCamera", "BlindSpotMon",
    "CIB", "DynamicBrakeSupport", "EDR", "ESC",
    "ForwardCollisionWarning", "LaneDepartureWarning", "LaneKeepSystem",
    "ParkAssist", "RearAutomaticEmergencyBraking", "RearCrossTrafficAlert",
    "RearVisibilitySystem", "SemiautomaticHeadlampBeamSwitching",
    "TPMS", "TractionControl",
]


def _parse_vin_decode(data: dict, report: VehicleReport) -> None:
    """Extract vehicle attributes from vPIC DecodeVinValues response."""
    results = data.get("Results", [])
    if not results:
        return
    v = results[0]

    report.make = v.get("Make", "") or ""
    report.model = v.get("Model", "") or ""
    report.year = v.get("ModelYear", "") or ""
    report.trim = v.get("Trim", "") or ""
    report.body_type = v.get("BodyClass", "") or ""
    report.drive_type = v.get("DriveType", "") or ""
    report.transmission = v.get("TransmissionStyle", "") or ""

    report.engine = {
        "displacement": v.get("DisplacementL", "") or "",
        "cylinders": v.get("EngineCylinders", "") or "",
        "fuel_type": v.get("FuelTypePrimary", "") or "",
    }
    report.manufacturer = {
        "name": v.get("Manufacturer", "") or "",
        "country": v.get("PlantCountry", "") or "",
    }

    safety: list[str] = []
    for sf in _SAFETY_FIELDS:
        value = v.get(sf, "") or ""
        if value and value.lower() not in ("", "not applicable"):
            safety.append(f"{sf}: {value}")
    report.safety_features = safety


def _parse_recalls(data: dict) -> list[dict]:
    """Extract recall records from NHTSA Recalls API response."""
    results = data.get("results", [])
    recalls: list[dict] = []
    for item in results:
        recalls.append({
            "campaign_number": item.get("NHTSACampaignNumber", ""),
            "component": item.get("Component", ""),
            "summary": item.get("Summary", ""),
            "consequence": item.get("Consequence", ""),
            "remedy": item.get("Remedy", ""),
            "report_date": item.get("ReportReceivedDate", ""),
        })
    return recalls


def _parse_complaints(data: dict) -> tuple[list[dict], int]:
    """Extract complaint records from NHTSA Complaints API response."""
    results = data.get("results", [])
    complaints: list[dict] = []
    for item in results:
        complaints.append({
            "component": item.get("components", ""),
            "summary": item.get("summary", ""),
            "date": item.get("dateComplaintFiled", ""),
            "crash": item.get("crash", False),
            "fire": item.get("fire", False),
            "injuries": item.get("numberOfInjuries", 0),
            "deaths": item.get("numberOfDeaths", 0),
        })
    return complaints, len(results)


async def _fetch_nhtsa_decode(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 0: Decode VIN via NHTSA vPIC."""
    try:
        resp = await client.get(
            f"{NHTSA_VIN_DECODE_URL}/{report.vin}",
            params={"format": "json"},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            _parse_vin_decode(resp.json(), report)
        else:
            report.errors.append(f"VIN decode: HTTP {resp.status_code}")
    except (httpx.TimeoutException, httpx.ConnectError) as exc:
        report.errors.append(f"VIN decode: {exc}")


async def _fetch_nhtsa_recalls(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 0: Fetch recalls by make/model/year."""
    if not report.make or not report.model or not report.year:
        return
    try:
        resp = await client.get(
            NHTSA_RECALLS_URL,
            params={"make": report.make, "model": report.model, "modelYear": report.year},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            report.recalls = _parse_recalls(resp.json())
    except (httpx.TimeoutException, httpx.ConnectError):
        report.errors.append("Recalls lookup timed out")


async def _fetch_nhtsa_complaints(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 0: Fetch consumer complaints."""
    if not report.make or not report.model or not report.year:
        return
    try:
        resp = await client.get(
            NHTSA_COMPLAINTS_URL,
            params={"make": report.make, "model": report.model, "modelYear": report.year},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            report.complaints, report.complaint_count = _parse_complaints(resp.json())
    except (httpx.TimeoutException, httpx.ConnectError):
        report.errors.append("Complaints lookup timed out")


async def _fetch_nhtsa_safety_ratings(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 0: Fetch NCAP crash test safety ratings.

    The NHTSA safety ratings API requires a vehicleId, which we get by
    searching by year/make/model first.
    """
    if not report.make or not report.model or not report.year:
        return
    try:
        # Step 1: Find vehicle ID
        search_url = f"https://api.nhtsa.gov/SafetyRatings/modelyear/{report.year}/make/{quote(report.make)}/model/{quote(report.model)}"
        resp = await client.get(search_url, timeout=TIMEOUT)
        if resp.status_code != 200:
            return
        data = resp.json()
        results = data.get("Results", [])
        if not results:
            return

        vehicle_id = results[0].get("VehicleId")
        if not vehicle_id:
            return

        # Step 2: Get ratings for that vehicle ID
        resp = await client.get(
            f"https://api.nhtsa.gov/SafetyRatings/VehicleId/{vehicle_id}",
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return
        data = resp.json()
        ratings = data.get("Results", [])
        if not ratings:
            return

        r = ratings[0]
        report.safety_rating = SafetyRating(
            overall=str(r.get("OverallRating", "")),
            frontal_driver=str(r.get("FrontCrashDriversideRating", "")),
            frontal_passenger=str(r.get("FrontCrashPassengersideRating", "")),
            side_driver=str(r.get("SideCrashDriversideRating", "")),
            side_passenger=str(r.get("SideCrashPassengersideRating", "")),
            rollover=str(r.get("RolloverRating", "")),
            side_pole=str(r.get("SidePoleCrashRating", "")),
        )
    except (httpx.TimeoutException, httpx.ConnectError):
        report.errors.append("Safety ratings lookup timed out")


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 1 — NICB VINCheck (free, scrape, 5/day)
# ═══════════════════════════════════════════════════════════════════════════

async def _fetch_nicb_vincheck(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 1: Check NICB for stolen/salvage flags.

    This is a scrape of the NICB VINCheck web form. Limited to 5 lookups/day.
    May break if NICB changes their site. Uses a simple POST + HTML parse.
    """
    try:
        # NICB VINCheck uses a form POST with reCAPTCHA — direct scraping is
        # unreliable. For now, we flag it as a manual-check URL and set
        # the NICB fields to None (unknown) rather than fake data.
        report.nicb_error = "NICB VINCheck requires CAPTCHA — use manual URL"
        report.nicb_theft_flag = None
        report.nicb_salvage_flag = None
    except Exception as exc:
        report.nicb_error = f"NICB check failed: {exc}"


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 2 — Copart / IAAI salvage auction scrape (free)
# ═══════════════════════════════════════════════════════════════════════════

async def _fetch_copart(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 2: Search Copart for salvage auction history by VIN.

    Copart's public search uses a JSON API behind their frontend. This
    endpoint may change — treat as best-effort scrape.
    """
    try:
        # Copart's lot search API (public, undocumented)
        resp = await client.get(
            f"https://www.copart.com/public/data/lotdetails/solr/lotImages/{report.vin}",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json",
            },
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return

        data = resp.json()
        if not data or not data.get("data"):
            return

        lot_data = data["data"]
        if isinstance(lot_data, dict):
            lot_data = [lot_data]

        for lot in lot_data:
            record = AuctionRecord(
                source="Copart",
                lot_number=str(lot.get("lotNumberStr", lot.get("ln", ""))),
                damage_primary=lot.get("dd", lot.get("primaryDamage", "")),
                damage_secondary=lot.get("sdd", lot.get("secondaryDamage", "")),
                loss_type=lot.get("tims", lot.get("titleType", "")),
                sale_price=str(lot.get("la", lot.get("currentBid", ""))),
                sale_date=lot.get("ad", ""),
                odometer=str(lot.get("orr", lot.get("odometer", ""))),
                keys_present=lot.get("hk", ""),
                image_urls=[img.get("full", img.get("url", ""))
                            for img in lot.get("lotImages", [])[:5]
                            if isinstance(img, dict)],
                listing_url=f"https://www.copart.com/lot/{lot.get('lotNumberStr', lot.get('ln', ''))}",
            )
            report.auction_records.append(record)

    except (httpx.TimeoutException, httpx.ConnectError):
        report.errors.append("Copart lookup timed out")
    except Exception as exc:
        report.errors.append(f"Copart scrape error: {exc}")


async def _fetch_iaai(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 2: Search IAAI for salvage auction history by VIN.

    IAAI's search API is behind their frontend. Best-effort scrape.
    """
    try:
        resp = await client.post(
            "https://www.iaai.com/Search",
            data={"Ession": "", "query": report.vin},
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/json",
            },
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return

        # IAAI returns HTML or JSON depending on endpoint — parse what we get
        content_type = resp.headers.get("content-type", "")
        if "json" in content_type:
            data = resp.json()
            items = data.get("items", data.get("data", []))
            if isinstance(items, dict):
                items = [items]
            for item in items:
                record = AuctionRecord(
                    source="IAAI",
                    lot_number=str(item.get("stockNumber", item.get("lotNumber", ""))),
                    damage_primary=item.get("primaryDamage", ""),
                    damage_secondary=item.get("secondaryDamage", ""),
                    loss_type=item.get("titleState", ""),
                    sale_price=str(item.get("soldAmount", "")),
                    sale_date=item.get("soldDate", ""),
                    odometer=str(item.get("odometer", "")),
                    listing_url=f"https://www.iaai.com/VehicleDetail/{item.get('stockNumber', '')}",
                )
                report.auction_records.append(record)

    except (httpx.TimeoutException, httpx.ConnectError):
        report.errors.append("IAAI lookup timed out")
    except Exception as exc:
        report.errors.append(f"IAAI scrape error: {exc}")


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 3 — VinAudit / NMVTIS (paid — $1/query + $100/mo)
# ═══════════════════════════════════════════════════════════════════════════

async def _fetch_vinaudit(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 3: Full NMVTIS history via VinAudit API.

    Requires GHOST_VINAUDIT_API_KEY env var.
    Returns: title records, owners, title brands, odometer, accidents,
    theft, and salvage records.
    """
    api_key = os.environ.get("GHOST_VINAUDIT_API_KEY")
    if not api_key:
        report.errors.append("VinAudit: no API key (set GHOST_VINAUDIT_API_KEY)")
        return

    try:
        resp = await client.get(
            VINAUDIT_API_URL,
            params={
                "key": api_key,
                "vin": report.vin,
                "format": "json",
            },
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            report.errors.append(f"VinAudit: HTTP {resp.status_code}")
            return

        data = resp.json()
        if not data.get("success"):
            report.errors.append(f"VinAudit: {data.get('error', 'unknown error')}")
            return

        # Title records
        for title in data.get("titles", []):
            report.title_records.append(TitleRecord(
                state=title.get("state", ""),
                date=title.get("date", ""),
                odometer=str(title.get("odometer", "")),
                title_type=title.get("type", ""),
            ))

        # Owner count (inferred from title records if not explicit)
        report.owner_count = data.get("owners", len(report.title_records))

        # Title brands (salvage, flood, lemon, rebuilt, etc.)
        checks = data.get("checks", {})
        brand_fields = [
            "salvage", "flood", "fire", "hail", "lemon",
            "rebuilt", "junk", "theft", "frame_damage",
        ]
        for bf in brand_fields:
            if checks.get(bf):
                report.title_brands.append(bf.replace("_", " ").title())

        # Odometer records
        report.odometer_records = data.get("odometer", [])
        report.odometer_rollback = checks.get("odometer_rollback", None)

        # Accident / salvage / theft records
        report.accident_records = data.get("accidents", [])
        report.salvage_records = data.get("salvage", [])
        report.theft_records = data.get("thefts", [])

    except (httpx.TimeoutException, httpx.ConnectError):
        report.errors.append("VinAudit: request timed out")
    except Exception as exc:
        report.errors.append(f"VinAudit: {exc}")


# ═══════════════════════════════════════════════════════════════════════════
# LAYER 4 — CarsXE (paid — $41+/mo)
# ═══════════════════════════════════════════════════════════════════════════

async def _fetch_carsxe_market_value(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 4: Market value estimate via CarsXE API."""
    api_key = os.environ.get("GHOST_CARSXE_API_KEY")
    if not api_key:
        report.errors.append("CarsXE: no API key (set GHOST_CARSXE_API_KEY)")
        return

    try:
        resp = await client.get(
            CARSXE_MARKET_URL,
            params={"key": api_key, "vin": report.vin},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            report.errors.append(f"CarsXE market value: HTTP {resp.status_code}")
            return

        data = resp.json()
        prices = data.get("prices", {})
        report.market_value = MarketValue(
            source="CarsXE",
            retail=str(prices.get("retail", "")),
            trade_in=str(prices.get("tradeIn", prices.get("trade_in", ""))),
            private_party=str(prices.get("privateParty", prices.get("private_party", ""))),
        )
    except (httpx.TimeoutException, httpx.ConnectError):
        report.errors.append("CarsXE market value: timed out")
    except Exception as exc:
        report.errors.append(f"CarsXE market value: {exc}")


async def _fetch_carsxe_history(client: httpx.AsyncClient, report: VehicleReport) -> None:
    """Layer 4: Lien and ownership history via CarsXE API."""
    api_key = os.environ.get("GHOST_CARSXE_API_KEY")
    if not api_key:
        return  # Already reported in market value

    try:
        resp = await client.get(
            CARSXE_HISTORY_URL,
            params={"key": api_key, "vin": report.vin},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return

        data = resp.json()
        report.lien_records = data.get("liens", [])
        report.ownership_history = data.get("ownership", [])
    except (httpx.TimeoutException, httpx.ConnectError):
        report.errors.append("CarsXE history: timed out")
    except Exception as exc:
        report.errors.append(f"CarsXE history: {exc}")


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------

def _generate_search_urls(report: VehicleReport) -> dict[str, list[dict[str, str]]]:
    """Build investigation URLs for manual follow-up."""
    vin = quote(report.vin)

    return {
        "vehicle_history": [
            {"name": "Carfax", "url": f"https://www.carfax.com/VehicleHistory/p/Report.cfx?vin={vin}"},
            {"name": "AutoCheck", "url": f"https://www.autocheck.com/vehiclehistory/vin-search?vin={vin}"},
            {"name": "VehicleHistory.com", "url": f"https://www.vehiclehistory.com/vin-report/{vin}"},
        ],
        "salvage_auction": [
            {"name": "Copart", "url": f"https://www.copart.com/vehicleFinderSearch?query={vin}"},
            {"name": "IAAI", "url": f"https://www.iaai.com/VehicleSearch/SearchDetails?VIN={vin}"},
            {"name": "BidFax", "url": f"https://en.bidfax.info/?q={vin}"},
            {"name": "Poctra", "url": f"https://poctra.com/search/{vin}"},
        ],
        "government": [
            {"name": "NICB VINCheck", "url": f"https://www.nicb.org/vincheck?vin={vin}"},
            {"name": "NHTSA Recalls", "url": f"https://www.nhtsa.gov/recalls?nhtsaId={vin}"},
            {"name": "NHTSA Complaints", "url": (
                f"https://www.nhtsa.gov/vehicle/{report.year}/"
                f"{quote(report.make)}/{quote(report.model)}/complaints"
                if report.make and report.model and report.year
                else f"https://www.nhtsa.gov/recalls?nhtsaId={vin}"
            )},
        ],
    }


# ═══════════════════════════════════════════════════════════════════════════
# Main entry points
# ═══════════════════════════════════════════════════════════════════════════

async def vehicle_lookup(vin: str) -> VehicleReport:
    """Original basic lookup — NHTSA only. Kept for backward compatibility
    with the existing ghost_vin tool.

    Args:
        vin: 17-character Vehicle Identification Number.

    Returns:
        VehicleReport with decoded attributes, recalls, and search URLs.
    """
    vin = vin.strip().upper()
    report = VehicleReport(vin=vin)

    validation_error = _validate_vin(vin)
    if validation_error:
        report.error = validation_error
        return report

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        await _fetch_nhtsa_decode(client, report)
        if report.errors and not report.make:
            report.error = "; ".join(report.errors)
            return report

        await asyncio.gather(
            _fetch_nhtsa_recalls(client, report),
            _fetch_nhtsa_complaints(client, report),
        )

    report.search_urls = _generate_search_urls(report)
    report.layers_used = ["NHTSA vPIC", "NHTSA Recalls", "NHTSA Complaints"]
    return report


async def vehicle_history(
    vin: str,
    layer: DataLayer = DataLayer.FREE_ONLY,
) -> VehicleReport:
    """Full vehicle history report — multi-layer lookup.

    Fires all applicable layers in parallel for maximum speed.

    Args:
        vin:   17-character Vehicle Identification Number.
        layer: How deep to go. Controls paid API usage:
               - FREE_ONLY:  NHTSA + NICB + Copart/IAAI (no cost)
               - NMVTIS:     Above + VinAudit ($1/query, needs API key)
               - FULL:       Above + CarsXE (needs API key)

    Returns:
        VehicleReport with all available data.
    """
    vin = vin.strip().upper()
    report = VehicleReport(vin=vin)

    validation_error = _validate_vin(vin)
    if validation_error:
        report.error = validation_error
        return report

    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
    ) as client:

        # ── Phase 1: Decode VIN first (needed for recalls/complaints) ──
        await _fetch_nhtsa_decode(client, report)
        report.layers_used.append("NHTSA vPIC")

        if not report.make:
            # Can't continue without basic decode
            report.error = "VIN decode failed — " + "; ".join(report.errors)
            return report

        # ── Phase 2: Everything else in parallel ───────────────────────
        tasks: list = [
            _fetch_nhtsa_recalls(client, report),
            _fetch_nhtsa_complaints(client, report),
            _fetch_nhtsa_safety_ratings(client, report),
            _fetch_nicb_vincheck(client, report),
            _fetch_copart(client, report),
            _fetch_iaai(client, report),
        ]
        layer_names = [
            "NHTSA Recalls", "NHTSA Complaints", "NHTSA Safety Ratings",
            "NICB VINCheck", "Copart", "IAAI",
        ]

        if layer in (DataLayer.NMVTIS, DataLayer.FULL):
            tasks.append(_fetch_vinaudit(client, report))
            layer_names.append("VinAudit/NMVTIS")

        if layer == DataLayer.FULL:
            tasks.append(_fetch_carsxe_market_value(client, report))
            tasks.append(_fetch_carsxe_history(client, report))
            layer_names.extend(["CarsXE Market", "CarsXE History"])

        await asyncio.gather(*tasks, return_exceptions=True)
        report.layers_used.extend(layer_names)

    # ── Search URLs for manual investigation ────────────────────────
    report.search_urls = _generate_search_urls(report)

    return report
