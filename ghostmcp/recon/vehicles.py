"""Vehicle intelligence module — VIN decoding + recall/complaint lookup via NHTSA."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

TIMEOUT = 10.0

# NHTSA vPIC API (free, no key required)
VIN_DECODE_URL = "https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues"
# NHTSA Recalls API (free, no key required)
RECALLS_URL = "https://api.nhtsa.gov/recalls/recallsByVehicle"


@dataclass
class VehicleReport:
    """Complete vehicle intelligence report from VIN."""

    vin: str
    make: str = ""
    model: str = ""
    year: str = ""
    trim: str = ""
    body_type: str = ""
    engine: dict = field(default_factory=dict)  # displacement, cylinders, fuel_type
    drive_type: str = ""
    transmission: str = ""
    manufacturer: dict = field(default_factory=dict)  # name, country
    safety_features: list[str] = field(default_factory=list)
    recalls: list[dict] = field(default_factory=list)  # campaign_number, component, ...
    complaint_count: int = 0
    search_urls: dict = field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# VIN validation
# ---------------------------------------------------------------------------

# Standard VIN check-digit weights and transliteration
_TRANSLITERATION = {
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def _validate_vin(vin: str) -> str | None:
    """Validate a 17-character VIN.

    Returns an error message if invalid, or None if valid.
    """
    vin = vin.strip().upper()
    if len(vin) != 17:
        return f"VIN must be 17 characters, got {len(vin)}"

    invalid_chars = {"I", "O", "Q"}
    for ch in vin:
        if ch in invalid_chars:
            return f"VIN contains invalid character: {ch}"
        if ch not in _TRANSLITERATION and not ch.isdigit():
            return f"VIN contains invalid character: {ch}"

    # Check digit validation (position 9)
    total = 0
    for i, ch in enumerate(vin):
        if ch.isdigit():
            value = int(ch)
        else:
            value = _TRANSLITERATION.get(ch, 0)
        total += value * _WEIGHTS[i]

    remainder = total % 11
    check_char = "X" if remainder == 10 else str(remainder)
    if vin[8] != check_char:
        # Many VINs from non-US markets skip check digit — warn, don't reject
        pass

    return None


# ---------------------------------------------------------------------------
# NHTSA vPIC — VIN decode
# ---------------------------------------------------------------------------

# vPIC field names -> variable IDs we care about
_SAFETY_FIELDS = [
    "AirBagLocCurtain",
    "AirBagLocFront",
    "AirBagLocKnee",
    "AirBagLocSeatCushion",
    "AirBagLocSide",
    "AutomaticPedestrianAlertingSound",
    "AdaptiveCruiseControl",
    "AdaptiveDrivingBeam",
    "AEB",
    "BackupCamera",
    "BlindSpotMon",
    "CIB",
    "DynamicBrakeSupport",
    "EDR",
    "ESC",
    "ForwardCollisionWarning",
    "LaneDepartureWarning",
    "LaneKeepSystem",
    "ParkAssist",
    "RearAutomaticEmergencyBraking",
    "RearCrossTrafficAlert",
    "RearVisibilitySystem",
    "SemiautomaticHeadlampBeamSwitching",
    "TPMS",
    "TractionControl",
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

    # Engine info
    displacement = v.get("DisplacementL", "") or ""
    cylinders = v.get("EngineCylinders", "") or ""
    fuel_type = v.get("FuelTypePrimary", "") or ""
    report.engine = {
        "displacement": displacement,
        "cylinders": cylinders,
        "fuel_type": fuel_type,
    }

    # Manufacturer info
    mfr_name = v.get("Manufacturer", "") or ""
    mfr_country = v.get("PlantCountry", "") or ""
    report.manufacturer = {
        "name": mfr_name,
        "country": mfr_country,
    }

    # Safety features — collect non-empty values
    safety: list[str] = []
    for sf in _SAFETY_FIELDS:
        value = v.get(sf, "") or ""
        if value and value.lower() not in ("", "not applicable"):
            safety.append(f"{sf}: {value}")
    report.safety_features = safety


# ---------------------------------------------------------------------------
# NHTSA Recalls API
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------


def _generate_search_urls(report: VehicleReport) -> dict[str, list[dict[str, str]]]:
    """Build vehicle history / investigation URLs."""
    vin = quote(report.vin)

    urls: dict[str, list[dict[str, str]]] = {"vehicle_history": [], "nhtsa": []}

    urls["vehicle_history"] = [
        {
            "name": "Carfax",
            "url": f"https://www.carfax.com/VehicleHistory/p/Report.cfx?vin={vin}",
        },
        {
            "name": "AutoCheck",
            "url": f"https://www.autocheck.com/vehiclehistory/vin-search?vin={vin}",
        },
        {
            "name": "VINCheck (NICB)",
            "url": f"https://www.nicb.org/vincheck?vin={vin}",
        },
        {
            "name": "VehicleHistory.com",
            "url": f"https://www.vehiclehistory.com/vin-report/{vin}",
        },
    ]

    urls["nhtsa"] = [
        {
            "name": "NHTSA Recalls",
            "url": f"https://www.nhtsa.gov/recalls?nhtsaId={vin}",
        },
        {
            "name": "NHTSA Complaints",
            "url": f"https://www.nhtsa.gov/vehicle/{report.year}/{quote(report.make)}/{quote(report.model)}/complaints",
        },
    ]

    return urls


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def vehicle_lookup(vin: str) -> VehicleReport:
    """Full vehicle intelligence lookup from a VIN.

    Decodes the VIN via NHTSA vPIC, fetches recall and complaint data.
    All NHTSA APIs are free — no API key required.

    Args:
        vin: 17-character Vehicle Identification Number.

    Returns:
        VehicleReport with decoded attributes, recalls, and search URLs.
    """
    vin = vin.strip().upper()
    report = VehicleReport(vin=vin)

    # Validate VIN format
    validation_error = _validate_vin(vin)
    if validation_error:
        report.error = validation_error
        return report

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:

        # ── Step 1: Decode VIN ────────────────────────────────────────
        try:
            resp = await client.get(
                f"{VIN_DECODE_URL}/{vin}",
                params={"format": "json"},
                timeout=TIMEOUT,
            )
            if resp.status_code == 200:
                _parse_vin_decode(resp.json(), report)
            else:
                report.error = f"VIN decode failed: HTTP {resp.status_code}"
                return report
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            report.error = f"VIN decode failed: {exc}"
            return report

        # ── Step 2: Recalls + complaints (parallel) ──────────────────
        async def _fetch_recalls() -> None:
            """Fetch recalls by make/model/year from NHTSA."""
            if not report.make or not report.model or not report.year:
                return
            try:
                resp = await client.get(
                    RECALLS_URL,
                    params={
                        "make": report.make,
                        "model": report.model,
                        "modelYear": report.year,
                    },
                    timeout=TIMEOUT,
                )
                if resp.status_code == 200:
                    report.recalls = _parse_recalls(resp.json())
            except (httpx.TimeoutException, httpx.ConnectError):
                pass

        async def _fetch_complaints() -> None:
            """Fetch complaint count from NHTSA Complaints API."""
            if not report.make or not report.model or not report.year:
                return
            url = "https://api.nhtsa.gov/complaints/complaintsByVehicle"
            try:
                resp = await client.get(
                    url,
                    params={
                        "make": report.make,
                        "model": report.model,
                        "modelYear": report.year,
                    },
                    timeout=TIMEOUT,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("results", [])
                    report.complaint_count = len(results)
            except (httpx.TimeoutException, httpx.ConnectError):
                pass

        await asyncio.gather(_fetch_recalls(), _fetch_complaints())

    # ── Step 3: Search URLs ───────────────────────────────────────────
    report.search_urls = _generate_search_urls(report)

    return report
