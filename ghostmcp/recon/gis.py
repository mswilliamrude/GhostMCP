"""GIS property and parcel lookup — nationwide property data with owner enrichment.

Supports multiple data sources:
- Regrid API (nationwide, requires GHOST_REGRID_KEY)
- State GIS endpoints (Texas, New York, Florida, Colorado)
- County ArcGIS endpoints

Enriches owner data with people search for alternate addresses and contact info.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import quote

import httpx


@dataclass
class GISResult:
    """Property/parcel lookup result."""
    
    # Property identification
    parcel_id: str = ""
    address: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = ""
    county: str = ""
    coordinates: tuple[float, float] = (0.0, 0.0)  # lat, lon
    
    # Land info
    acreage: float = 0.0
    zoning: str = ""
    land_use: str = ""
    legal_description: str = ""
    
    # Valuation
    land_value: float = 0.0
    improvement_value: float = 0.0
    total_value: float = 0.0
    tax_year: int = 0
    
    # Owner info
    owner_name: str = ""
    owner_type: str = ""  # individual, llc, trust, corporation
    mailing_address: str = ""
    mailing_city: str = ""
    mailing_state: str = ""
    mailing_zip: str = ""
    
    # Building info (if available)
    year_built: int = 0
    building_sqft: int = 0
    bedrooms: int = 0
    bathrooms: float = 0.0
    
    # Enrichment (populated by people search)
    alternate_addresses: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    associated_names: list[str] = field(default_factory=list)
    
    # Metadata
    source: str = ""  # regrid, texas, newyork, florida, etc.
    raw_data: dict = field(default_factory=dict)
    
    # Investigation URLs
    search_urls: dict[str, str] = field(default_factory=dict)


class GISError(Exception):
    """GIS lookup error."""
    pass


# ---------------------------------------------------------------------------
# Geocoding (Nominatim - free, no key required)
# ---------------------------------------------------------------------------

async def geocode_address(address: str) -> tuple[float, float]:
    """Geocode an address to lat/lon using Nominatim.
    
    Returns (lat, lon) tuple or raises GISError.
    """
    url = "https://nominatim.openstreetmap.org/search"
    params = {
        "q": address,
        "format": "json",
        "limit": 1,
        "addressdetails": 1,
    }
    headers = {
        "User-Agent": "GhostMCP/1.0 (OSINT toolkit)",
    }
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            
            if not data:
                raise GISError(f"Could not geocode address: {address}")
            
            lat = float(data[0]["lat"])
            lon = float(data[0]["lon"])
            return (lat, lon)
    except httpx.RequestError as e:
        raise GISError(f"Geocoding failed: {e}")


async def reverse_geocode(lat: float, lon: float) -> dict:
    """Reverse geocode coordinates to address components."""
    url = "https://nominatim.openstreetmap.org/reverse"
    params = {
        "lat": lat,
        "lon": lon,
        "format": "json",
        "addressdetails": 1,
    }
    headers = {
        "User-Agent": "GhostMCP/1.0 (OSINT toolkit)",
    }
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()
            return resp.json()
    except httpx.RequestError:
        return {}


# ---------------------------------------------------------------------------
# Regrid API (nationwide, requires API key)
# ---------------------------------------------------------------------------

async def regrid_lookup(
    address: str = "",
    lat: float = 0.0,
    lon: float = 0.0,
    parcel_id: str = "",
    county: str = "",
    state: str = "",
) -> GISResult:
    """Look up parcel via Regrid API.
    
    Requires GHOST_REGRID_KEY environment variable.
    Free tier: 25 lookups/day.
    """
    api_key = os.environ.get("GHOST_REGRID_KEY", "")
    if not api_key:
        raise GISError(
            "GHOST_REGRID_KEY not set. "
            "Get a free key (25 lookups/day) at https://app.regrid.com/"
        )
    
    base_url = "https://app.regrid.com/api/v2/parcels"
    
    if lat and lon:
        url = f"{base_url}/point?lat={lat}&lon={lon}&token={api_key}"
    elif address:
        url = f"{base_url}/address?query={quote(address)}&token={api_key}"
    elif parcel_id and state:
        county_param = f"&county={quote(county)}" if county else ""
        url = f"{base_url}/apn?apn={quote(parcel_id)}&state={state}{county_param}&token={api_key}"
    else:
        raise GISError("Must provide address, coordinates, or parcel_id+state")
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url)
            
            if resp.status_code == 401:
                raise GISError("Invalid GHOST_REGRID_KEY")
            if resp.status_code == 403:
                raise GISError("Regrid rate limit exceeded (25/day free)")
            if resp.status_code == 404:
                raise GISError("Parcel not found")
            
            resp.raise_for_status()
            data = resp.json()
    except httpx.RequestError as e:
        raise GISError(f"Regrid API error: {e}")
    
    results = data.get("results", [])
    if not results:
        raise GISError("No parcel found")
    
    parcel = results[0]
    props = parcel.get("properties", {})
    
    # Parse owner type from name
    owner = props.get("owner", "")
    owner_type = _detect_owner_type(owner)
    
    result = GISResult(
        parcel_id=props.get("parcel_id", props.get("apn", "")),
        address=props.get("address", ""),
        city=props.get("city", ""),
        state=props.get("state2", props.get("state", "")),
        zip_code=props.get("zip", ""),
        county=props.get("county", ""),
        coordinates=(
            float(props.get("lat", 0)),
            float(props.get("lon", 0)),
        ),
        acreage=float(props.get("acreage", 0) or 0),
        zoning=props.get("zoning", ""),
        land_use=props.get("land_use_code", props.get("usedesc", "")),
        legal_description=props.get("legaldesc", ""),
        land_value=float(props.get("land_value", 0) or 0),
        improvement_value=float(props.get("improvement_value", 0) or 0),
        total_value=float(props.get("total_value", props.get("market_value", 0)) or 0),
        tax_year=int(props.get("tax_year", 0) or 0),
        owner_name=owner,
        owner_type=owner_type,
        mailing_address=props.get("mail_address", props.get("mailadd", "")),
        mailing_city=props.get("mail_city", ""),
        mailing_state=props.get("mail_state2", props.get("mail_state", "")),
        mailing_zip=props.get("mail_zip", ""),
        year_built=int(props.get("year_built", 0) or 0),
        building_sqft=int(props.get("building_sq_ft", props.get("sqft", 0)) or 0),
        bedrooms=int(props.get("bedrooms", 0) or 0),
        bathrooms=float(props.get("bathrooms", 0) or 0),
        source="regrid",
        raw_data=props,
    )
    
    # Generate investigation URLs
    result.search_urls = _generate_search_urls(result)
    
    return result


# ---------------------------------------------------------------------------
# State GIS Endpoints (ArcGIS REST)
# ---------------------------------------------------------------------------

# State endpoint registry
STATE_ENDPOINTS = {
    "TX": {
        "name": "Texas (TNRIS)",
        "url": "https://feature.tnris.org/arcgis/rest/services/Parcels/stratmap19_land_parcels_48/MapServer/0",
        "fields": {
            "parcel_id": "prop_id",
            "address": ["situs_num", "situs_street"],
            "city": "situs_city",
            "owner": "owner",
            "acres": "acres",
            "legal": "legal_desc",
        },
    },
    "NY": {
        "name": "New York State",
        "url": "https://gisservices.its.ny.gov/arcgis/rest/services/NYS_Tax_Parcels_Public/MapServer/0",
        "fields": {
            "parcel_id": "PARCEL_ID",
            "address": "LOCATION",
            "city": "MUNI_NAME",
            "county": "COUNTY_NAME",
            "owner": "OWNER_NAME",
            "mail_address": "MAIL_ADDR",
            "land_value": "LAND_AV",
            "total_value": "FULL_MV",
            "tax_year": "ROLL_YEAR",
        },
    },
    "FL": {
        "name": "Florida",
        "url": "https://services9.arcgis.com/Gh9awoU677aKree0/arcgis/rest/services/Florida_Statewide_Cadastral/FeatureServer/0",
        "fields": {
            "parcel_id": "PARCELNO",
            "address": "PHY_ADDR1",
            "city": "PHY_CITY",
            "owner": "OWNER1",
            "mail_address": "OWN_ADDR1",
            "mail_city": "OWN_CITY",
            "mail_state": "OWN_STATE",
            "mail_zip": "OWN_ZIPCD",
            "acres": "ACRES",
            "land_value": "AV_LAND",
            "improvement_value": "AV_IMPR",
            "total_value": "JV",
        },
    },
    "CO": {
        "name": "Colorado",
        "url": "https://gis.colorado.gov/Public/rest/services/Parcels/Public_Parcel_Map_Services/MapServer/0",
        "fields": {
            "parcel_id": "PARCEL_ID",
            "address": "SITE_ADDR",
            "owner": "OWNER_NAME",
            "mail_address": "MAIL_ADDR",
            "county": "COUNTY",
            "subdivision": "SUBDIVISION",
            "zoning": "ZONING",
            "land_use": "LAND_USE",
            "assessor_link": "ASMT_LINK",
        },
    },
}


async def arcgis_query(
    endpoint_url: str,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    parcel_id: str = "",
    parcel_field: str = "PARCEL_ID",
) -> dict:
    """Query an ArcGIS REST endpoint.
    
    Returns raw feature attributes or raises GISError.
    """
    params = {
        "f": "json",
        "outFields": "*",
        "returnGeometry": "true",
    }
    
    # Check if coordinates were provided (0.0 is a valid coordinate, None means not provided)
    has_coords = lat is not None and lon is not None
    
    if has_coords:
        params["geometry"] = f"{lon},{lat}"
        params["geometryType"] = "esriGeometryPoint"
        params["spatialRel"] = "esriSpatialRelIntersects"
        params["inSR"] = "4326"  # WGS84
    elif parcel_id:
        # Escape single quotes in parcel ID
        safe_id = parcel_id.replace("'", "''")
        params["where"] = f"{parcel_field}='{safe_id}'"
    else:
        raise GISError("Must provide coordinates or parcel_id")
    
    url = f"{endpoint_url}/query"
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.RequestError as e:
        raise GISError(f"ArcGIS query failed: {e}")
    
    if "error" in data:
        raise GISError(f"ArcGIS error: {data['error'].get('message', 'Unknown')}")
    
    features = data.get("features", [])
    if not features:
        raise GISError("No parcel found at location")
    
    return features[0].get("attributes", {})


async def state_gis_lookup(
    state: str,
    lat: float = 0.0,
    lon: float = 0.0,
    parcel_id: str = "",
) -> GISResult:
    """Look up parcel via state GIS endpoint."""
    state = state.upper()
    
    if state not in STATE_ENDPOINTS:
        available = ", ".join(STATE_ENDPOINTS.keys())
        raise GISError(f"State '{state}' not supported. Available: {available}")
    
    config = STATE_ENDPOINTS[state]
    field_map = config["fields"]
    
    attrs = await arcgis_query(
        config["url"],
        lat=lat,
        lon=lon,
        parcel_id=parcel_id,
        parcel_field=field_map.get("parcel_id", "PARCEL_ID"),
    )
    
    def get_field(key: str, default: str = "") -> str:
        field_name = field_map.get(key)
        if isinstance(field_name, list):
            # Concatenate multiple fields (e.g., address components)
            parts = [str(attrs.get(f, "")).strip() for f in field_name]
            return " ".join(p for p in parts if p)
        return str(attrs.get(field_name, default) or default).strip()
    
    owner = get_field("owner")
    
    result = GISResult(
        parcel_id=get_field("parcel_id"),
        address=get_field("address"),
        city=get_field("city"),
        state=state,
        county=get_field("county"),
        coordinates=(lat, lon) if lat and lon else (0.0, 0.0),
        acreage=float(get_field("acres") or 0),
        zoning=get_field("zoning"),
        land_use=get_field("land_use"),
        legal_description=get_field("legal"),
        land_value=float(get_field("land_value") or 0),
        improvement_value=float(get_field("improvement_value") or 0),
        total_value=float(get_field("total_value") or 0),
        tax_year=int(get_field("tax_year") or 0),
        owner_name=owner,
        owner_type=_detect_owner_type(owner),
        mailing_address=get_field("mail_address"),
        mailing_city=get_field("mail_city"),
        mailing_state=get_field("mail_state"),
        mailing_zip=get_field("mail_zip"),
        source=f"state:{state.lower()}",
        raw_data=attrs,
    )
    
    result.search_urls = _generate_search_urls(result)
    
    return result


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _detect_owner_type(owner_name: str) -> str:
    """Detect owner type from name patterns."""
    if not owner_name:
        return "unknown"
    
    owner_upper = owner_name.upper()
    
    # Order matters - more specific patterns first
    if any(x in owner_upper for x in ["LLC", "L.L.C.", "LIMITED LIABILITY"]):
        return "llc"
    # Trust patterns: TRUST, TRUSTEE, " TR" at end or followed by space, LIVING/FAMILY TRUST
    if any(x in owner_upper for x in ["TRUST", "TRUSTEE", "LIVING TRUST", "FAMILY TRUST"]):
        return "trust"
    if re.search(r'\bTR\b', owner_upper):  # TR as standalone word
        return "trust"
    # Financial before corporation (MORTGAGE COMPANY should be financial)
    if any(x in owner_upper for x in ["BANK", "CREDIT UNION", "MORTGAGE", "LENDING"]):
        return "financial"
    if any(x in owner_upper for x in ["INC", "INC.", "CORP", "CORPORATION", "CO.", "COMPANY"]):
        return "corporation"
    if any(x in owner_upper for x in ["LP", "L.P.", "LIMITED PARTNERSHIP", "LTD"]):
        return "partnership"
    if any(x in owner_upper for x in ["CITY OF", "COUNTY OF", "STATE OF", "UNITED STATES", "USA"]):
        return "government"
    
    return "individual"


def _generate_search_urls(result: GISResult) -> dict[str, str]:
    """Generate investigation URLs for manual research."""
    urls = {}
    
    # County assessor (if we have county + state)
    if result.county and result.state:
        county_slug = result.county.lower().replace(" ", "-")
        urls["county_assessor"] = f"https://www.google.com/search?q={quote(result.county)}+{result.state}+property+assessor"
    
    # People search (if individual owner)
    if result.owner_name and result.owner_type == "individual":
        # Parse name (simple first/last split)
        parts = result.owner_name.replace(",", " ").split()
        if len(parts) >= 2:
            # Assume "LAST, FIRST" or "FIRST LAST" format
            if "," in result.owner_name:
                last, first = parts[0], parts[1]
            else:
                first, last = parts[0], parts[-1]
            
            state = result.state or result.mailing_state
            urls["truepeoplesearch"] = f"https://www.truepeoplesearch.com/results?name={quote(first)}%20{quote(last)}&citystatezip={quote(state)}"
            urls["fastpeoplesearch"] = f"https://www.fastpeoplesearch.com/name/{quote(first.lower())}-{quote(last.lower())}_{quote(state.lower())}"
            urls["whitepages"] = f"https://www.whitepages.com/name/{quote(first)}-{quote(last)}/{quote(state)}"
    
    # Business search (if not individual)
    if result.owner_type in ("llc", "corporation", "partnership"):
        urls["opencorporates"] = f"https://opencorporates.com/companies?q={quote(result.owner_name)}&jurisdiction_code={result.state.lower()}"
        urls["sec_edgar"] = f"https://www.sec.gov/cgi-bin/browse-edgar?company={quote(result.owner_name)}&type=&dateb=&owner=include&count=40&action=getcompany"
    
    # Property history
    if result.address:
        full_addr = f"{result.address}, {result.city}, {result.state}"
        urls["zillow"] = f"https://www.zillow.com/homes/{quote(full_addr)}"
        urls["redfin"] = f"https://www.redfin.com/search?term={quote(full_addr)}"
    
    # Parcel map
    if result.coordinates[0] and result.coordinates[1]:
        lat, lon = result.coordinates
        urls["google_maps"] = f"https://www.google.com/maps?q={lat},{lon}"
        urls["regrid"] = f"https://app.regrid.com/us?lat={lat}&lng={lon}&zoom=18"
    
    return urls


# ---------------------------------------------------------------------------
# Main Lookup Function
# ---------------------------------------------------------------------------

async def gis_lookup(
    address: str = "",
    lat: float = 0.0,
    lon: float = 0.0,
    parcel_id: str = "",
    county: str = "",
    state: str = "",
    provider: str = "auto",
    enrich_owner: bool = True,
) -> GISResult:
    """Look up property/parcel data.
    
    Args:
        address: Street address to look up
        lat, lon: Coordinates (WGS84)
        parcel_id: Parcel ID / APN
        county: County name (helps with parcel_id lookups)
        state: State abbreviation (e.g., 'TX', 'NY')
        provider: 'auto', 'regrid', 'state', or specific state code
        enrich_owner: Whether to enrich owner with people search URLs
    
    Returns:
        GISResult with property and owner information
    
    Raises:
        GISError on lookup failure
    """
    # If address provided but no coordinates, geocode first
    if address and not (lat and lon):
        lat, lon = await geocode_address(address)
    
    # Detect state from address if not provided
    if not state and address:
        # Simple state extraction from address
        state_match = re.search(r'\b([A-Z]{2})\b(?:\s+\d{5})?$', address.upper())
        if state_match:
            state = state_match.group(1)
    
    # Provider selection
    if provider == "auto":
        # Try Regrid first if key available
        if os.environ.get("GHOST_REGRID_KEY"):
            provider = "regrid"
        # Fall back to state endpoint if available
        elif state and state.upper() in STATE_ENDPOINTS:
            provider = "state"
        else:
            raise GISError(
                "No provider available. Either:\n"
                "  1. Set GHOST_REGRID_KEY for nationwide coverage, or\n"
                "  2. Provide a state with GIS coverage (TX, NY, FL, CO)"
            )
    
    # Execute lookup
    if provider == "regrid":
        result = await regrid_lookup(
            address=address,
            lat=lat,
            lon=lon,
            parcel_id=parcel_id,
            county=county,
            state=state,
        )
    elif provider == "state" or provider.upper() in STATE_ENDPOINTS:
        target_state = state if provider == "state" else provider
        result = await state_gis_lookup(
            state=target_state,
            lat=lat,
            lon=lon,
            parcel_id=parcel_id,
        )
    else:
        raise GISError(f"Unknown provider: {provider}")
    
    # Store coordinates if we geocoded
    if lat and lon and not result.coordinates[0]:
        result.coordinates = (lat, lon)
    
    return result
