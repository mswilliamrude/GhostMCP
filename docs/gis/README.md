# GIS Data Sources for ghost_gis

This directory documents publicly accessible GIS APIs for parcel and property data lookup.

## Coverage Summary

| Provider | Coverage | Cost | API Type | Owner Data |
|----------|----------|------|----------|------------|
| **Regrid** | US + Canada nationwide | 25 free/day, then $0.001/req | REST JSON | Yes |
| **Texas (TNRIS)** | 222/254 counties | Free | ArcGIS REST | Limited |
| **New York** | ~40 counties + NYC | Free | ArcGIS REST | Yes |
| **Florida** | All 67 counties | Free | ArcGIS REST | Yes |
| **Colorado** | 32+ counties | Free | ArcGIS REST | Yes |
| **California** | County-by-county | Free | ArcGIS REST | Varies |
| **Georgia** | County-by-county | Free | Varies | Varies |
| **Arizona (Maricopa)** | Maricopa County | Free | ArcGIS REST | Yes |

## Documentation Files

- [STATE_APIS.md](STATE_APIS.md) — State-level GIS REST endpoints
- [COUNTY_ENDPOINTS.md](COUNTY_ENDPOINTS.md) — Major county ArcGIS endpoints  
- [REGRID.md](REGRID.md) — Regrid API documentation
- [QUERY_PATTERNS.md](QUERY_PATTERNS.md) — Common ArcGIS REST query patterns

## Quick Start

### ArcGIS REST Query Pattern

Most state/county GIS services use ArcGIS REST. Basic query:

```
GET {service_url}/query?
    where=1=1
    &geometry={lon},{lat}
    &geometryType=esriGeometryPoint
    &spatialRel=esriSpatialRelIntersects
    &outFields=*
    &returnGeometry=true
    &f=json
```

### By Address (requires geocoding first)
```bash
# 1. Geocode address to lat/long (Nominatim - free)
curl "https://nominatim.openstreetmap.org/search?q=123+Main+St,+Austin,+TX&format=json"

# 2. Query parcel at coordinates
curl "https://feature.tnris.org/arcgis/rest/services/Parcels/.../query?geometry=-97.74,30.27&..."
```

### By Parcel ID
```
GET {service_url}/query?
    where=PARCEL_ID='123-456-789'
    &outFields=*
    &f=json
```

## Data Fields (Common)

| Field | Description | Availability |
|-------|-------------|--------------|
| `PARCEL_ID` / `APN` | Assessor Parcel Number | Universal |
| `OWNER_NAME` | Property owner | Most states |
| `MAIL_ADDR` | Mailing address (often different!) | Many states |
| `SITE_ADDR` | Property address | Universal |
| `ACREAGE` | Lot size | Universal |
| `LAND_VALUE` | Assessed land value | Most states |
| `IMPR_VALUE` | Improvement (building) value | Most states |
| `TOTAL_VALUE` | Total assessed value | Most states |
| `ZONING` | Zoning code | Many states |
| `LAND_USE` | Land use code | Most states |
| `YEAR_BUILT` | Structure year built | Some states |

## Limitations

1. **No nationwide free API** — Must query state-by-state or use Regrid
2. **Owner data restrictions** — Some counties redact owner names from public GIS
3. **Update frequency** — Typically annual (tax roll refresh)
4. **Rate limits** — ArcGIS REST typically allows 1000 records/query
5. **CORS** — Many county servers don't set CORS headers (need server-side proxy)

## See Also

- [Regrid API Docs](https://support.regrid.com/api/)
- [ArcGIS REST API Reference](https://developers.arcgis.com/rest/)
- [Nominatim Geocoding](https://nominatim.org/release-docs/latest/api/Search/)
