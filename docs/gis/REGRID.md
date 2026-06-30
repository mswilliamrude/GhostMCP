# Regrid API Documentation

Regrid provides nationwide parcel data for the US and Canada via REST API.

**Website:** https://regrid.com/  
**API Docs:** https://support.regrid.com/api/  
**Pricing:** 25 free lookups/day, then $0.001/request  

---

## Authentication

Set `GHOST_REGRID_KEY` environment variable with your API token.

```bash
export GHOST_REGRID_KEY="your-api-token-here"
```

Get a free API key at: https://app.regrid.com/

---

## API Endpoints

### Base URL
```
https://app.regrid.com/api/v2
```

### Parcel Search by Address

```bash
GET /api/v2/parcels/address?query={address}&token={token}
```

**Example:**
```bash
curl "https://app.regrid.com/api/v2/parcels/address?\
query=123+Main+St,+Austin,+TX&\
token=${GHOST_REGRID_KEY}"
```

**Response:**
```json
{
  "results": [
    {
      "ll_uuid": "abc123...",
      "properties": {
        "address": "123 MAIN ST",
        "city": "AUSTIN",
        "state": "TX",
        "zip": "78701",
        "county": "Travis",
        "owner": "DOE, JOHN",
        "mail_address": "PO BOX 456",
        "mail_city": "AUSTIN",
        "mail_state": "TX",
        "mail_zip": "78702",
        "parcel_id": "123-456-789",
        "acreage": 0.25,
        "land_value": 150000,
        "improvement_value": 350000,
        "total_value": 500000,
        "zoning": "SF-3",
        "land_use_code": "A1",
        "year_built": 1985
      },
      "geometry": {
        "type": "Polygon",
        "coordinates": [...]
      }
    }
  ]
}
```

---

### Parcel Search by Coordinates

```bash
GET /api/v2/parcels/point?lat={lat}&lon={lon}&token={token}
```

**Example:**
```bash
curl "https://app.regrid.com/api/v2/parcels/point?\
lat=30.2672&\
lon=-97.7431&\
token=${GHOST_REGRID_KEY}"
```

---

### Parcel Search by Parcel ID / APN

```bash
GET /api/v2/parcels/apn?apn={parcel_id}&county={county}&state={state}&token={token}
```

**Example:**
```bash
curl "https://app.regrid.com/api/v2/parcels/apn?\
apn=123-456-789&\
county=Travis&\
state=TX&\
token=${GHOST_REGRID_KEY}"
```

---

### Typeahead / Autocomplete

For address autocomplete during input:

```bash
GET /api/v2/typeahead?query={partial_address}&token={token}
```

**Example:**
```bash
curl "https://app.regrid.com/api/v2/typeahead?\
query=123+Main&\
token=${GHOST_REGRID_KEY}"
```

---

### Account Usage

Check your API usage (no cost):

```bash
GET /api/v2/account/usage?token={token}
```

---

## Response Fields

### Core Fields (Always Available)
| Field | Description |
|-------|-------------|
| `ll_uuid` | Regrid unique identifier |
| `parcel_id` | Assessor Parcel Number (APN) |
| `address` | Site/property address |
| `city` | City |
| `state` | State |
| `zip` | ZIP code |
| `county` | County name |

### Owner Fields (Most Parcels)
| Field | Description |
|-------|-------------|
| `owner` | Owner name(s) |
| `mail_address` | Mailing address line 1 |
| `mail_address2` | Mailing address line 2 |
| `mail_city` | Mailing city |
| `mail_state` | Mailing state |
| `mail_zip` | Mailing ZIP |

### Value Fields (Where Available)
| Field | Description |
|-------|-------------|
| `land_value` | Assessed land value |
| `improvement_value` | Building/improvement value |
| `total_value` | Total assessed value |
| `tax_amount` | Annual tax amount |

### Property Fields
| Field | Description |
|-------|-------------|
| `acreage` | Lot size in acres |
| `sq_ft` | Lot size in square feet |
| `zoning` | Zoning code |
| `land_use_code` | Land use classification |
| `year_built` | Year structure built |
| `bedrooms` | Number of bedrooms |
| `bathrooms` | Number of bathrooms |
| `building_sq_ft` | Building square footage |

---

## Rate Limits

| Tier | Limit | Cost |
|------|-------|------|
| Free (Starter) | 25 requests/day | $0 |
| Pro | 1,000 requests/day | ~$30/month |
| Team | 10,000 requests/day | ~$200/month |
| Enterprise | Unlimited | Custom |

---

## Error Responses

```json
{
  "error": "Invalid API token",
  "code": 401
}
```

| Code | Meaning |
|------|---------|
| 400 | Bad request (missing/invalid params) |
| 401 | Invalid or missing API token |
| 403 | Rate limit exceeded |
| 404 | Parcel not found |
| 500 | Server error |

---

## Best Practices

1. **Cache results** — Parcel data rarely changes (annual updates)
2. **Use typeahead** — Validate addresses before full lookup
3. **Check usage** — Monitor daily quota with `/account/usage`
4. **Handle missing data** — Not all fields available for all parcels
5. **Prefer coordinates** — More reliable than address matching

---

## Integration Notes for GhostMCP

```python
# ghost_gis implementation pattern
async def regrid_lookup(address: str = "", lat: float = 0, lon: float = 0) -> dict:
    api_key = os.environ.get("GHOST_REGRID_KEY")
    if not api_key:
        raise GISError("GHOST_REGRID_KEY not set")
    
    base = "https://app.regrid.com/api/v2/parcels"
    
    if lat and lon:
        url = f"{base}/point?lat={lat}&lon={lon}&token={api_key}"
    elif address:
        url = f"{base}/address?query={quote(address)}&token={api_key}"
    else:
        raise GISError("Must provide address or coordinates")
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json()
```

---

## See Also

- [Regrid Support](https://support.regrid.com/)
- [Regrid Data Store](https://app.regrid.com/us)
- [API v1 Docs](https://support.regrid.com/api/parcel-api-v1-endpoints) (legacy)
