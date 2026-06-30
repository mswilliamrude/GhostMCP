# State-Level GIS Parcel APIs

Publicly accessible ArcGIS REST endpoints for statewide parcel data.

---

## Texas (TNRIS)

**Coverage:** 222 of 254 counties  
**Update Frequency:** Annual (2019 schema, ongoing updates)  
**Data Portal:** https://data.tnris.org/

### REST Endpoints

```
MapServer:
https://feature.tnris.org/arcgis/rest/services/Parcels/stratmap19_land_parcels_48/MapServer

Layer 0 (Parcels):
https://feature.tnris.org/arcgis/rest/services/Parcels/stratmap19_land_parcels_48/MapServer/0
```

### Query Example

```bash
# Query by coordinates (WGS84)
curl "https://feature.tnris.org/arcgis/rest/services/Parcels/stratmap19_land_parcels_48/MapServer/0/query?\
geometry=-97.7431,30.2672&\
geometryType=esriGeometryPoint&\
spatialRel=esriSpatialRelIntersects&\
outFields=*&\
returnGeometry=true&\
f=json"
```

### Key Fields
- `prop_id` — Parcel ID
- `geo_id` — Geographic ID
- `situs_num`, `situs_street`, `situs_city` — Property address
- `owner` — Owner name (limited availability)
- `legal_desc` — Legal description
- `acres` — Acreage

### Notes
- Owner name data varies by county participation
- MaxRecordCount: 2000
- Contact: TNRIS at tnris@twdb.texas.gov

---

## New York State

**Coverage:** ~40 counties + NYC (via MapPLUTO)  
**Update Frequency:** Annual  
**Data Portal:** https://gis.ny.gov/parcels/

### REST Endpoints

```
Public Parcels (Statewide):
https://gisservices.its.ny.gov/arcgis/rest/services/NYS_Tax_Parcels_Public/MapServer

Layer 0:
https://gisservices.its.ny.gov/arcgis/rest/services/NYS_Tax_Parcels_Public/MapServer/0

State-Owned Parcels:
https://gisservices.its.ny.gov/arcgis/rest/services/NYS_Tax_Parcels_State_Owned/MapServer

Parcel Centroids:
https://gisservices.its.ny.gov/arcgis/rest/services/NYS_Tax_Parcel_Centroid_Points/MapServer
```

### Query Example

```bash
# Query by coordinates
curl "https://gisservices.its.ny.gov/arcgis/rest/services/NYS_Tax_Parcels_Public/MapServer/0/query?\
geometry=-73.9857,40.7484&\
geometryType=esriGeometryPoint&\
spatialRel=esriSpatialRelIntersects&\
outFields=*&\
f=json"
```

### Key Fields
- `PARCEL_ID` — Parcel identifier
- `COUNTY_NAME` — County
- `MUNI_NAME` — Municipality
- `OWNER_NAME` — Owner name
- `MAIL_ADDR` — Mailing address
- `PROP_CLASS` — Property class code
- `ROLL_YEAR` — Tax roll year
- `FULL_MV` — Full market value
- `AV_TOTAL` — Assessed value total
- `LAND_AV` — Land assessed value

### Participating Counties
Albany, Broome, Cayuga, Chautauqua, Cortland, Erie, Genesee, Greene, Hamilton, Lewis, Livingston, Montgomery, NYC (all 5 boroughs), Onondaga, Oneida, Ontario, Orange, Oswego, Otsego, Putnam, Rensselaer, Rockland, Schuyler, St Lawrence, Steuben, Suffolk, Sullivan, Tioga, Tompkins, Ulster, Warren, Wayne, Westchester

### NYC Note
NYC data comes from MapPLUTO: https://www.nyc.gov/content/planning/pages/resources/datasets/mappluto-pluto-change

---

## Florida

**Coverage:** All 67 counties  
**Update Frequency:** Annual (July tax roll)  
**Data Portal:** https://geodata.floridagio.gov/

### REST Endpoints

```
Statewide Cadastral (Primary):
https://services9.arcgis.com/Gh9awoU677aKree0/arcgis/rest/services/Florida_Statewide_Cadastral/FeatureServer

Layer 0:
https://services9.arcgis.com/Gh9awoU677aKree0/arcgis/rest/services/Florida_Statewide_Cadastral/FeatureServer/0

FDOT Parcels:
https://gis.fdot.gov/arcgis/rest/services/Parcels/FeatureServer
https://gis.fdot.gov/arcgis/rest/services/Parcels/MapServer
```

### Query Example

```bash
# Query by coordinates (Miami area)
curl "https://services9.arcgis.com/Gh9awoU677aKree0/arcgis/rest/services/Florida_Statewide_Cadastral/FeatureServer/0/query?\
geometry=-80.1918,25.7617&\
geometryType=esriGeometryPoint&\
spatialRel=esriSpatialRelIntersects&\
outFields=*&\
f=json"
```

### Key Fields
- `PARCELNO` — Parcel number
- `CO_NO` — County number (01-67)
- `OWNER1`, `OWNER2` — Owner names
- `OWN_ADDR1`, `OWN_CITY`, `OWN_STATE`, `OWN_ZIPCD` — Mailing address
- `PHY_ADDR1`, `PHY_CITY`, `PHY_ZIPCD` — Physical address
- `DOR_UC` — Department of Revenue Use Code
- `JV` — Just (market) value
- `AV_LAND`, `AV_IMPR` — Assessed values
- `ACRES` — Acreage
- `NO_BULDNG` — Number of buildings

### Notes
- MaxRecordCount: 1000
- Data joined with NAL (Name-Address-Legal) file
- Contact: Ana Nowak, 850-410-4365

---

## Colorado

**Coverage:** 32+ counties  
**Update Frequency:** Varies by county  
**Data Portal:** https://geodata.colorado.gov/

### REST Endpoints

```
Public Parcel MapServer:
https://gis.colorado.gov/Public/rest/services/Parcels/Public_Parcel_Map_Services/MapServer

Layer 0:
https://gis.colorado.gov/Public/rest/services/Parcels/Public_Parcel_Map_Services/MapServer/0

All Services:
https://gis.colorado.gov/public/rest/services/
```

### Participating Counties
Adams, Arapahoe, Archuleta, Boulder, Broomfield, Clear Creek, Custer, Denver, Delta, Douglas, Eagle, El Paso, Garfield, Gilpin, Grand, Jefferson, Lake, La Plata, Larimer, Logan, Mesa, Montezuma, Morgan, Ouray, Park, Pitkin, Pueblo, Rio Blanco, Routt, San Miguel, Sedgwick, Weld

### Key Fields
- `PARCEL_ID` — Parcel identifier
- `COUNTY` — County name
- `OWNER_NAME` — Owner
- `SITE_ADDR` — Site address
- `MAIL_ADDR` — Mailing address
- `SUBDIVISION` — Subdivision name
- `LEGAL_DESC` — Legal description
- `ZONING` — Zoning code
- `LAND_USE` — Land use code
- `ASMT_LINK` — URL to assessor data

---

## California

**Coverage:** No statewide API — county-by-county  
**Commercial Option:** ParcelQuest (https://www.parcelquest.com/)

### Major County Endpoints

#### Los Angeles County
```
Parcel Cache:
https://public.gis.lacounty.gov/public/rest/services/LACounty_Cache/LACounty_Parcel/MapServer/0

Open Data Portal:
https://data.lacounty.gov/
```

#### San Diego County (SanGIS)
```
REST Directory:
https://sdgis.sandag.org/arcgis/rest/services

Parcels:
https://sdgis.sandag.org/arcgis/rest/services/Parcels/MapServer
```

#### Orange County
```
REST Services:
https://gis.ocgov.com/arcgis/rest/services
```

### Notes
- Each county has different schemas and field names
- Owner data availability varies significantly
- Some counties require login for full data

---

## Georgia

**Coverage:** No statewide API — county-by-county  
**Data Hub:** https://data-hub.gio.georgia.gov/

### Major County Patterns

Most Georgia counties use qPublic for online assessor data:
- URL pattern: `https://qpublic.schneidercorp.com/Application.aspx?App={COUNTY}GA`

GIS typically through county-specific portals.

---

## Arizona (Maricopa County)

**Coverage:** Maricopa County only (Phoenix metro)  
**Data Portal:** https://maps.mcassessor.maricopa.gov/

### REST Endpoints

```
Parcels MapServer:
https://gis.mcassessor.maricopa.gov/arcgis/rest/services/Parcels/MapServer

Layer 0:
https://gis.mcassessor.maricopa.gov/arcgis/rest/services/Parcels/MapServer/0
```

### Query Example

```bash
# Query Phoenix area
curl "https://gis.mcassessor.maricopa.gov/arcgis/rest/services/Parcels/MapServer/0/query?\
geometry=-112.074,33.4484&\
geometryType=esriGeometryPoint&\
spatialRel=esriSpatialRelIntersects&\
outFields=*&\
f=json"
```

### Key Fields
- `APN` — Assessor Parcel Number
- `OWNER_NAME` — Owner
- `MAIL_ADDR` — Mailing address
- `SITE_ADDR` — Site address
- `LEGAL_CLASS` — Legal class
- `FCV` — Full cash value
- `LPV` — Limited property value

---

## Common Query Parameters

All ArcGIS REST services support these query parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `where` | SQL WHERE clause | `PARCEL_ID='123-456'` |
| `geometry` | Point/envelope for spatial query | `-97.74,30.27` |
| `geometryType` | Type of geometry | `esriGeometryPoint` |
| `spatialRel` | Spatial relationship | `esriSpatialRelIntersects` |
| `outFields` | Fields to return | `*` or `PARCEL_ID,OWNER_NAME` |
| `returnGeometry` | Include geometry | `true` or `false` |
| `f` | Output format | `json`, `geojson`, `html` |
| `resultRecordCount` | Limit results | `10` |

### Spatial Relationships
- `esriSpatialRelIntersects` — Geometry intersects
- `esriSpatialRelContains` — Query contains geometry
- `esriSpatialRelWithin` — Geometry within query

---

## Rate Limits & Best Practices

1. **MaxRecordCount**: Most services cap at 1000-2000 records per query
2. **No authentication required** for public services
3. **CORS**: Many county servers don't set CORS headers — proxy requests server-side
4. **Be polite**: Add 1-2 second delay between requests
5. **Cache results**: Parcel data changes slowly (annually)
