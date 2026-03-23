# Tenable ASM Sync Field Mapping Analysis

## Current Implementation

The `tenable_asm_sync.py` script syncs Tenable ASM (Attack Surface Management) assets to PostgreSQL.

## Field Mapping

### Database Schema vs API Response Fields

| Database Column | API Field | Type | Description |
|---|---|---|---|
| `id` | `id` | TEXT | Unique asset identifier |
| `name` | `bd.name` or `bd.hostname` | TEXT | Asset name |
| `hostname` | `bd.hostname` | TEXT | Hostname |
| `type` | `bd.record_type` | TEXT | Asset type/record type |
| `source` | `bd.sources` | TEXT | Source system(s) |
| `original` | `bd.original` | TEXT | Original registered domain |
| `apex_domain` | `bd.apex` | TEXT | Apex/root domain |
| `tags` | `bd.tags` | JSONB | Asset tags |
| `technologies` | `bd.tech` | JSONB | Technologies detected |
| `first_seen` | `bd.addedtoportfolio` | TIMESTAMP | When added to portfolio |
| `last_seen` | `bd.last_metadata_change` | TIMESTAMP | Last metadata change |
| `updated_at` | `bd.last_metadata_change` | TIMESTAMP | Last update time |
| `address` | `bd.ip_address` | TEXT | IP address |
| `ip_address` | `bd.ip_address` | TEXT | IP address |
| `port` | `ports.ports[0]` | INTEGER | Primary port (first in list) |
| `protocol` | - | TEXT | Protocol (not currently populated) |
| `service` | `ports.services[0]` | TEXT | Primary service |
| `open_ports` | `ports.ports` | TEXT[] | All open ports |
| `all_services` | `ports.services` | TEXT[] | All detected services |
| `severity_ranking` | `bd.severity_ranking` | TEXT | Severity ranking |
| `asn` | `ipgeo.asn` | TEXT | Autonomous System Number |
| `asn_number` | `ipgeo.asn_number` | INTEGER | ASN as integer |
| `city` | `ipgeo.city` | TEXT | City from geolocation |
| `country` | `ipgeo.country` | TEXT | Country from geolocation |
| `country_code` | `ipgeo.countrycode` | TEXT | Country code |
| `region` | `ipgeo.region` | TEXT | Region from geolocation |
| `isp` | `ipgeo.isp` | TEXT | ISP name |
| `latitude` | `ipgeo.latitude` | NUMERIC | Latitude coordinate |
| `longitude` | `ipgeo.longitude` | NUMERIC | Longitude coordinate |
| `is_cloud` | `ipgeo.cloudhosted` | BOOLEAN | Whether hosted in cloud |
| `cloud_provider` | `ipgeo.cloud` | TEXT | Cloud provider name |
| `registrar` | `domaininfo.registrarname` | TEXT | Domain registrar |
| `domain_registrant` | `domaininfo.registrant` | TEXT | Domain registrant info |
| `domain_created_at` | `domaininfo.createdate` | TEXT | Domain creation date |
| `domain_expires_at` | `domaininfo.expiredate` | TEXT | Domain expiration date |
| `ssl_grade` | `ssl.grade` | TEXT | SSL/TLS grade rating |
| `ssl_cert_expiry` | `ssl.certexpiry` | TEXT | SSL certificate expiry |
| `http_title` | `http.title` | TEXT | HTTP page title |
| `http_server` | `http.server` | TEXT | HTTP Server header |
| `raw_data` | (full asset JSON) | JSONB | Complete raw API response |

## Key Notes

1. **Field Name Format**: The API returns fields with dot notation (e.g., `bd.hostname`, `ipgeo.city`). These are treated as literal key names in the JSON response, not nested structures.

2. **Type Conversions**:
   - Ports are extracted from a list and the first item is stored as INTEGER
   - Latitude/Longitude are converted to NUMERIC
   - ASN number is converted to INTEGER
   - Tags and technologies are stored as JSONB

3. **Fallback Handling**:
   - If `bd.hostname` is not available, falls back to `bd.name`
   - Sources list is joined with ", " separator

4. **Missing Fields**:
   - `protocol` column in database is not currently populated from the API response

## Helper Functions Added

- `get_nested_value(obj, key)`: Supports both flattened JSON (literal dots) and nested structures
- `safe_int(value)`: Safely converts to INTEGER, returns None on failure
- `safe_float(value)`: Safely converts to NUMERIC, returns None on failure

## Debugging

Run the introspection script to verify available fields:
```bash
source venv/bin/activate
python introspect_tenable_asm.py
```

This will output the actual API response structure and available fields.
