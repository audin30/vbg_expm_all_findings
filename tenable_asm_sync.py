import os
import requests
import json
import logging
import time
import psycopg2
from datetime import datetime, timezone
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load Environment Variables
load_dotenv()

# Tenable Configuration
TENABLE_ASM_API_KEY = os.getenv("TENABLE_ASM_API_KEY")
TENABLE_ASM_URL = "https://asm.cloud.tenable.com/api/1.0"

if not TENABLE_ASM_API_KEY:
    logger.error("TENABLE_ASM_API_KEY not found in environment variables. Please check your .env file.")
    raise ValueError("Missing Tenable ASM API Key")

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

def get_session():
    session = requests.Session()
    session.headers.update({
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "TenableASMSync/1.0",
        "Authorization": TENABLE_ASM_API_KEY
    })
    return session

session = get_session()

def ensure_column(cur, table, column, col_type):
    """Adds a column to a table if it doesn't already exist."""
    cur.execute("""
        SELECT 1 FROM information_schema.columns
        WHERE table_name=%s AND column_name=%s;
    """, (table, column.lower()))
    if not cur.fetchone():
        logger.info(f"Migration: Adding missing column '{column}' to table '{table}'...")
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type};")

def setup_database(conn):
    """Initializes the database schema and performs automatic migrations."""
    logger.info("Synchronizing database schema...")
    try:
        with open("schema.sql", "r") as f:
            schema_sql = f.read()
        with conn.cursor() as cur:
            cur.execute(schema_sql)

            # tenable_asm_assets migrations
            ensure_column(cur, "tenable_asm_assets", "original", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "apex_domain", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "tags", "JSONB")
            ensure_column(cur, "tenable_asm_assets", "technologies", "JSONB")
            ensure_column(cur, "tenable_asm_assets", "open_ports", "TEXT[]")
            ensure_column(cur, "tenable_asm_assets", "all_services", "TEXT[]")
            ensure_column(cur, "tenable_asm_assets", "country_code", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "region", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "isp", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "latitude", "NUMERIC")
            ensure_column(cur, "tenable_asm_assets", "longitude", "NUMERIC")
            ensure_column(cur, "tenable_asm_assets", "domain_registrant", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "domain_created_at", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "domain_expires_at", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "ssl_grade", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "ssl_cert_expiry", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "http_title", "TEXT")
            ensure_column(cur, "tenable_asm_assets", "http_server", "TEXT")

        logger.info("Database schema is up to date.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

def get_last_cursor(conn, task_name):
    with conn.cursor() as cur:
        cur.execute("SELECT last_cursor FROM sync_state WHERE task_name = %s", (task_name,))
        row = cur.fetchone()
        return row[0] if row else None

def save_cursor(conn, task_name, cursor):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO sync_state (task_name, last_cursor, updated_at)
            VALUES (%s, %s, CURRENT_TIMESTAMP)
            ON CONFLICT (task_name) DO UPDATE SET
                last_cursor = EXCLUDED.last_cursor,
                updated_at = EXCLUDED.updated_at;
        """, (task_name, cursor))

def sanitize_data(data):
    """Recursively removes null bytes (\u0000) from a data structure."""
    if isinstance(data, str):
        return data.replace('\u0000', '')
    elif isinstance(data, dict):
        return {k: sanitize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(v) for v in data]
    return data

def ms_to_iso(ms):
    """Converts milliseconds to ISO format string."""
    if ms is None:
        return None
    try:
        return datetime.fromtimestamp(float(ms) / 1000.0, tz=timezone.utc).isoformat()
    except (ValueError, TypeError):
        return None

def get_nested_value(obj, key):
    """
    Get value from flattened keys (e.g., 'bd.hostname') or nested structure.
    Tries both approaches: direct key lookup and nested traversal.
    """
    # Try direct key lookup first (for flattened JSON responses)
    if key in obj:
        return obj.get(key)
    
    # Try nested traversal (for nested JSON responses)
    keys = key.split('.')
    current = obj
    for k in keys:
        if isinstance(current, dict):
            current = current.get(k)
            if current is None:
                return None
        else:
            return None
    return current

def safe_int(value):
    """Safely convert value to integer or return None."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None

def safe_float(value):
    """Safely convert value to float or return None."""
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None

def fetch_and_sync_asm_assets(conn):
    logger.info("Starting Tenable ASM Assets sync...")
    task_name = "tenable_asm_assets"
    last_sync_time = get_last_cursor(conn, f"{task_name}_last_sync")
    
    # ASM Export API Workflow
    # 1. Initiate Export
    url = f"{TENABLE_ASM_URL}/assets/export/json"
    payload = {}
    
    # Incremental filter: only assets updated since last sync
    if last_sync_time:
        # Tenable ASM Export API expects a list of filter objects
        payload["filters"] = [
            {
                "column": "bd.last_metadata_change",
                "type": "after",
                "value": last_sync_time
            }
        ]
        logger.info(f"Filtering assets updated after {last_sync_time}")

    response = session.post(url, json=payload, timeout=60)
    response.raise_for_status()
    export_token = response.json().get("token")
    
    if not export_token:
        logger.info("No export token returned. Possibly no new data.")
        return

    # 2. Wait and Download
    download_url = f"{TENABLE_ASM_URL}/export/download"
    download_payload = {"token": export_token}
    
    # ASM exports can take time. Simple poll mechanism.
    max_retries = 10
    assets = []
    for i in range(max_retries):
        time.sleep(10)
        logger.info(f"Checking export status (attempt {i+1})...")
        dl_resp = session.post(download_url, json=download_payload, timeout=300)
        
        if dl_resp.status_code == 200:
            try:
                # Try parsing as standard JSON first
                assets = dl_resp.json()
            except json.JSONDecodeError:
                # Fallback to NDJSON (one JSON object per line)
                logger.info("Export data is in NDJSON format. Parsing line by line...")
                assets = []
                for line in dl_resp.text.strip().split('\n'):
                    if line.strip():
                        try:
                            assets.append(json.loads(line))
                        except json.JSONDecodeError as je:
                            logger.error(f"Failed to parse line as JSON: {je}")
            break
        elif dl_resp.status_code == 202:
            continue # Still processing
        else:
            dl_resp.raise_for_status()

    if not assets:
        logger.info("No assets found in export.")
        return

    logger.info(f"Processing {len(assets)} ASM assets...")
    
    # Log sample asset structure for debugging
    if assets:
        logger.debug(f"Sample asset structure: {json.dumps(assets[0], indent=2, default=str)[:500]}...")
    
    records = []
    latest_update = last_sync_time
    
    for asset in assets:
        # Sanitize asset to remove null bytes that PostgreSQL doesn't like in JSONB
        asset = sanitize_data(asset)
        
        # Identify the most recent timestamp to use as cursor
        asset_updated = get_nested_value(asset, 'bd.last_metadata_change')
        if asset_updated and (not latest_update or asset_updated > latest_update):
            latest_update = asset_updated
        
        # Extract basic fields - support both flattened and nested JSON
        asset_id = asset.get('id')
        hostname = get_nested_value(asset, 'bd.hostname')
        ip_address = get_nested_value(asset, 'bd.ip_address')
        
        if not asset_id:
            logger.warning("Skipping asset with missing ID")
            continue
        
        # Port and Service extraction from lists
        ports = get_nested_value(asset, 'ports.ports')
        services = get_nested_value(asset, 'ports.services')
        
        # Ensure ports and services are lists
        if isinstance(ports, str):
            try:
                ports = json.loads(ports) if ports else []
            except json.JSONDecodeError:
                ports = []
        if not isinstance(ports, list):
            ports = []
            
        if isinstance(services, str):
            try:
                services = json.loads(services) if services else []
            except json.JSONDecodeError:
                services = []
        if not isinstance(services, list):
            services = []
        
        # Extract primary port (first in list) as integer
        primary_port = None
        if ports:
            primary_port = safe_int(ports[0])
        
        primary_service = services[0] if services else None
        
        # Convert ports to list of strings for storage
        open_ports = [str(p) for p in ports if p is not None]
        all_services = [str(s) for s in services if s is not None]

        # Sources/Source handling
        sources = get_nested_value(asset, 'bd.sources')
        if isinstance(sources, list):
            source_str = ", ".join([str(s) for s in sources if s])
        else:
            source_str = str(sources) if sources else None

        # Tags and technologies - store as JSON
        tags = get_nested_value(asset, 'bd.tags')
        tech = get_nested_value(asset, 'bd.tech')

        # Extract all available fields with proper type handling
        record = (
            asset_id,                                            # id
            hostname or get_nested_value(asset, 'bd.name'),     # name (fallback to bd.name)
            hostname,                                            # hostname
            get_nested_value(asset, 'bd.record_type'),          # type
            source_str,                                          # source
            get_nested_value(asset, 'bd.original'),             # original
            get_nested_value(asset, 'bd.apex'),                 # apex_domain
            json.dumps(tags) if tags is not None else None,     # tags
            json.dumps(tech) if tech is not None else None,     # technologies
            ms_to_iso(get_nested_value(asset, 'bd.addedtoportfolio')),  # first_seen
            get_nested_value(asset, 'bd.last_metadata_change'), # last_seen
            get_nested_value(asset, 'bd.last_metadata_change'), # updated_at
            ip_address,                                          # address (IP address)
            ip_address,                                          # ip_address
            primary_port,                                        # port (INTEGER)
            None,                                                # protocol
            primary_service,                                     # service
            open_ports,                                          # open_ports (TEXT array)
            all_services,                                        # all_services (TEXT array)
            get_nested_value(asset, 'bd.severity_ranking'),     # severity_ranking
            get_nested_value(asset, 'ipgeo.asn'),               # asn
            safe_int(get_nested_value(asset, 'ipgeo.asn_number')),  # asn_number (INTEGER)
            get_nested_value(asset, 'ipgeo.city'),              # city
            get_nested_value(asset, 'ipgeo.country'),           # country
            get_nested_value(asset, 'ipgeo.countrycode'),       # country_code
            get_nested_value(asset, 'ipgeo.region'),            # region
            get_nested_value(asset, 'ipgeo.isp'),               # isp
            safe_float(get_nested_value(asset, 'ipgeo.latitude')),   # latitude (NUMERIC)
            safe_float(get_nested_value(asset, 'ipgeo.longitude')),  # longitude (NUMERIC)
            get_nested_value(asset, 'ipgeo.cloudhosted'),       # is_cloud
            get_nested_value(asset, 'ipgeo.cloud'),             # cloud_provider
            get_nested_value(asset, 'domaininfo.registrarname'),# registrar
            get_nested_value(asset, 'domaininfo.registrant'),   # domain_registrant
            get_nested_value(asset, 'domaininfo.createdate'),   # domain_created_at
            get_nested_value(asset, 'domaininfo.expiredate'),   # domain_expires_at
            get_nested_value(asset, 'ssl.grade'),               # ssl_grade
            get_nested_value(asset, 'ssl.certexpiry'),          # ssl_cert_expiry
            get_nested_value(asset, 'http.title'),              # http_title
            get_nested_value(asset, 'http.server'),             # http_server
            json.dumps(asset)                                    # raw_data
        )
        records.append(record)

    logger.info(f"Prepared {len(records)} records for insertion")
    
    # Validate record structure
    if records:
        expected_columns = 40  # Number of columns in tenable_asm_assets table
        if len(records[0]) != expected_columns:
            logger.warning(f"Record tuple has {len(records[0])} elements, expected {expected_columns}")
    
    with conn.cursor() as cur:
        upsert_query = """
        INSERT INTO tenable_asm_assets (
            id, name, hostname, type, source, original, apex_domain, tags, technologies,
            first_seen, last_seen, updated_at,
            address, ip_address, port, protocol, service, open_ports, all_services,
            severity_ranking, asn, asn_number, city, country, country_code, region, isp,
            latitude, longitude, is_cloud, cloud_provider,
            registrar, domain_registrant, domain_created_at, domain_expires_at,
            ssl_grade, ssl_cert_expiry, http_title, http_server, raw_data
        )
        VALUES %s
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            hostname = EXCLUDED.hostname,
            type = EXCLUDED.type,
            source = EXCLUDED.source,
            original = EXCLUDED.original,
            apex_domain = EXCLUDED.apex_domain,
            tags = EXCLUDED.tags,
            technologies = EXCLUDED.technologies,
            first_seen = EXCLUDED.first_seen,
            last_seen = EXCLUDED.last_seen,
            updated_at = EXCLUDED.updated_at,
            address = EXCLUDED.address,
            ip_address = EXCLUDED.ip_address,
            port = EXCLUDED.port,
            protocol = EXCLUDED.protocol,
            service = EXCLUDED.service,
            open_ports = EXCLUDED.open_ports,
            all_services = EXCLUDED.all_services,
            severity_ranking = EXCLUDED.severity_ranking,
            asn = EXCLUDED.asn,
            asn_number = EXCLUDED.asn_number,
            city = EXCLUDED.city,
            country = EXCLUDED.country,
            country_code = EXCLUDED.country_code,
            region = EXCLUDED.region,
            isp = EXCLUDED.isp,
            latitude = EXCLUDED.latitude,
            longitude = EXCLUDED.longitude,
            is_cloud = EXCLUDED.is_cloud,
            cloud_provider = EXCLUDED.cloud_provider,
            registrar = EXCLUDED.registrar,
            domain_registrant = EXCLUDED.domain_registrant,
            domain_created_at = EXCLUDED.domain_created_at,
            domain_expires_at = EXCLUDED.domain_expires_at,
            ssl_grade = EXCLUDED.ssl_grade,
            ssl_cert_expiry = EXCLUDED.ssl_cert_expiry,
            http_title = EXCLUDED.http_title,
            http_server = EXCLUDED.http_server,
            raw_data = EXCLUDED.raw_data;
        """
        try:
            execute_values(cur, upsert_query, records)
            logger.info(f"Successfully inserted/updated {len(records)} records in tenable_asm_assets table")
        except psycopg2.Error as e:
            logger.error(f"Failed to execute upsert: {e}")
            logger.error(f"First record sample: {records[0] if records else 'No records'}")
            raise
    
    if latest_update:
        save_cursor(conn, f"{task_name}_last_sync", latest_update)
    
    logger.info(f"Successfully synced {len(assets)} ASM assets.")

def main():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        conn.autocommit = True
        
        setup_database(conn)
        fetch_and_sync_asm_assets(conn)
        
        logger.info("Tenable ASM Sync process finished.")
    except Exception as e:
        logger.error(f"Critical initialization failure: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    main()
