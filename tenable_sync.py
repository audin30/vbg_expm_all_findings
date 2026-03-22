import os
import requests
import json
import logging
import time
import psycopg2
from datetime import datetime, timezone
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load Environment Variables
load_dotenv()

# Tenable Configuration
TENABLE_ACCESS_KEY = os.getenv("TENABLE_ACCESS_KEY")
TENABLE_SECRET_KEY = os.getenv("TENABLE_SECRET_KEY")
TENABLE_API_URL = "https://cloud.tenable.com"

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

# Setup Session with Retries
def get_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST", "GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    # Headers for Tenable API
    session.headers.update({
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-ApiKeys": f"accessKey={TENABLE_ACCESS_KEY}; secretKey={TENABLE_SECRET_KEY}"
    })
    return session

session = get_session()

def ensure_column(cur, table, column, col_type):
    """Adds a column to a table if it doesn't already exist."""
    cur.execute(f"""
        SELECT 1 FROM information_schema.columns 
        WHERE table_name=%s AND column_name=%s;
    """, (table, column))
    if not cur.fetchone():
        logger.info(f"Migration: Adding missing column '{column}' to table '{table}'...")
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type};")

def setup_database(conn):
    """Initializes the database schema and performs automatic migrations."""
    logger.info("Synchronizing database schema and migrations...")
    try:
        with open("schema.sql", "r") as f:
            schema_sql = f.read()
        
        with conn.cursor() as cur:
            cur.execute(schema_sql)

            # Legacy migrations (kept for existing databases)
            ensure_column(cur, "tenable_assets", "os", "TEXT")
            ensure_column(cur, "tenable_assets", "system_type", "TEXT")
            ensure_column(cur, "tenable_findings", "plugin_family", "TEXT")
            ensure_column(cur, "tenable_findings", "cvss_score", "NUMERIC")
            ensure_column(cur, "tenable_findings", "cve", "TEXT")
            cur.execute("CREATE TABLE IF NOT EXISTS sync_state (task_name TEXT PRIMARY KEY, last_cursor TEXT, updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);")

            # tenable_assets new columns
            ensure_column(cur, "tenable_assets", "has_agent", "BOOLEAN")
            ensure_column(cur, "tenable_assets", "network_id", "TEXT")
            ensure_column(cur, "tenable_assets", "network_name", "TEXT")
            ensure_column(cur, "tenable_assets", "tags", "JSONB")
            ensure_column(cur, "tenable_assets", "sources", "JSONB")
            ensure_column(cur, "tenable_assets", "installed_software", "TEXT[]")
            ensure_column(cur, "tenable_assets", "last_licensed_scan_date", "TIMESTAMP WITH TIME ZONE")
            ensure_column(cur, "tenable_assets", "last_authenticated_scan_date", "TIMESTAMP WITH TIME ZONE")
            ensure_column(cur, "tenable_assets", "aws_ec2_instance_id", "TEXT")
            ensure_column(cur, "tenable_assets", "aws_region", "TEXT")
            ensure_column(cur, "tenable_assets", "aws_availability_zone", "TEXT")
            ensure_column(cur, "tenable_assets", "aws_vpc_id", "TEXT")
            ensure_column(cur, "tenable_assets", "aws_owner_id", "TEXT")
            ensure_column(cur, "tenable_assets", "aws_ec2_instance_type", "TEXT")
            ensure_column(cur, "tenable_assets", "azure_vm_id", "TEXT")
            ensure_column(cur, "tenable_assets", "azure_resource_id", "TEXT")
            ensure_column(cur, "tenable_assets", "azure_subscription_id", "TEXT")
            ensure_column(cur, "tenable_assets", "azure_resource_group", "TEXT")
            ensure_column(cur, "tenable_assets", "azure_location", "TEXT")
            ensure_column(cur, "tenable_assets", "gcp_project_id", "TEXT")
            ensure_column(cur, "tenable_assets", "gcp_zone", "TEXT")
            ensure_column(cur, "tenable_assets", "gcp_instance_id", "TEXT")
            ensure_column(cur, "tenable_assets", "servicenow_sysid", "TEXT")
            ensure_column(cur, "tenable_assets", "ssh_fingerprint_sha256", "TEXT[]")

            # tenable_findings new columns
            ensure_column(cur, "tenable_findings", "asset_hostname", "TEXT")
            ensure_column(cur, "tenable_findings", "asset_ipv4", "TEXT")
            ensure_column(cur, "tenable_findings", "asset_fqdn", "TEXT")
            ensure_column(cur, "tenable_findings", "plugin_synopsis", "TEXT")
            ensure_column(cur, "tenable_findings", "plugin_solution", "TEXT")
            ensure_column(cur, "tenable_findings", "risk_factor", "TEXT")
            ensure_column(cur, "tenable_findings", "port", "INTEGER")
            ensure_column(cur, "tenable_findings", "protocol", "TEXT")
            ensure_column(cur, "tenable_findings", "cvss3_score", "NUMERIC")
            ensure_column(cur, "tenable_findings", "vpr_score", "NUMERIC")
            ensure_column(cur, "tenable_findings", "cves", "TEXT[]")
            ensure_column(cur, "tenable_findings", "exploit_available", "BOOLEAN")
            ensure_column(cur, "tenable_findings", "exploited_by_malware", "BOOLEAN")
            ensure_column(cur, "tenable_findings", "patch_publication_date", "TIMESTAMP WITH TIME ZONE")

        logger.info("Database schema and migrations are up to date.")
    except Exception as e:
        logger.error(f"Failed to initialize/migrate database: {e}")
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

def clear_cursor(conn, task_name):
    with conn.cursor() as cur:
        cur.execute("UPDATE sync_state SET last_cursor = NULL WHERE task_name = %s", (task_name,))

def get_ips(asset, version='v4'):
    """
    Robustly extracts IP addresses from various Tenable API versions/formats.
    Checks top-level plural, top-level singular, and nested network objects.
    """
    keys = ['ipv4s', 'ipv4_addresses', 'ipv4'] if version == 'v4' else ['ipv6s', 'ipv6_addresses', 'ipv6']
    ips = []
    
    # Check top-level
    for key in keys:
        val = asset.get(key)
        if val:
            if isinstance(val, list):
                ips.extend(val)
            else:
                ips.append(val)
    
    # Check nested network object (v2 API model)
    network = asset.get('network')
    if isinstance(network, dict):
        for key in keys:
            val = network.get(key)
            if val:
                if isinstance(val, list):
                    ips.extend(val)
                else:
                    ips.append(val)
                    
    # Deduplicate and remove empty
    return list(dict.fromkeys([ip for ip in ips if ip]))

def wait_for_export(export_uuid, export_type):
    """Waits for a Tenable export to reach 'FINISHED' status."""
    logger.info(f"Waiting for {export_type} export {export_uuid} to finish...")
    while True:
        url = f"{TENABLE_API_URL}/{export_type}/export/{export_uuid}/status"
        response = session.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        status = data.get("status")
        
        if status == "FINISHED":
            logger.info(f"{export_type.capitalize()} export finished.")
            return data.get("chunks_available") or []
        elif status == "ERROR":
            raise Exception(f"{export_type.capitalize()} export failed with error status.")
        
        time.sleep(10)

def fetch_and_sync_assets(conn):
    logger.info("Starting Tenable Assets sync...")
    task_name = "tenable_assets"
    
    last_sync_time = get_last_cursor(conn, "tenable_assets_last_sync")
    logger.info(f"Last sync timestamp: {last_sync_time}")
    
    state_raw = get_last_cursor(conn, task_name)
    state = json.loads(state_raw) if state_raw else {}
    
    export_uuid = state.get("uuid")
    processed_chunks = set(state.get("processed_chunks", []))
    
    if not export_uuid:
        url = f"{TENABLE_API_URL}/assets/export"
        payload = {"chunk_size": 1000}
        
        # Incremental filter: only assets updated after last sync
        if last_sync_time:
            payload["filters"] = {"updated_at": int(last_sync_time)}
            
        response = session.post(url, json=payload, timeout=60)
        response.raise_for_status()
        export_uuid = response.json().get("export_uuid")
        state = {"uuid": export_uuid, "processed_chunks": []}
        save_cursor(conn, task_name, json.dumps(state))
    
    chunks = wait_for_export(export_uuid, "assets")
    
    current_sync_timestamp = int(time.time())
    
    for chunk_id in chunks:
        if chunk_id in processed_chunks:
            continue
            
        chunk_url = f"{TENABLE_API_URL}/assets/export/{export_uuid}/chunks/{chunk_id}"
        chunk_resp = session.get(chunk_url, timeout=300)
        chunk_resp.raise_for_status()
        assets = chunk_resp.json()
        
        records = []
        for asset in assets:
            ipv4_list = get_ips(asset, 'v4')
            ipv6_list = get_ips(asset, 'v6')

            # Primary names and identifiers
            fqdn_list = asset.get('fqdns', [])
            mac_list = asset.get('mac_addresses', [])
            netbios_list = asset.get('netbios_names', [])

            # ssh_fingerprint_sha256 may be a string or list
            ssh_raw = asset.get('ssh_fingerprint_sha256')
            ssh_list = ssh_raw if isinstance(ssh_raw, list) else ([ssh_raw] if ssh_raw else [])

            records.append((
                asset['id'],
                asset.get('hostname'),
                fqdn_list[0] if fqdn_list else None,
                fqdn_list,
                ipv4_list[0] if ipv4_list else None,
                ipv4_list,
                ipv6_list[0] if ipv6_list else None,
                ipv6_list,
                mac_list[0] if mac_list else None,
                mac_list,
                netbios_list[0] if netbios_list else None,
                netbios_list,
                asset.get('operating_systems', []),
                asset.get('system_types', []),
                asset.get('acr_score'),
                asset.get('exposure_score'),
                asset.get('agent_uuid'),
                asset.get('bios_uuid'),
                asset.get('has_agent'),
                asset.get('network_id'),
                asset.get('network_name'),
                json.dumps(asset.get('tags') or []),
                json.dumps(asset.get('sources') or []),
                asset.get('installed_software') or [],
                asset.get('last_licensed_scan_date'),
                asset.get('last_authenticated_scan_date'),
                asset.get('aws_ec2_instance_id'),
                asset.get('aws_region'),
                asset.get('aws_availability_zone'),
                asset.get('aws_vpc_id'),
                asset.get('aws_owner_id'),
                asset.get('aws_ec2_instance_type'),
                asset.get('azure_vm_id'),
                asset.get('azure_resource_id'),
                asset.get('azure_subscription_id'),
                asset.get('azure_resource_group'),
                asset.get('azure_location'),
                asset.get('gcp_project_id'),
                asset.get('gcp_zone'),
                asset.get('gcp_instance_id'),
                asset.get('servicenow_sysid'),
                ssh_list,
                asset.get('created_at'),
                asset.get('updated_at'),
                asset.get('last_seen'),
                json.dumps(asset)
            ))

        with conn.cursor() as cur:
            upsert_query = """
            INSERT INTO tenable_assets (
                id, hostname, fqdn, fqdns, ipv4, ipv4s, ipv6, ipv6s,
                mac_address, mac_addresses, netbios_name, netbios_names,
                operating_systems, system_types, acr_score, exposure_score,
                agent_uuid, bios_uuid,
                has_agent, network_id, network_name, tags, sources,
                installed_software, last_licensed_scan_date, last_authenticated_scan_date,
                aws_ec2_instance_id, aws_region, aws_availability_zone, aws_vpc_id,
                aws_owner_id, aws_ec2_instance_type,
                azure_vm_id, azure_resource_id, azure_subscription_id,
                azure_resource_group, azure_location,
                gcp_project_id, gcp_zone, gcp_instance_id,
                servicenow_sysid, ssh_fingerprint_sha256,
                created_at, updated_at, last_seen, raw_data
            )
            VALUES %s
            ON CONFLICT (id) DO UPDATE SET
                hostname = EXCLUDED.hostname,
                fqdn = EXCLUDED.fqdn,
                fqdns = EXCLUDED.fqdns,
                ipv4 = EXCLUDED.ipv4,
                ipv4s = EXCLUDED.ipv4s,
                ipv6 = EXCLUDED.ipv6,
                ipv6s = EXCLUDED.ipv6s,
                mac_address = EXCLUDED.mac_address,
                mac_addresses = EXCLUDED.mac_addresses,
                netbios_name = EXCLUDED.netbios_name,
                netbios_names = EXCLUDED.netbios_names,
                operating_systems = EXCLUDED.operating_systems,
                system_types = EXCLUDED.system_types,
                acr_score = EXCLUDED.acr_score,
                exposure_score = EXCLUDED.exposure_score,
                agent_uuid = EXCLUDED.agent_uuid,
                bios_uuid = EXCLUDED.bios_uuid,
                has_agent = EXCLUDED.has_agent,
                network_id = EXCLUDED.network_id,
                network_name = EXCLUDED.network_name,
                tags = EXCLUDED.tags,
                sources = EXCLUDED.sources,
                installed_software = EXCLUDED.installed_software,
                last_licensed_scan_date = EXCLUDED.last_licensed_scan_date,
                last_authenticated_scan_date = EXCLUDED.last_authenticated_scan_date,
                aws_ec2_instance_id = EXCLUDED.aws_ec2_instance_id,
                aws_region = EXCLUDED.aws_region,
                aws_availability_zone = EXCLUDED.aws_availability_zone,
                aws_vpc_id = EXCLUDED.aws_vpc_id,
                aws_owner_id = EXCLUDED.aws_owner_id,
                aws_ec2_instance_type = EXCLUDED.aws_ec2_instance_type,
                azure_vm_id = EXCLUDED.azure_vm_id,
                azure_resource_id = EXCLUDED.azure_resource_id,
                azure_subscription_id = EXCLUDED.azure_subscription_id,
                azure_resource_group = EXCLUDED.azure_resource_group,
                azure_location = EXCLUDED.azure_location,
                gcp_project_id = EXCLUDED.gcp_project_id,
                gcp_zone = EXCLUDED.gcp_zone,
                gcp_instance_id = EXCLUDED.gcp_instance_id,
                servicenow_sysid = EXCLUDED.servicenow_sysid,
                ssh_fingerprint_sha256 = EXCLUDED.ssh_fingerprint_sha256,
                created_at = EXCLUDED.created_at,
                updated_at = EXCLUDED.updated_at,
                last_seen = EXCLUDED.last_seen,
                raw_data = EXCLUDED.raw_data;
            """
            execute_values(cur, upsert_query, records)
        
        processed_chunks.add(chunk_id)
        state["processed_chunks"] = list(processed_chunks)
        save_cursor(conn, task_name, json.dumps(state))
        logger.info(f"Synced asset chunk {chunk_id}...")

    clear_cursor(conn, task_name)
    save_cursor(conn, "tenable_assets_last_sync", str(current_sync_timestamp))
    logger.info("Tenable Assets sync complete.")

def fetch_and_sync_findings(conn):
    logger.info("Starting Tenable Findings sync...")
    task_name = "tenable_findings"
    
    last_sync_time = get_last_cursor(conn, "tenable_findings_last_sync")
    logger.info(f"Last sync timestamp: {last_sync_time}")
    
    state_raw = get_last_cursor(conn, task_name)
    state = json.loads(state_raw) if state_raw else {}
    
    export_uuid = state.get("uuid")
    processed_chunks = set(state.get("processed_chunks", []))
    
    if not export_uuid:
        url = f"{TENABLE_API_URL}/vulns/export"
        payload = {
            "num_assets": 500,
            "filters": {
                "state": ["OPEN", "REOPENED", "FIXED"]
            }
        }
        
        # Incremental filter: only findings updated since last sync
        if last_sync_time:
            payload["filters"]["since"] = int(last_sync_time)
            
        response = session.post(url, json=payload, timeout=60)
        response.raise_for_status()
        export_uuid = response.json().get("export_uuid")
        state = {"uuid": export_uuid, "processed_chunks": []}
        save_cursor(conn, task_name, json.dumps(state))
    
    chunks = wait_for_export(export_uuid, "vulns")
    
    current_sync_timestamp = int(time.time())
    
    for chunk_id in chunks:
        if chunk_id in processed_chunks:
            continue
            
        chunk_url = f"{TENABLE_API_URL}/vulns/export/{export_uuid}/chunks/{chunk_id}"
        chunk_resp = session.get(chunk_url, timeout=300)
        chunk_resp.raise_for_status()
        findings = chunk_resp.json()
        
        records = []
        for finding in findings:
            asset = finding.get('asset') or {}
            plugin = finding.get('plugin') or {}
            finding_id = f"{asset.get('uuid')}-{plugin.get('id')}-{finding.get('port')}-{finding.get('protocol')}"

            cve_list = plugin.get('cve') or []
            cve = cve_list[0] if cve_list else None

            # cvss3_score may be at top level or nested in plugin
            cvss3 = finding.get('cvss3_score') or plugin.get('cvss3_base_score')
            # vpr_score may be at top level or nested in plugin
            vpr = finding.get('vpr_score') or plugin.get('vpr_score')

            records.append((
                finding_id,
                asset.get('uuid'),
                asset.get('hostname'),
                asset.get('ipv4'),
                asset.get('fqdn'),
                plugin.get('id'),
                plugin.get('name'),
                plugin.get('family'),
                plugin.get('synopsis'),
                plugin.get('solution'),
                finding.get('severity'),
                plugin.get('risk_factor'),
                finding.get('state'),
                finding.get('port'),
                finding.get('protocol'),
                finding.get('cvss_score'),
                cvss3,
                vpr,
                cve,
                cve_list,
                plugin.get('exploit_available'),
                plugin.get('exploited_by_malware'),
                plugin.get('patch_publication_date'),
                finding.get('first_found'),
                finding.get('last_found'),
                json.dumps(finding)
            ))

        with conn.cursor() as cur:
            upsert_query = """
            INSERT INTO tenable_findings (
                id, asset_id, asset_hostname, asset_ipv4, asset_fqdn,
                plugin_id, plugin_name, plugin_family, plugin_synopsis, plugin_solution,
                severity, risk_factor, state, port, protocol,
                cvss_score, cvss3_score, vpr_score,
                cve, cves, exploit_available, exploited_by_malware,
                patch_publication_date, first_found, last_found, raw_data
            )
            VALUES %s
            ON CONFLICT (id) DO UPDATE SET
                asset_hostname = EXCLUDED.asset_hostname,
                asset_ipv4 = EXCLUDED.asset_ipv4,
                asset_fqdn = EXCLUDED.asset_fqdn,
                plugin_name = EXCLUDED.plugin_name,
                plugin_family = EXCLUDED.plugin_family,
                plugin_synopsis = EXCLUDED.plugin_synopsis,
                plugin_solution = EXCLUDED.plugin_solution,
                severity = EXCLUDED.severity,
                risk_factor = EXCLUDED.risk_factor,
                state = EXCLUDED.state,
                port = EXCLUDED.port,
                protocol = EXCLUDED.protocol,
                cvss_score = EXCLUDED.cvss_score,
                cvss3_score = EXCLUDED.cvss3_score,
                vpr_score = EXCLUDED.vpr_score,
                cve = EXCLUDED.cve,
                cves = EXCLUDED.cves,
                exploit_available = EXCLUDED.exploit_available,
                exploited_by_malware = EXCLUDED.exploited_by_malware,
                patch_publication_date = EXCLUDED.patch_publication_date,
                last_found = EXCLUDED.last_found,
                raw_data = EXCLUDED.raw_data;
            """
            execute_values(cur, upsert_query, records)
        
        processed_chunks.add(chunk_id)
        state["processed_chunks"] = list(processed_chunks)
        save_cursor(conn, task_name, json.dumps(state))
        logger.info(f"Synced finding chunk {chunk_id}...")

    clear_cursor(conn, task_name)
    save_cursor(conn, "tenable_findings_last_sync", str(current_sync_timestamp))
    logger.info("Tenable Findings sync complete.")

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
        
        sync_tasks = [
            ("Assets", fetch_and_sync_assets),
            ("Findings", fetch_and_sync_findings)
        ]

        for name, task in sync_tasks:
            try:
                task(conn)
            except Exception as e:
                logger.error(f"Failed to sync Tenable {name}: {e}")
            
        logger.info("Tenable Sync process finished.")
    except Exception as e:
        logger.error(f"Critical initialization failure: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    main()
