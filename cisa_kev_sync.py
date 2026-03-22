import os
import requests
import json
import logging
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load Environment Variables
load_dotenv()

# CISA KEV URL
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

def setup_database(conn):
    """Initializes the database schema."""
    logger.info("Synchronizing database schema...")
    try:
        with open("schema.sql", "r") as f:
            schema_sql = f.read()
        with conn.cursor() as cur:
            cur.execute(schema_sql)
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

def fetch_and_sync_kev(conn):
    logger.info("Checking for CISA KEV Catalog updates...")
    task_name = "cisa_kev_catalog"
    last_version = get_last_cursor(conn, task_name)
    
    response = requests.get(CISA_KEV_URL, timeout=60)
    response.raise_for_status()
    data = response.json()
    
    current_version = data.get("catalogVersion")
    if last_version == current_version:
        logger.info(f"CISA KEV Catalog is already up to date (Version: {current_version}). Skipping sync.")
        return

    vulnerabilities = data.get("vulnerabilities", [])
    logger.info(f"New version detected: {current_version}. Syncing {len(vulnerabilities)} vulnerabilities...")
    
    records = []
    for v in vulnerabilities:
        records.append((
            v.get('cveID'),
            v.get('vendorProject'),
            v.get('product'),
            v.get('vulnerabilityName'),
            v.get('dateAdded'),
            v.get('shortDescription'),
            v.get('requiredAction'),
            v.get('dueDate'),
            v.get('knownRansomwareCampaignUse'),
            v.get('notes'),
            v.get('cwes', []),
            json.dumps(v)
        ))
    
    with conn.cursor() as cur:
        upsert_query = """
        INSERT INTO cisa_kev (
            cve_id, vendor_project, product, vulnerability_name, 
            date_added, short_description, required_action, due_date, 
            known_ransomware_use, notes, cwes, raw_data
        )
        VALUES %s
        ON CONFLICT (cve_id) DO UPDATE SET
            vendor_project = EXCLUDED.vendor_project,
            product = EXCLUDED.product,
            vulnerability_name = EXCLUDED.vulnerability_name,
            date_added = EXCLUDED.date_added,
            short_description = EXCLUDED.short_description,
            required_action = EXCLUDED.required_action,
            due_date = EXCLUDED.due_date,
            known_ransomware_use = EXCLUDED.known_ransomware_use,
            notes = EXCLUDED.notes,
            cwes = EXCLUDED.cwes,
            raw_data = EXCLUDED.raw_data,
            updated_at = CURRENT_TIMESTAMP;
        """
        execute_values(cur, upsert_query, records)
    
    save_cursor(conn, task_name, current_version)
    logger.info(f"Successfully synced CISA KEV Version {current_version}.")

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
        fetch_and_sync_kev(conn)
        
        logger.info("CISA KEV Sync process finished.")
    except Exception as e:
        logger.error(f"Critical initialization failure: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    main()
