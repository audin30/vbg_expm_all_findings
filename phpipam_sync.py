import os
import csv
import json
import logging
import psycopg2
from datetime import datetime, timezone
from psycopg2.extras import execute_values
from dotenv import load_dotenv

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load Environment Variables
load_dotenv()

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

def sanitize_header(header):
    """Sanitizes CSV headers to match database column names."""
    mapping = {
        'ip': 'ip_address',
        'ip_addr': 'ip_address',
        'ip address': 'ip_address',
        'id': 'phpipam_id',
        'tag': 'state',
        'deviceId': 'device',
        'mac': 'mac_address',
        'mac address': 'mac_address',
        'editDate': 'edit_date',
        'custom_Point_of_Contact': 'point_of_contact',
        'is_gateway': 'is_gateway'
    }
    header = header.lower().strip()
    return mapping.get(header, mapping.get(header.replace('_', ''), header.replace(' ', '_')))

def parse_bool(val):
    if not val: return None
    val = str(val).lower()
    return val in ('1', 'true', 'yes', 'y')

def sync_phpipam_csv(conn, csv_file_path):
    if not os.path.exists(csv_file_path):
        logger.error(f"CSV file not found: {csv_file_path}")
        return

    logger.info(f"Reading phpIPAM CSV: {csv_file_path}")
    
    records_map = {}
    now = datetime.now(timezone.utc)

    try:
        with open(csv_file_path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            # Standardize headers
            fieldnames = {h: sanitize_header(h) for h in reader.fieldnames}
            
            for row in reader:
                # Map row to standardized keys
                data = {fieldnames[k]: v for k, v in row.items()}
                
                ip = data.get('ip_address')
                if not ip:
                    continue
                
                # Using a dictionary key by IP to ensure we only have one entry per IP in the batch
                records_map[ip] = (
                    ip,
                    data.get('phpipam_id'),
                    data.get('hostname'),
                    data.get('description'),
                    data.get('state'),
                    data.get('mac_address'),
                    data.get('owner'),
                    data.get('device'),
                    data.get('port'),
                    data.get('note'),
                    data.get('edit_date'),
                    parse_bool(data.get('is_gateway')),
                    data.get('point_of_contact'),
                    data.get('subnet_description'),
                    data.get('subnet_owner'),
                    now,
                    json.dumps(row) # Original row as raw_data
                )

        if not records_map:
            logger.info("No records found in CSV.")
            return

        records = list(records_map.values())
        logger.info(f"Upserting {len(records)} unique records into phpipam_assets...")
        
        with conn.cursor() as cur:
            upsert_query = """
            INSERT INTO phpipam_assets (
                ip_address, phpipam_id, hostname, description, state, mac_address, 
                owner, device, port, note, edit_date, is_gateway, point_of_contact, 
                subnet_description, subnet_owner, last_seen, raw_data
            )
            VALUES %s
            ON CONFLICT (ip_address) DO UPDATE SET
                phpipam_id = EXCLUDED.phpipam_id,
                hostname = EXCLUDED.hostname,
                description = EXCLUDED.description,
                state = EXCLUDED.state,
                mac_address = EXCLUDED.mac_address,
                owner = EXCLUDED.owner,
                device = EXCLUDED.device,
                port = EXCLUDED.port,
                note = EXCLUDED.note,
                edit_date = EXCLUDED.edit_date,
                is_gateway = EXCLUDED.is_gateway,
                point_of_contact = EXCLUDED.point_of_contact,
                subnet_description = EXCLUDED.subnet_description,
                subnet_owner = EXCLUDED.subnet_owner,
                last_seen = EXCLUDED.last_seen,
                raw_data = EXCLUDED.raw_data;
            """
            execute_values(cur, upsert_query, records)
            
        logger.info("Sync completed successfully.")

    except Exception as e:
        logger.error(f"Failed to sync phpIPAM CSV: {e}")
        raise

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Sync phpIPAM CSV to PostgreSQL")
    parser.add_argument("csv_file", help="Path to the phpIPAM CSV export file")
    args = parser.parse_args()

    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        conn.autocommit = True
        
        sync_phpipam_csv(conn, args.csv_file)
        
    except Exception as e:
        logger.error(f"Critical failure: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    main()
