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
        'Key': 'key',
        'Asset Name': 'asset_name',
        'IP Addresses': 'ip_addresses',
        'OS Class': 'os_class',
        'OS Distribution': 'os_distribution',
        'OS Major Version': 'os_major_version',
        'OS Minor Version': 'os_minor_version',
        'OS Name': 'os_name',
        'Product Code': 'product_code',
        'Hardware Platform': 'hardware_platform',
        'Business Unit': 'business_unit',
        'Owner': 'owner',
        'AD Domain': 'ad_domain',
        'AD Distinguished Name': 'ad_distinguished_name',
        'Azure Subscription ID': 'azure_subscription_id',
        'Azure Subscription Name': 'azure_subscription_name',
        'Location Code': 'location_code',
        'Power State': 'power_state',
        'Is Appliance': 'is_appliance',
        'Is Physical': 'is_physical',
        'Is Cloud': 'is_cloud',
        'Is Ephemeral': 'is_ephemeral',
        'Is Network in IPAM': 'is_network_in_ipam',
        'Inbound IP': 'inbound_ip',
        'IPAM Owner': 'ipam_owner',
        'dcTrack Owner': 'dctrack_owner',
        'Tenable Groups': 'tenable_groups',
        'Last Seen': 'last_seen',
        'First Seen': 'first_seen',
        'Install Date': 'install_date',
        'BU Security Champion': 'bu_security_champion',
        'Xen Host IP': 'xen_host_ip',
        'Xen Pool': 'xen_pool',
        'Xen Pool UUID': 'xen_pool_uuid',
        'Hypervisor Owner': 'hypervisor_owner',
        'Labstage Owner': 'labstage_owner',
        'MAC Addresses': 'mac_addresses',
        'IP/MAC Map': 'ip_mac_map'
    }
    return mapping.get(header, header.lower().replace(' ', '_'))

def parse_bool(val):
    if not val: return None
    val = str(val).lower().strip()
    return val in ('true', '1', 'yes', 'y')

def parse_timestamp(val):
    if not val or val.lower() == 'na' or val.lower() == 'null':
        return None
    try:
        # Expected format: 2026-03-19 06:36:26
        return datetime.strptime(val, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        try:
            # Try ISO format if different
            return datetime.fromisoformat(val)
        except ValueError:
            return None

def sync_dto_assets_csv(conn, csv_file_path):
    if not os.path.exists(csv_file_path):
        logger.error(f"CSV file not found: {csv_file_path}")
        return

    logger.info(f"Reading DTO Asset Inventory CSV: {csv_file_path}")
    
    records = []
    now = datetime.now(timezone.utc)

    try:
        with open(csv_file_path, mode='r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                key = row.get('Key')
                if not key:
                    continue
                
                records.append((
                    key,
                    row.get('Asset Name'),
                    row.get('IP Addresses'),
                    row.get('OS Class'),
                    row.get('OS Distribution'),
                    row.get('OS Major Version'),
                    row.get('OS Minor Version'),
                    row.get('OS Name'),
                    row.get('Product Code'),
                    row.get('Hardware Platform'),
                    row.get('Business Unit'),
                    row.get('Owner'),
                    row.get('AD Domain'),
                    row.get('AD Distinguished Name'),
                    row.get('Azure Subscription ID'),
                    row.get('Azure Subscription Name'),
                    row.get('Location Code'),
                    row.get('Power State'),
                    parse_bool(row.get('Is Appliance')),
                    parse_bool(row.get('Is Physical')),
                    parse_bool(row.get('Is Cloud')),
                    parse_bool(row.get('Is Ephemeral')),
                    parse_bool(row.get('Is Network in IPAM')),
                    row.get('Inbound IP'),
                    row.get('IPAM Owner'),
                    row.get('dcTrack Owner'),
                    row.get('Tenable Groups'),
                    parse_timestamp(row.get('Last Seen')),
                    parse_timestamp(row.get('First Seen')),
                    parse_timestamp(row.get('Install Date')),
                    row.get('BU Security Champion'),
                    row.get('Xen Host IP'),
                    row.get('Xen Pool'),
                    row.get('Xen Pool UUID'),
                    row.get('Hypervisor Owner'),
                    row.get('Labstage Owner'),
                    row.get('MAC Addresses'),
                    row.get('IP/MAC Map'),
                    now
                ))

        if not records:
            logger.info("No records found in CSV.")
            return

        logger.info(f"Upserting {len(records)} records into dto_assets...")
        
        with conn.cursor() as cur:
            upsert_query = """
            INSERT INTO dto_assets (
                key, asset_name, ip_addresses, os_class, os_distribution, 
                os_major_version, os_minor_version, os_name, product_code, 
                hardware_platform, business_unit, owner, ad_domain, 
                ad_distinguished_name, azure_subscription_id, azure_subscription_name, 
                location_code, power_state, is_appliance, is_physical, 
                is_cloud, is_ephemeral, is_network_in_ipam, inbound_ip, 
                ipam_owner, dctrack_owner, tenable_groups, last_seen, 
                first_seen, install_date, bu_security_champion, xen_host_ip, 
                xen_pool, xen_pool_uuid, hypervisor_owner, labstage_owner, 
                mac_addresses, ip_mac_map, last_updated
            )
            VALUES %s
            ON CONFLICT (key) DO UPDATE SET
                asset_name = EXCLUDED.asset_name,
                ip_addresses = EXCLUDED.ip_addresses,
                os_class = EXCLUDED.os_class,
                os_distribution = EXCLUDED.os_distribution,
                os_major_version = EXCLUDED.os_major_version,
                os_minor_version = EXCLUDED.os_minor_version,
                os_name = EXCLUDED.os_name,
                product_code = EXCLUDED.product_code,
                hardware_platform = EXCLUDED.hardware_platform,
                business_unit = EXCLUDED.business_unit,
                owner = EXCLUDED.owner,
                ad_domain = EXCLUDED.ad_domain,
                ad_distinguished_name = EXCLUDED.ad_distinguished_name,
                azure_subscription_id = EXCLUDED.azure_subscription_id,
                azure_subscription_name = EXCLUDED.azure_subscription_name,
                location_code = EXCLUDED.location_code,
                power_state = EXCLUDED.power_state,
                is_appliance = EXCLUDED.is_appliance,
                is_physical = EXCLUDED.is_physical,
                is_cloud = EXCLUDED.is_cloud,
                is_ephemeral = EXCLUDED.is_ephemeral,
                is_network_in_ipam = EXCLUDED.is_network_in_ipam,
                inbound_ip = EXCLUDED.inbound_ip,
                ipam_owner = EXCLUDED.ipam_owner,
                dctrack_owner = EXCLUDED.dctrack_owner,
                tenable_groups = EXCLUDED.tenable_groups,
                last_seen = EXCLUDED.last_seen,
                first_seen = EXCLUDED.first_seen,
                install_date = EXCLUDED.install_date,
                bu_security_champion = EXCLUDED.bu_security_champion,
                xen_host_ip = EXCLUDED.xen_host_ip,
                xen_pool = EXCLUDED.xen_pool,
                xen_pool_uuid = EXCLUDED.xen_pool_uuid,
                hypervisor_owner = EXCLUDED.hypervisor_owner,
                labstage_owner = EXCLUDED.labstage_owner,
                mac_addresses = EXCLUDED.mac_addresses,
                ip_mac_map = EXCLUDED.ip_mac_map,
                last_updated = EXCLUDED.last_updated;
            """
            execute_values(cur, upsert_query, records)
            
        logger.info("Sync completed successfully.")

    except Exception as e:
        logger.error(f"Failed to sync DTO Asset CSV: {e}")
        raise

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Sync DTO Asset Inventory CSV to PostgreSQL")
    parser.add_argument("csv_file", help="Path to the DTO Asset Inventory CSV file")
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
        
        sync_dto_assets_csv(conn, args.csv_file)
        
    except Exception as e:
        logger.error(f"Critical failure: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    main()
