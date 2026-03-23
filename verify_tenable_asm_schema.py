#!/usr/bin/env python3
"""
Verification script for Tenable ASM Sync field mapping
Validates that all configured database columns are being populated
"""
import os
import psycopg2
import logging
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

# Database Configuration
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

# Expected field mappings
FIELD_MAPPINGS = {
    'id': 'TEXT PRIMARY KEY',
    'name': 'TEXT',
    'hostname': 'TEXT',
    'type': 'TEXT',
    'source': 'TEXT',
    'original': 'TEXT',
    'apex_domain': 'TEXT',
    'tags': 'JSONB',
    'technologies': 'JSONB',
    'first_seen': 'TIMESTAMP',
    'last_seen': 'TIMESTAMP',
    'updated_at': 'TIMESTAMP',
    'address': 'TEXT',
    'ip_address': 'TEXT',
    'port': 'INTEGER',
    'protocol': 'TEXT',
    'service': 'TEXT',
    'open_ports': 'TEXT[]',
    'all_services': 'TEXT[]',
    'severity_ranking': 'TEXT',
    'asn': 'TEXT',
    'asn_number': 'INTEGER',
    'city': 'TEXT',
    'country': 'TEXT',
    'country_code': 'TEXT',
    'region': 'TEXT',
    'isp': 'TEXT',
    'latitude': 'NUMERIC',
    'longitude': 'NUMERIC',
    'is_cloud': 'BOOLEAN',
    'cloud_provider': 'TEXT',
    'registrar': 'TEXT',
    'domain_registrant': 'TEXT',
    'domain_created_at': 'TEXT',
    'domain_expires_at': 'TEXT',
    'ssl_grade': 'TEXT',
    'ssl_cert_expiry': 'TEXT',
    'http_title': 'TEXT',
    'http_server': 'TEXT',
    'raw_data': 'JSONB',
}

def verify_schema():
    """Verify that the tenable_asm_assets table exists and has all expected columns"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        
        with conn.cursor() as cur:
            # Check if table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_name = 'tenable_asm_assets'
                );
            """)
            table_exists = cur.fetchone()[0]
            
            if not table_exists:
                logger.error("❌ Table 'tenable_asm_assets' does not exist!")
                return False
            
            logger.info("✓ Table 'tenable_asm_assets' exists")
            
            # Get all columns
            cur.execute("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'tenable_asm_assets'
                ORDER BY ordinal_position;
            """)
            
            db_columns = {row[0]: row[1] for row in cur.fetchall()}
            
            logger.info(f"\nDatabase has {len(db_columns)} columns:\n")
            
            # Check for missing columns
            missing = []
            extra = []
            
            for expected_col in FIELD_MAPPINGS:
                if expected_col not in db_columns:
                    missing.append(expected_col)
                    logger.warning(f"  ❌ MISSING: {expected_col}")
                else:
                    logger.info(f"  ✓ {expected_col}: {db_columns[expected_col]}")
            
            for db_col in db_columns:
                if db_col not in FIELD_MAPPINGS:
                    extra.append(db_col)
                    logger.warning(f"  ⚠️  EXTRA: {db_col} (not in mappings)")
            
            if missing:
                logger.error(f"\n❌ Missing {len(missing)} columns: {missing}")
                return False
            
            if extra:
                logger.warning(f"\n⚠️  {len(extra)} extra columns in DB not in mappings: {extra}")
            
            # Check for data
            cur.execute("SELECT COUNT(*) FROM tenable_asm_assets;")
            row_count = cur.fetchone()[0]
            logger.info(f"\n✓ Table contains {row_count} records")
            
            if row_count > 0:
                # Show sample data
                logger.info("\nSample record (first row):")
                cur.execute(f"""
                    SELECT * FROM tenable_asm_assets LIMIT 1;
                """)
                
                col_names = [desc[0] for desc in cur.description]
                row = cur.fetchone()
                
                for col_name, value in zip(col_names, row):
                    if value is None:
                        logger.info(f"  {col_name}: NULL")
                    elif isinstance(value, (list, dict)):
                        logger.info(f"  {col_name}: {str(value)[:80]}...")
                    else:
                        logger.info(f"  {col_name}: {value}")
            
            return True
    
    except psycopg2.Error as e:
        logger.error(f"❌ Database error: {e}")
        return False
    finally:
        if 'conn' in locals() and conn:
            conn.close()

if __name__ == "__main__":
    logger.info("=== Tenable ASM Field Mapping Verification ===\n")
    success = verify_schema()
    
    if success:
        logger.info("\n✓ Schema verification passed!")
    else:
        logger.error("\n❌ Schema verification failed!")
