#!/usr/bin/env python3
"""
Introspection script for Tenable ASM API
Examines the actual API response structure and available fields
"""
import os
import requests
import json
import logging
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

TENABLE_ASM_API_KEY = os.getenv("TENABLE_ASM_API_KEY")
TENABLE_ASM_URL = "https://asm.cloud.tenable.com/api/1.0"

if not TENABLE_ASM_API_KEY:
    logger.error("TENABLE_ASM_API_KEY not found in environment variables.")
    exit(1)

session = requests.Session()
session.headers.update({
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Authorization": TENABLE_ASM_API_KEY
})

def inspect_asm_export():
    """Fetch a small sample of ASM assets to inspect available fields"""
    logger.info("Initiating Tenable ASM export with filters to get a small sample...")
    
    # Request with a limit filter to get just 10 assets
    url = f"{TENABLE_ASM_URL}/assets/export/json"
    payload = {
        "filters": [
            {
                "column": "bd.name_has",
                "type": "contains",
                "value": ""  # Empty value acts as a catch-all
            }
        ]
    }
    
    response = session.post(url, json=payload, timeout=60)
    response.raise_for_status()
    export_token = response.json().get("token")
    
    if not export_token:
        logger.error("No export token returned.")
        return None
    
    logger.info(f"Export initiated with token: {export_token}")
    logger.info("Waiting for export to be ready...")
    
    import time
    download_url = f"{TENABLE_ASM_URL}/export/download"
    download_payload = {"token": export_token}
    
    for attempt in range(20):
        time.sleep(5)
        logger.info(f"Checking export status (attempt {attempt+1}/20)...")
        dl_resp = session.post(download_url, json=download_payload, timeout=300)
        
        if dl_resp.status_code == 200:
            try:
                assets = dl_resp.json()
                if not isinstance(assets, list):
                    assets = [assets]
            except json.JSONDecodeError:
                assets = []
                for line in dl_resp.text.strip().split('\n'):
                    if line.strip():
                        try:
                            assets.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
            
            logger.info(f"Successfully retrieved {len(assets)} assets")
            return assets[:5]  # Return first 5 assets for inspection
        elif dl_resp.status_code == 202:
            logger.info("Export still processing...")
            continue
        else:
            logger.error(f"Unexpected status code: {dl_resp.status_code}")
            return None
    
    logger.error("Timed out waiting for export")
    return None

def analyze_fields(assets):
    """Analyze and display all available fields in the assets"""
    if not assets:
        logger.error("No assets to analyze")
        return
    
    logger.info("\n=== ASM ASSETS FIELD ANALYSIS ===\n")
    
    all_fields = set()
    
    for idx, asset in enumerate(assets):
        logger.info(f"\n--- Asset #{idx+1} ---")
        logger.info(json.dumps(asset, indent=2, default=str))
        logger.info("\nFields in this asset:")
        
        def extract_keys(obj, prefix=""):
            keys = set()
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    keys.add(full_key)
                    if isinstance(value, (dict, list)):
                        keys.update(extract_keys(value, full_key))
            elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
                keys.update(extract_keys(obj[0], prefix))
            return keys
        
        asset_fields = extract_keys(asset)
        for field in sorted(asset_fields):
            logger.info(f"  - {field}")
            all_fields.add(field)
    
    logger.info("\n=== ALL UNIQUE FIELDS ACROSS ASSETS ===\n")
    for field in sorted(all_fields):
        logger.info(f"  - {field}")
    
    # Organize by prefix
    logger.info("\n=== FIELDS BY PREFIX ===\n")
    prefixes = {}
    for field in all_fields:
        prefix = field.split('.')[0] if '.' in field else field
        if prefix not in prefixes:
            prefixes[prefix] = []
        prefixes[prefix].append(field)
    
    for prefix in sorted(prefixes.keys()):
        logger.info(f"\n{prefix}:")
        for field in sorted(prefixes[prefix]):
            logger.info(f"  - {field}")
    
    return all_fields

if __name__ == "__main__":
    try:
        logger.info("Starting Tenable ASM API introspection...")
        assets = inspect_asm_export()
        if assets:
            all_fields = analyze_fields(assets)
            logger.info("\n=== READY TO USE FIELDS ===")
            logger.info("Copy these fields to understand what's available in your tenable_asm_sync.py")
    except Exception as e:
        logger.error(f"Error during introspection: {e}", exc_info=True)
