import os
import requests
import json
import logging
import psycopg2
import time
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

# Wiz Configuration
WIZ_CLIENT_ID = os.getenv("WIZ_CLIENT_ID")
WIZ_CLIENT_SECRET = os.getenv("WIZ_CLIENT_SECRET")
WIZ_API_URL = os.getenv("WIZ_API_URL")
WIZ_AUTH_URL = "https://auth.app.wiz.io/oauth/token"

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
    return session

session = get_session()

def get_wiz_token():
    logger.info("Fetching Wiz Access Token...")
    payload = {
        "grant_type": "client_credentials",
        "audience": "wiz-api",
        "client_id": WIZ_CLIENT_ID,
        "client_secret": WIZ_CLIENT_SECRET
    }
    response = session.post(WIZ_AUTH_URL, data=payload, timeout=60)
    if response.status_code != 200:
        logger.error(f"Auth failed with status {response.status_code}: {response.text}")
    response.raise_for_status()
    return response.json().get("access_token")

def query_wiz(token, query, variables=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = session.post(WIZ_API_URL, json={'query': query, 'variables': variables}, headers=headers, timeout=120)

    if response.status_code != 200:
        logger.error(f"HTTP Error {response.status_code}: {response.text}")
        response.raise_for_status()

    data = response.json()
    if 'errors' in data:
        logger.error(f"GraphQL Errors: {json.dumps(data['errors'], indent=2)}")
        raise Exception("API returned GraphQL errors")
    return data

def ensure_column(cur, table, column, col_type):
    """Adds a column to a table if it doesn't already exist."""
    cur.execute(f"""
        SELECT 1 FROM information_schema.columns
        WHERE table_name=%s AND column_name=%s;
    """, (table, column.lower()))
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

            # wiz_issues migrations
            ensure_column(cur, "wiz_issues", "resolved_at", "TIMESTAMP WITH TIME ZONE")
            ensure_column(cur, "wiz_issues", "due_at", "TIMESTAMP WITH TIME ZONE")
            ensure_column(cur, "wiz_issues", "status_changed_at", "TIMESTAMP WITH TIME ZONE")
            ensure_column(cur, "wiz_issues", "resolution_reason", "TEXT")
            ensure_column(cur, "wiz_issues", "control_id", "TEXT")
            ensure_column(cur, "wiz_issues", "entity_name", "TEXT")
            ensure_column(cur, "wiz_issues", "source_rule_id", "TEXT")
            ensure_column(cur, "wiz_issues", "source_rule_name", "TEXT")

            # wiz_vulnerabilities migrations
            ensure_column(cur, "wiz_vulnerabilities", "finding_name", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "vendor_severity", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "cvss_score", "NUMERIC")
            ensure_column(cur, "wiz_vulnerabilities", "epss_score", "NUMERIC")
            ensure_column(cur, "wiz_vulnerabilities", "epss_percentile", "NUMERIC")
            ensure_column(cur, "wiz_vulnerabilities", "has_exploit", "BOOLEAN")
            ensure_column(cur, "wiz_vulnerabilities", "description", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "fixed_version", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "package_name", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "package_version", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "package_manager", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "asset_name", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "project_id", "TEXT")

            # wiz_vulnerabilities asset context migrations
            ensure_column(cur, "wiz_vulnerabilities", "asset_external_id", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "asset_subscription_id", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "asset_subscription_name", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "asset_subscription_external_id", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "asset_has_wide_internet_exposure", "BOOLEAN")
            ensure_column(cur, "wiz_vulnerabilities", "asset_has_limited_internet_exposure", "BOOLEAN")
            ensure_column(cur, "wiz_vulnerabilities", "asset_is_accessible_from_vpn", "BOOLEAN")
            ensure_column(cur, "wiz_vulnerabilities", "asset_provider_unique_id", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "asset_resource_group", "TEXT")
            ensure_column(cur, "wiz_vulnerabilities", "asset_ip_addresses", "TEXT[]")

            # wiz_inventory migrations
            ensure_column(cur, "wiz_inventory", "provider", "TEXT")
            ensure_column(cur, "wiz_inventory", "region", "TEXT")
            ensure_column(cur, "wiz_inventory", "project_id", "TEXT")
            ensure_column(cur, "wiz_inventory", "native_type", "TEXT")
            ensure_column(cur, "wiz_inventory", "external_id", "TEXT")
            ensure_column(cur, "wiz_inventory", "subscription_id", "TEXT")
            ensure_column(cur, "wiz_inventory", "subscription_name", "TEXT")
            ensure_column(cur, "wiz_inventory", "subscription_external_id", "TEXT")
            ensure_column(cur, "wiz_inventory", "ip_addresses", "TEXT[]")
            ensure_column(cur, "wiz_inventory", "dns_names", "TEXT[]")
            ensure_column(cur, "wiz_inventory", "tags", "JSONB")
            ensure_column(cur, "wiz_inventory", "has_public_ip", "BOOLEAN")

        logger.info("Database schema and migrations are up to date.")
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

def clear_cursor(conn, task_name):
    with conn.cursor() as cur:
        cur.execute("UPDATE sync_state SET last_cursor = NULL WHERE task_name = %s", (task_name,))

def fetch_and_sync_issues(token, conn):
    logger.info("Starting Incremental Issues sync...")
    task_name = "wiz_issues"
    last_sync_time = get_last_cursor(conn, "wiz_issues_last_sync")
    session_latest_timestamp = last_sync_time
    after = get_last_cursor(conn, task_name)

    query = """
    query Issues($first: Int, $after: String, $filterBy: IssueFilters) {
      issues(first: $first, after: $after, filterBy: $filterBy) {
        nodes {
          id
          control { id name description }
          severity
          status
          createdAt
          updatedAt
          resolvedAt
          dueAt
          statusChangedAt
          resolutionReason
          sourceRule { id name }
          entity { id name type }
          projects { id }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    filter_by = {"severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    if last_sync_time:
        filter_by["updatedAt"] = {"after": last_sync_time}

    has_next_page = True
    total_synced = 0
    while has_next_page:
        variables = {"first": 500, "after": after, "filterBy": filter_by}
        data = query_wiz(token, query, variables)
        issues = data['data']['issues']['nodes']
        if not issues: break

        records = []
        for issue in issues:
            entity = issue.get('entity') or {}
            control = issue.get('control') or {}
            source_rule = issue.get('sourceRule') or {}
            projects = issue.get('projects', [])
            project_id = projects[0].get('id') if projects else None
            updated_at = issue['updatedAt']
            if not session_latest_timestamp or updated_at > session_latest_timestamp:
                session_latest_timestamp = updated_at
            records.append((
                issue['id'],
                control.get('name'),
                issue['severity'],
                issue['status'],
                control.get('description'),
                issue['createdAt'],
                issue['updatedAt'],
                issue.get('resolvedAt'),
                issue.get('dueAt'),
                issue.get('statusChangedAt'),
                issue.get('resolutionReason'),
                control.get('id'),
                entity.get('name'),
                entity.get('id'),
                entity.get('type'),
                project_id,
                source_rule.get('id'),
                source_rule.get('name'),
                json.dumps(issue)
            ))

        with conn.cursor() as cur:
            upsert_query = """
            INSERT INTO wiz_issues (
                id, name, severity, status, description,
                created_at, updated_at, resolved_at, due_at, status_changed_at,
                resolution_reason, control_id, entity_name,
                resource_id, resource_type, project_id,
                source_rule_id, source_rule_name, raw_data
            )
            VALUES %s
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                severity = EXCLUDED.severity,
                status = EXCLUDED.status,
                description = EXCLUDED.description,
                updated_at = EXCLUDED.updated_at,
                resolved_at = EXCLUDED.resolved_at,
                due_at = EXCLUDED.due_at,
                status_changed_at = EXCLUDED.status_changed_at,
                resolution_reason = EXCLUDED.resolution_reason,
                control_id = EXCLUDED.control_id,
                entity_name = EXCLUDED.entity_name,
                project_id = EXCLUDED.project_id,
                source_rule_id = EXCLUDED.source_rule_id,
                source_rule_name = EXCLUDED.source_rule_name,
                raw_data = EXCLUDED.raw_data;
            """
            execute_values(cur, upsert_query, records)

        total_synced += len(issues)
        page_info = data['data']['issues']['pageInfo']
        has_next_page = page_info['hasNextPage']
        after = page_info['endCursor']
        if has_next_page:
            save_cursor(conn, task_name, after)
            logger.info(f"Synced {len(issues)} issues (Total: {total_synced})...")
        else:
            clear_cursor(conn, task_name)
            if session_latest_timestamp:
                save_cursor(conn, "wiz_issues_last_sync", session_latest_timestamp)
            logger.info(f"Sync complete. Total Issues: {total_synced}.")

def fetch_and_sync_vulnerabilities(token, conn):
    logger.info("Starting Incremental Vulnerabilities sync...")
    task_name = "wiz_vulnerabilities"
    last_sync_time = get_last_cursor(conn, "wiz_vulnerabilities_last_sync")
    session_latest_timestamp = last_sync_time
    after = get_last_cursor(conn, task_name)

    query = """
    query VulnerabilityFindings($first: Int, $after: String, $filterBy: VulnerabilityFindingFilters) {
      vulnerabilityFindings(first: $first, after: $after, filterBy: $filterBy) {
        nodes {
          id
          name
          vulnerabilityExternalId
          severity
          vendorSeverity
          score
          hasExploit
          description
          status
          fixedVersion
          firstDetectedAt
          lastDetectedAt
          projects { id }
          vulnerableAsset {
            ... on VulnerableAssetVirtualMachine {
              id name externalId subscriptionId subscriptionName subscriptionExternalId
              hasWideInternetExposure hasLimitedInternetExposure isAccessibleFromVPN
              providerUniqueId resourceGroupExternalId
              ipAddresses operatingSystem
            }
            ... on VulnerableAssetServerless {
              id name externalId subscriptionId subscriptionName subscriptionExternalId
              hasWideInternetExposure hasLimitedInternetExposure isAccessibleFromVPN
              providerUniqueId resourceGroupExternalId
              runtime
            }
            ... on VulnerableAssetContainerImage {
              id name externalId subscriptionId subscriptionName subscriptionExternalId
              hasWideInternetExposure hasLimitedInternetExposure isAccessibleFromVPN
              providerUniqueId resourceGroupExternalId
              registry repository isPublic
            }
            ... on VulnerableAssetContainer {
              id name externalId subscriptionId subscriptionName subscriptionExternalId
              hasWideInternetExposure hasLimitedInternetExposure isAccessibleFromVPN
              providerUniqueId resourceGroupExternalId
              podNamespace podName nodeName
            }
            ... on VulnerableAssetCommon {
              id name externalId subscriptionId subscriptionName subscriptionExternalId
              hasWideInternetExposure hasLimitedInternetExposure isAccessibleFromVPN
              providerUniqueId resourceGroupExternalId
            }
            ... on VulnerableAssetNetworkAddress {
              id name
              hasWideInternetExposure hasLimitedInternetExposure isAccessibleFromVPN
              address addressType
            }
          }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
    """
    filter_by = {"severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    if last_sync_time:
        filter_by["lastDetectedAt"] = {"after": last_sync_time}

    has_next_page = True
    total_synced = 0
    while has_next_page:
        variables = {"first": 250, "after": after, "filterBy": filter_by}
        data = query_wiz(token, query, variables)
        findings = data['data']['vulnerabilityFindings']['nodes']
        if not findings: break

        records = []
        for finding in findings:
            asset = finding.get('vulnerableAsset') or {}
            projects = finding.get('projects', [])
            project_id = projects[0].get('id') if projects else None
            last_detected = finding.get('lastDetectedAt')
            if last_detected and (not session_latest_timestamp or last_detected > session_latest_timestamp):
                session_latest_timestamp = last_detected
            
            # Robust IP address extraction for vulnerable assets
            ip_addresses = asset.get('ipAddresses')
            if not ip_addresses:
                # Handle VulnerableAssetNetworkAddress
                addr = asset.get('address')
                if addr:
                    ip_addresses = [addr]
            
            records.append((
                finding['id'],
                finding.get('name'),
                finding.get('vulnerabilityExternalId'),
                finding.get('severity'),
                finding.get('vendorSeverity'),
                finding.get('score'),
                finding.get('hasExploit'),
                finding.get('description'),
                finding['status'],
                finding.get('fixedVersion'),
                finding.get('firstDetectedAt'),
                finding.get('lastDetectedAt'),
                asset.get('id'),
                asset.get('name'),
                project_id,
                asset.get('externalId'),
                asset.get('subscriptionId'),
                asset.get('subscriptionName'),
                asset.get('subscriptionExternalId'),
                asset.get('hasWideInternetExposure'),
                asset.get('hasLimitedInternetExposure'),
                asset.get('isAccessibleFromVPN'),
                asset.get('providerUniqueId'),
                asset.get('resourceGroupExternalId'),
                ip_addresses if isinstance(ip_addresses, list) else [],
                json.dumps(finding)
            ))

        with conn.cursor() as cur:
            upsert_query = """
            INSERT INTO wiz_vulnerabilities (
                id, finding_name, cve_id, severity, vendor_severity,
                cvss_score, has_exploit,
                description, status, fixed_version,
                first_detected_at, last_detected_at,
                resource_id, asset_name, project_id,
                asset_external_id, asset_subscription_id, asset_subscription_name,
                asset_subscription_external_id,
                asset_has_wide_internet_exposure, asset_has_limited_internet_exposure,
                asset_is_accessible_from_vpn, asset_provider_unique_id,
                asset_resource_group, asset_ip_addresses,
                raw_data
            )
            VALUES %s
            ON CONFLICT (id) DO UPDATE SET
                finding_name = EXCLUDED.finding_name,
                severity = EXCLUDED.severity,
                vendor_severity = EXCLUDED.vendor_severity,
                cvss_score = EXCLUDED.cvss_score,
                has_exploit = EXCLUDED.has_exploit,
                description = EXCLUDED.description,
                status = EXCLUDED.status,
                fixed_version = EXCLUDED.fixed_version,
                last_detected_at = EXCLUDED.last_detected_at,
                asset_name = EXCLUDED.asset_name,
                project_id = EXCLUDED.project_id,
                asset_external_id = EXCLUDED.asset_external_id,
                asset_subscription_id = EXCLUDED.asset_subscription_id,
                asset_subscription_name = EXCLUDED.asset_subscription_name,
                asset_subscription_external_id = EXCLUDED.asset_subscription_external_id,
                asset_has_wide_internet_exposure = EXCLUDED.asset_has_wide_internet_exposure,
                asset_has_limited_internet_exposure = EXCLUDED.asset_has_limited_internet_exposure,
                asset_is_accessible_from_vpn = EXCLUDED.asset_is_accessible_from_vpn,
                asset_provider_unique_id = EXCLUDED.asset_provider_unique_id,
                asset_resource_group = EXCLUDED.asset_resource_group,
                asset_ip_addresses = EXCLUDED.asset_ip_addresses,
                raw_data = EXCLUDED.raw_data;
            """
            execute_values(cur, upsert_query, records)

        total_synced += len(findings)
        page_info = data['data']['vulnerabilityFindings']['pageInfo']
        has_next_page = page_info['hasNextPage']
        after = page_info['endCursor']
        if has_next_page:
            save_cursor(conn, task_name, after)
            logger.info(f"Synced {len(findings)} vulnerabilities (Total: {total_synced})...")
        else:
            clear_cursor(conn, task_name)
            if session_latest_timestamp:
                save_cursor(conn, "wiz_vulnerabilities_last_sync", session_latest_timestamp)
            logger.info(f"Sync complete. Total Vulnerabilities: {total_synced}.")

def fetch_and_sync_inventory(token, conn):
    logger.info("Starting Incremental Read-Only Inventory sync...")
    task_name_base = "wiz_inventory"
    resource_types = ["VIRTUAL_MACHINE", "CONTAINER_IMAGE", "SERVERLESS", "NETWORK_INTERFACE", "NETWORK_ADDRESS"]

    for r_type in resource_types:
        logger.info(f"Syncing {r_type} resources...")
        task_name = f"{task_name_base}_{r_type.lower()}"
        last_sync_key = f"{task_name}_last_sync"

        last_sync_time = get_last_cursor(conn, last_sync_key)
        session_latest_timestamp = last_sync_time
        after = get_last_cursor(conn, task_name)

        query = """
        query Inventory($first: Int, $after: String, $filterBy: CloudResourceV2Filters) {
          cloudResourcesV2(first: $first, after: $after, filterBy: $filterBy) {
            nodes {
              id
              name
              type
              nativeType
              externalId
              cloudPlatform
              region
              status
              createdAt
              updatedAt
              tags { key value }
              projects { id }
              cloudAccount {
                id
                name
                externalId
              }
              isOpenToAllInternet
              typeFields {
                ... on CloudResourceV2VirtualMachine {
                  ipAddresses
                }
              }
              graphEntity {
                properties
              }
            }
            pageInfo { hasNextPage endCursor }
          }
        }
        """
        filter_by = {"type": {"equals": r_type}}
        if last_sync_time:
            filter_by["updatedAt"] = {"after": last_sync_time}

        has_next_page = True
        total_synced = 0
        while has_next_page:
            variables = {"first": 500, "after": after, "filterBy": filter_by}
            data = query_wiz(token, query, variables)
            nodes = data['data']['cloudResourcesV2']['nodes']
            if not nodes: break

            records = []
            for node in nodes:
                projects = node.get('projects', [])
                project_id = projects[0].get('id') if projects else None

                # Convert tags list [{ key, value }] to a flat JSON object
                tags_list = node.get('tags') or []
                tags_json = json.dumps({t['key']: t['value'] for t in tags_list if isinstance(t, dict) and 'key' in t})

                updated_at = node.get('updatedAt')
                if updated_at and (not session_latest_timestamp or updated_at > session_latest_timestamp):
                    session_latest_timestamp = updated_at

                cloud_account = node.get('cloudAccount') or {}
                type_fields = node.get('typeFields') or {}
                graph_entity = node.get('graphEntity') or {}
                properties = graph_entity.get('properties') or {}

                ip_addresses = []
                if r_type == "VIRTUAL_MACHINE":
                    ip_addresses = type_fields.get('ipAddresses') or []
                elif r_type == "NETWORK_ADDRESS":
                    addr = properties.get('address')
                    if addr:
                        ip_addresses = [addr]

                has_public_ip = node.get('isOpenToAllInternet') or False
                if r_type == "NETWORK_ADDRESS":
                    has_public_ip = properties.get('isPublic') or has_public_ip

                records.append((
                    node['id'],
                    node['name'],
                    node['type'],
                    node.get('nativeType'),
                    node.get('externalId'),
                    node['cloudPlatform'],
                    node['region'],
                    cloud_account.get('id'),
                    cloud_account.get('name'),
                    cloud_account.get('externalId'),
                    node['status'],
                    node.get('createdAt'),
                    node.get('updatedAt'),
                    project_id,
                    ip_addresses,
                    [], # dns_names - placeholder if not easily available
                    tags_json,
                    has_public_ip,
                    json.dumps(node)
                ))

            with conn.cursor() as cur:
                upsert_query = """
                INSERT INTO wiz_inventory (
                    id, name, type, native_type, external_id,
                    provider, region,
                    subscription_id, subscription_name, subscription_external_id,
                    status, first_seen, last_seen, project_id,
                    ip_addresses, dns_names, tags, has_public_ip, raw_data
                )
                VALUES %s
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    type = EXCLUDED.type,
                    native_type = EXCLUDED.native_type,
                    external_id = EXCLUDED.external_id,
                    provider = EXCLUDED.provider,
                    region = EXCLUDED.region,
                    subscription_id = EXCLUDED.subscription_id,
                    subscription_name = EXCLUDED.subscription_name,
                    subscription_external_id = EXCLUDED.subscription_external_id,
                    status = EXCLUDED.status,
                    first_seen = EXCLUDED.first_seen,
                    last_seen = EXCLUDED.last_seen,
                    project_id = EXCLUDED.project_id,
                    ip_addresses = EXCLUDED.ip_addresses,
                    dns_names = EXCLUDED.dns_names,
                    tags = EXCLUDED.tags,
                    has_public_ip = EXCLUDED.has_public_ip,
                    raw_data = EXCLUDED.raw_data;
                """
                execute_values(cur, upsert_query, records)

            total_synced += len(nodes)
            page_info = data['data']['cloudResourcesV2']['pageInfo']
            has_next_page = page_info['hasNextPage']
            after = page_info['endCursor']
            if has_next_page:
                save_cursor(conn, task_name, after)
                logger.info(f"Synced {len(nodes)} {r_type} assets (Total: {total_synced})...")
            else:
                clear_cursor(conn, task_name)
                if session_latest_timestamp:
                    save_cursor(conn, last_sync_key, session_latest_timestamp)
                logger.info(f"Finished syncing {r_type}. Total: {total_synced}.")

    logger.info("Inventory sync complete.")

def main():
    try:
        token = get_wiz_token()
        conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, database=DB_NAME, user=DB_USER, password=DB_PASS)
        conn.autocommit = True
        setup_database(conn)
        sync_tasks = [
            ("Issues", fetch_and_sync_issues),
            ("Vulnerabilities", fetch_and_sync_vulnerabilities),
            ("Inventory", fetch_and_sync_inventory)
        ]
        for name, task in sync_tasks:
            try:
                task(token, conn)
            except Exception as e:
                logger.error(f"Failed to sync {name}: {e}")
        logger.info("Wiz Sync process finished.")
    except Exception as e:
        logger.error(f"Critical initialization failure: {e}")
    finally:
        if 'conn' in locals() and conn: conn.close()

if __name__ == "__main__":
    main()
