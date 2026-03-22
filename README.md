# Security Data Synchronizer (Tenable & Wiz)

A Python-based utility to synchronize security findings, assets, and vulnerabilities from **Tenable Cloud** and **Wiz** into a centralized **PostgreSQL** database. This tool supports incremental syncs using cursors to ensure efficiency and resumability.

## 🚀 Features

- **Tenable Integration**: Synchronizes assets and vulnerability findings.
- **Tenable ASM Integration**: Synchronizes attack surface assets and discovery data.
- **Wiz Integration**: Synchronizes issues, vulnerabilities, and cloud inventory (VMs, Container Images, Serverless).
- **CISA KEV Integration**: Synchronizes the Catalog of Known Exploited Vulnerabilities.
- **Incremental Sync**: Uses a `sync_state` table to track the last processed records and resume from where it left off.
- **Automated Schema Management**: Automatically initializes and migrates the database schema on startup.
- **GraphQL Introspection**: Includes utilities to explore and debug the Wiz GraphQL API.

## 🛠️ Prerequisites

- **Python 3.8+**
- **PostgreSQL Database**
- **API Credentials**:
  - Tenable: Access Key and Secret Key.
  - Wiz: Client ID, Client Secret, and API URL.

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd all-findings
   ```

2. **Install dependencies**:
   ```bash
   pip install requests psycopg2-binary python-dotenv
   ```

3. **Configure Environment Variables**:
   Create a `.env` file in the root directory with the following variables:
   ```env
   # Database Configuration
   DB_HOST=localhost
   DB_PORT=5432
   DB_NAME=your_db_name
   DB_USER=your_db_user
   DB_PASS=your_db_password

   # Tenable Configuration
   TENABLE_ACCESS_KEY=your_tenable_access_key
   TENABLE_SECRET_KEY=your_tenable_secret_key
   TENABLE_ASM_API_KEY=your_tenable_asm_api_key

   # Wiz Configuration
   WIZ_CLIENT_ID=your_wiz_client_id
   WIZ_CLIENT_SECRET=your_wiz_client_secret
   WIZ_API_URL=https://api.us1.wiz.io/graphql
   ```

## 🚦 Usage

### 1. Synchronize Tenable Cloud Data
Run the Tenable sync script to fetch assets and findings:
```bash
python tenable_sync.py
```

### 2. Synchronize Tenable ASM Data
Run the Tenable ASM sync script to fetch attack surface discovery data:
```bash
python tenable_asm_sync.py
```

### 3. Synchronize Wiz Data
Run the Wiz sync script to fetch issues, vulnerabilities, and inventory:
```bash
python wiz_sync.py
```

### 4. Synchronize CISA KEV Data
Run the CISA KEV sync script to fetch the Catalog of Known Exploited Vulnerabilities:
```bash
python cisa_kev_sync.py
```

### 5. API Exploration (Optional)
Use the introspection scripts to explore the Wiz GraphQL schema:
```bash
python introspect_wiz.py
```

## 📂 Project Structure

- `tenable_sync.py`: Main script for Tenable Cloud synchronization.
- `tenable_asm_sync.py`: Main script for Tenable ASM synchronization.
- `wiz_sync.py`: Main script for Wiz API synchronization.
- `cisa_kev_sync.py`: Main script for CISA KEV catalog synchronization.
- `schema.sql`: SQL definitions for the database tables.
- `introspect_*.py`: Various scripts for exploring Wiz GraphQL types and filters.
- `check_*.py`: Validation scripts for filters and data types.

## 📊 Data Mapping

The following tables and fields are synchronized from each source:

### 🔹 Tenable Cloud
... (existing Tenable mapping) ...

### 🔹 Tenable ASM

| Database Table | Field | Source Field (ASM API) | Description |
| :--- | :--- | :--- | :--- |
| **tenable_asm_assets** | `id` | `id` | Unique ASM asset ID. |
| | `name` | `name` | Asset name/domain. |
| | `type` | `type` | Asset type (Domain, IP, etc). |
| | `address` | `address` | IP address. |
| | `port` | `port` | Open port number. |
| | `protocol` | `protocol` | TCP/UDP. |
| | `service` | `service` | Detected service (HTTP, SSH, etc). |
| | `last_seen` | `last_seen` | Last discovery time. |

### 🔹 Wiz
... (existing Wiz mapping) ...

### 🔹 CISA KEV

| Database Table | Field | Source Field (CISA JSON) | Description |
| :--- | :--- | :--- | :--- |
| **cisa_kev** | `cve_id` | `cveID` | Unique CVE identifier. |
| | `vendor_project` | `vendorProject` | Vendor or project name. |
| | `product` | `product` | Affected product. |
| | `vulnerability_name` | `vulnerabilityName` | Name of the vulnerability. |
| | `date_added` | `dateAdded` | Date added to the KEV catalog. |
| | `short_description` | `shortDescription` | Brief summary of the risk. |
| | `required_action` | `requiredAction` | Remediation steps required. |
| | `due_date` | `dueDate` | Deadline for remediation. |
| | `known_ransomware_use`| `knownRansomwareCampaignUse`| If used in ransomware. |
| | `cwes` | `cwes` | Array of associated CWEs. |

> **Note**: Every table includes a `raw_data` JSONB column containing the full original API response for audit and extended analysis.

## 🛡️ Security

- Never commit your `.env` file or any credentials to source control.
- Ensure the PostgreSQL database is secured with appropriate access controls.
