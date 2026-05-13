# VulnAnalyzer - Web Interface & API Guide

This guide covers the web interface, REST API, and database system of VulnAnalyzer.

## Table of Contents

1. [Installation](#1-installation)
2. [Web Interface](#2-web-interface)
3. [Subdomain Enumeration (Web)](#3-subdomain-enumeration-web)
4. [Path Fuzzing (Web)](#4-path-fuzzing-web)
5. [REST API](#5-rest-api)
6. [Database](#6-database)
7. [Configuration](#7-configuration)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Installation

### Prerequisites

- Python 3.10+
- nmap installed on the system

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Start the Server

```bash
python main.py web
```

The server starts at <http://localhost:8000> by default.

---

## 2. Web Interface

The web interface provides a visual way to manage scans, view results, and generate reports.

### Access

1. Start the web server:

```bash
python main.py web
```

2. Open your browser at:
   - **Dashboard:** <http://localhost:8000/web/dashboard>
   - **Scan List:** <http://localhost:8000/web/scans>
   - **New Scan:** <http://localhost:8000/web/scan/new>
   - **Subdomains:** <http://localhost:8000/web/subdomain/new>
   - **Fuzzing:** <http://localhost:8000/web/fuzz/new>

### Pages

#### Dashboard

Displays a summary with:

- Total scans performed
- Targets analyzed
- Total vulnerabilities found
- Severity distribution (chart)
- Top 5 most vulnerable targets
- Recent scans

#### Scan List

Allows you to:

- View all scans performed
- Filter by target, type, and status
- Search by target name
- View details of each scan
- Delete scans

#### Scan Detail

Shows:

- Scan information (target, type, status, date)
- Ports and services detected
- Vulnerabilities found with severity
- Remediation recommendations
- Links to download reports

#### New Scan

Form to:

- Enter target (IP, domain, or CIDR range)
- Select scan type (quick, full, stealth)
- Start the scan (runs in background)

#### Report Viewer

Displays generated reports with options to download in HTML or JSON format.

---

## 3. Subdomain Enumeration (Web)

The web interface allows visual subdomain enumeration.

### Form Options

- **Target Domain**: Target domain (e.g., example.com)
- **Wordlist**: Predefined wordlist selection or custom path
- **Threads**: Number of threads (default: 40)
- **Run Nuclei**: Option to run nuclei on discovered hosts

### URL

- **New Enumeration:** <http://localhost:8000/web/subdomain/new>
- **Enumeration List:** <http://localhost:8000/web/enum/subdomains>
- **Enumeration Detail:** <http://localhost:8000/web/enum/subdomains/{id}>

### Flow

1. Enter the target domain
2. Select the wordlist
3. Adjust the number of threads
4. Click "Start Enumeration"
5. Results are displayed on screen

---

## 4. Path Fuzzing (Web)

The web interface allows directory and path fuzzing.

### Form Options

- **Target URL**: Full URL with protocol (http:// or https://)
- **Wordlist**: Predefined wordlist selection or custom path
- **Extensions**: File extensions to test (e.g., .php,.html,.txt)
- **Threads**: Number of threads (default: 40)

### URL

- **New Fuzzing:** <http://localhost:8000/web/fuzz/new>
- **Fuzzing List:** <http://localhost:8000/web/enum/fuzz>
- **Fuzzing Detail:** <http://localhost:8000/web/enum/fuzz/{id}>

### Flow

1. Enter the target URL
2. Select the wordlist
3. Optionally: Add extensions
4. Click "Start Fuzzing"
5. Results are displayed on screen

---

## 5. REST API

The REST API allows integration with other tools and automation of processes.

### Interactive Documentation

Access the Swagger documentation at: <http://localhost:8000/docs>

### Scan Endpoints (`/api/scans`)

| Method | Endpoint | Description | Response Model |
|--------|----------|-------------|----------------|
| GET | `/api/scans` | List scans (paginated, filterable) | ScanListResponse |
| POST | `/api/scans` | Create scan (runs async) | ScanResponse |
| GET | `/api/scans/{id}` | Get scan details | ScanDetail |
| DELETE | `/api/scans/{id}` | Delete scan | dict |
| PATCH | `/api/scans/{id}/status` | Update scan status | ScanResponse |
| GET | `/api/scans/stats` | Global statistics | StatsResponse |

### Vulnerability Endpoints (`/api/vulns`)

| Method | Endpoint | Description | Response Model |
|--------|----------|-------------|----------------|
| GET | `/api/vulns/scan/{scan_id}` | Get vulnerabilities for a scan | List[VulnerabilityResponse] |
| GET | `/api/vulns/enum/{enum_id}` | Get vulnerabilities for a subdomain enum | List[VulnerabilityResponse] |
| GET | `/api/vulns/host/{host}` | Get vulnerabilities for a host | List[VulnerabilityResponse] |
| GET | `/api/vulns/stats` | Vulnerability statistics | VulnerabilityStatsResponse |
| POST | `/api/vulns/cve` | Lookup CVE by ID | CVEDetailResponse |
| POST | `/api/vulns/cve/search` | Search CVEs by keyword | List[CVEDetailResponse] |
| GET | `/api/vulns/exploit/{cve_id}` | Get exploits for a CVE | List[ExploitResponse] |
| POST | `/api/vulns/exploit/search` | Search exploits by service | List[ExploitResponse] |
| DELETE | `/api/vulns/{vuln_id}` | Delete a vulnerability | dict |
| POST | `/api/vulns/check-scan/{scan_id}` | Trigger CVE/exploit check for a scan | dict |

> For detailed vulnerability API usage, see the [Vulnerability Database Guide](./03_vulnerability_database.md).

### Report Endpoints (`/api/reports`)

| Method | Endpoint | Description | Response Model |
|--------|----------|-------------|----------------|
| GET | `/api/reports/{scan_id}` | Get report data (JSON) | ReportResponse |
| GET | `/api/reports/{scan_id}/html` | Get report as HTML | HTMLResponse |
| GET | `/api/reports/{scan_id}/preview` | Report preview (Jinja2 rendered) | HTMLResponse |
| GET | `/api/reports/{scan_id}/download/{format}` | Download report (html/json) | FileResponse |

### Enumeration Endpoints (`/api/enum`)

| Method | Endpoint | Description | Response Model |
|--------|----------|-------------|----------------|
| GET | `/api/enum/wordlists` | Available wordlists (type=subdomain/fuzz) | List[WordlistResponse] |
| POST | `/api/enum/subdomain` | Start subdomain enumeration | SubdomainResponse |
| GET | `/api/enum/subdomain` | List all enumerations | List[SubdomainDetail] |
| GET | `/api/enum/subdomain/{id}` | Get enumeration details | SubdomainDetail |
| GET | `/api/enum/subdomain/{id}/results` | Get subdomains found | List[SubdomainResultResponse] |
| POST | `/api/enum/fuzz` | Start path fuzzing | FuzzResponse |
| GET | `/api/enum/fuzz` | List all fuzzing jobs | List[FuzzDetail] |
| GET | `/api/enum/fuzz/{id}` | Get fuzzing details | FuzzDetail |
| GET | `/api/enum/fuzz/{id}/results` | Get paths found | List[PathResultResponse] |

### Health Endpoint

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |

### API Examples with curl

**List scans:**

```bash
curl http://localhost:8000/api/scans
```

**Create a scan:**

```bash
curl -X POST http://localhost:8000/api/scans \
    -H "Content-Type: application/json" \
    -d '{"target": "192.168.1.10", "scan_type": "quick"}'
```

**Get scan details:**

```bash
curl http://localhost:8000/api/scans/1
```

**Get scan statistics:**

```bash
curl http://localhost:8000/api/scans/stats
```

**Download a report (JSON):**

```bash
curl -O http://localhost:8000/api/reports/1/download/json
```

**Download a report (HTML):**

```bash
curl -O http://localhost:8000/api/reports/1/download/html
```

**Preview a report:**

```bash
curl http://localhost:8000/api/reports/1/preview
```

**List available wordlists:**

```bash
curl "http://localhost:8000/api/enum/wordlists?type=subdomain"
curl "http://localhost:8000/api/enum/wordlists?type=fuzz"
```

**Start subdomain enumeration:**

```bash
curl -X POST http://localhost:8000/api/enum/subdomain \
    -H "Content-Type: application/json" \
    -d '{"target": "example.com", "wordlist": "", "threads": 40, "use_nuclei": false}'
```

**Start path fuzzing:**

```bash
curl -X POST http://localhost:8000/api/enum/fuzz \
    -H "Content-Type: application/json" \
    -d '{"target": "http://example.com", "wordlist": "", "threads": 40, "extensions": ".php,.html"}'
```

**Get vulnerabilities for a scan:**

```bash
curl http://localhost:8000/api/vulns/scan/1
```

**Get vulnerabilities for a host:**

```bash
curl http://localhost:8000/api/vulns/host/192.168.1.10
```

**Lookup a CVE:**

```bash
curl -X POST http://localhost:8000/api/vulns/cve \
    -H "Content-Type: application/json" \
    -d '{"cve_id": "CVE-2021-44228"}'
```

**Search CVEs by keyword:**

```bash
curl -X POST http://localhost:8000/api/vulns/cve/search \
    -H "Content-Type: application/json" \
    -d '{"keyword": "apache log4j", "limit": 10}'
```

**Get exploits for a CVE:**

```bash
curl http://localhost:8000/api/vulns/exploit/CVE-2021-44228
```

**Search exploits by service:**

```bash
curl -X POST http://localhost:8000/api/vulns/exploit/search \
    -H "Content-Type: application/json" \
    -d '{"service": "apache", "version": "2.4"}'
```

**Trigger CVE/exploit check for a scan:**

```bash
curl -X POST http://localhost:8000/api/vulns/check-scan/1
```

**Get vulnerability statistics:**

```bash
curl http://localhost:8000/api/vulns/stats
```

---

## 6. Database

VulnAnalyzer uses SQLite for persistent storage of scans, vulnerabilities, and enumeration results.

### Location

The database file is at:

```
data/vulnanalyzer.db
```

### Tables

#### `scans`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Unique scan ID (PK) |
| target | VARCHAR(255) | Target scanned |
| scan_type | VARCHAR(50) | Scan type (quick/full/stealth) |
| status | VARCHAR(20) | Status (pending/running/completed/failed) |
| created_at | DATETIME | Creation timestamp |
| completed_at | DATETIME | Completion timestamp |
| results_json | TEXT | JSON-encoded scan results |
| error_message | TEXT | Error message if scan failed |
| total_vulnerabilities | INTEGER | Total vulnerabilities found |
| critical_count | INTEGER | Critical severity count |
| high_count | INTEGER | High severity count |
| medium_count | INTEGER | Medium severity count |
| low_count | INTEGER | Low severity count |
| info_count | INTEGER | Informational count |

#### `subdomain_enum`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Unique enumeration ID (PK) |
| target | VARCHAR(255) | Target domain |
| status | VARCHAR(20) | Status (pending/running/completed/failed) |
| wordlist | VARCHAR(255) | Wordlist used |
| total_found | INTEGER | Total subdomains found |
| alive_count | INTEGER | Alive subdomain count |
| created_at | DATETIME | Creation timestamp |
| completed_at | DATETIME | Completion timestamp |
| error_message | TEXT | Error message if failed |

#### `subdomain_results`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Unique result ID (PK) |
| enum_id | INTEGER | FK -> subdomain_enum.id |
| subdomain | VARCHAR(255) | Discovered subdomain |
| is_alive | BOOLEAN | Whether the subdomain is alive |
| created_at | DATETIME | Creation timestamp |

#### `path_fuzz`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Unique fuzz job ID (PK) |
| target | VARCHAR(255) | Target URL |
| status | VARCHAR(20) | Status (pending/running/completed/failed) |
| wordlist | VARCHAR(255) | Wordlist used |
| extensions | VARCHAR(255) | File extensions tested |
| total_found | INTEGER | Total paths found |
| created_at | DATETIME | Creation timestamp |
| completed_at | DATETIME | Completion timestamp |
| error_message | TEXT | Error message if failed |

#### `path_results`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Unique result ID (PK) |
| fuzz_id | INTEGER | FK -> path_fuzz.id |
| path | VARCHAR(500) | Discovered path |
| status_code | VARCHAR(10) | HTTP status code |
| created_at | DATETIME | Creation timestamp |

#### `vulnerabilities`

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Unique vulnerability ID (PK) |
| scan_type | VARCHAR(50) | Source scan type |
| scan_id | INTEGER | FK -> scans.id (nullable) |
| enum_id | INTEGER | FK -> subdomain_enum.id (nullable) |
| host | VARCHAR(255) | Affected host |
| subdomain | VARCHAR(255) | Affected subdomain |
| service | VARCHAR(100) | Affected service |
| port | INTEGER | Affected port |
| cve_id | VARCHAR(20) | CVE identifier (indexed) |
| title | VARCHAR(255) | Vulnerability title |
| severity | VARCHAR(20) | Severity level |
| cvss_score | VARCHAR(10) | CVSS score |
| is_exploited | BOOLEAN | Whether the vulnerability is known exploited |
| exploit_available | BOOLEAN | Whether an exploit is available |
| edb_id | VARCHAR(20) | Exploit-DB ID |
| description | TEXT | Vulnerability description |
| created_at | DATETIME | Creation timestamp |

> For more details on the vulnerability database, see the [Vulnerability Database Guide](./03_vulnerability_database.md).

### Direct Database Access

You can query the database directly with sqlite3:

```bash
sqlite3 data/vulnanalyzer.db
```

**Useful queries:**

```sql
-- View all tables
.schema

-- List recent scans
SELECT * FROM scans ORDER BY created_at DESC LIMIT 10;

-- Scans with most critical vulnerabilities
SELECT target, critical_count FROM scans ORDER BY critical_count DESC;

-- General statistics
SELECT
    COUNT(*) as total,
    SUM(total_vulnerabilities) as total_vulns,
    SUM(critical_count) as total_critical
FROM scans;

-- All vulnerabilities for a specific host
SELECT cve_id, title, severity, cvss_score FROM vulnerabilities WHERE host = '192.168.1.10';

-- Known exploited vulnerabilities
SELECT cve_id, title, severity, host FROM vulnerabilities WHERE is_exploited = 1;

-- Vulnerability counts by severity
SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity ORDER BY count DESC;
```

---

## 7. Configuration

### Environment Variables (.env)

```env
# Caldera Configuration
CALDERA_BASE_URL=http://localhost:8888
CALDERA_API_KEY=your-api-key

# General
LOG_LEVEL=INFO
OUTPUT_DIR=./reports
```

### Application Settings (`config/settings.py`)

| Setting | Default | Description |
|---------|---------|-------------|
| `DEBUG` | True | Debug mode |
| `VERSION` | "1.0.0" | Application version |
| `DEFAULT_SCAN_TYPE` | "full" | Default scan type |
| `DEFAULT_THREADS` | 10 | Default thread count |
| `DEFAULT_TIMEOUT` | 30 | Default timeout (seconds) |
| `REPORT_COMPANY_NAME` | - | Company name for reports |
| `LOG_LEVEL` | "INFO" | Logging level |
| `LOG_FILE` | - | Log file path |
| `EXPLOIT_TIMEOUT` | - | Exploit execution timeout |

---

## 8. Troubleshooting

### Error: nmap not found

```bash
# Linux (Debian/Ubuntu)
sudo apt install nmap

# Linux (Fedora/CentOS)
sudo dnf install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html
```

### Port already in use

```bash
# Use a different port
python main.py web --port 8080
```

### Database permission error

```bash
chmod 755 data/
chmod 644 data/vulnanalyzer.db
```

### CVE cache is stale

If CVE data appears outdated, delete the cache directory to force fresh lookups:

```bash
rm -rf data/cve_cache/
```

The next CVE query will fetch fresh data from NVD and CISA KEV.
