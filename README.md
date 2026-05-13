# VulnAnalyzer Framework

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Description

VulnAnalyzer Framework is a vulnerability analysis tool that integrates MITRE Caldera to perform automated security assessments. It enables efficient identification, analysis, and exploitation of vulnerabilities in systems and networks through an integrated CLI, web interface, and REST API.

## Features

- **Vulnerability Scanning** - Automated scanning with Nmap (quick, full, stealth modes)
- **CVE Detection** - Automatic CVE lookup via NVD API and CISA Known Exploited Vulnerabilities (KEV) catalog
- **Exploit Finding** - Search for available exploits via searchsploit and pyexploitdb
- **Vulnerability Database** - Full CRUD for vulnerabilities with per-scan, per-host, and per-enum querying
- **Subdomain Enumeration** - Passive enumeration (subfinder) and active fuzzing (ffuf)
- **Path/Directory Fuzzing** - Discover hidden paths and directories on web servers (ffuf)
- **Host Discovery** - Network host discovery via Nmap
- **Exploit Execution** - Run exploits against detected vulnerabilities
- **MITRE Caldera Integration** - Adversary emulation and agent deployment
- **Report Generation** - Detailed reports in HTML, JSON, and PDF formats
- **Web Interface** - Dashboard, scan management, report viewer, and enumeration UI
- **REST API** - Full API for integration with other tools and automation
- **SQLite Database** - Persistent storage for scans, vulnerabilities, and enumeration results
- **Web Vulnerability Scanning** - Security header checking on web targets
- **Docker Support** - Docker Compose for Caldera and optional OpenVAS

## Installation

### Prerequisites

- Python 3.10 or higher
- Nmap (for network scanning)
- Docker (for Caldera deployment)
- subfinder (optional, for passive subdomain enumeration)
- ffuf (optional, for subdomain/path fuzzing)
- nuclei (optional, for vulnerability scanning on discovered hosts)
- searchsploit (optional, for exploit search)

### Installation Steps

#### 1. Clone the Repository

```bash
git clone https://github.com/sentryuc/vulnanalyzer.git
cd vulnanalyzer
```

#### 2. Create a Virtual Environment

```bash
# Create the virtual environment
python -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

#### 3. Run the Setup Script

The setup script installs Python dependencies, clones Caldera, and builds its Docker image:

```bash
chmod +x setup.sh
./setup.sh
```

What the script does:
1. Checks for `pip`, `git`, and `docker` commands
2. Verifies Docker daemon is running
3. Installs `requirements.txt`
4. Creates `tools/` and output directories
5. Clones Caldera (branch 5.3.0, recursive)
6. Builds the Caldera Docker image

#### 4. Install Nmap (if not available)

```bash
# Debian/Ubuntu
sudo apt update && sudo apt install nmap -y

# Fedora/CentOS/RHEL
sudo dnf install nmap -y

# Arch/Manjaro
sudo pacman -S nmap

# macOS (with Homebrew)
brew install nmap
```

## Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```bash
# Caldera Configuration
CALDERA_BASE_URL=http://your-caldera-server:8888
CALDERA_API_KEY=your-caldera-api-key

# General Configuration
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

### Obtaining the Caldera API Key

1. Access Caldera through the Docker container:

```bash
docker exec -it caldera-server /bin/bash
```

2. Retrieve the login credentials (Caldera generates a new API key and password at each startup):

```bash
cat conf/local.yml
```

3. Use the startup credentials depending on whether you want to work with the `red` or `blue` agent.
4. Copy the API key into the `.env` file.

## Project Structure

```
vulnanalyzer/
├── api/                        # FastAPI REST API
│   ├── routers/                # API endpoints
│   │   ├── scans.py            # Scan CRUD endpoints
│   │   ├── reports.py          # Report generation/viewing
│   │   ├── enum.py             # Subdomain & fuzzing endpoints
│   │   └── vulns.py            # Vulnerability & CVE endpoints
│   ├── tools/                  # Tool assets (wordlists, fuzzing output)
│   ├── models.py               # SQLAlchemy models (6 tables)
│   ├── schemas.py              # Pydantic schemas (21 schemas)
│   ├── database.py             # SQLite connection
│   └── main.py                 # FastAPI app + web routes
├── core/                       # Core functionality
│   ├── scanner.py              # Vulnerability scanner (nmap + CVE + exploits)
│   ├── cve_scanner.py          # CVE lookup (NVD API, CISA KEV, local cache)
│   ├── exploit_finder.py       # Exploit search (searchsploit, pyexploitdb)
│   ├── discover.py             # Host discovery
│   ├── exploiter.py            # Exploit execution
│   ├── caldera_client.py       # MITRE Caldera integration
│   ├── subdomain_enum.py       # Subdomain enumeration (subfinder + ffuf)
│   ├── path_fuzz.py            # Path/directory fuzzing (ffuf)
│   └── utils.py                # Utility functions
├── services/                   # Business logic
│   ├── scan_service.py         # Scan orchestration service
│   └── report_service.py       # Report generation service
├── config/                     # Configuration
│   └── settings.py             # Application settings
├── modules/                    # Fingerprints and detection modules
│   └── fingerprints/           # Service fingerprinting
├── data/                       # Runtime data
│   ├── vulnanalyzer.db         # SQLite database
│   └── cve_cache/              # CVE JSON cache + KEV cache
├── web/                        # Web interface
│   ├── templates/              # Jinja2 HTML templates
│   └── static/                 # Static assets
├── reports/                    # Report generation
│   └── report_generator.py     # HTML, JSON, PDF report generation
├── docs/                       # Documentation
│   ├── 01_usage.md             # CLI usage guide
│   ├── 02_web_interface.md     # Web & API guide
│   └── 03_vulnerability_database.md  # Vulnerability system guide
├── docker-compose.yml          # Docker config (Caldera + optional OpenVAS)
├── main.py                     # CLI entry point
├── requirements.txt            # Python dependencies
└── setup.sh                    # Setup script (deps + Caldera + dirs)
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# CLI Usage
python main.py scan 192.168.1.10 --type full
python main.py discover 192.168.1.0/24
python main.py subdomain example.com
python main.py fuzz http://example.com
python main.py exploit --list

# Start Web Interface
python main.py web

# Access at http://localhost:8000/web/dashboard
```

## Documentation

- [CLI Usage Guide](./docs/01_usage.md) - Complete CLI command reference
- [Web Interface & API Guide](./docs/02_web_interface.md) - Web UI and REST API documentation
- [Vulnerability Database Guide](./docs/03_vulnerability_database.md) - CVE scanning, exploit finding, and vulnerability management

## Useful Links

- [Caldera Documentation](https://caldera.readthedocs.io/)
- [Nmap Guide](https://nmap.org/docs.html)
- [NVD API](https://nvd.nist.gov/vuln/data-feeds)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

**Note**: This project is under active development. Features may change without prior notice.
