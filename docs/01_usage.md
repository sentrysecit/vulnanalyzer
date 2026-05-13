# VulnAnalyzer - CLI Usage Guide

This guide explains how to use all VulnAnalyzer CLI commands.

## Table of Contents

1. [Host Discovery](#1-host-discovery)
2. [Vulnerability Scanning](#2-vulnerability-scanning)
3. [Exploitation](#3-exploitation)
4. [MITRE Caldera Integration](#4-mitre-caldera-integration)
5. [Subdomain Enumeration](#5-subdomain-enumeration)
6. [Path Fuzzing](#6-path-fuzzing)
7. [Web Interface](#7-web-interface)
8. [Typical Workflows](#8-typical-workflows)

## 1. Host Discovery

Discover which hosts are active on a network before scanning for vulnerabilities.

**Command:**

```bash
python main.py discover <network_range> [-o OUTPUT]
```

**Example:**

```bash
python main.py discover 192.168.1.0/24
```

**Output:** The command displays a list of active IP addresses in JSON format.

```json
{
    "active_hosts": [
        "192.168.1.1",
        "192.168.1.10",
        "192.168.1.54"
    ]
}
```

**Save output to a file:**

```bash
python main.py discover 192.168.1.0/24 -o discovered_hosts.json
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `-o, --output <file>` | Save results to JSON file | None |

---

## 2. Vulnerability Scanning

Scan a target for vulnerabilities. The scanner performs Nmap scanning, CVE detection, and optionally searches for available exploits.

**Command:**

```bash
python main.py scan <target> [--type {quick|full|stealth}] [-o OUTPUT] [--report REPORT]
```

**Example:**

```bash
python main.py scan 192.168.1.10
```

### Scan Types

| Type | Description |
|------|-------------|
| `quick` | Scan most common ports |
| `full` | Scan all TCP ports + OS detection (default) |
| `stealth` | Slow and stealthy scan to avoid detection |

**Example of a quick scan:**

```bash
python main.py scan 192.168.1.10 --type quick
```

### Save Scan Results

Save scan results to a JSON file for later analysis or use in the exploitation phase:

```bash
python main.py scan 192.168.1.10 --type quick -o scan_results.json
```

### Generate Report

Generate an HTML report from the scan:

```bash
python main.py scan 192.168.1.10 --type full --report report.html
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--type {quick\|full\|stealth}` | Scan type | full |
| `-o, --output <file>` | Save results to JSON file | None |
| `--report <file.html>` | Generate HTML report | None |

---

## 3. Exploitation

Execute exploits based on detected vulnerabilities.

**Command:**

```bash
python main.py exploit [options]
```

**Examples:**

```bash
# List available exploits
python main.py exploit --list

# Run exploits from a previous scan file
python main.py exploit --scan-file scan_results.json

# Run a specific exploit against a target
python main.py exploit --scan-file scan_results.json --target 192.168.1.10 --exploit exploit_name
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--scan-file <file>` | Previous scan results JSON | None |
| `--target <target>` | Specific target IP | None |
| `--exploit <name>` | Specific exploit to execute | None |
| `--list` | List available exploits | - |

---

## 4. MITRE Caldera Integration

Interact with MITRE Caldera for adversary emulation and agent deployment.

**Command:**

```bash
python main.py caldera [options]
```

**Examples:**

```bash
# Deploy an agent for a Linux target
python main.py caldera --deploy --platform linux

# Run a Caldera assessment with a specific adversary profile
python main.py caldera --run --adversary "APT29"
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--deploy` | Generate agent for target | - |
| `--platform {windows\|linux\|darwin}` | Agent platform | windows |
| `--run` | Run Caldera assessment | - |
| `--adversary <name>` | Adversary profile name | None |

### Prerequisites

- Caldera server must be running (use `docker-compose up` or the setup script)
- Set `CALDERA_BASE_URL` and `CALDERA_API_KEY` in `.env`

---

## 5. Subdomain Enumeration

Discover subdomains for a target domain using passive enumeration (subfinder) and active fuzzing (ffuf).

**Command:**

```bash
python main.py subdomain <domain> [options]
```

**Example:**

```bash
python main.py subdomain example.com
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--wordlist`, `-w` | Wordlist for subdomain fuzzing | SecLists medium |
| `--output`, `-o` | Output file for results | subdomains.txt |
| `--threads`, `-t` | Number of threads | 40 |
| `--nuclei` | Run nuclei on discovered hosts | disabled |
| `--silent` | Minimal output | disabled |

**Example with custom wordlist:**

```bash
python main.py subdomain example.com -w /path/to/wordlist.txt -o results.txt
```

**Example with nuclei scanning:**

```bash
python main.py subdomain example.com --nuclei
```

---

## 6. Path Fuzzing

Discover directories and paths on a web server using ffuf.

**Command:**

```bash
python main.py fuzz <url> [options]
```

**Example:**

```bash
python main.py fuzz http://example.com
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--wordlist`, `-w` | Wordlist for path fuzzing | common.txt |
| `--output`, `-o` | Output file for results | paths.txt |
| `--threads`, `-t` | Number of threads | 40 |
| `--extensions`, `-e` | File extensions | None |
| `--silent` | Minimal output | disabled |

**Example with extensions:**

```bash
python main.py fuzz http://example.com -e .php,.html,.txt -o paths.txt
```

**Example with large wordlist:**

```bash
python main.py fuzz http://example.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

---

## 7. Web Interface

Start the web interface for a graphical user interface with dashboard, scan management, and report viewing.

**Command:**

```bash
python main.py web [--host HOST] [--port PORT] [--reload]
```

**Example:**

```bash
python main.py web --port 8000
```

**Options:**

| Option | Description | Default |
|--------|-------------|---------|
| `--host <addr>` | Bind host | 0.0.0.0 |
| `--port <port>` | Bind port | 8000 |
| `--reload` | Enable auto-reload for development | disabled |

**Access at:** <http://localhost:8000/web/dashboard>

For full web interface documentation, see the [Web Interface & API Guide](./02_web_interface.md).

---

## 8. Typical Workflows

### Option 1: CLI Only

```bash
# 1. Discover hosts
python main.py discover 192.168.1.0/24 -o hosts.json

# 2. Scan a target
python main.py scan 192.168.1.10 --type full -o results.json

# 3. Generate a report
python main.py scan 192.168.1.10 --type full --report report.html

# 4. List available exploits
python main.py exploit --list

# 5. Run exploits
python main.py exploit --scan-file results.json
```

### Option 2: CLI + Web

```bash
# 1. Start the web interface
python main.py web --port 8000

# 2. In your browser, go to New Scan
# 3. Enter target and scan type
# 4. The scan is saved automatically to the database
# 5. View results, reports, and statistics from the web interface
```

### Option 3: API + External Tools

```bash
# 1. Start the server
python main.py web

# 2. Integrate with other tools using the REST API
curl -X POST http://localhost:8000/api/scans \
    -H "Content-Type: application/json" \
    -d '{"target": "example.com", "scan_type": "quick"}'

# 3. Check vulnerability results
curl http://localhost:8000/api/vulns/scan/1

# 4. Search for CVEs
curl -X POST http://localhost:8000/api/vulns/cve/search \
    -H "Content-Type: application/json" \
    -d '{"keyword": "apache", "limit": 10}'
```

For full API documentation, see the [Web Interface & API Guide](./02_web_interface.md). For the vulnerability database system, see the [Vulnerability Database Guide](./03_vulnerability_database.md).
