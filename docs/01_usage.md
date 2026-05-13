# Using VulnAnalyzer

This guide explains how to use the main features of VulnAnalyzer.

## Table of Contents

1. [Host Discovery](#1-host-discovery)
2. [Vulnerability Scanning](#2-vulnerability-scanning)
3. [Subdomain Enumeration](#3-subdomain-enumeration)
4. [Path Fuzzing](#4-path-fuzzing)
5. [Web Interface](#5-web-interface)

## 1. Host Discovery

Before scanning for vulnerabilities, you can discover which hosts are active on your network.

**Command:**

```bash
python3 main.py discover <network_range> [options]
```

**Example:**

```bash
python3 main.py discover 192.168.1.0/24
```

**Output:**
The command will display a list of active IP addresses in JSON format.

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
python3 main.py discover 192.168.1.0/24 -o discovered_hosts.json
```

## 2. Vulnerability Scanning

Once you have identified a target, you can scan it for vulnerabilities.

**Command:**

```bash
python3 main.py scan <ip_or_domain> [options]
```

**Example:**

```bash
python3 main.py scan 192.168.1.10
```

### Scan Types

You can specify the scan type using the `--type` option:

- `quick`: A quick scan of the most common ports.
- `full`: A full scan of all TCP ports.
- `stealth`: A stealthy scan to avoid detection.

**Example of a quick scan:**

```bash
python3 main.py scan 192.168.1.10 --type quick
```

### Save Scan Results

Save the scan results in a JSON file for later analysis or to use them in the exploitation phase.

```bash
python3 main.py scan 192.168.1.10 --type quick -o scan_results.json
```

## 3. Subdomain Enumeration

Discover subdomains for a target domain using passive enumeration (subfinder) and active fuzzing (ffuf).

**Command:**

```bash
python3 main.py subdomain <domain> [options]
```

**Example:**

```bash
python3 main.py subdomain example.com
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--wordlist`, `-w` | Wordlist for subdomain fuzzing | seclists medium |
| `--output`, `-o` | Output file for results | subdomains.txt |
| `--threads`, `-t` | Number of threads | 40 |
| `--nuclei` | Run nuclei on discovered hosts | disabled |
| `--silent` | Minimal output | disabled |

**Example with custom wordlist:**

```bash
python3 main.py subdomain example.com -w /path/to/wordlist.txt -o results.txt
```

**Example with nuclei:**

```bash
python3 main.py subdomain example.com --nuclei
```

## 4. Path Fuzzing

Discover directories and paths on a web server using ffuf.

**Command:**

```bash
python3 main.py fuzz <url> [options]
```

**Example:**

```bash
python3 main.py fuzz http://example.com
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--wordlist`, `-w` | Wordlist for path fuzzing | common.txt |
| `--output`, `-o` | Output file for results | paths.txt |
| `--threads`, `-t` | Number of threads | 40 |
| `--extensions`, `-e` | File extensions | None |
| `--silent` | Minimal output | disabled |

**Example with extensions:**

```bash
python3 main.py fuzz http://example.com -e .php,.html,.txt -o paths.txt
```

**Example with large wordlist:**

```bash
python3 main.py fuzz http://example.com -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

## 5. Web Interface

Access the web interface for a graphical user interface.

**Command:**

```bash
python3 main.py web [--port PORT] [--host HOST]
```

**Example:**

```bash
python3 main.py web --port 8000
```

Access at: <http://localhost:8000/web/dashboard>
