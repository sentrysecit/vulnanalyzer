# Using VulnAnalyzer

This guide explains how to use the main features of VulnAnalyzer.

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
