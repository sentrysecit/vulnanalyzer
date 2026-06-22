import requests
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CACHE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "cve_cache")
os.makedirs(CACHE_DIR, exist_ok=True)


SERVICE_KEYWORDS = {
    "apache": ["Apache", "httpd"],
    "nginx": ["Nginx"],
    "openssh": ["OpenSSH", "sshd"],
    "mysql": ["MySQL", "mariadb"],
    "postgresql": ["PostgreSQL"],
    "redis": ["Redis"],
    "mongodb": ["MongoDB"],
    "elasticsearch": ["Elasticsearch"],
    "tomcat": ["Apache Tomcat", "Tomcat"],
    "wordpress": ["WordPress"],
    "drupal": ["Drupal"],
    "joomla": ["Joomla"],
    "iis": ["Microsoft-IIS", "IIS"],
    "vsftpd": ["vsftpd"],
    "proftpd": ["ProFTPD"],
    "samba": ["Samba"],
    "ssh": ["ssh"],
    "ftp": ["ftp"],
    "smtp": ["smtp", "sendmail", "postfix"],
    "dns": ["bind", "named"],
    "http": ["httpd", "apache", "nginx", "iis"],
}


class CVEScanner:
    def __init__(self, nvd_api_key=None, use_cache=True):
        self.nvd_key = nvd_api_key
        self.use_cache = use_cache
        self.cache = {}
        self.kev_cache = None
        self._load_kev_cache()

    def _load_kev_cache(self):
        cache_file = os.path.join(CACHE_DIR, "kev_cache.json")
        if self.use_cache and os.path.exists(cache_file):
            age = time.time() - os.path.getmtime(cache_file)
            if age < 86400:
                import json

                with open(cache_file) as f:
                    self.kev_cache = set(json.load(f))
                return

        try:
            resp = requests.get(CISA_KEV_URL, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            cve_ids = [v["cveID"] for v in data.get("vulnerabilities", [])]
            self.kev_cache = set(cve_ids)

            if self.use_cache:
                import json

                with open(cache_file, "w") as f:
                    json.dump(list(cve_ids), f)
        except Exception as e:
            print(f"[!] Error loading CISA KEV: {e}")
            self.kev_cache = set()

    def is_in_kev(self, cve_id):
        if self.kev_cache is None:
            self._load_kev_cache()
        return cve_id.upper() in self.kev_cache

    def check_cve(self, cve_id):
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        cache_file = os.path.join(CACHE_DIR, f"{cve_id.replace('-', '_')}.json")
        if self.use_cache and os.path.exists(cache_file):
            import json

            with open(cache_file) as f:
                return json.load(f)

        headers = {}
        if self.nvd_key:
            headers["apiKey"] = self.nvd_key

        try:
            url = f"{NVD_API_BASE}?cveId={cve_id}"
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            items = data.get("vulnerabilities", [])
            if not items:
                return None

            cve_data = items[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_v2 = metrics.get("cvssMetricV2", [])

            cvss_score = None
            cvss_severity = None

            if cvss_v31:
                cvss = cvss_v31[0].get("cvssData", {})
                cvss_score = cvss.get("baseScore")
                cvss_severity = cvss.get("baseSeverity")
            elif cvss_v30:
                cvss = cvss_v30[0].get("cvssData", {})
                cvss_score = cvss.get("baseScore")
                cvss_severity = cvss.get("baseSeverity")
            elif cvss_v2:
                cvss = cvss_v2[0].get("cvssData", {})
                cvss_score = cvss.get("baseScore")

            description = ""
            descriptions = cve_data.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            result = {
                "id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "severity": cvss_severity,
                "is_exploited": self.is_in_kev(cve_id),
                "published": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
            }

            if self.use_cache:
                import json

                with open(cache_file, "w") as f:
                    json.dump(result, f)

            time.sleep(0.1)
            return result

        except Exception as e:
            print(f"[!] Error fetching CVE {cve_id}: {e}")
            return None

    def search_cves_by_keyword(self, keyword, limit=20):
        headers = {}
        if self.nvd_key:
            headers["apiKey"] = self.nvd_key

        try:
            url = f"{NVD_API_BASE}?keywordSearch={keyword}&resultsPerPage={limit}"
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()

            results = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id")

                metrics = cve.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                cvss_score = None
                severity = None

                if cvss_v31:
                    cvss = cvss_v31[0].get("cvssData", {})
                    cvss_score = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity")

                results.append(
                    {
                        "id": cve_id,
                        "cvss_score": cvss_score,
                        "severity": severity,
                        "is_exploited": self.is_in_kev(cve_id),
                    }
                )

                time.sleep(0.05)

            return results

        except Exception as e:
            print(f"[!] Error searching CVEs for '{keyword}': {e}")
            return []

    def check_service(self, service_name, version=None, limit=10):
        results = []

        search_term = service_name
        if version:
            search_term = f"{service_name} {version}"

        cves = self.search_cves_by_keyword(search_term, limit=limit)

        for cve in cves:
            if cve.get("cvss_score"):
                if cve["cvss_score"] >= 7.0:
                    results.append(cve)

        return results

    def detect_vulnerabilities(self, services_info):
        print(f"[*] Checking {len(services_info)} services for vulnerabilities...")

        all_vulns = []
        seen = set()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for service_info in services_info:
                service = service_info.get("service", "")
                version = service_info.get("version", "")
                host = service_info.get("host", "")
                port = service_info.get("port", "")

                if not service:
                    continue

                key = f"{service}_{version}".lower()
                if key in seen:
                    continue
                seen.add(key)

                future = executor.submit(
                    self._check_service_async, service, version, host, port
                )
                futures[future] = (service, version, host, port)

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        all_vulns.extend(result)
                except Exception as e:
                    print(f"[!] Error checking service: {e}")

        critical = [v for v in all_vulns if v.get("cvss_score", 0) >= 9.0]
        high = [v for v in all_vulns if 7.0 <= v.get("cvss_score", 0) < 9.0]

        print(f"[+] Found {len(all_vulns)} potential vulnerabilities")
        print(f"    Critical: {len(critical)}, High: {len(high)}")

        return all_vulns

    def _check_service_async(self, service, version, host, port):
        results = []

        cves = self.check_service(service, version, limit=15)

        for cve in cves:
            results.append(
                {
                    "cve_id": cve["id"],
                    "service": service,
                    "version": version,
                    "host": host,
                    "port": port,
                    "cvss_score": cve.get("cvss_score"),
                    "severity": cve.get("severity"),
                    "is_exploited": cve.get("is_exploited", False),
                }
            )

        return results


def get_service_vulns(service, version, host=None, port=None):
    scanner = CVEScanner()
    services = [{"service": service, "version": version, "host": host, "port": port}]
    return scanner.detect_vulnerabilities(services)
