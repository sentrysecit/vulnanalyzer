import nmap
import requests
from concurrent.futures import ThreadPoolExecutor
from core.utils import parse_target

from modules.fingerprints.service_fingerprints import (
    detect_web_technology,
    detect_services,
    detect_os,
    detect_dc_ports,
)


class VulnerabilityScanner:
    def __init__(
        self, target, scan_type="full", threads=10, check_cve=True, find_exploits=False
    ):
        self.target = parse_target(target)
        self.scan_type = scan_type
        self.threads = threads
        self.check_cve = check_cve
        self.find_exploits = find_exploits
        self.results = {}
        self.nm = nmap.PortScanner()
        self.cve_results = []

    def scan_network(self):
        print(f"[*] Starting network scan on {self.target}")

        scan_types = {
            "quick": "-F -T4",
            "full": "-sS -sV -O -A -T4",
            "stealth": "-sS -T2",
        }

        args = scan_types.get(self.scan_type, scan_types["full"])

        try:
            self.nm.scan(hosts=self.target, arguments=args)
        except Exception as e:
            print(f"[!] Error running Nmap: {e}")
            return {}

        for host in self.nm.all_hosts():
            try:
                host_state = self.nm[host].state()
                os_matches = self.nm[host].get("osmatch", [])
                os_normalized = detect_os(os_matches)
                self.results[host] = {
                    "status": host_state,
                    "ports": {},
                    "os": os_matches,
                    "os_name": os_normalized.get("name"),
                    "os_family": os_normalized.get("family"),
                    "os_accuracy": os_normalized.get("accuracy"),
                    "os_cpe": os_normalized.get("cpe"),
                    "vulnerabilities": [],
                }

                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto]:
                        service = self.nm[host][proto][port]
                        fingerprint = detect_services(host, service)
                        product = service.get("product", "")
                        version = service.get("version", "")
                        full_version = f"{product} {version}".strip()

                        self.results[host]["ports"][port] = {
                            "state": service["state"],
                            "service": service["name"],
                            "version": full_version,
                            "fingerprint": fingerprint,
                        }
            except Exception as e:
                print(f"[!] Error processing host {host}: {e}")

        return self.results

    def analyze_ad(self):
        """Run Active Directory analysis on Windows hosts"""
        from core.ad_scanner import ADScanner
        
        for host in self.results:
            host_data = self.results[host]
            os_family = host_data.get("os_family")
            
            if os_family != "Windows":
                continue
            
            open_ports = host_data.get("ports", {})
            dc_info = detect_dc_ports(open_ports)
            
            if dc_info.get("is_domain_controller") or dc_info.get("dc_score", 0) >= 1:
                print(f"[*] Running AD analysis on Windows host: {host}")
                
                ad_scanner = ADScanner(host)
                ad_results = ad_scanner.run(open_ports)
                
                self.results[host]["ad"] = ad_results
                
                if ad_results.get("vulnerabilities"):
                    for vuln in ad_results["vulnerabilities"]:
                        vuln_entry = {
                            "type": "ad",
                            "cve_id": vuln.get("cve"),
                            "title": vuln.get("name"),
                            "description": vuln.get("description"),
                            "severity": vuln.get("severity"),
                            "service": "Active Directory",
                            "recommendation": f"Check {vuln.get('name')} - {vuln.get('description')}",
                        }
                        host_data["vulnerabilities"].append(vuln_entry)

    def detect_vulnerabilities(self):
        if not self.check_cve:
            return

        print("[*] Detecting vulnerabilities (CVE scan)...")

        try:
            from core.cve_scanner import CVEScanner

            scanner = CVEScanner()
            services_info = []

            for host in self.results:
                for port, port_data in self.results[host].get("ports", {}).items():
                    if port_data.get("state") != "open":
                        continue

                    service = port_data.get("service", "")
                    version = port_data.get("version", "")

                    if service:
                        services_info.append(
                            {
                                "host": host,
                                "port": port,
                                "service": service,
                                "version": version,
                            }
                        )

            if not services_info:
                print("[*] No services to check for vulnerabilities")
                return

            self.cve_results = scanner.detect_vulnerabilities(services_info)

            for vuln in self.cve_results:
                host = vuln.get("host")
                cve_id = vuln.get("cve_id")

                cve_details = scanner.check_cve(cve_id) if cve_id else {}

                vuln_entry = {
                    "type": "cve",
                    "cve_id": cve_id,
                    "title": cve_details.get("description", f"CVE {cve_id}"),
                    "description": cve_details.get("description", ""),
                    "service": vuln.get("service"),
                    "version": vuln.get("version"),
                    "port": vuln.get("port"),
                    "cvss_score": cve_details.get("cvss_score")
                    or vuln.get("cvss_score"),
                    "severity": cve_details.get("severity") or vuln.get("severity"),
                    "is_exploited": cve_details.get(
                        "is_exploited", vuln.get("is_exploited", False)
                    ),
                    "published": cve_details.get("published"),
                    "recommendation": self._get_recommendation(
                        cve_id, vuln.get("service")
                    ),
                }

                if host in self.results:
                    self.results[host]["vulnerabilities"].append(vuln_entry)

        except ImportError as e:
            print(f"[!] CVE scanner module not available: {e}")
        except Exception as e:
            print(f"[!] Error detecting vulnerabilities: {e}")

    def find_exploits_for_vulns(self):
        if not self.find_exploits or not self.cve_results:
            return

        print("[*] Searching for available exploits...")

        try:
            from core.exploit_finder import ExploitFinder

            finder = ExploitFinder()
            for host in self.results:
                for vuln in self.results[host]["vulnerabilities"]:
                    if vuln.get("type") == "cve":
                        cve_id = vuln.get("cve_id")
                        exploits = finder.search_by_cve(cve_id)
                        vuln["exploits"] = exploits if exploits else []

        except ImportError as e:
            print(f"[!] Exploit finder module not available: {e}")
        except Exception as e:
            print(f"[!] Error finding exploits: {e}")

    def scan_web_vulnerabilities(self, urls=None):
        if not urls:
            urls = []
            web_ports = [80, 443, 8080, 8443, 8000, 8888]

            for host in self.results:
                for port in web_ports:
                    if port in self.results[host]["ports"]:
                        protocol = "https" if port in [443, 8443] else "http"
                        urls.append(f"{protocol}://{host}:{port}")

        if not urls:
            return self.results

        print(f"[*] Scanning web vulnerabilities for {len(urls)} URLs")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            web_results = list(executor.map(self._scan_single_web_target, urls))

        for url, result in zip(urls, web_results):
            host = url.split("://")[1].split(":")[0]
            if host in self.results:
                self.results[host]["web_vulnerabilities"] = result

        return self.results

    def _scan_single_web_target(self, url):
        result = {
            "url": url,
            "technologies": detect_web_technology(url),
            "vulnerabilities": [],
        }

        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers

            security_headers = {
                "X-XSS-Protection": "Missing XSS protection header",
                "X-Content-Type-Options": "Missing content type options header",
                "X-Frame-Options": "Missing clickjacking protection",
                "Content-Security-Policy": "Missing content security policy",
                "Strict-Transport-Security": "Missing HSTS header",
            }

            for header, issue in security_headers.items():
                if header not in headers:
                    result["vulnerabilities"].append(
                        {
                            "type": "missing_security_header",
                            "name": issue,
                            "severity": "medium",
                        }
                    )

        except Exception as e:
            result["error"] = str(e)

        return result

    def get_vulnerability_summary(self):
        summary = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "exploited": 0,
        }

        for host in self.results:
            for vuln in self.results[host].get("vulnerabilities", []):
                summary["total"] += 1

                if vuln.get("type") == "cve":
                    score = vuln.get("cvss_score", 0)
                    if score >= 9.0:
                        summary["critical"] += 1
                    elif score >= 7.0:
                        summary["high"] += 1
                    elif score >= 4.0:
                        summary["medium"] += 1
                    else:
                        summary["low"] += 1

                    if vuln.get("is_exploited"):
                        summary["exploited"] += 1

        return summary

    def run(self):
        self.scan_network()
        
        if self.scan_type == "full":
            self.analyze_ad()

        if self.check_cve or self.find_exploits:
            self.detect_vulnerabilities()

        if self.find_exploits:
            self.find_exploits_for_vulns()

        self.scan_web_vulnerabilities()
        return self.results

    def _get_recommendation(self, cve_id, service):
        if not cve_id:
            return "Update the service to the latest version."

        recommendations = {
            "apache": "Update Apache to the latest version. Consider using ModSecurity for additional protection.",
            "nginx": "Update Nginx to the latest version. Review configuration for security best practices.",
            "openssh": "Update OpenSSH to the latest version. Disable weak ciphers and algorithms.",
            "mysql": "Update MySQL to the latest version. Review user privileges and grant only necessary permissions.",
            "postgresql": "Update PostgreSQL to the latest version. Review pg_hba.conf for secure access control.",
            "redis": "Update Redis to the latest version. Enable AUTH and use TLS for connections.",
            "wordpress": "Update WordPress, themes, and plugins. Remove unused plugins. Implement WAF.",
            "drupal": "Update Drupal core and modules. Follow Drupal security best practices.",
            "tomcat": "Update Apache Tomcat. Disable manager interface in production. Use secure session cookies.",
            "iis": "Apply Microsoft security updates. Review URL authorization rules.",
        }

        service_lower = service.lower() if service else ""

        for key, rec in recommendations.items():
            if key in service_lower:
                return f"[{service}] {rec}"

        return f"Review CVE {cve_id} and apply vendor-supplied patches or mitigations. Check https://nvd.nist.gov/vuln/detail/{cve_id} for details."
