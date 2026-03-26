import datetime
import os
from jinja2 import Environment, FileSystemLoader


class ReportService:
    def __init__(self):
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        template_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "reports",
            "templates",
        )
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def generate_summary(self, data: dict) -> dict:
        summary = {
            "total_hosts": 0,
            "total_vulnerabilities": 0,
            "severity_counts": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "vulnerability_types": {},
        }

        if "scan_results" in data:
            scan_results = data["scan_results"]
            summary["total_hosts"] = len(scan_results)

            for host, host_data in scan_results.items():
                host_vulns = host_data.get("vulnerabilities", [])
                summary["total_vulnerabilities"] += len(host_vulns)

                for vuln in host_vulns:
                    severity = vuln.get("severity", "info").lower()
                    if severity in summary["severity_counts"]:
                        summary["severity_counts"][severity] += 1

                    vuln_type = vuln.get("type", "unknown")
                    if vuln_type not in summary["vulnerability_types"]:
                        summary["vulnerability_types"][vuln_type] = 0
                    summary["vulnerability_types"][vuln_type] += 1

        if "owasp_results" in data:
            owasp_results = data["owasp_results"]
            owasp_vulns = owasp_results.get("vulnerabilities", [])

            summary["total_vulnerabilities"] += len(owasp_vulns)

            for vuln in owasp_vulns:
                severity = vuln.get("severity", "info").lower()
                if severity in summary["severity_counts"]:
                    summary["severity_counts"][severity] += 1

                vuln_type = vuln.get("type", "unknown")
                if vuln_type not in summary["vulnerability_types"]:
                    summary["vulnerability_types"][vuln_type] = 0
                summary["vulnerability_types"][vuln_type] += 1

        if "exploit_results" in data:
            exploit_results = data["exploit_results"]

            for host, exploits in exploit_results.items():
                for exploit in exploits:
                    if exploit.get("success", False):
                        summary["total_vulnerabilities"] += 1
                        summary["severity_counts"]["critical"] += 1

                        exploit_name = exploit.get("exploit", "unknown")
                        if exploit_name not in summary["vulnerability_types"]:
                            summary["vulnerability_types"][exploit_name] = 0
                        summary["vulnerability_types"][exploit_name] += 1

        return summary

    def generate_html_from_data(self, data: dict, title: str = "Reporte de Análisis") -> str:
        template = self.env.get_template("report_template.html")

        context = {
            "title": title,
            "timestamp": self.timestamp,
            "data": data,
            "summary": self.generate_summary(data),
        }

        return template.render(**context)
