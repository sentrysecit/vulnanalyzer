import datetime
import os
from jinja2 import Environment, FileSystemLoader


class ReportService:
    def __init__(self):
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir = os.path.join(base_dir, "web", "templates")
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

    def generate_html_from_data(
        self, data: dict, title: str = "Reporte de Análisis", context: dict = None
    ) -> str:
        template = self.env.get_template("reports/view.html")

        ctx = {
            "title": title,
            "timestamp": self.timestamp,
            "data": data,
            "summary": self.generate_summary(data),
        }
        if context:
            ctx.update(context)

        return template.render(**ctx)

    def generate_markdown_from_data(
        self, data: dict, scan=None, title: str = "Vulnerability Report"
    ) -> str:
        summary = self.generate_summary(data)
        scan_results = data.get("scan_results") or {}

        lines = []

        # Header
        lines.append(f"# {title}")
        lines.append("")
        if scan:
            lines.append(f"**Target:** {scan.target}  ")
            lines.append(f"**Scan Type:** {scan.scan_type}  ")
            lines.append(f"**Status:** {scan.status}  ")
            date_str = (
                scan.created_at.strftime("%Y-%m-%d %H:%M:%S")
                if scan.created_at
                else "N/A"
            )
            lines.append(f"**Date:** {date_str}  ")
        lines.append(f"**Generated:** {self.timestamp}")
        lines.append("")

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Total Hosts | {summary['total_hosts']} |")
        lines.append(f"| Total Vulnerabilities | {summary['total_vulnerabilities']} |")
        sc = summary["severity_counts"]
        lines.append(f"| Critical | {sc['critical']} |")
        lines.append(f"| High | {sc['high']} |")
        lines.append(f"| Medium | {sc['medium']} |")
        lines.append(f"| Low | {sc['low']} |")
        lines.append(f"| Info | {sc.get('info', 0)} |")
        lines.append("")

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        for host, host_data in scan_results.items():
            if not isinstance(host_data, dict):
                continue

            status = host_data.get("status", "unknown")
            lines.append(f"## Host: {host}")
            lines.append("")
            lines.append(f"**Status:** {status}")
            lines.append("")

            # OS information
            os_name = host_data.get("os_name") or host_data.get("os", {})
            os_family = host_data.get("os_family", "")
            os_accuracy = host_data.get("os_accuracy", "")
            if os_family or os_name:
                os_label = (
                    os_name if isinstance(os_name, str) and os_name else os_family
                )
                acc_label = f" ({os_accuracy}% accuracy)" if os_accuracy else ""
                lines.append(
                    f"**OS:** {os_family} — {os_label}{acc_label}"
                    if os_family and isinstance(os_name, str) and os_name
                    else f"**OS:** {os_family or os_label}{acc_label}"
                )
                lines.append("")

            # Open ports
            ports = host_data.get("ports", {})
            if ports:
                lines.append("### Open Ports")
                lines.append("")
                lines.append("| Port | Service | Version |")
                lines.append("|------|---------|---------|")
                for port, port_data in ports.items():
                    if not isinstance(port_data, dict):
                        continue
                    service = port_data.get("service", "")
                    version = port_data.get("version", "").replace("|", "\\|")
                    lines.append(f"| {port} | {service} | {version} |")
                lines.append("")

            # Vulnerabilities
            vulns = host_data.get("vulnerabilities", [])
            if vulns:
                lines.append("### Vulnerabilities")
                lines.append("")
                sorted_vulns = sorted(
                    vulns,
                    key=lambda v: severity_order.get(
                        v.get("severity", "info").lower(), 4
                    ),
                )
                for vuln in sorted_vulns:
                    cve_id = vuln.get("cve_id", "")
                    vuln_title = vuln.get("title", "")
                    heading = cve_id if cve_id else vuln_title or "Unknown"
                    lines.append(f"#### {heading}")
                    lines.append("")
                    severity = vuln.get("severity", "").capitalize()
                    cvss = vuln.get("cvss_score", "")
                    cvss_label = f" (CVSS: {cvss})" if cvss else ""
                    lines.append(f"**Severity:** {severity}{cvss_label}")
                    if vuln.get("service") or vuln.get("port"):
                        svc = vuln.get("service", "")
                        port = vuln.get("port", "")
                        ver = vuln.get("version", "")
                        parts = [p for p in [svc, str(port) if port else "", ver] if p]
                        lines.append(f"**Affected:** {' / '.join(parts)}")
                    description = vuln.get("description", "")
                    if description:
                        lines.append(f"**Description:** {description}")
                    if vuln.get("is_exploited"):
                        lines.append("**⚠ Exploited in the wild (CISA KEV)**")
                    recommendation = vuln.get("recommendation", "")
                    if recommendation:
                        lines.append(f"**Recommendation:** {recommendation}")
                    lines.append("")

            # Web vulnerabilities
            web_vulns = host_data.get("web_vulnerabilities", {})
            if web_vulns and isinstance(web_vulns, dict):
                web_vuln_list = web_vulns.get("vulnerabilities", [])
                if web_vuln_list:
                    lines.append("### Web Vulnerabilities")
                    lines.append("")
                    for wv in web_vuln_list:
                        name = wv.get("name", wv.get("type", "Unknown"))
                        sev = wv.get("severity", "").capitalize()
                        lines.append(f"- **{name}** — {sev}")
                    lines.append("")
                techs = web_vulns.get("technologies", [])
                if techs:
                    lines.append(f"**Technologies detected:** {', '.join(techs)}")
                    lines.append("")

            # Active Directory
            ad = host_data.get("ad", {})
            if ad and isinstance(ad, dict):
                lines.append("### Active Directory")
                lines.append("")
                domain = ad.get("domain") or ad.get("domain_name", "")
                if domain:
                    lines.append(f"**Domain:** {domain}")
                dc_ports = ad.get("dc_ports", [])
                if dc_ports:
                    lines.append(f"**DC Ports:** {', '.join(str(p) for p in dc_ports)}")
                lines.append("")

                ad_vulns = ad.get("vulnerabilities", [])
                if ad_vulns:
                    lines.append("#### AD Vulnerabilities")
                    lines.append("")
                    for adv in ad_vulns:
                        cve = adv.get("cve", "")
                        name = adv.get("name", "")
                        sev = adv.get("severity", "").capitalize()
                        desc = adv.get("description", "")
                        heading = f"{name} ({cve})" if cve else name
                        lines.append(f"**{heading}** — {sev}")
                        if desc:
                            lines.append(f"> {desc}")
                        lines.append("")

                shares = ad.get("shares", [])
                if shares:
                    lines.append("#### SMB Shares")
                    lines.append("")
                    for share in shares:
                        if isinstance(share, dict):
                            share_name = share.get("name", str(share))
                            access = share.get("access", "")
                            lines.append(
                                f"- `{share_name}`" + (f" ({access})" if access else "")
                            )
                        else:
                            lines.append(f"- `{share}`")
                    lines.append("")

        lines.append("---")
        lines.append("_Generated by VulnAnalyzer — Confidential_")

        return "\n".join(lines)
