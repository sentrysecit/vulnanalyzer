import datetime
import os
from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportService:
    def __init__(self):
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        template_dir = os.path.join(base_dir, "web", "templates")
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

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

    # ------------------------------------------------------------------
    # Professional pentest report (HTML + PDF)
    # ------------------------------------------------------------------
    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    _IMPACT_BY_SEVERITY = {
        "critical": (
            "Successful exploitation could lead to full compromise of the affected "
            "asset (e.g. remote code execution, privilege escalation or data breach) "
            "with severe impact on confidentiality, integrity and availability."
        ),
        "high": (
            "Exploitation could allow an attacker to gain significant unauthorised "
            "access or disrupt the affected service, materially impacting the security "
            "of the environment."
        ),
        "medium": (
            "Exploitation may expose sensitive information or provide an attacker with "
            "a foothold that can be chained with other weaknesses."
        ),
        "low": (
            "Limited direct impact, but the weakness reduces the overall security "
            "posture and may aid an attacker during reconnaissance."
        ),
        "info": (
            "Informational finding with no direct security impact; included for "
            "completeness and situational awareness."
        ),
    }

    def _norm_severity(self, sev: str) -> str:
        sev = (sev or "info").lower()
        return sev if sev in self.SEVERITY_ORDER else "info"

    @staticmethod
    def _short_desc(text: str, limit: int = 600) -> str:
        """Clamp verbose CVE descriptions for the report. NVD text (especially
        Linux kernel CVEs) can run to thousands of characters including console
        traces; keep the first paragraph up to `limit` chars."""
        text = (text or "").strip()
        if not text:
            return ""
        para = text.split("\n\n", 1)[0].strip() or text
        if len(para) > limit:
            para = para[:limit].rsplit(" ", 1)[0].rstrip() + "…"
        return para

    @staticmethod
    def _clean_title(title: str, cve_id: str = "", limit: int = 90) -> str:
        """A finding title should be a short label, not a dumped description.
        Fall back to the CVE id (or a clamp) when it is too long."""
        title = (title or "").strip().splitlines()[0] if title else ""
        # A title ending in ':' is a description lead-in (e.g. the Linux-kernel
        # CVE boilerplate), not a label — prefer the CVE id when available.
        if cve_id and (len(title) > limit or title.rstrip().endswith(":")):
            return cve_id
        if len(title) > limit:
            return title[: limit - 1].rstrip() + "…"
        return title or cve_id or "Unknown"

    def _build_findings(self, scan_results: dict) -> list:
        """Flatten per-host vulnerabilities into deduplicated findings.

        Findings are keyed by CVE (or title/name when no CVE is available), so the
        same issue affecting several hosts becomes a single finding listing all
        affected assets. Severity is escalated to the worst observed value.
        """
        findings: dict = {}
        order: list = []

        def add(key, *, severity, title, asset, cve_id="", cvss="",
                description="", remediation="", is_exploited=False):
            if not key:
                return
            sev = self._norm_severity(severity)
            if key not in findings:
                findings[key] = {
                    "title": title or key,
                    "severity": sev,
                    "cve_id": cve_id or "",
                    "cvss": cvss or "",
                    "description": description or "",
                    "remediation": remediation or "",
                    "is_exploited": bool(is_exploited),
                    "affected": [],
                }
                order.append(key)
            f = findings[key]
            if self.SEVERITY_ORDER[sev] < self.SEVERITY_ORDER[f["severity"]]:
                f["severity"] = sev
            if cvss and not f["cvss"]:
                f["cvss"] = cvss
            if cve_id and not f["cve_id"]:
                f["cve_id"] = cve_id
            if description and not f["description"]:
                f["description"] = description
            if remediation and not f["remediation"]:
                f["remediation"] = remediation
            if is_exploited:
                f["is_exploited"] = True
            if asset:
                # De-duplicate affected assets across data sources. The same AD
                # vulnerability arrives both as a host vuln (service "Active
                # Directory") and from the "ad" block (labelled "AD"); normalise
                # so one host is not listed twice under different labels.
                norm = asset.lower().replace("(active directory)", "(ad)")
                seen = f.setdefault("_affected_norm", set())
                if norm not in seen:
                    seen.add(norm)
                    f["affected"].append(asset)

        for host, host_data in scan_results.items():
            if not isinstance(host_data, dict):
                continue

            for vuln in host_data.get("vulnerabilities", []) or []:
                cve_id = vuln.get("cve_id", "")
                title = cve_id or vuln.get("title") or vuln.get("type") or "Unknown"
                port = vuln.get("port")
                svc = vuln.get("service", "")
                asset = host + (f":{port}" if port else "") + (f" ({svc})" if svc else "")
                add(
                    cve_id or title,
                    severity=vuln.get("severity"),
                    title=vuln.get("title") or cve_id or title,
                    asset=asset,
                    cve_id=cve_id,
                    cvss=vuln.get("cvss_score", ""),
                    description=vuln.get("description", ""),
                    remediation=vuln.get("recommendation", ""),
                    is_exploited=vuln.get("is_exploited", False),
                )

            web = host_data.get("web_vulnerabilities", {})
            if isinstance(web, dict):
                for wv in web.get("vulnerabilities", []) or []:
                    name = wv.get("name") or wv.get("type") or "Web Vulnerability"
                    add(
                        f"web:{name}",
                        severity=wv.get("severity"),
                        title=name,
                        asset=f"{host} (web)",
                        description=wv.get("description", ""),
                        remediation=wv.get("recommendation", ""),
                    )

            ad = host_data.get("ad", {})
            if isinstance(ad, dict):
                for adv in ad.get("vulnerabilities", []) or []:
                    cve = adv.get("cve", "")
                    name = adv.get("name") or cve or "AD Vulnerability"
                    add(
                        cve or f"ad:{name}",
                        severity=adv.get("severity"),
                        title=name,
                        asset=f"{host} (AD)",
                        cve_id=cve,
                        description=adv.get("description", ""),
                        remediation=adv.get("recommendation", ""),
                    )

        ordered = sorted(
            (findings[k] for k in order),
            key=lambda f: (self.SEVERITY_ORDER[f["severity"]], f["title"]),
        )

        for idx, f in enumerate(ordered, start=1):
            f.pop("_affected_norm", None)
            f["id"] = f"F-{idx:03d}"
            f["title"] = self._clean_title(f["title"], f["cve_id"])
            f["description"] = self._short_desc(f["description"])
            f["impact"] = self._IMPACT_BY_SEVERITY[f["severity"]]
            if not f["remediation"]:
                f["remediation"] = (
                    "Apply the latest vendor-supplied patches or mitigations for the "
                    "affected component and validate the fix."
                )
            refs = []
            if f["cve_id"]:
                refs.append(f"https://nvd.nist.gov/vuln/detail/{f['cve_id']}")
            if f["is_exploited"]:
                refs.append(
                    "CISA KEV — "
                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                )
            f["references"] = refs
            n = len(f["affected"])
            f["affected_short"] = (
                f["affected"][0] + (f" (+{n - 1} more)" if n > 1 else "")
                if f["affected"]
                else "—"
            )

        return ordered

    def _build_host_inventory(self, scan_results: dict) -> list:
        hosts = []
        for host, host_data in scan_results.items():
            if not isinstance(host_data, dict):
                continue
            os_name = host_data.get("os_name")
            os_family = host_data.get("os_family")
            if os_name and os_family and os_family.lower() in os_name.lower():
                os_str = os_name
            else:
                os_str = " ".join(p for p in [os_family, os_name] if p)
            ports = []
            for port, pdata in (host_data.get("ports", {}) or {}).items():
                if not isinstance(pdata, dict):
                    continue
                ports.append(
                    {
                        "port": port,
                        "service": pdata.get("service", ""),
                        "version": pdata.get("version", ""),
                    }
                )
            hosts.append(
                {
                    "name": host,
                    "status": host_data.get("status", "unknown"),
                    "os": os_str,
                    "ports": ports,
                    "vuln_count": len(host_data.get("vulnerabilities", []) or []),
                }
            )
        return hosts

    @staticmethod
    def _risk_rating(severity_counts: dict) -> str:
        if severity_counts.get("critical"):
            return "Critical"
        if severity_counts.get("high"):
            return "High"
        if severity_counts.get("medium"):
            return "Medium"
        if severity_counts.get("low"):
            return "Low"
        return "Informational"

    def build_report_context(
        self, data: dict, scan=None, title: str = "Penetration Test Report"
    ) -> dict:
        scan_results = data.get("scan_results") or {}
        findings = self._build_findings(scan_results)

        severity_counts = {k: 0 for k in self.SEVERITY_ORDER}
        for f in findings:
            severity_counts[f["severity"]] += 1

        summary = {
            "total_vulnerabilities": len(findings),
            "total_hosts": len(scan_results),
            "severity_counts": severity_counts,
            "kev_count": sum(1 for f in findings if f["is_exploited"]),
            "risk_rating": self._risk_rating(severity_counts),
        }

        date_str = "N/A"
        target = ""
        scan_type = "full"
        status = "completed"
        if scan is not None:
            target = getattr(scan, "target", "") or ""
            scan_type = getattr(scan, "scan_type", "full") or "full"
            status = getattr(scan, "status", "completed") or "completed"
            created = getattr(scan, "created_at", None)
            if created:
                date_str = created.strftime("%Y-%m-%d %H:%M")
        target = target or data.get("target", "N/A")

        meta = {
            "title": title,
            "target": target,
            "scan_type": scan_type,
            "status": status,
            "date": date_str,
            "generated": self.timestamp,
            "classification": "CONFIDENTIAL",
        }

        return {
            "title": title,
            "meta": meta,
            "summary": summary,
            "findings": findings,
            "hosts": self._build_host_inventory(scan_results),
        }

    def generate_pentest_html(
        self, data: dict, scan=None, title: str = "Penetration Test Report"
    ) -> str:
        template = self.env.get_template("reports/pentest_report.html")
        return template.render(**self.build_report_context(data, scan, title))

    def generate_pdf(
        self, data: dict, scan=None, title: str = "Penetration Test Report"
    ) -> bytes:
        import weasyprint

        html = self.generate_pentest_html(data, scan, title)
        # The template is self-contained; refuse every non-data: URL so injected
        # CSS/HTML from scan data cannot trigger SSRF or read local files.
        url_fetcher = weasyprint.URLFetcher(allowed_protocols=["data"])
        return weasyprint.HTML(string=html, url_fetcher=url_fetcher).write_pdf()

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
