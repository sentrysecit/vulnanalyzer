import json
import os
import datetime
from jinja2 import Environment, FileSystemLoader
import weasyprint


class ReportGenerator:
    def __init__(self, data):
        self.data = data
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.template_dir = os.path.join(base_dir, "web", "templates", "reports")
        self.env = Environment(loader=FileSystemLoader(self.template_dir))

    def generate_html_report(self, output_file):
        template = self.env.get_template("view.html")
        
        context = {
            "title": f"Vulnerability Report - {self.data.get('target', 'Scan')}",
            "timestamp": self.timestamp,
            "data": self.data,
            "summary": self._generate_summary(),
        }
        
        html_content = template.render(**context)
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

    def generate_pdf_report(self, output_file):
        html_file = output_file.replace(".pdf", ".html")
        self.generate_html_report(html_file)
        
        html = weasyprint.HTML(filename=html_file)
        html.write_pdf(output_file)
        
        os.remove(html_file)

    def generate_json_report(self, output_file):
        report_data = {
            "title": "Vulnerability Report",
            "timestamp": self.timestamp,
            "summary": self._generate_summary(),
            "data": self.data,
        }
        
        with open(output_file, "w") as f:
            json.dump(report_data, f, indent=4)

    def generate_html_string(self):
        template = self.env.get_template("view.html")
        
        context = {
            "title": f"Vulnerability Report - {self.data.get('target', 'Scan')}",
            "timestamp": self.timestamp,
            "data": self.data,
            "summary": self._generate_summary(),
        }
        
        return template.render(**context)

    def _generate_summary(self):
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
        
        if "scan_results" in self.data:
            scan_results = self.data["scan_results"]
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
        
        if "owasp_results" in self.data:
            owasp_results = self.data["owasp_results"]
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
        
        if "exploit_results" in self.data:
            exploit_results = self.data["exploit_results"]
            
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
