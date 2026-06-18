import subprocess
import re
from typing import Dict, List, Optional, Any


DC_PORTS = {
    389: "LDAP",
    636: "LDAPS",
    88: "Kerberos",
    53: "DNS",
    464: "Kerberos Password Change",
    3268: "LDAP Global Catalog",
    3269: "LDAP GC SSL",
}

COMMON_CREDENTIALS = [
    ("", ""),
    ("guest", ""),
    ("Administrator", "password"),
    ("Administrator", ""),
    ("admin", "admin"),
]


class ADScanner:
    def __init__(self, target: str, credentials: List[tuple] = None):
        self.target = target
        self.credentials = credentials or COMMON_CREDENTIALS
        self.results: Dict[str, Any] = {
            "is_domain_controller": False,
            "is_domain_joined": False,
            "domain": None,
            "dc_ports": [],
            "vulnerabilities": [],
            "shares": [],
            "users": [],
            "computers": [],
        }

    def check_dc_ports(self, open_ports: Dict[int, dict]) -> List[str]:
        """Check which DC-related ports are open"""
        dc_open = []
        for port in open_ports:
            if port in DC_PORTS:
                dc_open.append(DC_PORTS[port])
        return dc_open

    def is_likely_dc(self, open_ports: Dict[int, dict]) -> bool:
        """Determine if host is likely a Domain Controller based on ports"""
        dc_score = sum(1 for p in open_ports if p in DC_PORTS)
        return dc_score >= 3

    def check_zerologon(self) -> Optional[Dict]:
        """Check for ZeroLogon vulnerability (CVE-2020-1472)"""
        try:
            cmd = ["crackmapexec", "smb", self.target, "-u", "", "-p", "", "-M", "zerologon"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            
            if "VULNERABLE" in output.upper() or "ZEROLOGON" in output.upper():
                return {
                    "name": "ZeroLogon",
                    "cve": "CVE-2020-1472",
                    "severity": "critical",
                    "description": "Allow domain admin password reset via Netlogon",
                    "status": "vulnerable"
                }
            return None
        except Exception:
            return None

    def check_petitpotam(self) -> Optional[Dict]:
        """Check for PetitPotam vulnerability (CVE-2022-26925)"""
        try:
            cmd = ["crackmapexec", "smb", self.target, "-u", "", "-p", "", "-M", "petitpotam"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            
            if "VULNERABLE" in output.upper() or "PETITPOTAM" in output.upper():
                return {
                    "name": "PetitPotam",
                    "cve": "CVE-2022-26925",
                    "severity": "critical",
                    "description": "NTLM relay to coerce machine account authentication",
                    "status": "vulnerable"
                }
            return None
        except Exception:
            return None

    def check_dfscoerce(self) -> Optional[Dict]:
        """Check for DFSCoerce vulnerability (CVE-2022-37918)"""
        try:
            cmd = ["crackmapexec", "smb", self.target, "-u", "", "-p", "", "-M", "dfscoerce"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            
            if "VULNERABLE" in output.upper() or "DFSCOERCE" in output.upper():
                return {
                    "name": "DFSCoerce",
                    "cve": "CVE-2022-37918",
                    "severity": "high",
                    "description": "NTLM relay via DFS referral requests",
                    "status": "vulnerable"
                }
            return None
        except Exception:
            return None

    def check_spooler(self) -> Optional[Dict]:
        """Check if Print Spooler service is available (PrintNightmare)"""
        for username, password in self.credentials:
            try:
                cmd = ["crackmapexec", "smb", self.target]
                if username:
                    cmd.extend(["-u", username, "-p", password])
                cmd.extend(["-M", "spooler"])
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                output = result.stdout + result.stderr
                
                if "spooler" in output.lower() and "enabled" in output.lower():
                    return {
                        "name": "Print Spooler",
                        "cve": "CVE-2021-34527",
                        "severity": "high",
                        "description": "Print Spooler service enabled - potential RCE",
                        "status": "enabled"
                    }
                if "vulnerable" in output.lower():
                    return {
                        "name": "PrintNightmare",
                        "cve": "CVE-2021-34527",
                        "severity": "critical",
                        "description": "Remote code execution via Print Spooler",
                        "status": "vulnerable"
                    }
            except Exception:
                continue
        return None

    def check_nopac(self) -> Optional[Dict]:
        """Check for NoPAC vulnerability (CVE-2021-42278/42287)"""
        for username, password in self.credentials:
            if not username:
                continue
            try:
                cmd = ["crackmapexec", "smb", self.target, "-u", username, "-p", password, "-M", "nopac"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                output = result.stdout + result.stderr
                
                if "VULNERABLE" in output.upper() or "NOPAC" in output.upper():
                    return {
                        "name": "NoPAC",
                        "cve": "CVE-2021-42278",
                        "severity": "critical",
                        "description": "Domain privilege escalation via SAMR account manipulation",
                        "status": "vulnerable"
                    }
            except Exception:
                continue
        return None

    def check_ldap_signing(self) -> Optional[Dict]:
        """Check LDAP signing and channel binding status"""
        for username, password in self.credentials:
            if not username:
                continue
            try:
                cmd = ["crackmapexec", "ldap", self.target, "-u", username, "-p", password, "-M", "ldap-checker"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                output = result.stdout + result.stderr
                
                if "LDAP" in output and "signing" in output.lower():
                    if "disabled" in output.lower() or "not required" in output.lower():
                        return {
                            "name": "LDAP Signing Disabled",
                            "cve": None,
                            "severity": "high",
                            "description": "LDAP signing not required - susceptible to relay attacks",
                            "status": "disabled"
                        }
            except Exception:
                continue
        return None

    def enum_shares(self) -> List[Dict]:
        """Enumerate SMB shares using null session"""
        shares = []
        try:
            cmd = ["crackmapexec", "smb", self.target, "-u", "", "-p", "", "--shares"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = result.stdout
            
            for line in output.split("\n"):
                if "READ" in line or "WRITE" in line or "ADMIN" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        shares.append({
                            "name": parts[0],
                            "access": " ".join(parts[1:]) if len(parts) > 1 else "Unknown"
                        })
        except Exception:
            pass
        return shares[:10]

    def get_domain_info_ldap(self) -> Optional[Dict]:
        """Get domain info via LDAP root DSE"""
        try:
            cmd = ["nmap", "-p", "389", "--script", "ldap-rootdse", self.target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            output = result.stdout
            
            domain_info = {}
            
            if "dnsHostName" in output:
                match = re.search(r'dnsHostName[^\n]+', output)
                if match:
                    domain_info["hostname"] = match.group(0).split("=")[-1].strip() if "=" in match.group(0) else None
            
            if "ldapServiceName" in output:
                match = re.search(r'ldapServiceName[^\n]+', output)
                if match:
                    domain_info["service_name"] = match.group(0).split("=")[-1].strip() if "=" in match.group(0) else None
            
            if "defaultNamingContext" in output:
                match = re.search(r'defaultNamingContext[^\n]+', output)
                if match:
                    domain_info["domain"] = match.group(0).split("=")[-1].strip() if "=" in match.group(0) else None
            
            return domain_info if domain_info else None
        except Exception:
            return None

    def run(self, open_ports: Dict[int, dict]) -> Dict[str, Any]:
        """Run full AD assessment on Windows host"""
        print(f"[*] Running AD assessment on {self.target}")
        
        self.results["dc_ports"] = self.check_dc_ports(open_ports)
        
        if self.is_likely_dc(open_ports):
            self.results["is_domain_controller"] = True
            print(f"[+] {self.target} appears to be a Domain Controller")
            
            domain_info = self.get_domain_info_ldap()
            if domain_info:
                self.results["domain"] = domain_info.get("domain")
                self.results["hostname"] = domain_info.get("hostname")
        
        print("[*] Checking AD vulnerabilities...")
        
        vulns = []
        
        zerologon = self.check_zerologon()
        if zerologon:
            vulns.append(zerologon)
            print(f"[!] Found: {zerologon['name']}")
        
        petitpotam = self.check_petitpotam()
        if petitpotam:
            vulns.append(petitpotam)
            print(f"[!] Found: {petitpotam['name']}")
        
        dfscoerce = self.check_dfscoerce()
        if dfscoerce:
            vulns.append(dfscoerce)
            print(f"[!] Found: {dfscoerce['name']}")
        
        spooler = self.check_spooler()
        if spooler:
            vulns.append(spooler)
            print(f"[!] Found: {spooler['name']}")
        
        nopac = self.check_nopac()
        if nopac:
            vulns.append(nopac)
            print(f"[!] Found: {nopac['name']}")
        
        ldap_signing = self.check_ldap_signing()
        if ldap_signing:
            vulns.append(ldap_signing)
            print(f"[!] Found: {ldap_signing['name']}")
        
        self.results["vulnerabilities"] = vulns
        
        print("[*] Enumerating shares...")
        self.results["shares"] = self.enum_shares()
        
        if self.results["is_domain_controller"]:
            print(f"[+] AD assessment complete for DC: {self.target}")
        else:
            print(f"[+] AD assessment complete for Windows host: {self.target}")
        
        return self.results