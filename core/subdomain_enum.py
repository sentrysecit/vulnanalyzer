import subprocess
import os
import re
from urllib.parse import urlparse


WORDLISTS = {
    "small": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-2000.txt",
    "medium": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "large": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
}

DEFAULT_WORDLIST = WORDLISTS["medium"]


def clean_domain(domain):
    if domain.startswith("http"):
        return urlparse(domain).netloc
    return domain


def check_tool(tool):
    result = subprocess.run(
        f"which {tool}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def file_has_content(file):
    return os.path.exists(file) and os.path.getsize(file) > 0


def save_unique(file):
    if not os.path.exists(file):
        return []

    with open(file) as f:
        lines = set(line.strip() for line in f if line.strip())

    with open(file, "w") as f:
        for line in sorted(lines):
            f.write(line + "\n")

    return sorted(lines)


def run_subfinder(domain, output="subdomains.txt", silent=True):
    print("[*] Subfinder (modo pasivo)...")

    if not check_tool("subfinder"):
        print("[!] subfinder no instalado")
        return False

    cmd = f"subfinder -d {domain}"
    if silent:
        cmd += " -silent"
    cmd += f" -o {output}"

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if file_has_content(output):
        print(f"[+] Subfinder encontró resultados: {output}")
        return True
    else:
        print("[-] Subfinder no encontró nada")
        return False


def detect_wildcard(domain):
    print("[*] Detectando wildcard...")

    random_sub = f"rnd{subprocess.getoutput('date +%s')}"
    cmd = f"curl -s -o /dev/null -w '%{{size_download}}' -H 'Host: {random_sub}.{domain}' http://{domain}"

    size = subprocess.getoutput(cmd)

    print(f"[+] Wildcard size detectado: {size}")
    return size


def run_ffuf_subdomain(
    domain,
    output="subdomains.txt",
    wordlist=None,
    threads=40,
    silent=True,
):
    print("[*] Fallback: fuzzing de subdominios (ffuf)...")

    if not check_tool("ffuf"):
        print("[!] ffuf no instalado")
        return False

    if not wordlist:
        wordlist = DEFAULT_WORDLIST

    if not os.path.exists(wordlist):
        print(f"[!] Wordlist no encontrada: {wordlist}")
        return False

    wildcard_size = detect_wildcard(domain)

    cmd = [
        "ffuf",
        "-u",
        f"http://{domain}",
        "-H",
        f"Host: FUZZ.{domain}",
        "-w",
        wordlist,
        "-fs",
        wildcard_size,
        "-mc",
        "200,301,302,400",
        "-t",
        str(threads),
    ]

    if silent:
        cmd.append("-s")

    cmd.extend(["-of", "csv", "-o", "ffuf_subs.csv"])

    result = subprocess.run(cmd, capture_output=True, text=True)

    found = set()

    if os.path.exists("ffuf_subs.csv"):
        with open("ffuf_subs.csv") as f:
            for line in f:
                if "FUZZ" not in line and line.strip():
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip().strip('"')
                        if sub and sub != "FUZZ":
                            found.add(f"{sub}.{domain}")

    if found:
        with open(output, "w") as f:
            for sub in sorted(found):
                f.write(sub + "\n")

        print(f"[+] FFUF encontró {len(found)} subdominios")
        return True
    else:
        print("[-] FFUF no encontró subdominios")
        return False


def run_httpx(input_file, output="alive.txt", silent=True):
    print("[*] Ejecutando httpx...")

    httpx_path = os.path.expanduser("~/go/bin/httpx")

    if not os.path.exists(httpx_path):
        httpx_path = subprocess.getoutput("which httpx").strip()
        if not httpx_path:
            print("[!] httpx no instalado")
            return False

    cmd = f"{httpx_path} -l {input_file}"
    if silent:
        cmd += " -silent"
    cmd += f" -o {output}"

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    return file_has_content(output)


def run_nuclei(input_file, severity="medium,high,critical"):
    print("[*] Ejecutando nuclei...")

    if not check_tool("nuclei"):
        print("[!] nuclei no instalado")
        return

    cmd = f"nuclei -l {input_file} -severity {severity}"
    subprocess.run(cmd, shell=True)


class SubdomainEnumerator:
    def __init__(
        self,
        target,
        wordlist=None,
        threads=40,
        use_httpx=True,
        use_nuclei=False,
        output=None,
        output_dir=None,
        enum_id=None,
        check_cve=False,
        find_exploits=False,
    ):
        self.target = clean_domain(target)
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.threads = threads
        self.use_httpx = use_httpx
        self.use_nuclei = use_nuclei
        self.check_cve = check_cve
        self.find_exploits = find_exploits

        output_dir = output_dir or "tools/fuzzing"
        if output:
            self.output = output
        elif enum_id:
            self.output = os.path.join(output_dir, f"subdomains_{enum_id}.txt")
        else:
            self.output = os.path.join(output_dir, "subdomains.txt")

        if enum_id:
            self.alive_output = os.path.join(
                output_dir, f"subdomains_{enum_id}_alive.txt"
            )
        else:
            self.alive_output = os.path.join(output_dir, "subdomains_alive.txt")

        self.results = {
            "all": [],
            "alive": [],
            "found": False,
            "vulnerabilities": [],
        }

    def detect_vulnerabilities(self):
        if not self.check_cve or not self.results["alive"]:
            return

        print("[*] Detecting vulnerabilities for alive hosts...")

        try:
            from core.cve_scanner import CVEScanner

            scanner = CVEScanner()
            services_info = []

            for host_url in self.results["alive"]:
                host = (
                    host_url.replace("http://", "")
                    .replace("https://", "")
                    .split(":")[0]
                    .split("/")[0]
                )
                services_info.append(
                    {
                        "host": host,
                        "subdomain": host_url,
                        "service": "http",
                        "version": "",
                    }
                )

            vulns = scanner.detect_vulnerabilities(services_info)
            self.results["vulnerabilities"] = vulns

            for vuln in vulns:
                cve_id = vuln.get("cve_id")
                cve_details = scanner.check_cve(cve_id) if cve_id else {}

                vuln["description"] = cve_details.get("description", "")
                vuln["title"] = cve_details.get("description", f"CVE {cve_id}")
                vuln["is_exploited"] = cve_details.get(
                    "is_exploited", vuln.get("is_exploited", False)
                )

                print(
                    f"    [+] {cve_id} ({cve_details.get('severity', 'N/A')}) - {vuln.get('service')}"
                )

        except Exception as e:
            print(f"[!] Error detecting vulnerabilities: {e}")

    def find_exploits_for_vulns(self):
        if not self.find_exploits or not self.results["vulnerabilities"]:
            return

        print("[*] Searching for available exploits...")

        try:
            from core.exploit_finder import ExploitFinder

            finder = ExploitFinder()
            cve_ids = list(
                set(
                    v.get("cve_id")
                    for v in self.results["vulnerabilities"]
                    if v.get("cve_id")
                )
            )

            for vuln in self.results["vulnerabilities"]:
                cve_id = vuln.get("cve_id")
                if cve_id:
                    exploits = finder.search_by_cve(cve_id)
                    vuln["exploits"] = exploits if exploits else []
                    if exploits:
                        print(f"    [+] {cve_id}: {len(exploits)} exploit(s) found")

        except Exception as e:
            print(f"[!] Error finding exploits: {e}")

    def run(self):
        print(f"\n=== Subdomain Enumeration: {self.target} ===\n")

        found = run_subfinder(self.target, self.output)

        if not found:
            found = run_ffuf_subdomain(
                self.target,
                self.output,
                self.wordlist,
                self.threads,
            )

        if not found:
            print("[!] No se encontraron subdominios")
            return self.results

        save_unique(self.output)
        self.results["all"] = save_unique(self.output)
        self.results["found"] = True

        print(f"[+] Total subdominios encontrados: {len(self.results['all'])}")

        alive_file = self.alive_output

        if self.use_httpx:
            ok = run_httpx(self.output, self.alive_output)
            if ok:
                self.results["alive"] = save_unique(self.alive_output)
                print(f"[+] Hosts vivos: {len(self.results['alive'])}")
            else:
                print("[!] No hay hosts vivos")
        else:
            alive_file = self.output

        if self.check_cve or self.find_exploits:
            self.detect_vulnerabilities()

        if self.find_exploits:
            self.find_exploits_for_vulns()

        if self.use_nuclei and self.results["alive"]:
            run_nuclei(alive_file)

        print("\n[+] Enumeración completada")
        return self.results
