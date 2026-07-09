import subprocess
import os
from urllib.parse import urlparse


WORDLISTS = {
    "small": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "large": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-large.txt",
}

DEFAULT_WORDLIST = WORDLISTS["small"]

EXTENSIONS = ["", ".php", ".html", ".txt", ".json", ".xml", ".asp", ".aspx", ".jsp"]


def check_tool(tool):
    result = subprocess.run(
        ["which", tool],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def parse_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    parsed = urlparse(url)
    return {
        "scheme": parsed.scheme,
        "host": parsed.netloc.split(":")[0],
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "path": parsed.path or "/",
    }


def detect_base_response(url, extensions=None):
    print("[*] Detectando respuesta base...")

    if not url.endswith("/"):
        url = url.rstrip("/") + "/"

    result = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}:%{size}", url],
        capture_output=True,
        text=True,
    )
    response = result.stdout.strip()

    parts = response.split(":")
    status_code = parts[0] if parts else "000"
    base_size = parts[1] if len(parts) > 1 else "0"

    print(f"[+] Respuesta base: HTTP {status_code}, size: {base_size}")

    return {
        "status_code": status_code,
        "size": base_size,
    }


def run_ffuf_path(
    url,
    output="paths.txt",
    wordlist=None,
    extensions=None,
    threads=40,
    silent=True,
    follow_redirects=False,
):
    print("[*] Fuzzing de rutas (ffuf)...")

    if not check_tool("ffuf"):
        print("[!] ffuf no instalado")
        return False

    if not wordlist:
        wordlist = DEFAULT_WORDLIST

    if not os.path.exists(wordlist):
        print(f"[!] Wordlist no encontrada: {wordlist}")
        return False

    base_response = detect_base_response(url)
    exclude_sizes = base_response["size"]

    url_info = parse_url(url)
    target_url = f"{url_info['scheme']}://{url_info['host']}:{url_info['port']}{url_info['path']}"

    cmd = [
        "ffuf",
        "-u", f"{target_url}FUZZ",
        "-w", wordlist,
        "-fs", exclude_sizes,
        "-mc", "200,201,204,301,302,307,401,403,500",
        "-t", str(threads),
    ]

    if extensions:
        ext_str = ",".join(e for e in extensions if e)
        if ext_str:
            cmd.extend(["-e", ext_str])

    if silent:
        cmd.append("-s")

    if follow_redirects:
        cmd.extend(["-recursion", "-recursion-depth", "2"])

    cmd.extend(["-of", "csv", "-o", "ffuf_paths.csv"])

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[!] ffuf error: {result.stderr}")

    found = []

    if os.path.exists("ffuf_paths.csv"):
        with open("ffuf_paths.csv") as f:
            for line in f:
                if "FUZZ" not in line and line.strip():
                    parts = line.split(",")
                    if parts:
                        path = parts[0].strip().strip('"')
                        if path and path != "FUZZ":
                            found.append(path)

    if found:
        found = list(set(found))
        with open(output, "w") as f:
            for path in sorted(found):
                f.write(path + "\n")

        print(f"[+] FFUF encontró {len(found)} rutas")
        return True
    else:
        print("[-] FFUF no encontró rutas")
        return False


def run_httpx(input_file, output="alive_paths.txt", silent=True):
    print("[*] Verificando endpoints con httpx...")

    httpx_path = os.path.expanduser("~/go/bin/httpx")

    if not os.path.exists(httpx_path):
        httpx_path = subprocess.run(
            ["which", "httpx"], capture_output=True, text=True
        ).stdout.strip()
        if not httpx_path:
            print("[!] httpx no instalado")
            return False

    cmd = [httpx_path, "-l", input_file, "-o", output]
    if silent:
        cmd.append("-silent")

    subprocess.run(cmd, capture_output=True, text=True)

    return os.path.exists(output) and os.path.getsize(output) > 0


def save_unique(file):
    if not os.path.exists(file):
        return []

    with open(file) as f:
        lines = list(set(line.strip() for line in f if line.strip()))

    with open(file, "w") as f:
        for line in sorted(lines):
            f.write(line + "\n")

    return sorted(lines)


class PathFuzzer:
    def __init__(
        self,
        target,
        wordlist=None,
        extensions=None,
        threads=40,
        use_httpx=False,
        output=None,
        output_dir=None,
        fuzz_id=None,
    ):
        self.target = target
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.extensions = extensions or EXTENSIONS
        self.threads = threads
        self.use_httpx = use_httpx
        
        output_dir = output_dir or "tools/fuzzing"
        if output:
            self.output = output
        elif fuzz_id:
            self.output = os.path.join(output_dir, f"paths_{fuzz_id}.txt")
        else:
            self.output = os.path.join(output_dir, "paths.txt")
            
        self.results = {
            "all": [],
            "found": False,
        }

    def run(self):
        print(f"\n=== Path Fuzzing: {self.target} ===\n")

        found = run_ffuf_path(
            self.target,
            self.output,
            self.wordlist,
            self.extensions,
            self.threads,
        )

        if not found:
            print("[!] No se encontraron rutas")
            return self.results

        save_unique(self.output)
        self.results["all"] = save_unique(self.output)
        self.results["found"] = True

        print(f"[+] Total rutas encontradas: {len(self.results['all'])}")

        if self.use_httpx:
            run_httpx(self.output)

        print("\n[+] Fuzzing completado")
        return self.results


def get_available_wordlists():
    available = {}

    for name, path in WORDLISTS.items():
        if os.path.exists(path):
            available[name] = path
        else:
            alt_path = path.replace("/usr/share/seclists", "~/.seclists")
            if os.path.exists(os.path.expanduser(alt_path)):
                available[name] = os.path.expanduser(alt_path)

    return available