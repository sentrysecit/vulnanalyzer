import requests
from bs4 import BeautifulSoup


def detect_web_technology(url):
    """Detects web technologies using headers and HTML"""
    technologies = []

    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers
        content = response.text

        # Detection by headers
        if "Server" in headers:
            technologies.append(f"Server: {headers['Server']}")

        if "X-Powered-By" in headers:
            technologies.append(f"Powered-By: {headers['X-Powered-By']}")

        # HTML Detection
        soup = BeautifulSoup(content, "html.parser")
        generator_meta = soup.find("meta", attrs={"name": "generator"})
        if generator_meta and "content" in generator_meta.attrs:
            technologies.append(f"Generator: {generator_meta['content']}")

        if '<script src="/wp-includes/' in content:
            technologies.append("CMS: WordPress")

    except Exception as e:
        technologies.append(f"Error: {str(e)}")

    return technologies


def detect_services(host, port_info):
    """Detecta servicios usando heurísticas simples basadas en nmap"""
    name = port_info.get("service", "").lower()
    version = port_info.get("version", "").lower()

    if "http" in name:
        if "apache" in version:
            return "Apache HTTP Server"
        elif "nginx" in version:
            return "Nginx"
        elif "iis" in version:
            return "Microsoft IIS"
        else:
            return "Generic HTTP Server"

    elif "ssh" in name:
        return "SSH Service"

    elif "mysql" in name or "mariadb" in version:
        return "MySQL/MariaDB"

    elif "ftp" in name:
        return "FTP Service"

    return f"Unknown Service: {name} {version}"


def detect_os(osmatch_data):
    """
    Normaliza los datos de OS detection de nmap.

    Args:
        osmatch_data: Lista de osmatch de nmap (cada elemento tiene 'name', 'accuracy', 'osclass')

    Returns:
        Dict con 'name', 'family', 'accuracy', 'cpe'
    """
    if not osmatch_data:
        return {"name": None, "family": "Unknown", "accuracy": None, "cpe": None}

    best_match = osmatch_data[0]
    name = best_match.get("name", "Unknown")
    accuracy = best_match.get("accuracy", "0")

    osclass_list = best_match.get("osclass", [])
    cpe = None

    family = "Unknown"
    for osclass in osclass_list:
        os_family = osclass.get("osfamily", "").lower()

        if "windows" in os_family:
            family = "Windows"
            cpe = osclass.get("cpe", "")
            break
        elif "linux" in os_family:
            family = "Linux"
            cpe = osclass.get("cpe", "")
            break
        elif "mac" in os_family or "darwin" in os_family:
            family = "macOS"
            cpe = osclass.get("cpe", "")
            break
        elif os_family and family == "Unknown":
            family = os_family.capitalize()
            cpe = osclass.get("cpe", "")

    return {"name": name, "family": family, "accuracy": accuracy, "cpe": cpe}


DC_PORTS = {
    389: "LDAP",
    636: "LDAPS",
    88: "Kerberos",
    53: "DNS",
    464: "Kerberos Password Change",
    3268: "LDAP Global Catalog",
    3269: "LDAP GC SSL",
}


def detect_dc_ports(open_ports):
    """
    Detecta si un host Windows es un Domain Controller basado en puertos.
    
    Args:
        open_ports: Dict de puertos abiertos {port: info}
        
    Returns:
        Dict con 'is_domain_controller', 'dc_ports', 'dc_score'
    """
    if not open_ports:
        return {"is_domain_controller": False, "dc_ports": [], "dc_score": 0}
    
    dc_open = []
    for port in open_ports:
        if port in DC_PORTS:
            dc_open.append(DC_PORTS[port])
    
    dc_score = len(dc_open)
    is_dc = dc_score >= 3
    
    return {
        "is_domain_controller": is_dc,
        "dc_ports": dc_open,
        "dc_score": dc_score
    }
