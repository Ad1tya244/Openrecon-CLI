import socket
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from openrecon.config import settings

PRIVACY_PATTERNS = [
    r"redacted",
    r"privacy",
    r"whoisguard",
    r"proxy",
    r"gdpr",
    r"withheld",
    r"contact privacy",
    r"not disclosed",
    r"statutory mask",
    r"data protected",
    r"private person"
]

def is_redacted_value(val: Optional[str]) -> bool:
    """Checks whether a WHOIS value is an obvious privacy/redaction placeholder."""
    if not val or not isinstance(val, str):
        return True
    val_lower = val.lower().strip()
    if not val_lower or val_lower in ("none", "n/a", "unknown", "null"):
        return True
    for p in PRIVACY_PATTERNS:
        if re.search(p, val_lower):
            return True
    return False

def get_whois_server(domain: str) -> Optional[str]:
    """Finds the appropriate whois server for a domain."""
    tld = domain.split(".")[-1].lower()
    servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "edu": "whois.educause.edu",
        "gov": "whois.nic.gov",
        "io": "whois.nic.io",
        "co": "whois.nic.co",
        "uk": "whois.nic.uk",
        "jp": "whois.jprs.jp",
        "in": "whois.nixiregistry.in",
        "de": "whois.denic.de",
        "ca": "whois.cira.ca",
        "eu": "whois.eu",
        "me": "whois.nic.me",
        "ai": "whois.nic.ai",
        "dev": "whois.nic.google",
        "app": "whois.nic.google",
    }
    if domain.endswith(".ac.in") or domain.endswith(".co.in") or domain.endswith(".net.in") or domain.endswith(".org.in"):
        return "whois.nixiregistry.in"

    if tld in servers:
        return servers[tld]

    server = f"whois.nic.{tld}"
    try:
        socket.gethostbyname(server)
        return server
    except socket.gaierror:
        return None

def parse_date(date_str: str) -> Optional[datetime]:
    """Attempts to parse WHOIS date strings in various formats."""
    if not date_str:
        return None
        
    date_str = date_str.strip()
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%Y.%m.%d",
        "%a %b %d %H:%M:%S %Z %Y",
        "%d/%m/%Y",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
            
    if "T" in date_str:
        try:
            return datetime.strptime(date_str.split("T")[0], "%Y-%m-%d")
        except ValueError:
            pass
            
    return None

def parse_whois_data(raw_text: str) -> Dict[str, Any]:
    """
    Parses raw WHOIS text for genuine information without fabricating fields.
    Filters privacy/redaction placeholders.
    """
    data: Dict[str, Any] = {
        "registrar": None,
        "registry_domain_id": None,
        "registrar_iana_id": None,
        "creation_date": None,
        "updated_date": None,
        "expiration_date": None,
        "age_years": None,
        "status": None,
        "registrant": None,
        "scan_date": datetime.now().isoformat(),
        "raw_preview": raw_text[:500] + "..." if raw_text else ""
    }
    
    patterns = {
        "registrar": [
            r"Registrar:\s*(.+)",
            r"Sponsoring Registrar:\s*(.+)",
            r"registrar:\s*(.+)",
            r"Organization:\s*(.+)"
        ],
        "registry_domain_id": [
            r"Registry Domain ID:\s*(.+)",
            r"Domain ID:\s*(.+)"
        ],
        "registrar_iana_id": [
            r"Registrar IANA ID:\s*(\d+)",
            r"IANA ID:\s*(\d+)"
        ],
        "creation_date": [
            r"Creation Date:\s*(.+)",
            r"Created:\s*(.+)",
            r"Registered on:\s*(.+)",
            r"created:\s*(.+)",
            r"Created On:\s*(.+)",
            r"Domain record activated:\s*(.+)"
        ],
        "updated_date": [
            r"Updated Date:\s*(.+)",
            r"Last Updated On:\s*(.+)",
            r"modified:\s*(.+)",
            r"last-update:\s*(.+)",
            r"Last Modified:\s*(.+)",
            r"Domain record last updated:\s*(.+)"
        ],
        "expiration_date": [
            r"Registry Expiry Date:\s*(.+)",
            r"Expiration Date:\s*(.+)",
            r"Expiry date:\s*(.+)",
            r"paid-till:\s*(.+)",
            r"Expires On:\s*(.+)",
            r"Domain expires:\s*(.+)"
        ],
        "registrant": [
            r"Registrant Organization:\s*(.+)",
            r"Registrant Name:\s*(.+)",
            r"registrant:\s*(.+)",
            r"tech-c:\s*(.+)"
        ]
    }
    
    for key, regex_list in patterns.items():
        for pattern in regex_list:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                val = match.group(1).strip()
                if key == "registrant":
                    if not is_redacted_value(val):
                        data[key] = val
                else:
                    data[key] = val
                break

    # EPP Status Codes
    status_matches = re.findall(r"(?:Domain Status|status):\s*([a-zA-Z0-9]+)", raw_text, re.IGNORECASE)
    if status_matches:
        unique_statuses = []
        for st in status_matches:
            st_clean = st.strip()
            if st_clean and st_clean.lower() not in [s.lower() for s in unique_statuses]:
                unique_statuses.append(st_clean)
        data["status"] = unique_statuses[:3] if unique_statuses else None

    # Calculate Age & Normalize Date Formats for Formatter
    for key in ["creation_date", "updated_date", "expiration_date"]:
        if data[key]:
            dt = parse_date(data[key])
            if dt:
                if "T" in data[key] or ":" in data[key]:
                    data[key] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                else:
                    data[key] = dt.strftime("%Y-%m-%d")

    if data["creation_date"]:
        created_dt = parse_date(data["creation_date"])
        if created_dt:
            data["creation_date_iso"] = created_dt.isoformat()
            now = datetime.now()
            age_days = (now - created_dt).days
            data["age_years"] = round(age_days / 365.25, 1)

    return data

def get_whois_info(domain: str) -> Dict[str, Any]:
    """Retrieves and parses WHOIS info using raw sockets."""
    server = get_whois_server(domain)
    if not server:
        tld = domain.split(".")[-1].lower()
        return {
            "error": f"Cannot determine a valid WHOIS server for TLD .{tld}"
        }
    
    try:
        with socket.create_connection((server, 43), timeout=settings.SOCKET_TIMEOUT) as sock:
            sock.sendall(f"{domain}\r\n".encode())
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data.decode(errors='replace'))
            
            response = "".join(chunks)
            parsed_data = parse_whois_data(response)
            parsed_data["server_queried"] = server
            return parsed_data

    except socket.timeout:
        return {
            "error": f"Whois connection to {server} timed out"
        }
    except Exception as e:
        return {
            "error": "Whois lookup failed",
            "details": str(e)
        }
