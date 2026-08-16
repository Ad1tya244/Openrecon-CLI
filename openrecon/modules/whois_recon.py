import socket
import re
from typing import Dict, Any, Optional
from datetime import datetime
from openrecon.config import settings

def get_whois_server(domain: str) -> str:
    """
    Simple heuristic to find whois server.
    """
    tld = domain.split('.')[-1]
    servers = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'uk': 'whois.nic.uk',
        'jp': 'whois.jprs.jp',
        'in': 'whois.nixiregistry.in',
        'ac.in': 'whois.nixiregistry.in',
        'de': 'whois.denic.de',
        'ca': 'whois.cira.ca',
        'eu': 'whois.eu',
        'me': 'whois.nic.me',
        'ai': 'whois.nic.ai',
        'dev': 'whois.nic.google',
        'app': 'whois.nic.google',
    }
    if domain.endswith('.ac.in') or domain.endswith('.co.in') or domain.endswith('.net.in') or domain.endswith('.org.in'):
        return 'whois.nixiregistry.in'

    return servers.get(tld, f"whois.nic.{tld}")

def parse_date(date_str: str) -> Optional[datetime]:
    """
    Attempts to parse WHOIS date strings in various formats.
    """
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
    Parses raw WHOIS text for key information using regex.
    """
    data = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "age_days": None,
        "name_servers": [],
        "scan_date": datetime.now().isoformat(),
        "flags": [],
        "raw_preview": raw_text[:500] + "..." if raw_text else ""
    }
    
    patterns = {
        "registrar": [
            r"Registrar:\s*(.+)",
            r"Sponsoring Registrar:\s*(.+)",
            r"registrar:\s*(.+)",
            r"Organization:\s*(.+)"
        ],
        "creation_date": [
            r"Creation Date:\s*(.+)",
            r"Created:\s*(.+)",
            r"Registered on:\s*(.+)",
            r"created:\s*(.+)",
            r"Created On:\s*(.+)",
            r"Creation Date\s*:\s*(.+)"
        ],
        "expiration_date": [
            r"Registry Expiry Date:\s*(.+)",
            r"Expiration Date:\s*(.+)",
            r"Expiry date:\s*(.+)",
            r"paid-till:\s*(.+)",
            r"Expires On:\s*(.+)",
            r"Expiration Date\s*:\s*(.+)"
        ]
    }
    
    for key, regex_list in patterns.items():
        for pattern in regex_list:
            match = re.search(pattern, raw_text, re.IGNORECASE)
            if match:
                data[key] = match.group(1).strip()
                break

    # Name servers
    ns_matches = re.findall(r"Name Server:\s*([^\s\r\n]+)", raw_text, re.IGNORECASE)
    if ns_matches:
        data["name_servers"] = sorted(list(set([ns.lower() for ns in ns_matches])))
                
    # Calculate Age
    if data["creation_date"]:
        created_dt = parse_date(data["creation_date"])
        if created_dt:
            data["creation_date_iso"] = created_dt.isoformat()
            now = datetime.now()
            age = (now - created_dt).days
            data["age_days"] = age
            
            if age < 90:
                data["flags"].append("Recently registered (Domain age < 90 days)")
        else:
            data["creation_date_parsed"] = "Failed to parse"

    return data

def get_whois_info(domain: str) -> Dict[str, Any]:
    """
    Retrieves and parses WHOIS info using raw sockets (No subprocess).
    Safely handles connection errors and timeouts.
    """
    server = get_whois_server(domain)
    
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
            "error": f"Whois connection to {server} timed out",
            "registrar": "Unknown",
            "creation_date": "Unknown",
            "flags": ["Whois Timeout"]
        }
    except Exception as e:
        return {
            "error": "Whois lookup failed",
            "details": str(e), 
            "registrar": "Unknown",
            "creation_date": "Unknown"
        }
