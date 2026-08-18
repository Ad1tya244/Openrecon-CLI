import asyncio
import re
from typing import Dict, Any, List, Optional

TOP_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    3306: "MySQL",
    3389: "RDP"
}

def parse_service_version(service: str, banner: Optional[str]) -> Optional[str]:
    """Extracts genuine version from service banner if clearly observed."""
    if not banner or not isinstance(banner, str):
        return None
    b = banner.strip()
    if service == "SSH":
        # e.g. SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2
        m = re.search(r"SSH-[0-9\.]+-([^\s]+)", b)
        if m:
            ver = m.group(1).replace("_", " ")
            return ver
    elif service == "FTP":
        # e.g. 220 ProFTPD 1.3.5 Server or 220 (vsFTPd 3.0.3)
        m = re.search(r"220[- ](?:\()?([a-zA-Z]+[a-zA-Z0-9\.\-_ ]+)(?:\))?", b)
        if m:
            return m.group(1).strip()
    elif service == "SMTP":
        # e.g. 220 mail.example.com ESMTP Postfix
        m = re.search(r"220[- ].*?(?:ESMTP|SMTP)\s+([a-zA-Z0-9\.\-_]+)", b, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None

async def check_port_with_banner(domain: str, port: int) -> Optional[Dict[str, Any]]:
    """
    Checks if a port is open and safely grabs the identification banner
    for services that speak first (SSH, FTP, SMTP) without aggressive probing.
    """
    try:
        future = asyncio.open_connection(domain, port)
        reader, writer = await asyncio.wait_for(future, timeout=2.0)
        
        service_name = TOP_PORTS.get(port, f"Port-{port}")
        banner_text = None

        # For banner-speaking services, read the identification line
        if port in (21, 22, 25):
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                if data:
                    banner_text = data.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        version = parse_service_version(service_name, banner_text)

        return {
            "port": port,
            "service": service_name,
            "version": version,
            "banner": banner_text
        }
    except Exception:
        return None

async def scan_ports(domain: str) -> Dict[str, Any]:
    """
    Scans top common ports concurrently and extracts verified versions where available.
    """
    ports_list = list(TOP_PORTS.keys())
    tasks = [check_port_with_banner(domain, port) for port in ports_list]
    
    check_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    open_ports = []
    for res in check_results:
        if isinstance(res, dict) and res is not None:
            open_ports.append(res)
            
    open_ports.sort(key=lambda x: x["port"])

    return {
        "open_ports": open_ports,
        "scanned_ports": ports_list
    }
