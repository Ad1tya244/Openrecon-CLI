import asyncio
from typing import Dict, Any, List

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

async def check_port(domain: str, port: int) -> bool:
    """
    Checks if a single port is open using asyncio.open_connection.
    Timeout is strict (1.5s) to avoid hanging.
    """
    try:
        future = asyncio.open_connection(domain, port)
        reader, writer = await asyncio.wait_for(future, timeout=1.5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def scan_ports(domain: str) -> Dict[str, Any]:
    """
    Scans top common ports concurrently using asyncio.gather.
    """
    results = {
        "open_ports": [],
        "scanned_ports": list(TOP_PORTS.keys())
    }
    
    ports_list = list(TOP_PORTS.keys())
    tasks = [check_port(domain, port) for port in ports_list]
    
    check_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for port, is_open in zip(ports_list, check_results):
        if is_open is True:
            results["open_ports"].append({
                "port": port,
                "service": TOP_PORTS[port]
            })
            
    return results
