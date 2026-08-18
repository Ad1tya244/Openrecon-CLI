import httpx
import json
import re
import asyncio
import urllib.parse
from typing import List, Dict, Any, Optional, Set, Tuple
from openrecon.config import settings

MAX_SUBDOMAINS = 50
DEFAULT_SOURCE_TIMEOUT = 10.0

def normalize_subdomain(raw: str, target_domain: str) -> Optional[str]:
    """
    Strictly normalizes and validates a candidate subdomain:
    - Strips whitespace, quotes, and trailing dots
    - Lowercases
    - Strips wildcard prefix (*. or *)
    - Excludes the apex domain itself
    - Ensures it strictly ends with '.{target_domain}'
    - Validates DNS label syntax
    - NEVER manufactures or infers 'www.' variants
    """
    if not raw or not isinstance(raw, str):
        return None
    
    target = target_domain.lower().strip().rstrip('.')
    s = raw.lower().strip().rstrip('.').strip('"\'')
    
    # Handle wildcard prefixes
    while s.startswith('*.'):
        s = s[2:]
    if s.startswith('*'):
        s = s[1:]
    if s.startswith('.'):
        s = s[1:]
        
    if not s:
        return None
        
    # Apex domain itself is not a subdomain
    if s == target:
        return None
        
    # Must strictly end with .{target}
    if not s.endswith(f".{target}"):
        return None
        
    # Check that labels are valid
    labels = s.split('.')
    if any(not l for l in labels):
        return None
        
    # Verify valid DNS label characters
    for l in labels:
        if not re.match(r'^[a-z0-9](?:[a-z0-9-_]*[a-z0-9])?$', l):
            return None
            
    return s

async def _fetch_certspotter(domain: str, client: httpx.AsyncClient) -> List[str]:
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    resp = await client.get(url, timeout=DEFAULT_SOURCE_TIMEOUT)
    items = []
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    items.extend(entry.get("dns_names", []))
    return items

async def _fetch_rapiddns(domain: str, client: httpx.AsyncClient) -> List[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    resp = await client.get(url, timeout=DEFAULT_SOURCE_TIMEOUT)
    items = []
    if resp.status_code == 200:
        items = re.findall(rf'[\w\.-]+\.{re.escape(domain)}', resp.text)
    return items

async def _fetch_urlscan(domain: str, client: httpx.AsyncClient) -> List[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    resp = await client.get(url, timeout=DEFAULT_SOURCE_TIMEOUT)
    items = []
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, dict):
            for item in data.get("results", []):
                if isinstance(item, dict):
                    page_domain = item.get("page", {}).get("domain", "")
                    if page_domain:
                        items.append(page_domain)
                    task_domain = item.get("task", {}).get("domain", "")
                    if task_domain:
                        items.append(task_domain)
    return items

async def _fetch_crt_sh(domain: str, client: httpx.AsyncClient) -> List[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = await client.get(url, timeout=12.0)
    items = []
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        if name.strip():
                            items.append(name.strip())
    return items

async def _fetch_hackertarget(domain: str, client: httpx.AsyncClient) -> List[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = await client.get(url, timeout=DEFAULT_SOURCE_TIMEOUT)
    items = []
    if resp.status_code == 200 and "error" not in resp.text.lower():
        for line in resp.text.split("\n"):
            line = line.strip()
            if line:
                parts = line.split(",")
                if parts:
                    items.append(parts[0].strip())
    return items

async def _fetch_wayback(domain: str, client: httpx.AsyncClient) -> List[str]:
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=200"
    resp = await client.get(url, timeout=DEFAULT_SOURCE_TIMEOUT)
    items = []
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list) and len(data) > 1:
            for row in data[1:]:
                if row and isinstance(row, list) and len(row) > 0:
                    try:
                        parsed = urllib.parse.urlparse(row[0])
                        if parsed.hostname:
                            items.append(parsed.hostname)
                    except Exception:
                        pass
    return items

async def _fetch_anubis(domain: str, client: httpx.AsyncClient) -> List[str]:
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    resp = await client.get(url, timeout=DEFAULT_SOURCE_TIMEOUT, follow_redirects=True)
    items = []
    if resp.status_code == 200:
        data = resp.json()
        if isinstance(data, list):
            items = [str(x) for x in data if x]
    return items

async def _fetch_source_safe(
    source_name: str,
    fetch_func,
    domain: str,
    client: httpx.AsyncClient
) -> List[str]:
    try:
        return await fetch_func(domain, client)
    except Exception:
        return []

async def enumerate_subdomains(domain: str) -> Dict[str, Any]:
    """
    Enumerates subdomains using genuine passive intelligence sources:
    - Merges and deduplicates case-insensitively
    - Strictly normalizes and validates
    - Excludes the apex domain
    - Never generates synthetic www variants
    - Caps at exactly MAX_SUBDOMAINS (50)
    - Total equals exact displayed count
    """
    target = domain.lower().strip().rstrip('.')
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OpenRecon/1.0"
    }
    
    source_registry = [
        ("certspotter", _fetch_certspotter),
        ("rapiddns", _fetch_rapiddns),
        ("urlscan", _fetch_urlscan),
        ("crt_sh", _fetch_crt_sh),
        ("hackertarget", _fetch_hackertarget),
        ("wayback", _fetch_wayback),
        ("anubis", _fetch_anubis),
    ]
    
    collected_raw: List[str] = []
    async with httpx.AsyncClient(verify=False, headers=headers) as client:
        tasks = [
            _fetch_source_safe(name, func, target, client)
            for name, func in source_registry
        ]
        results = await asyncio.gather(*tasks)
        for res in results:
            if isinstance(res, list):
                collected_raw.extend(res)

    # Normalize, validate, deduplicate
    unique_subdomains: Set[str] = set()
    for raw in collected_raw:
        clean = normalize_subdomain(raw, target)
        if clean:
            unique_subdomains.add(clean)

    # Sort alphabetically and cap at MAX_SUBDOMAINS (50)
    sorted_subdomains = sorted(list(unique_subdomains))[:MAX_SUBDOMAINS]

    subdomain_objects = [{"hostname": s} for s in sorted_subdomains]

    return {
        "subdomains": subdomain_objects,
        "total": len(sorted_subdomains)
    }
