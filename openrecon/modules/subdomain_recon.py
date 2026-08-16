import httpx
import json
import re
import asyncio
import urllib.parse
import dns.resolver
from typing import List, Dict, Any, Optional, Set, Tuple
from openrecon.config import settings

MAX_SUBDOMAINS = 50
DEFAULT_SOURCE_TIMEOUT = 10.0

SENSITIVE_KEYWORDS = {
    "dev": "Development Environment",
    "staging": "Staging Environment",
    "stg": "Staging Environment",
    "test": "Test Environment",
    "uat": "UAT Environment",
    "admin": "Administrative Interface",
    "api": "API Endpoint",
    "internal": "Internal Infrastructure",
    "vpn": "Remote Access",
    "demo": "Demo Environment",
    "beta": "Beta Environment",
    "mail": "Mail Server",
    "corp": "Corporate Network",
    "portal": "Access Portal",
    "auth": "Authentication Service",
}

def normalize_subdomain(raw: str, target_domain: str) -> Optional[str]:
    """
    Normalizes and validates a candidate subdomain:
    - Strips whitespace, quotes, and trailing dots
    - Lowercases
    - Strips wildcard prefix (*. or *)
    - Excludes the apex domain itself
    - Ensures it strictly ends with '.{target_domain}'
    - Validates label syntax
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
    client: httpx.AsyncClient,
    max_retries: int = 1
) -> Tuple[str, List[str], str]:
    """
    Executes a single passive source query with bounded retries and timeout isolation.
    Returns: (source_name, raw_candidates_list, error_str_or_dash)
    """
    last_err = "-"
    for attempt in range(max_retries + 1):
        try:
            results = await fetch_func(domain, client)
            return (source_name, results, "-")
        except Exception as e:
            last_err = str(e) or "Request failed"
            if attempt < max_retries:
                await asyncio.sleep(0.5)
                continue
    return (source_name, [], last_err)

async def _check_dns_resolution(hostname: str, resolver: dns.resolver.Resolver) -> Dict[str, Any]:
    def _sync_resolve():
        resolved_ips = []
        try:
            answers = resolver.resolve(hostname, "A")
            for rdata in answers:
                resolved_ips.append(rdata.to_text())
        except Exception:
            pass
        try:
            answers = resolver.resolve(hostname, "AAAA")
            for rdata in answers:
                resolved_ips.append(rdata.to_text())
        except Exception:
            pass
        return resolved_ips
    
    ips = await asyncio.to_thread(_sync_resolve)
    return {
        "resolves": len(ips) > 0,
        "ips": ips
    }

async def enumerate_subdomains(domain: str) -> Dict[str, Any]:
    """
    Enumerates subdomains using genuine passive intelligence sources,
    normalizes, deduplicates, enforces MAX_SUBDOMAINS cap, verifies DNS
    resolution, and records internal diagnostics.
    """
    target = domain.lower().strip().rstrip('.')
    source_map: Dict[str, List[str]] = {}
    diagnostics: List[Dict[str, Any]] = []
    
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
    
    async with httpx.AsyncClient(verify=False, headers=headers) as client:
        tasks = [
            _fetch_source_safe(name, func, target, client, max_retries=1)
            for name, func in source_registry
        ]
        
        results = await asyncio.gather(*tasks)
        
        for source_name, raw_candidates, err in results:
            accepted_count = 0
            rejected_count = 0
            
            for raw in raw_candidates:
                norm = normalize_subdomain(raw, target)
                if norm:
                    accepted_count += 1
                    if norm not in source_map:
                        source_map[norm] = []
                    source_map[norm].append(source_name)
                else:
                    rejected_count += 1
            
            diagnostics.append({
                "source": source_name,
                "candidates": len(raw_candidates),
                "accepted": accepted_count,
                "rejected": rejected_count,
                "error": err
            })
        
    all_unique_subs = sorted(list(source_map.keys()))
    limit_reached = len(all_unique_subs) > MAX_SUBDOMAINS
    final_subs = all_unique_subs[:MAX_SUBDOMAINS]
    
    # Perform concurrent DNS resolution verification (verification only; never adds/removes subdomains)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_RESOLVERS
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    dns_tasks = [_check_dns_resolution(sub, resolver) for sub in final_subs]
    dns_results = await asyncio.gather(*dns_tasks, return_exceptions=True)
    
    cleaned_results = []
    for i, sub in enumerate(final_subs):
        dns_info = dns_results[i] if i < len(dns_results) and isinstance(dns_results[i], dict) else {"resolves": False, "ips": []}
        resolves = dns_info.get("resolves", False)
        
        flags = []
        context = "Public"
        is_interesting = False
        
        prefix = sub.replace(f".{target}", "")
        parts = prefix.split(".")
        
        for part in parts:
            if part in SENSITIVE_KEYWORDS:
                flags.append(SENSITIVE_KEYWORDS[part])
                is_interesting = True
                context = "Potentially Sensitive"
        
        cleaned_results.append({
            "hostname": sub,
            "resolves": resolves,
            "ips": dns_info.get("ips", []),
            "sources": sorted(list(set(source_map.get(sub, [])))),
            "flags": flags,
            "context": context,
            "is_interesting": is_interesting
        })

    return {
        "subdomains": cleaned_results,
        "count": len(cleaned_results),
        "total_discovered": len(all_unique_subs),
        "limit_reached": limit_reached,
        "diagnostics": diagnostics
    }
