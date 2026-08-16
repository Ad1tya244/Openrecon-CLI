import dns.resolver
import httpx
import asyncio
import re
from typing import Dict, Any, List
from openrecon.config import settings

CDN_PROVIDERS = [
    "Cloudflare", "Akamai", "Fastly", "CloudFront", "EdgeCast", 
    "Limelight", "Incapsula", "Imperva", "Sucuri", "Netlify", "Vercel"
]

CLOUD_PROVIDERS = [
    "Amazon", "AWS", "Google", "Microsoft", "Azure", "DigitalOcean", 
    "Linode", "Vultr", "Oracle", "Alibaba", "Hetzner", "OVH"
]

SHARED_HOSTING_INDICATORS = [
    "GoDaddy", "Bluehost", "HostGator", "Namecheap", "DreamHost", 
    "SiteGround", "InMotion", "Hostinger", "1&1", "Ionos"
]

def normalize_provider(name: str) -> str:
    if not name or name.strip().lower() in ("unknown", "unknown isp", "unknown asn", ""):
        return ""
    n = name.strip()
    
    # Strip common corporate suffixes
    n = re.sub(r'(?i)[,\s]+(inc|llc|ltd|pvt\s*ltd|private\s*limited|limited|gmbh|corp|corporation)\.?$', '', n)
    n = re.sub(r'(?i)[,\s]+(isp\s*as|connected\s*cloud|technologies|division|telecom)\.?$', '', n)
    n = n.strip()
    
    if re.search(r'(?i)\bcloudfront\b', n):
        return "Amazon CloudFront"
    if re.search(r'(?i)\b(amazon|aws)\b', n):
        return "Amazon AWS"
    if re.search(r'(?i)\bgoogle\b', n):
        return "Google Cloud"
    if re.search(r'(?i)\bdigital\s*ocean\b', n):
        return "DigitalOcean"
    if re.search(r'(?i)\bcloudflare\b', n):
        return "Cloudflare"
    if re.search(r'(?i)\b(microsoft|azure)\b', n):
        return "Microsoft Azure"
    if re.search(r'(?i)\bakamai\b', n):
        return "Akamai"
    if re.search(r'(?i)\bfastly\b', n):
        return "Fastly"
    if re.search(r'(?i)\blinode\b', n):
        return "Linode"
    if re.search(r'(?i)\bhetzner\b', n):
        return "Hetzner"
    if re.search(r'(?i)\bsify\b', n):
        return "Sify Limited"
    if re.search(r'(?i)\b(tata\s*teleservices|tata\s*indicom)\b', n):
        return "Tata Teleservices"
    if re.search(r'(?i)\bnettigritty\b', n):
        return "Nettigritty"
    if re.search(r'(?i)\bovh\b', n):
        return "OVHcloud"
    if re.search(r'(?i)\bvultr\b', n):
        return "Vultr"
    if re.search(r'(?i)\boracle\b', n):
        return "Oracle Cloud"
        
    return n.strip()

def clean_asn_info(as_raw: str, isp: str = "", org: str = "") -> Dict[str, str]:
    """
    Cleans and deduplicates ASN code and organization/ISP description.
    """
    if not as_raw:
        return {"asn": "Unknown", "org": isp or org or "Unknown"}
    
    parts = as_raw.strip().split(" ", 1)
    asn_code = parts[0] if parts[0].upper().startswith("AS") else ""
    as_desc = parts[1].strip() if len(parts) > 1 else ""
    
    candidates = [c.strip() for c in [org, isp, as_desc] if c and c.strip()]
    if not candidates:
        return {"asn": asn_code or as_raw, "org": "Unknown"}
    
    chosen = candidates[0]
    for c in candidates:
        if len(c) > len(chosen) and chosen.lower() in c.lower():
            chosen = c
            
    return {
        "asn": asn_code if asn_code else as_raw,
        "org": chosen
    }

async def get_ip_data(ip: str) -> Dict[str, Any]:
    """
    Queries public IP intelligence (ISP, ASN, Org) using ip-api.com.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {"status": "fail"}

def analyze_hosting(data: Dict[str, Any]) -> Dict[str, Any]:
    isp = data.get("isp", "") or ""
    org = data.get("org", "") or ""
    as_info = data.get("as", "") or ""
    
    combined_info = f"{isp} {org} {as_info}".lower()
    hosting_type = "Unknown"
    flags = []
    
    is_cdn = False
    for provider in CDN_PROVIDERS:
        if provider.lower() in combined_info:
            hosting_type = "CDN / Edge Network"
            is_cdn = True
            flags.append(f"CDN detected: {provider}")
            break
            
    if not is_cdn:
        for provider in CLOUD_PROVIDERS:
            if provider.lower() in combined_info:
                hosting_type = "Cloud Infrastructure"
                flags.append(f"Cloud Provider: {provider}")
                break
                
    if hosting_type == "Unknown":
        for provider in SHARED_HOSTING_INDICATORS:
            if provider.lower() in combined_info:
                hosting_type = "Shared/Managed Hosting"
                flags.append("Potential shared infrastructure")
                break
                
    if hosting_type == "Unknown" and data.get("hosting") is True:
        hosting_type = "Generic Hosting / Datacenter"

    if not is_cdn:
        flags.append("Direct Origin IP (No CDN / Edge Proxy detected)")

    cleaned = clean_asn_info(as_info, isp, org)
    norm_provider = normalize_provider(cleaned["org"]) or cleaned["org"]

    return {
        "type": hosting_type,
        "flags": flags,
        "provider": norm_provider,
        "asn_code": cleaned["asn"],
        "asn_desc": cleaned["org"]
    }

async def get_domain_intelligence(domain: str) -> Dict[str, Any]:
    """
    Main entry point. Resolves domain and analyzes IP infrastructure.
    """
    results = {
        "domain": domain,
        "ips": [],
        "flags": []
    }
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_RESOLVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_TIMEOUT
    
    resolved_ips = set()
    
    try:
        answers = resolver.resolve(domain, "A")
        for rdata in answers:
            resolved_ips.add(rdata.to_text())
    except Exception:
        pass
        
    try:
        answers = resolver.resolve(domain, "AAAA")
        for rdata in answers:
            resolved_ips.add(rdata.to_text())
    except Exception:
        pass
        
    if not resolved_ips:
        return {"error": "Could not resolve domain IP addresses", "flags": ["Resolution Failed"]}
        
    ip_details = []
    global_flags = set()
    
    for ip in sorted(list(resolved_ips)):
        ip_info = await get_ip_data(ip)
        
        if ip_info.get("status") == "success":
            analysis = analyze_hosting(ip_info)
            detail = {
                "ip": ip,
                "asn": analysis["asn_code"],
                "isp": analysis["asn_desc"],
                "provider": analysis["provider"],
                "location": f"{ip_info.get('city', '')}, {ip_info.get('countryCode', '')}".strip(', '),
                "hosting_type": analysis["type"],
                "analysis_flags": analysis["flags"]
            }
            ip_details.append(detail)
            for f in analysis["flags"]:
                global_flags.add(f)
        else:
            ip_details.append({
                "ip": ip,
                "error": "Failed to query IP geolocation and ASN data"
            })

    results["ips"] = ip_details
    results["flags"] = list(global_flags)
    return results
