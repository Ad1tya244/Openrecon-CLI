import dns.resolver
import httpx
import asyncio
import re
from typing import Dict, Any, List, Optional
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
    if re.search(r'(?i)\bovh\b', n):
        return "OVHcloud"
    if re.search(r'(?i)\bvultr\b', n):
        return "Vultr"
    if re.search(r'(?i)\boracle\b', n):
        return "Oracle Cloud"
        
    return n.strip()

def clean_asn_info(as_raw: str, isp: str = "", org: str = "") -> Dict[str, str]:
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
    """Queries public IP intelligence for ISP, ASN, and location."""
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
    
    for provider in CDN_PROVIDERS:
        if provider.lower() in combined_info:
            hosting_type = "CDN / Edge Network"
            break
            
    if hosting_type == "Unknown":
        for provider in CLOUD_PROVIDERS:
            if provider.lower() in combined_info:
                hosting_type = "Cloud Infrastructure"
                break
                
    if hosting_type == "Unknown":
        for provider in SHARED_HOSTING_INDICATORS:
            if provider.lower() in combined_info:
                hosting_type = "Shared/Managed Hosting"
                break
                
    if hosting_type == "Unknown" and data.get("hosting") is True:
        hosting_type = "Generic Hosting / Datacenter"

    cleaned = clean_asn_info(as_info, isp, org)
    norm_provider = normalize_provider(cleaned["org"]) or cleaned["org"]

    return {
        "type": hosting_type,
        "provider": norm_provider,
        "asn_code": cleaned["asn"],
        "asn_desc": cleaned["org"]
    }

async def get_domain_intelligence(domain: str) -> Dict[str, Any]:
    """
    Resolves domain IPv4/IPv6 and retrieves target-centric infrastructure intelligence.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_RESOLVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_TIMEOUT
    
    ipv4_list = []
    ipv6_list = []
    
    try:
        answers = resolver.resolve(domain, "A")
        for rdata in answers:
            ip_str = rdata.to_text()
            if ip_str not in ipv4_list:
                ipv4_list.append(ip_str)
    except Exception:
        pass
        
    try:
        answers = resolver.resolve(domain, "AAAA")
        for rdata in answers:
            ip_str = rdata.to_text()
            if ip_str not in ipv6_list:
                ipv6_list.append(ip_str)
    except Exception:
        pass
        
    if not ipv4_list and not ipv6_list:
        return {"error": "Could not resolve domain IP addresses"}

    primary_ip = ipv4_list[0] if ipv4_list else (ipv6_list[0] if ipv6_list else None)
    additional_ips = ipv4_list[1:] if len(ipv4_list) > 1 else []

    primary_info = await get_ip_data(primary_ip) if primary_ip else {}
    
    if primary_info.get("status") == "success":
        analysis = analyze_hosting(primary_info)
        loc_city = primary_info.get("city", "")
        loc_country = primary_info.get("countryCode", "")
        loc_str = f"{loc_city}, {loc_country}".strip(", ")
        
        return {
            "primary_ip": primary_ip,
            "ipv6": ipv6_list[0] if ipv6_list else None,
            "additional_ips": additional_ips,
            "location": loc_str if loc_str else None,
            "isp": primary_info.get("isp"),
            "asn": analysis["asn_code"],
            "provider": analysis["provider"],
            "hosting_type": analysis["type"]
        }
    else:
        return {
            "primary_ip": primary_ip,
            "ipv6": ipv6_list[0] if ipv6_list else None,
            "additional_ips": additional_ips,
            "location": None,
            "isp": None,
            "asn": None,
            "provider": None,
            "hosting_type": None
        }
