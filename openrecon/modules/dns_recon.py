import dns.resolver
from typing import Dict, Any, List
from openrecon.config import settings

MAX_RECORDS_PER_TYPE = 10

def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves standard DNS records for a given domain and analyzes email security posture.
    Passive queries only (Standard Resolver).
    """
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    results = {}
    flags = []
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_RESOLVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_TIMEOUT 
    
    def query_record(name: str, rtype: str) -> List[str]:
        try:
            answers = resolver.resolve(name, rtype)
            records = []
            for rdata in answers:
                if rtype == 'TXT':
                    try:
                        text = b''.join(rdata.strings).decode('utf-8')
                    except Exception:
                        text = rdata.to_text().strip('"')
                else:
                    text = rdata.to_text().strip('"')
                    
                records.append(text)
                if len(records) >= MAX_RECORDS_PER_TYPE:
                    break
            return records
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            return []
        except Exception:
            return []

    # 1. Standard Records
    for record_type in record_types:
        results[record_type] = query_record(domain, record_type)

    # 2. Specific Security Records (DMARC)
    dmarc_records = query_record(f"_dmarc.{domain}", "TXT")
    
    # 3. DKIM Broad Check
    domainkey_records = query_record(f"_domainkey.{domain}", "TXT")
    
    # SPF Analysis
    root_txt = results.get("TXT", [])
    spf_record = next((r for r in root_txt if "v=spf1" in r), None)
    
    spf_data = {
        "present": bool(spf_record),
        "record": spf_record,
        "status": "Missing"
    }

    if spf_record:
        if "+all" in spf_record:
            spf_data["status"] = "Over-permissive (+all)"
            flags.append("Over-permissive SPF policy (+all)")
        elif "-all" in spf_record:
            spf_data["status"] = "Strict (-all)"
        elif "~all" in spf_record:
            spf_data["status"] = "SoftFail (~all)"
        elif "?all" in spf_record:
            spf_data["status"] = "Neutral (?all)"
        else:
            spf_data["status"] = "Unknown/Loose"
    else:
        flags.append("Missing SPF record")
            
    # DMARC Analysis
    dmarc_record = next((r for r in dmarc_records if "v=DMARC1" in r), None)
    dmarc_policy = "None"
    
    if dmarc_record:
        parts = dmarc_record.split(";")
        for part in parts:
            if part.strip().startswith("p="):
                dmarc_policy = part.split("=")[1].strip()
                break
    else:
        flags.append("Missing DMARC record")

    dmarc_data = {
        "present": bool(dmarc_record),
        "record": dmarc_record,
        "policy": dmarc_policy
    }

    dkim_present = len(domainkey_records) > 0
    
    results["email_security"] = {
        "spf": spf_data,
        "dmarc": dmarc_data,
        "dkim_dns_check": {
            "_domainkey_exists": dkim_present,
            "note": "Selectors not enumerated passively"
        }
    }
    
    results["flags"] = flags
    return results
