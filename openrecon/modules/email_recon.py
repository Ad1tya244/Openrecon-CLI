"""
OpenRecon Email Security Module (SPF, DMARC, DKIM DNS checks).
"""
import dns.resolver
from typing import Dict, Any, List
from openrecon.config import settings

def analyze_email_security(domain: str) -> Dict[str, Any]:
    """
    Performs passive email security posture checks:
    - SPF TXT record extraction and policy evaluation
    - DMARC TXT record extraction and policy enforcement level
    - DKIM _domainkey existence check
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_RESOLVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_TIMEOUT

    def query_txt(name: str) -> List[str]:
        try:
            answers = resolver.resolve(name, "TXT")
            records = []
            for rdata in answers:
                try:
                    text = b''.join(rdata.strings).decode('utf-8')
                except Exception:
                    text = rdata.to_text().strip('"')
                records.append(text)
            return records
        except Exception:
            return []

    # 1. SPF TXT Query
    domain_txt = query_txt(domain)
    spf_record = next((r for r in domain_txt if "v=spf1" in r), None)
    
    spf_data = {
        "present": bool(spf_record),
        "record": spf_record,
        "status": "Missing"
    }

    if spf_record:
        if "+all" in spf_record:
            spf_data["status"] = "Over-permissive (+all)"
        elif "-all" in spf_record:
            spf_data["status"] = "Strict (-all)"
        elif "~all" in spf_record:
            spf_data["status"] = "SoftFail (~all)"
        elif "?all" in spf_record:
            spf_data["status"] = "Neutral (?all)"
        else:
            spf_data["status"] = "Unknown/Loose"
    else:
        spf_data["status"] = "None"

    # 2. DMARC TXT Query
    dmarc_records = query_txt(f"_dmarc.{domain}")
    dmarc_record = next((r for r in dmarc_records if "v=DMARC1" in r), None)
    dmarc_policy = "None"

    if dmarc_record:
        parts = dmarc_record.split(";")
        for part in parts:
            if part.strip().startswith("p="):
                dmarc_policy = part.split("=")[1].strip()
                break

    dmarc_data = {
        "present": bool(dmarc_record),
        "record": dmarc_record,
        "policy": dmarc_policy
    }

    # 3. DKIM Broad Check
    domainkey_records = query_txt(f"_domainkey.{domain}")
    dkim_present = len(domainkey_records) > 0

    return {
        "spf": spf_data,
        "dmarc": dmarc_data,
        "dkim_dns_check": {
            "_domainkey_exists": dkim_present,
            "note": "Selectors not enumerated passively"
        }
    }
