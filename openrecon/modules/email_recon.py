import re
import dns.resolver
from typing import Dict, Any, List, Optional
from openrecon.config import settings

def analyze_email_security(
    domain: str,
    txt_records: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Performs passive email security posture checks:
    - SPF: Parses the single authoritative SPF TXT record returned for the target domain.
           Derives SPF Value, Final Qualifier, Includes, and Status strictly from this record.
           Flags multiple SPF records as INVALID per RFC 7208.
    - DMARC: Extracts policy, subdomain policy, rua, ruf, percentage.
    - DKIM: Reports NOT ENUMERATED unless selectors are observed passively.
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
                    text = b''.join(rdata.strings).decode('utf-8', errors='replace')
                except Exception:
                    text = rdata.to_text().strip('"')
                records.append(text)
            return records
        except Exception:
            return []

    # 1. SPF Analysis
    domain_txt = txt_records if txt_records is not None else query_txt(domain)
    
    spf_candidates = []
    for r in domain_txt:
        s = r.strip()
        if re.match(r"^v=spf1(?:\s|$)", s, re.IGNORECASE):
            spf_candidates.append(s)

    spf_data: Dict[str, Any] = {
        "record": "MISSING",
        "status": "MISSING",
        "value": None,
        "final_qualifier": None,
        "includes": []
    }

    if len(spf_candidates) > 1:
        # RFC 7208 Section 3.2: Multiple SPF records -> PermError / INVALID
        spf_data["record"] = "INVALID"
        spf_data["status"] = "INVALID (Multiple SPF records published)"
        spf_data["value"] = None
        spf_data["final_qualifier"] = None
        spf_data["includes"] = []
    elif len(spf_candidates) == 1:
        raw_spf = spf_candidates[0]
        
        # Check basic syntax
        if not raw_spf.lower().startswith("v=spf1"):
            spf_data["record"] = "INVALID"
            spf_data["status"] = "INVALID"
        else:
            spf_data["record"] = "PRESENT"
            spf_data["value"] = raw_spf

            # Qualifier extraction strictly from this record
            m = re.search(r"(?:^|\s)([-+~?]all)(?:\s|$)", raw_spf, re.IGNORECASE)
            if m:
                final_q = m.group(1).lower()
                spf_data["final_qualifier"] = final_q

                if final_q == "-all":
                    spf_data["status"] = "STRICT"
                elif final_q == "~all":
                    spf_data["status"] = "SOFTFAIL"
                elif final_q == "+all":
                    spf_data["status"] = "OVER-PERMISSIVE"
                elif final_q == "?all":
                    spf_data["status"] = "NEUTRAL"
            elif re.search(r"(?:^|\s)redirect=([^\s]+)", raw_spf, re.IGNORECASE):
                spf_data["final_qualifier"] = None
                spf_data["status"] = "REDIRECT"
            else:
                spf_data["final_qualifier"] = None
                spf_data["status"] = "UNKNOWN"

            # Includes: strictly from this single authoritative record
            includes = re.findall(r"(?:^|\s)include:([^\s]+)", raw_spf, re.IGNORECASE)
            spf_data["includes"] = sorted(list(set(includes)))

    # 2. DMARC Analysis
    dmarc_records = query_txt(f"_dmarc.{domain}")
    dmarc_candidates = [r.strip() for r in dmarc_records if re.match(r"^v=DMARC1(?:\s|;|$)", r.strip(), re.IGNORECASE)]

    dmarc_data: Dict[str, Any] = {
        "record": "MISSING",
        "policy": None,
        "subdomain_policy": None,
        "rua": None,
        "ruf": None,
        "percentage": None
    }

    if len(dmarc_candidates) > 1:
        dmarc_data["record"] = "INVALID"
        dmarc_data["policy"] = "INVALID (Multiple DMARC records published)"
    elif len(dmarc_candidates) == 1:
        dmarc_raw = dmarc_candidates[0]
        dmarc_data["record"] = "PRESENT"
        tags = {}
        for part in dmarc_raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        p = tags.get("p", "none").lower()
        dmarc_data["policy"] = p
        
        sp = tags.get("sp")
        dmarc_data["subdomain_policy"] = sp.lower() if sp else f"Inherit ({p})"
        
        dmarc_data["rua"] = tags.get("rua")
        dmarc_data["ruf"] = tags.get("ruf")
        
        pct = tags.get("pct")
        dmarc_data["percentage"] = f"{pct}%" if pct else "100%"

    # 3. DKIM Broad Check (Never brute-forced)
    dkim_data: Dict[str, Any] = {
        "status": "NOT ENUMERATED",
        "selector": None
    }

    return {
        "spf": spf_data,
        "dmarc": dmarc_data,
        "dkim": dkim_data
    }
