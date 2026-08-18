import dns.resolver
from typing import Dict, Any, List
from openrecon.config import settings

MAX_RECORDS_PER_TYPE = 10
MAX_TXT_RECORDS = 50

def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves standard DNS records for a given domain with TTLs and structured fields.
    Includes A, AAAA, CNAME, MX (priority + hostname), NS, SOA (structured), and complete TXT.
    """
    results: Dict[str, Any] = {
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "MX": [],
        "NS": [],
        "SOA": [],
        "TXT": []
    }
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_RESOLVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_TIMEOUT 

    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            ttl = answers.ttl
            
            for rdata in answers:
                if rtype == "A":
                    results["A"].append(f"{rdata.address} (TTL: {ttl})")
                elif rtype == "AAAA":
                    results["AAAA"].append(f"{rdata.address} (TTL: {ttl})")
                elif rtype == "CNAME":
                    target_str = str(rdata.target)
                    results["CNAME"].append(f"{domain} → {target_str} (TTL: {ttl})")
                elif rtype == "MX":
                    results["MX"].append(f"{rdata.preference} {rdata.exchange} (TTL: {ttl})")
                elif rtype == "NS":
                    results["NS"].append(f"{rdata.target} (TTL: {ttl})")
                elif rtype == "SOA":
                    soa_formatted = f"{rdata.mname} (Serial: {rdata.serial}, Refresh: {rdata.refresh}, Retry: {rdata.retry}, Expire: {rdata.expire}, Min TTL: {rdata.minimum})"
                    results["SOA"].append(soa_formatted)
                elif rtype == "TXT":
                    try:
                        full_txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    except Exception:
                        full_txt = rdata.to_text().strip('"')
                    results["TXT"].append(full_txt)

                limit = MAX_TXT_RECORDS if rtype == "TXT" else MAX_RECORDS_PER_TYPE
                if len(results[rtype]) >= limit:
                    break

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
            continue
        except Exception:
            continue

    return results
