import dns.resolver
from typing import Dict, Any, List
from openrecon.config import settings

MAX_RECORDS_PER_TYPE = 10

def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves standard DNS records for a given domain.
    Passive queries only (Standard Resolver).
    """
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]
    results = {}
    
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

    # Standard Records
    for record_type in record_types:
        results[record_type] = query_record(domain, record_type)

    return results
