import dns.resolver
import dns.reversename
from typing import Dict, Any, List
from openrecon.config import settings

MAX_RECORDS_PER_TYPE = 10
MAX_TXT_RECORDS = 50

SRV_COMMON_PREFIXES = [
    "_sip._tcp",
    "_sip._udp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_kerberos._udp",
]

def get_dns_records(domain: str) -> Dict[str, Any]:
    """
    Retrieves standard and extended DNS records for a given domain with TTLs and structured fields.
    Includes A, AAAA, CNAME, MX (priority + hostname), NS, SOA (structured), TXT (complete),
    CAA (flags, tag, value, TTL), SRV (common services), and PTR (reverse DNS for resolved IPs).
    """
    results: Dict[str, Any] = {
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "MX": [],
        "NS": [],
        "SOA": [],
        "TXT": [],
        "CAA": [],
        "SRV": [],
        "PTR": [],
    }

    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_RESOLVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_TIMEOUT

    resolved_ips: List[str] = []

    # Standard forward record types
    record_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            ttl = answers.ttl

            for rdata in answers:
                if rtype == "A":
                    ip_str = str(rdata.address)
                    results["A"].append(f"{ip_str} (TTL: {ttl})")
                    if ip_str not in resolved_ips:
                        resolved_ips.append(ip_str)
                elif rtype == "AAAA":
                    ip_str = str(rdata.address)
                    results["AAAA"].append(f"{ip_str} (TTL: {ttl})")
                    if ip_str not in resolved_ips:
                        resolved_ips.append(ip_str)
                elif rtype == "CNAME":
                    target_str = str(rdata.target)
                    results["CNAME"].append(f"{target_str} (TTL: {ttl})")
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
                elif rtype == "CAA":
                    try:
                        tag = rdata.tag.decode("utf-8", errors="replace") if isinstance(rdata.tag, bytes) else str(rdata.tag)
                        val = rdata.value.decode("utf-8", errors="replace") if isinstance(rdata.value, bytes) else str(rdata.value)
                    except Exception:
                        tag = str(rdata.tag)
                        val = str(rdata.value)
                    val_clean = val.strip('"')
                    results["CAA"].append(f'{rdata.flags} {tag} "{val_clean}" (TTL: {ttl})')

                limit = MAX_TXT_RECORDS if rtype == "TXT" else MAX_RECORDS_PER_TYPE
                if len(results[rtype]) >= limit:
                    break

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            continue
        except Exception:
            continue

    # Explicit common SRV queries
    for prefix in SRV_COMMON_PREFIXES:
        srv_query = f"{prefix}.{domain}"
        try:
            srv_answers = resolver.resolve(srv_query, "SRV")
            srv_ttl = srv_answers.ttl
            for rdata in srv_answers:
                results["SRV"].append(f"{prefix} {rdata.priority} {rdata.weight} {rdata.port} {rdata.target} (TTL: {srv_ttl})")
                if len(results["SRV"]) >= MAX_RECORDS_PER_TYPE:
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            continue
        except Exception:
            continue

    # Reverse DNS (PTR) for all resolved A and AAAA IPs
    for ip in resolved_ips:
        try:
            rev_name = dns.reversename.from_address(ip)
            ptr_answers = resolver.resolve(rev_name, "PTR")
            ptr_ttl = ptr_answers.ttl
            for rdata in ptr_answers:
                results["PTR"].append(f"{ip} -> {rdata.target} (TTL: {ptr_ttl})")
                if len(results["PTR"]) >= MAX_RECORDS_PER_TYPE:
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
            continue
        except Exception:
            continue

    return results
