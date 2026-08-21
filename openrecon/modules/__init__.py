"""
OpenRecon Reconnaissance Modules.
"""

MODULE_REGISTRY = {
    "dns": {
        "name": "DNS Recon",
        "description": "Standard DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA)",
        "module": "openrecon.modules.dns_recon",
        "func": "get_dns_records",
        "async": False
    },
    "whois": {
        "name": "Domain Registration",
        "description": "Domain registration details, registrar, creation/expiration dates, and age",
        "module": "openrecon.modules.whois_recon",
        "func": "get_whois_info",
        "async": False
    },
    "ssl": {
        "name": "SSL/TLS Analysis",
        "description": "SSL/TLS certificate validity, issuer, dates, SANs, and cipher suite details",
        "module": "openrecon.modules.ssl_recon",
        "func": "analyze_ssl",
        "async": False
    },
    "email": {
        "name": "Email Security",
        "description": "Email security posture (SPF records, DMARC policy, DKIM broad check)",
        "module": "openrecon.modules.email_recon",
        "func": "analyze_email_security",
        "async": False
    },
    "headers": {
        "name": "HTTP Analysis",
        "description": "HTTP status code, server, content-type, length, redirects, and final URL",
        "module": "openrecon.modules.headers_recon",
        "func": "analyze_headers",
        "async": True
    },
    "security-headers": {
        "name": "Security Headers",
        "description": "Security posture evaluation (HSTS, CSP, X-Frame-Options, X-Content-Type)",
        "module": "openrecon.modules.security_headers_recon",
        "func": "analyze_security_headers",
        "async": True
    },
    "subdomains": {
        "name": "Subdomain Enumeration",
        "description": "Passive subdomain discovery via Certificate Transparency logs and public feeds",
        "module": "openrecon.modules.subdomain_recon",
        "func": "enumerate_subdomains",
        "async": True
    },
    "tech": {
        "name": "Tech Fingerprinting",
        "description": "Passive detection of server software, frameworks, CMS, CDN, and OS hints",
        "module": "openrecon.modules.tech_fingerprint",
        "func": "get_tech_fingerprint",
        "async": True
    },
    "ports": {
        "name": "Port Recon",
        "description": "Fast concurrent check of top common ports (HTTP, HTTPS, SSH, FTP, etc.)",
        "module": "openrecon.modules.port_recon",
        "func": "scan_ports",
        "async": True
    },
    "ip": {
        "name": "Infrastructure & Hosting",
        "description": "IP geolocation, ASN, ISP, provider, and Cloud/Hosting infrastructure",
        "module": "openrecon.modules.ip_hosting_asn",
        "func": "get_domain_intelligence",
        "async": True
    },
    "public-files": {
        "name": "Public Files",
        "description": "Safe check for standard public metadata files (robots.txt, sitemap.xml, security.txt)",
        "module": "openrecon.modules.public_files",
        "func": "check_public_files",
        "async": True
    },
    "directories": {
        "name": "Directory Exposure",
        "description": "Safe exposure check for indexable directory paths (/assets/, /uploads/, etc.)",
        "module": "openrecon.modules.directory_exposure",
        "func": "check_directory_exposure",
        "async": True
    },
    "page-intel": {
        "name": "Page & Client-Side Intelligence",
        "description": "Inspect HTML metadata, forms, scripts, API routes, libraries, and source maps",
        "module": "openrecon.modules.page_intel",
        "func": "analyze_page_intel",
        "async": True
    }
}
