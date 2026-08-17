<p align="center">
  <img src="assets/banner.png" alt="OpenRecon Banner" width="100%">
</p>

<p align="center">
  <strong>OSINT based Passive Reconnaissance</strong>
</p>

<p align="center">
  <a href="#-key-features">Key Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-available-modules">Available Modules</a> •
  <a href="#-running-tests">Running Tests</a>
</p>

---

## 📖 Overview

**OpenRecon** is a modern, modular, non-intrusive local OSINT (Open Source Intelligence) and reconnaissance command-line tool built for security researchers, penetration testers, and system administrators.

It performs passive, targeted reconnaissance against target domains and IP addresses without using noisy wordlists, directory brute-forcing, or disruptive scanners.

---

## 🚀 Key Features

*   **🛡️ Passive Subdomain Discovery**: Discovers valid subdomains exclusively through Certificate Transparency logs (`crt.sh`) and public DNS records.
*   **🌐 DNS Intelligence**: Queries and analyzes standard DNS record sets (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`).
*   **✉️ Dedicated Email Security Posture**: Evaluates `SPF` records and policy enforcement levels (`Strict`, `SoftFail`, `Over-permissive`), `DMARC` policies (`None`, `Quarantine`, `Reject`), and `DKIM` presence.
*   **🔒 SSL/TLS Certificate Analysis**: Inspects certificate validity, issuer, dates, SANs, cipher suites, signature algorithms, and TLS protocol versions.
*   **🧱 Wappalyzer-Style Technology Fingerprinting**:
    *   Data-driven engine powered by an authoritative database of **470+ technologies** across 17 categories.
    *   Multi-signal passive inspection across HTTP response headers, cookies, scripts, CSS assets, DOM markers, `<meta>` generator tags, inline JS properties, robots.txt, and URL patterns.
    *   Exact version extraction when directly exposed in headers/assets (never guesses or infers versions).
    *   Recursive, cycle-safe relationship resolution (`implies`, `requires`, `excludes`).
    *   Targeted active probing with wildcard SPA fallback protection and negative signature filtering.
*   **📁 Target-Derived Directory Exposure**: Discovers directory references directly from target HTML attributes (`<a href>`, `<link href>`, `<script src>`, `<img src>`), `robots.txt`, and `sitemap.xml`, verifying whether discovered directories expose open listings without brute-forcing.
*   **📂 Public Metadata Files Check**: Safe allowlisted discovery of `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`, and `ads.txt`.
*   **🔐 HTTP Security Headers Posture**: Evaluates essential headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
*   **🔌 Port Reconnaissance**: Fast, concurrent TCP banner inspection of top common service ports (`80`, `443`, `22`, `21`, `25`, `53`, `3306`, `8080`, `8443`).
*   **🌍 IP & Infrastructure Intelligence**: Geolocation, ISP classification, Autonomous System Number (ASN), Provider, and Cloud/Hosting categorization.
*   **✨ Clean Terminal UX**: TrueColor ANSI banner with transparent terminal background support and clean aligned output.
*   **💾 Text Report Export**: Direct export of structured scan results to formatted text reports (`.txt`).

---

## 💻 Installation

OpenRecon requires **Python 3.9+**.

```bash
# Navigate to the OpenRecon repository
cd "Openrecon CLI"

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install OpenRecon in editable mode
pip install -e .
```

After installation, the `openrecon` command is available directly in your terminal.

---

## ⚡ Usage

```bash
# 1. Full reconnaissance scan (runs all 12 modules concurrently)
openrecon example.com

# 2. Targeted module scan (-m / --modules)
openrecon example.com -m tech
openrecon example.com -m dns,ssl,headers
openrecon example.com -m dns,email,whois
openrecon example.com -m tech,directories,public-files

# 3. Export scan results to a text file (-o / --output)
openrecon example.com -o results.txt
openrecon example.com -m tech,dns -o report.txt

# 4. Custom module timeout in seconds (-t / --timeout, default: 60s)
openrecon example.com -t 120

# 5. List all available reconnaissance modules
openrecon list-modules

# 6. Check version and help
openrecon --version
openrecon --help
```

---

## 📋 Available Modules

| Module Identifier (`-m`) | Module Name | Primary Reconnaissance Signals |
| :--- | :--- | :--- |
| `dns` | DNS Recon | Standard records (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`) |
| `whois` | Domain Registration | Registrar, creation/expiration dates, domain age |
| `ssl` | SSL / TLS Analysis | Certificate validity, issuer, SANs, cipher, TLS protocol version |
| `email` | Email Security | SPF records, DMARC policies (`reject`/`quarantine`/`none`), DKIM check |
| `headers` | HTTP Analysis | Status codes, server header, content-type, redirects, final URL |
| `security-headers` | Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options posture |
| `subdomains` | Subdomain Discovery | Passive enumeration via Certificate Transparency logs (`crt.sh`) |
| `tech` | Technology Stack | 470+ technologies (Web servers, CDN, CMS, Frameworks, Analytics) |
| `ports` | Open Ports | Concurrent TCP inspection on common service ports |
| `ip` | Infrastructure Intelligence | IP geolocation, ISP, ASN, provider, and cloud hosting classification |
| `public-files` | Public Files | Checks `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`, `ads.txt` |
| `directories` | Directory Exposure | Verifies open listings on target-referenced asset directories |

---

## 🧪 Running Tests

OpenRecon includes a comprehensive automated test suite covering all modules, version tracking, CLI options, and technology fingerprint regression tests:

```bash
python -m unittest discover tests
```

---

## 🛑 Disclaimer

**OpenRecon is intended strictly for defensive, educational, and authorized security audits.**
Always obtain proper authorization before testing target infrastructure you do not own.
