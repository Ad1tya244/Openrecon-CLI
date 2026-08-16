# OpenRecon CLI

**OpenRecon** is a fast, modular, lightweight local OSINT (Open Source Intelligence) and reconnaissance CLI tool designed for security researchers, penetration testers, and system administrators.

It performs passive, non-intrusive reconnaissance against target domains and IP addresses without using wordlists, directory brute-forcing, or aggressive scanners.

---

## 🚀 Key Features

*   **🛡️ Passive Subdomain Enumeration**: Discovers subdomains exclusively through Certificate Transparency logs (`crt.sh`) and public DNS evidence.
*   **🌐 DNS Intelligence & Email Security**: Analyzes standard DNS records (`A`, `MX`, `NS`, `SOA`, `TXT`) and assesses email security posture (`SPF`, `DMARC`, `DKIM`).
*   **🔒 SSL/TLS Certificate Analysis**: Inspects certificate validity, issuer, dates, SANs, cipher suites, signature algorithms, and TLS protocol versions.
*   **🧱 Wappalyzer-Style Technology Fingerprinting**:
    *   Data-driven engine powered by an authoritative database of **470+ technologies** across 17 categories.
    *   Multi-signal passive inspection across HTTP response headers, cookies, scripts, CSS assets, DOM markers, `<meta>` generator tags, inline JS properties, robots.txt, and URL patterns.
    *   Exact version extraction when directly exposed in headers/assets (never guesses or infers versions).
    *   Recursive, cycle-safe relationship resolution (`implies`, `requires`, `excludes`).
    *   Targeted active probing with wildcard SPA fallback protection and negative signature filtering.
*   **📁 Target-Derived Directory Exposure**: Discovers directory references directly from target HTML attributes (`<a href>`, `<link href>`, `<script src>`, `<img src>`), `robots.txt`, and `sitemap.xml`, verifying whether discovered directories expose open listings without brute-forcing.
*   **📂 Public Metadata Files Check**: Safe allowlisted discovery of `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`, and `ads.txt`.
*   **🔐 Security Headers Posture**: Evaluates essential headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
*   **🔌 Port Reconnaissance**: Fast, concurrent TCP banner inspection of top common service ports (80, 443, 22, 21, 25, 53, 3306, 8080, 8443).
*   **🌍 IP & Infrastructure Intelligence**: Geolocation, ISP classification, Autonomous System Number (ASN), Provider, and Cloud/Hosting categorization.
*   **✨ Linux-Native Terminal UX**: Rich formatted tables with aligned `Key → Combined Value` multi-item categories and automatic continuation line wrapping.
*   **💾 Flexible Export**: Direct export of structured scan results to JSON (`.json`) or formatted text reports (`.txt`).

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
# 1. Full reconnaissance scan (runs all 11 modules concurrently)
openrecon example.com

# 2. Targeted module scan (-m / --module)
openrecon example.com -m tech
openrecon example.com -m dns,ssl,headers
openrecon example.com -m tech,directories,public-files

# 3. Export results to file (-o / --output)
openrecon example.com -o results.json
openrecon example.com -o report.txt

# 4. List all available reconnaissance modules
openrecon list-modules

# 5. Check version
openrecon --version
```

---

## 📋 Available Modules

| Module Key (`-m`) | Module Name | Primary Reconnaissance Signals |
| :--- | :--- | :--- |
| `dns` | DNS Recon | Standard records (`A`, `MX`, `NS`, `SOA`, `TXT`) & SPF / DMARC evaluation |
| `whois` | Domain Registration | Registrar, creation/expiration dates, and domain age |
| `ssl` | SSL / TLS Analysis | Certificate validity, issuer, SANs, cipher, protocol version |
| `headers` | HTTP Headers | Server headers, content type, content length, redirect chains |
| `security-headers` | Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options posture |
| `subdomains` | Subdomain Discovery | Passive enumeration via Certificate Transparency logs |
| `tech` | Technology Stack | 470+ technologies (Web servers, CDN, CMS, Frameworks, Analytics) |
| `ports` | Open Ports | Concurrent check on common TCP service ports |
| `ip` | Infrastructure Intelligence | IP geolocation, ISP, ASN, provider, and cloud hosting classification |
| `public-files` | Public Files | Checks `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`, `ads.txt` |
| `directories` | Directory Exposure | Verifies open listings on target-referenced asset directories |

---

## 🧪 Running Tests

OpenRecon includes a comprehensive automated test suite covering all modules, version tracking, and technology fingerprint regression tests:

```bash
python -m unittest discover tests
```

---

## 🛑 Disclaimer

**OpenRecon is intended strictly for defensive, educational, and authorized security audits.**
Always obtain proper authorization before testing target infrastructure you do not own.
