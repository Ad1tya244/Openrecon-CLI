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

**OpenRecon** is a modern, modular, non-intrusive local OSINT (Open Source Intelligence) command-line reconnaissance tool built for security researchers, penetration testers, and system administrators.

It performs high-precision, evidence-based reconnaissance against target domains and IP addresses without using noisy wordlists, aggressive brute-forcing, or disruptive scanners. Every reported observation is strictly derived from direct protocol handshakes, DNS records, HTTP responses, certificate metadata, and passive intelligence sources.

---

## 🚀 Key Features

*   **🌐 Comprehensive DNS Intelligence**: Resolves 10 standard and extended DNS record types (`A`, `AAAA`, `CNAME`, `MX` with priority/null MX, `NS`, `SOA` with structured fields, complete un-truncated `TXT`, `CAA` with flags/tag/value, `SRV` for defined common services, and `PTR` reverse DNS for resolved IPs) with TTLs.
*   **📄 Page & Client-Side Intelligence (`page-intel`)**: Inspects root HTML page metadata (`<title>`, description, canonical, language, generator), analyzes forms (actions, methods, inputs, file-upload fields), extracts deterministic API endpoints (`/api/...`, `/graphql`, `/rest/...`, `/auth/...`, `/oauth/...`), application routes (`/login`, `/dashboard`, `/upload`), verifies public source-map accessibility & metadata, identifies JavaScript libraries/versions, discovers resource references (`manifest.json`, config files), and extracts meaningful source comments without executing code or crawling.
*   **🛡️ Multi-Source Passive Subdomain Discovery**: Aggregates genuine subdomains across Certificate Transparency logs and passive intelligence feeds (`crt.sh`, `certspotter`, `urlscan`, `hackertarget`, `wayback`, `rapiddns`, `anubis`) with case-insensitive deduplication, apex exclusion, zero synthetic `www.` generation, and a 50-item hard cap.
*   **✉️ Authoritative Email Security Posture**: Evaluates single-record `SPF` with strict qualifier semantics (`-all` → `STRICT`, `~all` → `SOFTFAIL`, `?all` → `NEUTRAL`, `+all` → `OVER-PERMISSIVE`, `redirect=` → `REDIRECT`) and RFC 7208 multiple-SPF invalidation; parses `DMARC` policies (`reject`, `quarantine`, `none`), subdomain policies, rua/ruf, and percentage; reports `DKIM` presence without brute-forcing.
*   **🔒 SSL/TLS Certificate Analysis**: Inspects certificate validity, Certificate Version (e.g. `v3`), Key Type (RSA, EC, Ed25519), Key Size (bits), Certificate Chain Status (`VERIFIED`, `SELF-SIGNED`, `UNTRUSTED`), RFC 6125 SAN hostname validation, handshake cipher suites, and TLS protocol version.
*   **🧱 Evidence-Based Technology Fingerprinting**: Multi-signal passive inspection across HTTP response headers, cookies, scripts, CSS assets, DOM markers, `<meta>` generator tags, inline JS properties, and robots.txt across 10 standardized categories (`Web Server`, `Backend`, `Frontend`, `CMS`, `Framework`, `Runtime`, `Analytics`, `JavaScript Libraries`, `CDN / Proxy`, `Fonts`). Reports versions only when directly observed.
*   **📁 Deterministic Directory Exposure**: Tests candidate paths derived from target HTML, `robots.txt`, and `sitemap.xml`; strictly distinguishes verified directory indexing signatures (`200 EXPOSED`) from ordinary HTTP 200/401/403 pages, outputting `No exposed directories found.` when no open listings exist.
*   **📂 Public Metadata Files Check**: Safe allowlisted discovery of `robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/security.txt`, `humans.txt`, and `ads.txt` (only reporting files returning HTTP 200 OK).
*   **🔐 HTTP Security Headers Posture**: Evaluates 8 standard headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`) with duplicate value normalization.
*   **🔌 Port Reconnaissance**: Fast, concurrent TCP banner inspection of top common service ports (`21`, `22`, `25`, `53`, `80`, `443`, `3306`, `3389`, `8080`, `8443`) with banner version parsing for SSH, FTP, and SMTP without guessing.
*   **🌍 Infrastructure & IP Intelligence**: Resolves Primary IPv4, IPv6, Additional IPs, Geolocation, ISP, Autonomous System Number (ASN), Provider, and Cloud/CDN Hosting categorization.
*   **📋 Domain Registration Details**: Extracts Registrar, Registry Domain ID, Registrar IANA ID, Creation/Updated/Expiration dates, domain age, and EPP status codes while filtering privacy placeholders.
*   **✨ Unified Aligned Key-Value CLI**: Clean terminal formatting with TrueColor ANSI gradient banner, 4-space indentation, consistent key widths, and transparent background support.
*   **💾 Formatted Text & JSON Report Export**: Direct export of structured scan results to `.txt` or `.json` files (`-o / --output`).
*   **✉️ Email Enumeration (`email-enum`)**: Discovers and normalizes publicly available email addresses associated with the target domain.
*   **👥 Social Media OSINT & Verification (`social`)**: Passive discovery of social media profiles, classified using an evaluation layer into official and personal accounts.
*   **🔄 Confirmed Opt-In GitHub Updater**: Check and install official GitHub releases or tags on demand (`openrecon --check-update`) with zero startup latency for normal scans.

---

## 💻 Installation

OpenRecon supports interactive first-time installation.

```bash
# Clone the repository and navigate into it
git clone <repository_url>
cd Openrecon-CLI

# Run the interactive setup script
./setup.sh

# Activate venv
source venv/bin/activate
```

After installation, the `openrecon` command is available directly in your terminal.

---

## ⚡ Usage

> [!NOTE]
> OpenRecon accepts target domains or the `list-modules` command only (public/private IPv4 target addresses are not accepted).

```bash
# 1. Full reconnaissance scan (runs all 13 modules concurrently)
openrecon example.com

# 2. Targeted module scan (-m / --modules)
openrecon example.com -m dns,ssl,tech,page-intel
openrecon example.com -m page-intel,headers,security-headers
openrecon example.com -m dns,email,whois

# 3. Export scan results to a text or JSON file (-o / --output, .txt or .json)
openrecon example.com -o results.json
openrecon example.com -o results.txt
openrecon example.com -m page-intel,tech,dns -o report.txt

# 4. Custom module timeout in seconds (-t / --timeout, default: 60s)
openrecon example.com -t 120

# 5. List all available reconnaissance modules
openrecon list-modules

# 6. Opt-In manual update check (checks official GitHub releases/tags)
openrecon --check-update

# 7. Check version and help (100% network-free)
openrecon --version
openrecon --help
```

---

## 📋 Available Modules

| Module Identifier (`-m`) | Module Name | Primary Reconnaissance Signals |
| :--- | :--- | :--- |
| `email-enum` | Email Enumeration | Discovers publicly available email addresses associated with the target domain |
| `social` | Social Media OSINT | Discovers publicly available social-media profiles with verification classification |
| `dns` | DNS Recon | Standard & extended records (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`, `CAA`, `SRV`, `PTR`) with TTLs |
| `whois` | Domain Registration | Registrar, Registry ID, Registrar ID, Creation/Updated/Expiration dates, Age, Status |
| `ssl` | SSL / TLS Analysis | Certificate validity, Version, Key Type/Size, Chain Status, SANs, Cipher, TLS protocol |
| `email` | Email Security | Authoritative SPF records, qualifiers, includes, DMARC policies, DKIM check |
| `headers` | HTTP Analysis | Status codes, Server, Content-Type, Content-Length, HTTP Version, Redirects, Final URL |
| `security-headers` | Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `subdomains` | Subdomain Discovery | Passive enumeration across CT logs & public feeds (`crt.sh`, `certspotter`, `urlscan`, etc.) |
| `tech` | Technology Stack | Evidence-based detection across 9 categories (Web Server, Backend, CMS, CDN, etc.) |
| `ports` | Open Ports | Concurrent TCP check and safe banner interrogation (SSH, FTP, SMTP) on top ports |
| `ip` | Infrastructure Intelligence | IPv4, IPv6, Additional IPs, Geolocation, ISP, ASN, Provider, Hosting Type |
| `public-files` | Public Files | Checks HTTP 200 status for `robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`, etc. |
| `directories` | Directory Exposure | Verifies confirmed open directory listing indexing signatures (`200 EXPOSED`) |
| `page-intel` | Page & Client-Side Intelligence | Inspects HTML metadata, forms, scripts, API routes, libraries, and source maps |

---

## 🧪 Running Tests

OpenRecon includes a comprehensive automated test suite covering all 13 modules, version tracking, CLI options, updater diagnostics, cross-module consistency, and regression checks:

```bash
venv/bin/python -m unittest discover tests
```

---

## 🛑 Disclaimer

**OpenRecon is intended strictly for defensive, educational, and authorized security audits.**
Always obtain proper authorization before testing target infrastructure you do not own.
