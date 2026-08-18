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

*   **🛡️ Multi-Source Passive Subdomain Discovery**: Aggregates genuine subdomains across Certificate Transparency logs and passive intelligence feeds (`crt.sh`, `certspotter`, `urlscan`, `hackertarget`, `wayback`, `rapiddns`, `anubis`) with case-insensitive deduplication, apex exclusion, zero synthetic `www.` generation, and a 50-item hard cap.
*   **🌐 Comprehensive DNS Intelligence**: Extracts `A`, `AAAA` (IPv6), `CNAME`, structured `MX` (hostname + priority), `NS`, structured `SOA` (primary nameserver, mailbox, serial, refresh, retry, expire, min TTL), record TTLs, and complete un-truncated `TXT` values.
*   **✉️ Authoritative Email Security Posture**: Evaluates single-record `SPF` with strict qualifier semantics (`-all` → `STRICT`, `~all` → `SOFTFAIL`, `?all` → `NEUTRAL`, `+all` → `OVER-PERMISSIVE`, `redirect=` → `REDIRECT`) and RFC 7208 multiple-SPF invalidation; parses `DMARC` policies (`reject`, `quarantine`, `none`), subdomain policies, rua/ruf, and percentage; reports `DKIM` presence without brute-forcing.
*   **🔒 SSL/TLS Certificate Analysis**: Inspects certificate validity, Certificate Version (e.g. `v3`), Key Type (RSA, EC, Ed25519), Key Size (bits), Certificate Chain Status (`VERIFIED`, `SELF-SIGNED`, `UNTRUSTED`), RFC 6125 SAN hostname validation, handshake cipher suites, and TLS protocol version.
*   **🧱 Evidence-Based Technology Fingerprinting**: Multi-signal passive inspection across HTTP response headers, cookies, scripts, CSS assets, DOM markers, `<meta>` generator tags, inline JS properties, and robots.txt across 9 standardized categories (`Web Server`, `Backend`, `Frontend`, `CMS`, `Framework`, `Runtime`, `Analytics`, `JavaScript Libraries`, `CDN / Proxy`). Reports versions only when directly observed.
*   **📁 Deterministic Directory Exposure**: Tests candidate paths derived from target HTML, `robots.txt`, and `sitemap.xml`; strictly distinguishes verified directory indexing signatures (`200 EXPOSED`) from ordinary HTTP 200/401/403 pages, outputting `No exposed directories found.` when no open listings exist.
*   **📂 Public Metadata Files Check**: Safe allowlisted discovery of `robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/security.txt`, `humans.txt`, and `ads.txt` (only reporting files returning HTTP 200 OK).
*   **🔐 HTTP Security Headers Posture**: Evaluates 8 standard headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`) with duplicate value normalization.
*   **🔌 Port Reconnaissance**: Fast, concurrent TCP banner inspection of top common service ports (`21`, `22`, `25`, `53`, `80`, `443`, `3306`, `3389`, `8080`, `8443`) with banner version parsing for SSH, FTP, and SMTP without guessing.
*   **🌍 Infrastructure & IP Intelligence**: Resolves Primary IPv4, IPv6, Additional IPs, Geolocation, ISP, Autonomous System Number (ASN), Provider, and Cloud/CDN Hosting categorization.
*   **📋 Domain Registration Details**: Extracts Registrar, Registry Domain ID, Registrar IANA ID, Creation/Updated/Expiration dates, domain age, and EPP status codes while filtering privacy placeholders.
*   **✨ Unified Aligned Key-Value CLI**: Clean terminal formatting with 4-space indentation, consistent key widths, and transparent background support.
*   **💾 Formatted Text Report Export**: Direct export of structured scan results to `.txt` files (`-o / --output`).
*   **🔄 Confirmed Opt-In GitHub Updater**: Check and install official GitHub releases or tags on demand (`openrecon --check-update`) with zero startup latency for normal scans.

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
openrecon example.com -m dns,ssl,tech
openrecon example.com -m dns,email,whois
openrecon example.com -m headers,security-headers,directories

# 3. Export scan results to a text file (-o / --output, .txt only)
openrecon example.com -o results.txt
openrecon example.com -m tech,dns -o report.txt

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
| `dns` | DNS Recon | Standard records (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`) with TTLs and structured fields |
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

---

## 🧪 Running Tests

OpenRecon includes a comprehensive automated test suite covering all 12 modules, version tracking, CLI options, updater diagnostics, cross-module consistency, and regression checks:

```bash
venv/bin/python -m unittest discover tests
```

---

## 🛑 Disclaimer

**OpenRecon is intended strictly for defensive, educational, and authorized security audits.**
Always obtain proper authorization before testing target infrastructure you do not own.
