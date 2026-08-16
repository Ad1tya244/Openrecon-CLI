import json
import io
import textwrap
from typing import Dict, Any, List, Optional
from rich.console import Console
from openrecon import __version__

console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)

BANNER_ART = """[0;38;2;140;255;255;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒░   [0;38;2;75;75;75;49m▄[0;38;2;0;180;185;49m [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒░   [0;38;2;75;75;75;49m▄[0;38;2;0;180;185;49m [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒░    [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒░[0;38;2;75;75;75;49m▄[0;38;2;140;255;255;49m   [0;38;2;140;255;255;48;2;0;180;185m▓▒[0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒░   [0;38;2;75;75;75;49m▄[0;38;2;0;180;185;49m [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒░    [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒░   [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒░   [0;38;2;75;75;75;49m▄[0;38;2;0;180;185;49m [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒░[0;38;2;75;75;75;49m▄[0;38;2;140;255;255;49m   [0;38;2;140;255;255;48;2;0;180;185m▓▒[0;38;2;75;75;75;49m▄[0m
[0;38;2;140;255;255;48;2;0;180;185m▓▒[0;38;2;75;75;75;49m█▀▀▀[0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▒░[0;38;2;75;75;75;49m█▀▀[0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▒░[0;38;2;75;75;75;49m█▀▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▒░  [0;38;2;75;75;75;49m▄[0;38;2;140;255;255;49m  [0;38;2;140;255;255;48;2;0;180;185m▒░[0;38;2;75;75;75;49m█[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▒░[0;38;2;75;75;75;49m█▀▀[0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▒░[0;38;2;75;75;75;49m█▀▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒[0;38;2;75;75;75;49m█▀▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▓▒[0;38;2;75;75;75;49m█▀▀▀[0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▒░  [0;38;2;75;75;75;49m▄[0;38;2;140;255;255;49m  [0;38;2;140;255;255;48;2;0;180;185m▒░[0;38;2;75;75;75;49m█[0m
[0;38;2;140;255;255;48;2;0;180;185m▒░[0;38;2;75;75;75;49m█[0;38;2;140;255;255;49m   [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m░     [0;38;2;75;75;75;49m█▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m░    [0;38;2;75;75;75;49m▄[0;38;2;0;180;185;49m  [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m░ [0;38;2;75;75;75;49m█[0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m▄[0;38;2;140;255;255;49m [0;38;2;140;255;255;48;2;0;180;185m░ [0;38;2;75;75;75;49m█[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m░     [0;38;2;75;75;75;49m█▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m░    [0;38;2;75;75;75;49m▄[0;38;2;0;180;185;49m  [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▒░[0;38;2;75;75;75;49m█[0;38;2;0;180;185;49m     [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m▒░[0;38;2;75;75;75;49m█[0;38;2;140;255;255;49m   [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m░ [0;38;2;75;75;75;49m█[0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m▄[0;38;2;140;255;255;49m [0;38;2;140;255;255;48;2;0;180;185m░ [0;38;2;75;75;75;49m█[0m
[0;38;2;140;255;255;48;2;0;180;185m░ [0;38;2;75;75;75;49m█[0;38;2;140;255;255;49m   [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█▀▀▀▀[0;38;2;0;180;185;49m [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█▀▀▀[0;38;2;0;180;185;49m  [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█ [0;38;2;0;180;185;49m██[0;38;2;75;75;75;49m▄[0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█▀▀[0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█▀▀▀[0;38;2;0;180;185;49m  [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m░ [0;38;2;75;75;75;49m█[0;38;2;0;180;185;49m     [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m░ [0;38;2;75;75;75;49m█[0;38;2;140;255;255;49m   [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█ [0;38;2;0;180;185;49m██[0;38;2;75;75;75;49m▄[0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0m
[0;38;2;140;255;255;49m [0;38;2;140;255;255;48;2;0;180;185m      [0;38;2;75;75;75;49m█▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;0;180;185;49m     [0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m       [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;140;255;255;49m [0;38;2;75;75;75;49m [0;38;2;140;255;255;48;2;0;180;185m    [0;38;2;75;75;75;49m█[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;140;255;255;49m  [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m       [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;140;255;255;48;2;0;180;185m      [0;38;2;75;75;75;49m▄[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;140;255;255;48;2;0;180;185m      [0;38;2;75;75;75;49m█▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;48;2;0;180;185m  [0;38;2;75;75;75;49m█[0;38;2;140;255;255;49m [0;38;2;75;75;75;49m [0;38;2;140;255;255;48;2;0;180;185m    [0;38;2;75;75;75;49m█[0m
[0;38;2;140;255;255;49m  [0;38;2;75;75;75;49m▀▀▀▀▀▀[0;38;2;0;180;185;49m [0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀[0;38;2;0;180;185;49m     [0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀▀▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀[0;38;2;140;255;255;49m   [0;38;2;75;75;75;49m▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀[0;38;2;140;255;255;49m  [0;38;2;75;75;75;49m ▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀▀▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m  [0;38;2;75;75;75;49m▀▀▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m  [0;38;2;75;75;75;49m▀▀▀▀▀▀[0;38;2;0;180;185;49m [0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀[0;38;2;140;255;255;49m   [0;38;2;75;75;75;49m▀▀▀▀[0m"""

def print_startup_banner():
    print(BANNER_ART)
    console.print(f"[bold white]OpenRecon v{__version__}[/bold white]")
    console.print("[dim]Local OSINT & Reconnaissance CLI[/dim]\n")

def print_scan_header(target: str):
    console.print(f"\n[bold white]OpenRecon v{__version__}[/bold white] [dim]—[/dim] [bold cyan]{target}[/bold cyan]\n")

def _colorize_status(status_word: str) -> str:
    w = status_word.upper()
    if w in ("VALID", "PRESENT", "OPEN", "PROTECTED", "FOUND", "STRICT"):
        return f"[green]{status_word}[/green]"
    elif w in ("INVALID", "MISSING", "CLOSED", "EXPOSED", "EXPIRED"):
        return f"[red]{status_word}[/red]"
    elif w in ("WARNING", "SOFTFAIL", "OVER-PERMISSIVE"):
        return f"[yellow]{status_word}[/yellow]"
    elif w in ("NOT DETECTED", "NOT ENUMERATED", "UNKNOWN", "NONE", "N/A"):
        return f"[dim]{status_word}[/dim]"
    return status_word

def _print_kv(key: str, value: str, indent: int = 4, key_width: int = 16, max_width: int = 84):
    if value is None or value == "":
        return
    value_str = str(value)
    prefix = " " * indent + f"{key:<{key_width}} "
    sub_indent = " " * (indent + key_width + 1)
    avail_width = max(35, max_width - len(sub_indent))

    # Single line optimization
    if len(prefix) + len(value_str) <= max_width and "\n" not in value_str:
        console.print(f"{prefix}{value_str}")
        return

    # List wrapping by comma (e.g. MX, NS, Locations, Providers)
    if ", " in value_str and "\n" not in value_str:
        parts = [p.strip() for p in value_str.split(", ") if p.strip()]
        lines = []
        current_line = []
        current_len = 0
        for part in parts:
            item_len = len(part) + (2 if current_line else 0)
            if current_line and (current_len + item_len > avail_width):
                lines.append(", ".join(current_line) + ",")
                current_line = [part]
                current_len = len(part)
            else:
                current_line.append(part)
                current_len += item_len
        if current_line:
            lines.append(", ".join(current_line))

        for i, line in enumerate(lines):
            if i == 0:
                console.print(f"{prefix}{line}")
            else:
                console.print(f"{sub_indent}{line}")
        return

    # Text wrapping for general text
    wrapped = textwrap.wrap(value_str, width=avail_width)
    if not wrapped:
        console.print(f"{prefix}{value_str}")
        return
    for i, line in enumerate(wrapped):
        if i == 0:
            console.print(f"{prefix}{line}")
        else:
            console.print(f"{sub_indent}{line}")

def render_dns(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]DNS[/bold]\n    [red]Error: {data.get('error', 'No data')}[/red]\n")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]DNS[/bold]")
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]:
        records = data.get(rtype, [])
        if records:
            _print_kv(rtype, ", ".join(records))

    for rtype, records in data.items():
        if rtype not in ("A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "email_security", "flags", "domain") and isinstance(records, list) and records:
            _print_kv(rtype, ", ".join(str(r) for r in records))

    console.print("")

    # Dedicated Email Security Section
    email_sec = data.get("email_security", {})
    if email_sec:
        console.print("[bold cyan][+][/bold cyan] [bold]Email Security[/bold]")
        spf = email_sec.get("spf", {})
        spf_present = spf.get("present", False)
        _print_kv("SPF Record", _colorize_status("PRESENT" if spf_present else "MISSING"))
        
        spf_status = spf.get("status", "N/A").upper()
        if "STRICT" in spf_status:
            _print_kv("SPF Status", _colorize_status("STRICT"))
        elif "SOFT" in spf_status:
            _print_kv("SPF Status", _colorize_status("SOFTFAIL"))
        elif "OVER-PERMISSIVE" in spf_status:
            _print_kv("SPF Status", _colorize_status("OVER-PERMISSIVE"))
        elif spf_present:
            _print_kv("SPF Status", _colorize_status(spf_status))
        else:
            _print_kv("SPF Status", _colorize_status("NONE"))
            
        if spf.get("record"):
            _print_kv("SPF Value", spf["record"])

        dmarc = email_sec.get("dmarc", {})
        dmarc_present = dmarc.get("present", False)
        _print_kv("DMARC Record", _colorize_status("PRESENT" if dmarc_present else "MISSING"))
        
        dmarc_policy = (dmarc.get("policy") or "NONE").upper()
        _print_kv("DMARC Policy", _colorize_status(dmarc_policy) if dmarc_present else _colorize_status("NONE"))

        dkim = email_sec.get("dkim_dns_check", {})
        dkim_found = dkim.get("_domainkey_exists", False)
        _print_kv("DKIM", _colorize_status("PRESENT" if dkim_found else "NOT ENUMERATED"))

def render_whois(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Domain Registration[/bold]\n    [red]Error: {data.get('error', 'Lookup failed')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Domain Registration[/bold]")
    if data.get("registrar"):
        _print_kv("Registrar", str(data["registrar"]))

    created = data.get("creation_date", "")
    age = data.get("age_days")
    if created:
        date_clean = str(created)[:10]
        _print_kv("Created", date_clean)
        if age is not None:
            years = round(age / 365.25, 1)
            _print_kv("Age", f"{years} years")

    expires = data.get("expiration_date", "")
    if expires:
        date_clean = str(expires)[:10]
        _print_kv("Expires", date_clean)

    status = data.get("status")
    if status and status != "Unknown":
        if isinstance(status, list):
            _print_kv("Status", ", ".join(status[:2]))
        else:
            _print_kv("Status", str(status))

    flags = data.get("flags", [])
    for f in flags:
        _print_kv("Warning", _colorize_status("WARNING") + f" {f}")

def render_ssl(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]SSL / TLS[/bold]\n    [red]Error: {data.get('error', 'Handshake failed')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]SSL / TLS[/bold]")
    valid = data.get("valid", False)
    _print_kv("Status", _colorize_status("VALID" if valid else "INVALID"))

    issuer = data.get("issuer", {})
    if isinstance(issuer, dict):
        cn = issuer.get("commonName")
        org = issuer.get("organizationName")
        issuer_str = f"{cn} ({org})" if cn and org else (cn or org or str(issuer))
    else:
        issuer_str = str(issuer)
    if issuer_str:
        _print_kv("Issuer", issuer_str)

    subject = data.get("subject", {})
    if isinstance(subject, dict):
        subj_str = subject.get("commonName") or str(subject)
    else:
        subj_str = str(subject)
    if subj_str:
        _print_kv("Subject", subj_str)

    if data.get("valid_from"):
        _print_kv("Valid From", str(data["valid_from"])[:10])
    if data.get("valid_until"):
        _print_kv("Valid Until", str(data["valid_until"])[:10])

    days = data.get("days_remaining")
    if days is not None:
        _print_kv("Days Remaining", str(days))

    if data.get("serial_number"):
        _print_kv("Serial Number", str(data["serial_number"]))

    if data.get("signature_algorithm"):
        _print_kv("Signature", str(data["signature_algorithm"]))

    sans = data.get("subject_alt_names", [])
    if sans:
        _print_kv("SANs", ", ".join(sans))

    cipher = data.get("cipher_suite")
    if cipher:
        c_name = cipher[0] if isinstance(cipher, (list, tuple)) and len(cipher) > 0 else str(cipher)
        c_proto = cipher[1] if isinstance(cipher, (list, tuple)) and len(cipher) > 1 else ""
        _print_kv("Cipher", str(c_name))
        if c_proto:
            _print_kv("Protocol", str(c_proto))

def render_headers(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]HTTP[/bold]\n    [red]Error: {data.get('error', 'Unreachable')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]HTTP[/bold]")
    if data.get("status_code"):
        _print_kv("Status Code", str(data["status_code"]))
    if data.get("server") and data["server"] != "Unknown":
        _print_kv("Server", str(data["server"]))
    if data.get("content_type"):
        _print_kv("Content-Type", str(data["content_type"]))
    if data.get("content_length") is not None:
        _print_kv("Content-Length", str(data["content_length"]))
    if "redirects" in data and data["redirects"] is not None:
        _print_kv("Redirects", str(data["redirects"]))
    if data.get("final_url"):
        _print_kv("Final URL", str(data["final_url"]))

def render_security_headers(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Security Headers[/bold]\n    [red]Error: {data.get('error', 'Unreachable')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Security Headers[/bold]")

    standard_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]
    present = data.get("present_headers", {})
    
    for h_name in standard_headers:
        if h_name in present:
            _print_kv(h_name, _colorize_status("PRESENT"), key_width=28)
        else:
            _print_kv(h_name, _colorize_status("MISSING"), key_width=28)

def render_subdomains(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Subdomains[/bold]\n    [red]Error: {data.get('error', 'Enumeration failed')}[/red]")
        return

    subs = data.get("subdomains", [])
    limit_reached = data.get("limit_reached", False)
    
    console.print("[bold cyan][+][/bold cyan] [bold]Subdomains[/bold]")
    if limit_reached:
        _print_kv("Total", f"{len(subs)}+ (limit reached)")
    else:
        _print_kv("Total", str(len(subs)))

    if not subs:
        console.print("    [dim]No subdomains discovered[/dim]")
        return

    # Sort subdomains alphabetically and display all entries
    sorted_subs = sorted(subs, key=lambda s: s.get("hostname", ""))
    for s in sorted_subs:
        host = s.get("hostname", "")
        if host:
            console.print(f"    {host}")

def render_tech(data: Dict[str, Any]):
    if not data:
        console.print("[bold cyan][+][/bold cyan] [bold]Technology Stack[/bold]\n    No technologies identified.")
        return
    if "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Technology Stack[/bold]\n    [red]Error: {data.get('error', 'Unreachable')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Technology Stack[/bold]")
    categories = data.get("categories", {})
    technologies = data.get("technologies", [])
    
    if not categories and technologies:
        categories = {}
        for t in technologies:
            cat = t.get("category", "Other")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(t)
            
    if not categories or not any(categories.values()):
        console.print("    No technologies identified.")
        return

    preferred_order = ["Web Server", "Frontend", "Backend", "CMS", "CDN"]
    sorted_cat_keys = sorted(
        categories.keys(),
        key=lambda c: (preferred_order.index(c) if c in preferred_order else 999, c)
    )

    has_output = False
    for cat in sorted_cat_keys:
        items = categories.get(cat, [])
        if not items:
            continue
        formatted_items = []
        for item in items:
            name = item.get("name", "")
            ver = item.get("version")
            display_name = f"{name} {ver}" if ver else name
            if display_name:
                formatted_items.append(display_name)
        if formatted_items:
            combined_val = ", ".join(formatted_items)
            _print_kv(cat, combined_val, indent=4, key_width=16)
            has_output = True

    if not has_output:
        console.print("    No technologies identified.")

def render_ports(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Open Ports[/bold]\n    [red]Error: {data.get('error', 'Scan failed')}[/red]")
        return

    open_ports = data.get("open_ports", [])
    console.print("[bold cyan][+][/bold cyan] [bold]Open Ports[/bold]")

    if not open_ports:
        console.print("    [dim]No open ports detected[/dim]")
        return

    sorted_ports = sorted(open_ports, key=lambda x: x.get("port", 0))
    for p in sorted_ports:
        port_str = f"{p.get('port')}/tcp"
        service = p.get("service", "Unknown")
        _print_kv(port_str, service, indent=4, key_width=16)

def render_ip_asn(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Infrastructure[/bold]\n    [red]Error: {data.get('error', 'Lookup failed')}[/red]")
        return

    ips = data.get("ips", [])
    console.print("[bold cyan][+][/bold cyan] [bold]Infrastructure[/bold]")

    if not ips:
        console.print("    [dim]No infrastructure data available[/dim]")
        return

    primary = ips[0]
    if "error" in primary:
        _print_kv("Primary IP", f"{primary.get('ip', '')} (Lookup failed)")
    else:
        _print_kv("Primary IP", str(primary.get("ip", "Unknown")))
        if primary.get("location"):
            _print_kv("Location", str(primary["location"]))
        if primary.get("isp"):
            _print_kv("ISP", str(primary["isp"]))
        if primary.get("asn"):
            _print_kv("ASN", str(primary["asn"]))
        if primary.get("provider"):
            _print_kv("Provider", str(primary["provider"]))
        if primary.get("hosting_type"):
            _print_kv("Hosting Type", str(primary["hosting_type"]))

    # Additional target IPs if DNS returns multiple
    if len(ips) > 1:
        console.print("    Additional IPs")
        for item in ips[1:]:
            if "error" not in item:
                ip_val = item.get("ip", "")
                asn_val = item.get("asn", "")
                prov_val = item.get("provider", item.get("isp", ""))
                meta = f"{asn_val} | {prov_val}".strip(" |")
                _print_kv(ip_val, meta, indent=8, key_width=16)

def render_public_files(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Public Files[/bold]\n    [red]Error: {data.get('error', 'Check failed')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Public Files[/bold]")
    found = data.get("found", [])
    if found:
        for f in found:
            console.print(f"    {f}")
    else:
        console.print("    None detected")

HTTP_STATUS_REASONS = {
    200: "200 OK",
    301: "301 Moved Permanently",
    302: "302 Found",
    400: "400 Bad Request",
    401: "401 Unauthorized",
    403: "403 Forbidden",
    404: "404 Not Found",
    500: "500 Internal Server Error",
    502: "502 Bad Gateway",
    503: "503 Service Unavailable"
}

def render_directories(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Directory Exposure[/bold]\n    [red]Error: {data.get('error', 'Check failed')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Directory Exposure[/bold]")
    exposed_dirs = data.get("exposed_directories", [])
    findings = data.get("findings", [])
    
    paths = []
    if exposed_dirs:
        paths = exposed_dirs
    elif findings:
        paths = [f.get("path") if isinstance(f, dict) else str(f) for f in findings]

    if paths:
        max_path_len = max(len(p) for p in paths)
        col_width = max(24, max_path_len + 4)
        for p in paths:
            console.print(f"    {p:<{col_width}}" + _colorize_status("Exposed"))
        console.print(f"    Total: {len(paths)}")
    else:
        console.print("    No exposed directories found.")
        console.print("    Total: 0")

RENDER_MAP = {
    "dns": render_dns,
    "whois": render_whois,
    "ssl": render_ssl,
    "headers": render_headers,
    "security-headers": render_security_headers,
    "subdomains": render_subdomains,
    "tech": render_tech,
    "ports": render_ports,
    "ip": render_ip_asn,
    "public-files": render_public_files,
    "directories": render_directories
}

def render_results(
    results: Dict[str, Any],
    elapsed_seconds: Optional[float] = None,
    module_count: Optional[int] = None
):
    target = results.get("target", "Target")
    modules = results.get("modules", {})
    
    print_scan_header(target)

    for mod_key, mod_result in modules.items():
        data = mod_result.get("data", {}) if isinstance(mod_result, dict) else mod_result
        if mod_key in RENDER_MAP:
            RENDER_MAP[mod_key](data)
        else:
            console.print(f"[bold cyan][+][/bold cyan] [bold]{mod_key}[/bold]")
            console.print(f"    {data}")
        console.print("")

    if elapsed_seconds is not None:
        count_str = f" ({module_count} modules completed)" if module_count else ""
        console.print(f"[dim]Scan completed in {elapsed_seconds:.1f}s{count_str}[/dim]\n")

def render_modules_list(registry: Dict[str, Any]):
    console.print(f"\n[bold white]OpenRecon v{__version__}[/bold white] [dim]— Available Modules[/dim]\n")
    for k, v in sorted(registry.items()):
        desc = v.get("description", "")
        console.print(f"  [bold cyan]{k:<18}[/bold cyan] [white]{desc}[/white]")
    console.print("")

def export_json(results: Dict[str, Any], indent: int = 2) -> str:
    return json.dumps(results, indent=indent, default=str)

def export_text_report(
    results: Dict[str, Any],
    elapsed_seconds: Optional[float] = None,
    module_count: Optional[int] = None
) -> str:
    str_buf = io.StringIO()
    text_console = Console(file=str_buf, force_terminal=False, no_color=True, highlight=False)
    
    global console
    orig_console = console
    console = text_console
    try:
        render_results(results, elapsed_seconds=elapsed_seconds, module_count=module_count)
    finally:
        console = orig_console

    return str_buf.getvalue()
