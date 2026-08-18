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
[0;38;2;140;255;255;49m  [0;38;2;75;75;75;49m▀▀▀▀▀▀[0;38;2;0;180;185;49m [0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀[0;38;2;0;180;185;49m     [0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀▀▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀[0;38;2;140;255;255;49m   [0;38;2;75;75;75;49m▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀[0;38;2;140;255;255;49m  [0;38;2;75;75;75;49m ▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀▀▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m  [0;38;2;75;75;75;49m▀▀▀▀▀▀[0;38;2;180;180;180;49m [0;38;2;140;255;255;49m  [0;38;2;75;75;75;49m▀▀▀▀▀▀[0;38;2;0;180;185;49m [0;38;2;180;180;180;49m [0;38;2;140;255;255;49m [0;38;2;75;75;75;49m▀▀[0;38;2;140;255;255;49m   [0;38;2;75;75;75;49m▀▀▀▀[0m
"""

def print_startup_banner():
    print(BANNER_ART)
    console.print(f"[bold white]OpenRecon v{__version__}[/bold white]")
    console.print("[dim]OSINT based Passive Reconnaissance[/dim]\n")

def print_scan_header(target: str):
    console.print(f"\n[bold white]OpenRecon v{__version__}[/bold white] [dim]—[/dim] [bold cyan]{target}[/bold cyan]\n")

def _colorize_status(status_word: str) -> str:
    if not status_word or not isinstance(status_word, str):
        return str(status_word)
    w = status_word.upper().strip()
    if w in ("VALID", "PRESENT", "OPEN", "PROTECTED", "VERIFIED", "STRICT"):
        return f"[green]{status_word}[/green]"
    elif "INVALID" in w or w in ("MISSING", "CLOSED", "EXPOSED", "EXPIRED", "UNTRUSTED", "HOSTNAME_MISMATCH"):
        return f"[red]{status_word}[/red]"
    elif w in ("WARNING", "SOFTFAIL", "OVER-PERMISSIVE", "SELF-SIGNED", "INCOMPLETE", "REDIRECT"):
        return f"[yellow]{status_word}[/yellow]"
    elif w in ("NOT DETECTED", "NOT ENUMERATED", "UNKNOWN", "NONE", "N/A"):
        return f"[dim]{status_word}[/dim]"
    return status_word

def _print_kv(key: str, value: Any, indent: int = 4, key_width: int = 28, max_width: int = 90):
    if value is None or value == "":
        return
    value_str = str(value)
    prefix = " " * indent + f"{key:<{key_width}} "
    sub_indent = " " * (indent + key_width + 1)
    avail_width = max(35, max_width - len(sub_indent))

    if len(prefix) + len(value_str) <= max_width and "\n" not in value_str:
        console.print(f"{prefix}{value_str}")
        return

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

    wrapped = textwrap.wrap(value_str, width=avail_width)
    if not wrapped:
        console.print(f"{prefix}{value_str}")
        return
    for i, line in enumerate(wrapped):
        if i == 0:
            console.print(f"{prefix}{line}")
        else:
            console.print(f"{sub_indent}{line}")

ABSENT_DNS_MESSAGES = {
    "A": "No A records",
    "AAAA": "No AAAA records",
    "CNAME": "No CNAME record",
    "MX": "No MX records",
    "NS": "No NS records",
    "SOA": "No SOA records",
    "TXT": "No TXT records",
    "CAA": "No CAA records",
    "SRV": "No SRV records",
    "PTR": "No PTR records"
}

# 1. DNS
def render_dns(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]DNS[/bold]\n    [red]Error: {data.get('error', 'No data')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]DNS[/bold]")
    for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA", "SRV", "PTR"]:
        records = data.get(rtype, [])
        if records:
            for i, r in enumerate(records):
                k = rtype if i == 0 else ""
                _print_kv(k, str(r), indent=4, key_width=16)
        else:
            absent_msg = ABSENT_DNS_MESSAGES.get(rtype, f"No {rtype} records")
            _print_kv(rtype, absent_msg, indent=4, key_width=16)

# 2. WHOIS
def render_whois(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Domain Registration[/bold]\n    [red]Error: {data.get('error', 'Lookup failed')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Domain Registration[/bold]")
    if data.get("registrar"):
        _print_kv("Registrar", str(data["registrar"]), indent=4, key_width=16)
    if data.get("registry_domain_id"):
        _print_kv("Registry ID", str(data["registry_domain_id"]), indent=4, key_width=16)
    if data.get("registrar_iana_id"):
        _print_kv("Registrar ID", str(data["registrar_iana_id"]), indent=4, key_width=16)
    if data.get("creation_date"):
        _print_kv("Created", str(data["creation_date"])[:10], indent=4, key_width=16)
    if data.get("updated_date"):
        _print_kv("Updated", str(data["updated_date"])[:10], indent=4, key_width=16)
    if data.get("expiration_date"):
        _print_kv("Expires", str(data["expiration_date"])[:10], indent=4, key_width=16)
    if data.get("age_years") is not None:
        _print_kv("Age", f"{data['age_years']} years", indent=4, key_width=16)

    status = data.get("status")
    if status:
        status_str = ", ".join(status) if isinstance(status, list) else str(status)
        _print_kv("Status", status_str, indent=4, key_width=16)

    if data.get("registrant"):
        _print_kv("Registrant", str(data["registrant"]), indent=4, key_width=16)

# 3. SSL / TLS
def render_ssl(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]SSL / TLS[/bold]\n    [red]Error: {data.get('error', 'Handshake failed')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]SSL / TLS[/bold]")
    status_label = data.get("status_label") or ("VALID" if data.get("valid", False) else "INVALID")
    _print_kv("Status", _colorize_status(status_label), indent=4, key_width=16)

    if data.get("chain_status"):
        _print_kv("Chain Status", _colorize_status(data["chain_status"]), indent=4, key_width=16)

    if data.get("version"):
        _print_kv("Version", str(data["version"]), indent=4, key_width=16)
    if data.get("key_type"):
        _print_kv("Key Type", str(data["key_type"]), indent=4, key_width=16)
    if data.get("key_size"):
        _print_kv("Key Size", str(data["key_size"]), indent=4, key_width=16)

    issuer = data.get("issuer", {})
    if isinstance(issuer, dict):
        cn = issuer.get("commonName")
        org = issuer.get("organizationName")
        issuer_str = f"{cn} ({org})" if cn and org else (cn or org or str(issuer))
    else:
        issuer_str = str(issuer) if issuer else None
    if issuer_str:
        _print_kv("Issuer", issuer_str, indent=4, key_width=16)

    subject = data.get("subject", {})
    if isinstance(subject, dict):
        subj_str = subject.get("commonName") or str(subject)
    else:
        subj_str = str(subject) if subject else None
    if subj_str:
        _print_kv("Subject", subj_str, indent=4, key_width=16)

    if data.get("valid_from"):
        _print_kv("Valid From", str(data["valid_from"])[:10], indent=4, key_width=16)
    if data.get("valid_until"):
        _print_kv("Valid Until", str(data["valid_until"])[:10], indent=4, key_width=16)

    days = data.get("days_remaining")
    if days is not None:
        _print_kv("Days Remaining", str(days), indent=4, key_width=16)

    if data.get("serial_number"):
        _print_kv("Serial Number", str(data["serial_number"]), indent=4, key_width=16)

    if data.get("signature_algorithm"):
        _print_kv("Signature", str(data["signature_algorithm"]), indent=4, key_width=16)

    sans = data.get("subject_alt_names", [])
    if sans:
        _print_kv("SANs", ", ".join(sans), indent=4, key_width=16)

    if data.get("cipher"):
        _print_kv("Cipher", str(data["cipher"]), indent=4, key_width=16)
    if data.get("protocol"):
        _print_kv("Protocol", str(data["protocol"]), indent=4, key_width=16)

# 4. Email Security
def render_email(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Email Security[/bold]\n    [red]Error: {data.get('error', 'No data')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Email Security[/bold]")
    spf = data.get("spf", {})
    _print_kv("SPF Record", _colorize_status(spf.get("record", "MISSING")), indent=4, key_width=16)
    if spf.get("record") in ("PRESENT", "INVALID"):
        _print_kv("SPF Status", _colorize_status(spf.get("status", "UNKNOWN")), indent=4, key_width=16)
        if spf.get("value"):
            _print_kv("SPF Value", str(spf["value"]), indent=4, key_width=16)
        if spf.get("final_qualifier"):
            _print_kv("Final Qualifier", str(spf["final_qualifier"]), indent=4, key_width=16)
        if spf.get("includes"):
            _print_kv("Includes", ", ".join(spf["includes"]), indent=4, key_width=16)

    dmarc = data.get("dmarc", {})
    _print_kv("DMARC Record", _colorize_status(dmarc.get("record", "MISSING")), indent=4, key_width=16)
    if dmarc.get("record") == "PRESENT":
        if dmarc.get("policy"):
            _print_kv("DMARC Policy", str(dmarc["policy"]), indent=4, key_width=16)
        if dmarc.get("subdomain_policy"):
            _print_kv("Subdomain Policy", str(dmarc["subdomain_policy"]), indent=4, key_width=16)
        if dmarc.get("rua"):
            _print_kv("Rua", str(dmarc["rua"]), indent=4, key_width=16)
        if dmarc.get("ruf"):
            _print_kv("Ruf", str(dmarc["ruf"]), indent=4, key_width=16)
        if dmarc.get("percentage"):
            _print_kv("Percentage", str(dmarc["percentage"]), indent=4, key_width=16)

    dkim = data.get("dkim", {})
    _print_kv("DKIM", _colorize_status(dkim.get("status", "NOT ENUMERATED")), indent=4, key_width=16)

# 5. HTTP
def render_headers(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]HTTP[/bold]\n    [red]Error: {data.get('error', 'Unreachable')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]HTTP[/bold]")
    if data.get("url"):
        _print_kv("URL", str(data["url"]), indent=4, key_width=16)
    if data.get("status_code"):
        _print_kv("Status Code", str(data["status_code"]), indent=4, key_width=16)
    if data.get("server"):
        _print_kv("Server", str(data["server"]), indent=4, key_width=16)
    if data.get("content_type"):
        _print_kv("Content-Type", str(data["content_type"]), indent=4, key_width=16)
    if data.get("content_length"):
        _print_kv("Content-Length", str(data["content_length"]), indent=4, key_width=16)
    if data.get("http_version"):
        _print_kv("HTTP Version", str(data["http_version"]), indent=4, key_width=16)
    if data.get("redirects") is not None:
        _print_kv("Redirects", str(data["redirects"]), indent=4, key_width=16)
    if data.get("location"):
        _print_kv("Location", str(data["location"]), indent=4, key_width=16)
    if data.get("final_url"):
        _print_kv("Final URL", str(data["final_url"]), indent=4, key_width=16)
    if data.get("cookies"):
        _print_kv("Set-Cookie", str(data["cookies"]), indent=4, key_width=16)
    if data.get("date"):
        _print_kv("Date", str(data["date"]), indent=4, key_width=16)
    if data.get("last_modified"):
        _print_kv("Last-Modified", str(data["last_modified"]), indent=4, key_width=16)
    if data.get("etag"):
        _print_kv("ETag", str(data["etag"]), indent=4, key_width=16)

# 6. Security Headers
def render_security_headers(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Security Headers[/bold]\n    [red]Error: {data.get('error', 'Unreachable')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Security Headers[/bold]")
    headers_dict = data.get("headers", {})
    
    for h_name, h_info in headers_dict.items():
        val = h_info.get("value", "MISSING")
        colorized_val = _colorize_status(val) if val == "MISSING" else val
        _print_kv(h_name, colorized_val, indent=4, key_width=28)

# 7. Subdomains
def render_subdomains(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Subdomains[/bold]\n    [red]Error: {data.get('error', 'Lookup failed')}[/red]")
        return

    subdomains = data.get("subdomains", [])
    total = len(subdomains)
    console.print("[bold cyan][+][/bold cyan] [bold]Subdomains[/bold]")
    _print_kv("Total", str(total), indent=4, key_width=16)

    for s in subdomains:
        host = s.get("hostname", "") if isinstance(s, dict) else str(s)
        if host:
            console.print(f"    {host}")

# 8. Technology Stack
def render_tech(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Technology Stack[/bold]\n    [red]Error: {data.get('error', 'Unreachable')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Technology Stack[/bold]")
    categories = data.get("categories", {})
    
    preferred_order = [
        "Web Server", "Backend", "Frontend", "CMS", "Framework",
        "Runtime", "Analytics", "JavaScript Libraries", "CDN / Proxy"
    ]
    
    has_output = False
    for cat in preferred_order:
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
            _print_kv(cat, combined_val, indent=4, key_width=20)
            has_output = True

    for cat, items in categories.items():
        if cat not in preferred_order and items:
            formatted_items = [f"{i.get('name')} {i.get('version')}".strip() for i in items if i.get("name")]
            if formatted_items:
                _print_kv(cat, ", ".join(formatted_items), indent=4, key_width=20)
                has_output = True

    if not has_output:
        console.print("    No technologies identified.")

# 9. Open Ports
def render_ports(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Open Ports[/bold]\n    [red]Error: {data.get('error', 'Scan failed')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Open Ports[/bold]")
    open_ports = data.get("open_ports", [])

    if not open_ports:
        console.print("    [dim]No open ports detected[/dim]")
        return

    for p in open_ports:
        port_num = p.get("port")
        service = p.get("service", "Unknown")
        version = p.get("version")
        val_str = f"{service} {version}".strip() if version else service
        _print_kv(f"{port_num}/tcp", val_str, indent=4, key_width=16)

# 10. Infrastructure
def render_ip_asn(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Infrastructure[/bold]\n    [red]Error: {data.get('error', 'Lookup failed')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Infrastructure[/bold]")
    if data.get("primary_ip"):
        _print_kv("Primary IP", str(data["primary_ip"]), indent=4, key_width=16)
    if data.get("ipv6"):
        _print_kv("IPv6", str(data["ipv6"]), indent=4, key_width=16)
    if data.get("additional_ips"):
        _print_kv("Additional IPs", ", ".join(data["additional_ips"]), indent=4, key_width=16)
    if data.get("location"):
        _print_kv("Location", str(data["location"]), indent=4, key_width=16)
    if data.get("isp"):
        _print_kv("ISP", str(data["isp"]), indent=4, key_width=16)
    if data.get("asn"):
        _print_kv("ASN", str(data["asn"]), indent=4, key_width=16)
    if data.get("provider"):
        _print_kv("Provider", str(data["provider"]), indent=4, key_width=16)
    if data.get("hosting_type"):
        _print_kv("Hosting Type", str(data["hosting_type"]), indent=4, key_width=16)

# 11. Public Files
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

# 12. Directory Exposure
def render_directories(data: Dict[str, Any]):
    if not data or "error" in data:
        console.print(f"[bold cyan][+][/bold cyan] [bold]Directory Exposure[/bold]\n    [red]Error: {data.get('error', 'Check failed')}[/red]")
        return

    console.print("[bold cyan][+][/bold cyan] [bold]Directory Exposure[/bold]")
    findings = data.get("findings", [])

    exposed_items = []
    for f in findings:
        if isinstance(f, dict):
            if f.get("is_exposed") or "EXPOSED" in f.get("status", ""):
                exposed_items.append((f.get("path", ""), f.get("status", "200 EXPOSED")))
        elif isinstance(f, str):
            exposed_items.append((f, "200 EXPOSED"))

    if exposed_items:
        for path, status in exposed_items:
            colorized = f"200 {_colorize_status('EXPOSED')}" if "EXPOSED" in status else _colorize_status(status)
            _print_kv(path, colorized, indent=4, key_width=16)
    else:
        console.print("    No exposed directories found.")

RENDER_MAP = {
    "dns": render_dns,
    "whois": render_whois,
    "ssl": render_ssl,
    "email": render_email,
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
