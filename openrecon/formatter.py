import json
import io
import textwrap
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.theme import Theme

custom_theme = Theme({
    "custom_cyan": "#02d1b5",
    "bold_custom_cyan": "bold #02d1b5",
    "custom_green": "#58ad03",
    "bold_custom_green": "bold #58ad03",
    "custom_red": "#de2302",
    "bold_custom_red": "bold #de2302",
    "custom_yellow": "#dec402",
    "bold_custom_yellow": "bold #dec402"
})
from openrecon import __version__

console = Console(theme=custom_theme, highlight=False)
err_console = Console(stderr=True, theme=custom_theme, highlight=False)

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
    console.print(f"\n[bold white]OpenRecon v{__version__}[/bold white] [dim]—[/dim] [bold_custom_cyan]{target}[/bold_custom_cyan]\n")

def print_module_heading(title: str, error: Optional[str] = None):
    """
    Centralized module/section heading formatter.
    Ensures that [+] and the complete heading text use the same bold cyan/turquoise color.
    """
    if error:
        console.print(f"[bold_custom_cyan][+] {title}[/bold_custom_cyan]\n    [custom_red]Error: {error}[/custom_red]")
    else:
        console.print(f"[bold_custom_cyan][+] {title}[/bold_custom_cyan]")

def _colorize_status(status_word: str) -> str:
    if not status_word or not isinstance(status_word, str):
        return str(status_word)
    w = status_word.upper().strip()
    if w in ("VALID", "PRESENT", "OPEN", "PROTECTED", "VERIFIED", "STRICT"):
        return f"[custom_green]{status_word}[/custom_green]"
    elif "INVALID" in w or w in ("MISSING", "CLOSED", "EXPOSED", "EXPIRED", "UNTRUSTED", "HOSTNAME_MISMATCH"):
        return f"[custom_red]{status_word}[/custom_red]"
    elif w in ("WARNING", "SOFTFAIL", "OVER-PERMISSIVE", "SELF-SIGNED", "INCOMPLETE", "REDIRECT"):
        return f"[custom_yellow]{status_word}[/custom_yellow]"
    elif w in ("NOT DETECTED", "NOT ENUMERATED", "UNKNOWN", "NONE", "N/A"):
        return f"[dim]{status_word}[/dim]"
    return status_word

def _print_kv(key: str, value: Any, indent: int = 4, key_width: int = 28, max_width: Optional[int] = None):
    if value is None or value == "":
        return
    value_str = str(value)
    width = max_width or (console.width if (console and getattr(console, "width", None)) else 90)
    prefix = " " * indent + f"{key:<{key_width}} "
    sub_indent = " " * (indent + key_width + 1)
    
    prefix_len = len(prefix)
    sub_indent_len = len(sub_indent)
    
    first_avail = max(30, width - prefix_len)
    next_avail = max(30, width - sub_indent_len)

    if prefix_len + len(value_str) <= width and chr(10) not in value_str:
        console.print(f"{prefix}{value_str}")
        return

    if ", " in value_str and chr(10) not in value_str:
        parts = [p.strip() for p in value_str.split(", ") if p.strip()]
        lines = []
        current_line = []
        current_len = 0
        for part in parts:
            current_avail = first_avail if not lines else next_avail
            item_len = len(part) + (2 if current_line else 0)
            if current_line and (current_len + item_len > current_avail):
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

    wrapped = textwrap.wrap(value_str, width=next_avail)
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
        print_module_heading("DNS", error=data.get('error', 'No data'))
        return

    print_module_heading("DNS")
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
        print_module_heading("Domain Registration", error=data.get('error', 'Lookup failed'))
        return

    print_module_heading("Domain Registration")
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
        print_module_heading("SSL / TLS", error=data.get('error', 'Handshake failed'))
        return

    print_module_heading("SSL / TLS")
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
        print_module_heading("Email Security", error=data.get('error', 'No data'))
        return

    print_module_heading("Email Security")
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
        print_module_heading("HTTP", error=data.get('error', 'Unreachable'))
        return

    print_module_heading("HTTP")
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
def render_security_headers(data: Dict[str, Any], show_evidence: bool = False):
    if not data or "error" in data:
        print_module_heading("Security Headers", error=data.get('error', 'Unreachable'))
        return

    print_module_heading("Security Headers")
    headers_dict = data.get("headers", {})
    
    for h_name, h_info in headers_dict.items():
        present = h_info.get("present", False)
        status_word = "PRESENT" if present else "MISSING"
        colorized_val = _colorize_status(status_word)
        _print_kv(h_name, colorized_val, indent=4, key_width=28)
        
        if show_evidence and present:
            raw_val = h_info.get("value")
            if raw_val and raw_val != "MISSING":
                _print_kv("└─ Value:", raw_val, indent=6, key_width=9)

# 7. Subdomains
def render_subdomains(data: Dict[str, Any]):
    if not data or "error" in data:
        print_module_heading("Subdomains", error=data.get('error', 'Lookup failed'))
        return

    subdomains = data.get("subdomains", [])
    total = len(subdomains)
    print_module_heading("Subdomains")
    _print_kv("Total", str(total), indent=4, key_width=16)

    for s in subdomains:
        host = s.get("hostname", "") if isinstance(s, dict) else str(s)
        if host:
            console.print(f"    {host}")

# 8. Technology Stack
def render_tech(data: Dict[str, Any], show_evidence: bool = False):
    if not data or "error" in data:
        print_module_heading("Technology Stack", error=data.get('error', 'Unreachable'))
        return

    print_module_heading("Technology Stack")
    
    if not show_evidence:
        categories = data.get("categories", {})
        preferred_order = [
            "Web Server", "Backend", "Frontend frameworks/libraries",
            "JavaScript Libraries", "CMS", "Analytics", "CDN / Proxy",
            "Security / Infrastructure", "Web standards / metadata"
        ]
        category_mappings = {
            "Frontend frameworks/libraries": "Frontend",
            "JavaScript Libraries": "JavaScript",
            "Security / Infrastructure": "Security",
            "Web standards / metadata": "Web standards"
        }
        has_output = False
        for cat in preferred_order:
            items = categories.get(cat, [])
            if not items:
                continue
            formatted_items = []
            for item in items:
                name = item.get("name", "")
                ver = getattr(item, "version", None) or (item.get("version") if isinstance(item, dict) else None)
                display_name = f"{name} {ver}" if ver else name
                if display_name:
                    formatted_items.append(display_name)
            if formatted_items:
                combined_val = ", ".join(formatted_items)
                display_cat = category_mappings.get(cat, cat)
                _print_kv(display_cat, combined_val, indent=4, key_width=16)
                has_output = True

        for cat, items in categories.items():
            if cat not in preferred_order and items:
                formatted_items = [f"{i.get('name')} {i.get('version')}".strip() for i in items if i.get("name")]
                if formatted_items:
                    display_cat = category_mappings.get(cat, cat)
                    _print_kv(display_cat, ", ".join(formatted_items), indent=4, key_width=16)
                    has_output = True

        if not has_output:
            console.print("    No technologies identified.")
        return

    # Evidence verbose mode
    findings = data.get("findings", [])
    if not findings:
        console.print("    No technologies identified.")
        return

    # Group findings by category
    categories_dict = {}
    for f in findings:
        cat = getattr(f, "category", None) or (f.get("category") if isinstance(f, dict) else None) or "Other"
        if cat not in categories_dict:
            categories_dict[cat] = []
        categories_dict[cat].append(f)

    preferred_order = [
        "Web Server", "Backend", "Frontend frameworks/libraries",
        "JavaScript Libraries", "CMS", "Analytics", "CDN / Proxy",
        "Security / Infrastructure", "Web standards / metadata"
    ]

    all_cats = preferred_order + [c for c in categories_dict.keys() if c not in preferred_order]
    
    first = True
    for cat in all_cats:
        items = categories_dict.get(cat, [])
        if not items:
            continue
        
        for item in items:
            if not first:
                console.print("")
            first = False
            
            ver = getattr(item, "version", None) or (item.get("version") if isinstance(item, dict) else None)
            val = getattr(item, 'value', None) or (item.get('value') if isinstance(item, dict) else None)
            display_name = f"{val} {ver}" if ver else val
            console.print(f"    {display_name}")
            
            ev_list = getattr(item, "evidence", []) or (item.get("evidence", []) if isinstance(item, dict) else [])
            for ev in ev_list:
                ev_type = getattr(ev, "type", None) or ev.get("type", "unknown")
                ev_src = getattr(ev, "source", None) or (ev.get("source") if isinstance(ev, dict) else None) or ""
                ev_snip = getattr(ev, "snippet", None) or (ev.get("snippet") if isinstance(ev, dict) else None) or ""
                
                label = ev_type.capitalize()
                if ev_type == "headers":
                    label = "Header"
                elif ev_type == "cookies":
                    label = "Cookie"
                elif ev_type == "meta":
                    label = "Meta"
                elif ev_type == "url":
                    label = "URL"
                elif ev_type == "html":
                    label = "HTML"
                elif ev_type == "dns":
                    label = "DNS"
                elif label == "Scriptsrc":
                    label = "Script"
                elif label == "Css":
                    label = "Stylesheet"
                elif label == "Relational":
                    label = "Relation"
                
                val = ev_snip
                if ev_type == "relational":
                    val = f"Implied by {ev_src}"
                elif ev_src and ev_src != val and label not in ("Fallback", "Relation"):
                    val = f"{ev_src}: {val}"
                
                console.print(f"      └─ {label}: {val}")

def render_ports(data: Dict[str, Any]):
    if not data or "error" in data:
        print_module_heading("Open Ports", error=data.get('error', 'Scan failed'))
        return

    print_module_heading("Open Ports")
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
        print_module_heading("Infrastructure", error=data.get('error', 'Lookup failed'))
        return

    print_module_heading("Infrastructure")
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
        print_module_heading("Public Files", error=data.get('error', 'Check failed'))
        return

    print_module_heading("Public Files")
    found = data.get("found", [])
    if found:
        for f in found:
            console.print(f"    {f}")
    else:
        console.print("    None detected")

# 12. Directory Exposure
def render_directories(data: Dict[str, Any]):
    if not data or "error" in data:
        print_module_heading("Directory Exposure", error=data.get('error', 'Check failed'))
        return

    print_module_heading("Directory Exposure")
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

# 13. Page & Client-Side Intelligence
def render_page_intel(data: Dict[str, Any], show_evidence: bool = False):
    if data is None or (isinstance(data, dict) and "error" in data):
        err = data.get("error", "Lookup failed") if isinstance(data, dict) else "Lookup failed"
        print_module_heading("Page Intelligence", error=err)
        return

    if not show_evidence:
        print_module_heading("Page Intelligence")
        has_findings = False

        # 1. API Endpoints
        api_refs = data.get("api_references", [])
        if api_refs:
            for idx, ref in enumerate(api_refs):
                k = "API Endpoint" if idx == 0 else ""
                if isinstance(ref, dict):
                    disp = ref.get("display") or f"{ref.get('method', 'GET')} {ref.get('url', '/')}"
                    params = ref.get("params", [])
                    if params:
                        disp = f"{disp} ({', '.join(params)})"
                    _print_kv(k, disp, indent=4, key_width=18)
                else:
                    _print_kv(k, str(ref), indent=4, key_width=18)
                has_findings = True

        # 1b. GraphQL Operations
        graphql_ops = data.get("graphql_operations", [])
        if graphql_ops:
            for idx, op in enumerate(graphql_ops):
                k = "GraphQL Operation" if idx == 0 else ""
                disp = op.get("display") if isinstance(op, dict) else str(op)
                _print_kv(k, disp, indent=4, key_width=18)
                has_findings = True

        # 2. Functional Forms
        forms = data.get("forms", [])
        if forms:
            for idx, f in enumerate(forms):
                k = "Functional Form" if idx == 0 else ""
                if isinstance(f, dict):
                    method = f.get("method", "POST")
                    action = f.get("action", "/")
                    fields = f.get("fields", [])
                    fields_str = f" ({', '.join(fields)})" if fields else ""
                    _print_kv(k, f"{method} {action}{fields_str}", indent=4, key_width=18)
                else:
                    _print_kv(k, str(f), indent=4, key_width=18)
                has_findings = True

        # 3. Application Routes
        app_paths = data.get("application_paths", [])
        if app_paths:
            for idx, path in enumerate(app_paths):
                k = "Application Route" if idx == 0 else ""
                _print_kv(k, str(path), indent=4, key_width=18)
                has_findings = True

        # 4-7. Client Config
        client_config = data.get("client_config", {})
        if client_config.get("api_base"):
            _print_kv("API Base", str(client_config["api_base"]), indent=4, key_width=18)
            has_findings = True
        if client_config.get("backend_url"):
            _print_kv("Backend URL", str(client_config["backend_url"]), indent=4, key_width=18)
            has_findings = True
        if client_config.get("environment"):
            _print_kv("Environment", str(client_config["environment"]), indent=4, key_width=18)
            has_findings = True
        if client_config.get("base_path"):
            _print_kv("Base Path", str(client_config["base_path"]), indent=4, key_width=18)
            has_findings = True

        # 7b. OAuth & Identity Configurations
        oauth_configs = data.get("oauth_configurations", [])
        if oauth_configs:
            for idx, cfg in enumerate(oauth_configs):
                k = "OAuth Configuration" if idx == 0 else ""
                disp = cfg.get("display") if isinstance(cfg, dict) else str(cfg)
                _print_kv(k, disp, indent=4, key_width=18)
                has_findings = True

        # 8. WebSockets
        websockets = data.get("websockets", [])
        if websockets:
            for idx, ws in enumerate(websockets):
                k = "WebSocket" if idx == 0 else ""
                _print_kv(k, str(ws), indent=4, key_width=18)
                has_findings = True

        # 9. Internal Hosts
        internal_hosts = data.get("internal_hosts", [])
        if internal_hosts:
            for idx, host in enumerate(internal_hosts):
                k = "Internal Host" if idx == 0 else ""
                _print_kv(k, str(host), indent=4, key_width=18)
                has_findings = True

        # 10. Cloud Storage
        cloud_storage = data.get("cloud_storage", [])
        if cloud_storage:
            for idx, cs in enumerate(cloud_storage):
                k = "Cloud Storage" if idx == 0 else ""
                _print_kv(k, str(cs), indent=4, key_width=18)
                has_findings = True

        # 11. Config References
        configs = data.get("config_references", [])
        if configs:
            for idx, cfg in enumerate(configs):
                k = "Config Reference" if idx == 0 else ""
                _print_kv(k, str(cfg), indent=4, key_width=18)
                has_findings = True
        elif data.get("config"):
            _print_kv("Config Reference", str(data["config"]), indent=4, key_width=18)
            has_findings = True

        # 12. API Specifications
        api_specs = data.get("api_specifications", [])
        if api_specs:
            for idx, spec in enumerate(api_specs):
                k = "API Specification" if idx == 0 else ""
                _print_kv(k, str(spec), indent=4, key_width=18)
                has_findings = True

        # 13. Debug Endpoints
        debug_eps = data.get("debug_endpoints", [])
        if debug_eps:
            for idx, dbg in enumerate(debug_eps):
                k = "Debug Endpoint" if idx == 0 else ""
                _print_kv(k, str(dbg), indent=4, key_width=18)
                has_findings = True

        # 14. Source Maps
        source_maps = data.get("source_maps", [])
        if source_maps:
            for idx, sm in enumerate(source_maps):
                k = "Source Map" if idx == 0 else ""
                _print_kv(k, str(sm), indent=4, key_width=18)
                has_findings = True

        # 15. Sensitive References
        sensitive = data.get("sensitive_references", [])
        if sensitive:
            for idx, s in enumerate(sensitive):
                k = "Exposed Token" if idx == 0 else ""
                _print_kv(k, str(s), indent=4, key_width=18)
                has_findings = True

        if not has_findings:
            console.print("    No significant page intelligence found.")
        return

    # Evidence verbose mode
    print_module_heading("Page Intelligence")
    findings = data.get("findings", [])
    if not findings:
        console.print("    No significant page intelligence found.")
        return

    first = True
    for f in findings:
        if not first:
            console.print("")
        first = False
        
        cat = getattr(f, "category", None) or (f.get("category") if isinstance(f, dict) else None) or "Other"
        val = getattr(f, "value", None) or (f.get("value") if isinstance(f, dict) else None) or ""
        console.print(f"    {cat} {val}")
        
        ev_list = getattr(f, "evidence", []) or (f.get("evidence", []) if isinstance(f, dict) else [])
        for ev in ev_list:
            ev_type = getattr(ev, "type", None) or (ev.get("type") if isinstance(ev, dict) else "unknown")
            ev_snip = getattr(ev, "snippet", None) or (ev.get("snippet") if isinstance(ev, dict) else "")
            
            # Capitalize type
            label = ev_type.capitalize()
            if label == "Javascript":
                label = "JavaScript"
            console.print(f"      └─ {label}: {ev_snip}")
            
        # For API Endpoints, print classification Type
        if cat == "API Endpoint":
            api_type = "REST/XHR"
            for api_ref in data.get("api_references", []):
                disp_val = api_ref.get("display") or f"{api_ref.get('method', 'GET')} {api_ref.get('url', '/')}"
                params = api_ref.get("params", [])
                if params:
                    disp_val = f"{disp_val} ({', '.join(params)})"
                if disp_val == val:
                    api_type = api_ref.get("class", "xhr").upper()
                    if api_type == "XHR":
                        api_type = "REST/XHR"
                    break
            console.print(f"      └─ Type: {api_type}")


def render_email_enum(data: Dict[str, Any], show_evidence: bool = False):
    if not data or "error" in data:
        print_module_heading("Email Enumeration", error=data.get('error', 'Unreachable'))
        return

    emails = data.get("emails", [])
    print_module_heading("Email Enumeration")
    _print_kv("Total", len(emails), indent=4, key_width=16)
    
    for email_info in emails:
        val = email_info.get("value") if isinstance(email_info, dict) else email_info
        console.print(f"    {val}")
        if show_evidence and isinstance(email_info, dict):
            src = email_info.get("source")
            if src:
                console.print(f"      └─ Source: {src}")

def render_social_osint(data: Dict[str, Any], show_evidence: bool = False):
    if not data or "error" in data:
        print_module_heading("Social Media OSINT", error=data.get('error', 'Unreachable'))
        return

    print_module_heading("Social Media OSINT")
    
    profiles = data.get("social_profiles", {})
    unfiltered = data.get("unfiltered_profiles", {})
    sources = data.get("sources", {})
    classifications = data.get("classifications", {})
    reasons = data.get("reasons", {})
    
    platforms_order = ["LinkedIn", "Instagram", "Facebook", "YouTube", "X", "GitHub", "Telegram", "Discord"]
    target_dict = unfiltered if show_evidence else profiles
    
    all_platforms = list(platforms_order)
    for p in target_dict:
        if p not in all_platforms:
            all_platforms.append(p)

    for p in all_platforms:
        urls = target_dict.get(p, [])
        if not urls:
            continue
        if isinstance(urls, str):
            urls = [urls]
            
        for idx, url in enumerate(urls):
            if idx == 0:
                _print_kv(p, url, indent=4, key_width=16)
            else:
                val_indent = " " * (4 + 16 + 1)
                console.print(f"{val_indent}{url}")
                
            if show_evidence:
                classification = classifications.get(url, "UNVERIFIED")
                reason = reasons.get(url, "No verification details available.")
                src = sources.get(p, {}).get(url, "")
                
                info_indent = " " * (4 + 16 + 3)
                console.print(f"{info_indent}Classification: {classification}")
                
                import textwrap
                wrapped_reason = textwrap.wrap(reason, width=60)
                for r_idx, r_line in enumerate(wrapped_reason):
                    if r_idx == 0:
                        console.print(f"{info_indent}Reason: {r_line}")
                    else:
                        console.print(f"{info_indent}        {r_line}")
                        
                if src:
                    console.print(f"{info_indent}Source: {src}")

RENDER_MAP = {
    "dns": render_dns,
    "whois": render_whois,
    "ssl": render_ssl,
    "email": render_email,
    "headers": render_headers,
    "security-headers": render_security_headers,
    "subdomains": render_subdomains,
    "tech": render_tech,
    "page-intel": render_page_intel,
    "ports": render_ports,
    "ip": render_ip_asn,
    "public-files": render_public_files,
    "directories": render_directories,
    "email-enum": render_email_enum,
    "social": render_social_osint
}

def render_results(
    results: Dict[str, Any],
    elapsed_seconds: Optional[float] = None,
    module_count: Optional[int] = None,
    show_evidence: bool = False
):
    target = results.get("target", "Target")
    modules = results.get("modules", {})
    
    print_scan_header(target)

    import inspect
    for mod_key, mod_result in modules.items():
        data = mod_result.get("data", {}) if isinstance(mod_result, dict) else mod_result
        if mod_key in RENDER_MAP:
            func = RENDER_MAP[mod_key]
            sig = inspect.signature(func)
            if "show_evidence" in sig.parameters:
                func(data, show_evidence=show_evidence)
            else:
                func(data)
        else:
            print_module_heading(mod_key)
            console.print(f"    {data}")
        console.print("")

    if elapsed_seconds is not None:
        count_str = f" ({module_count} modules completed)" if module_count else ""
        console.print(f"[dim]Scan completed in {elapsed_seconds:.1f}s{count_str}[/dim]\n")

def render_modules_list(registry: Dict[str, Any]):
    console.print(f"\n[bold white]OpenRecon v{__version__}[/bold white] [dim]— Available Modules[/dim]\n")
    for k, v in sorted(registry.items()):
        desc = v.get("description", "")
        console.print(f"  [bold_custom_cyan]{k:<18}[/bold_custom_cyan] [white]{desc}[/white]")
    console.print("")

def export_json(results: Dict[str, Any], indent: int = 2) -> str:
    return json.dumps(results, indent=indent, default=str)

def export_text_report(
    results: Dict[str, Any],
    elapsed_seconds: Optional[float] = None,
    module_count: Optional[int] = None,
    show_evidence: bool = False
) -> str:
    str_buf = io.StringIO()
    text_console = Console(file=str_buf, force_terminal=False, no_color=True, highlight=False)
    
    global console
    orig_console = console
    console = text_console
    try:
        render_results(results, elapsed_seconds=elapsed_seconds, module_count=module_count, show_evidence=show_evidence)
    finally:
        console = orig_console

    return str_buf.getvalue()
