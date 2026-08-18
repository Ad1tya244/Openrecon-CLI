from typing import Dict, Any, List
from openrecon.utils.safe_http import safe_get

SECURITY_HEADERS_LIST = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy"
]

def deduplicate_header_value(raw_val: str) -> str:
    """
    Deduplicates identical comma-separated duplicate header values
    (e.g. 'nosniff, nosniff' -> 'nosniff') without corrupting multi-value policies.
    """
    if not raw_val or not isinstance(raw_val, str):
        return str(raw_val)
    parts = [p.strip() for p in raw_val.split(",") if p.strip()]
    if len(parts) > 1:
        unique_lower = set(p.lower() for p in parts)
        if len(unique_lower) == 1:
            return parts[0]
    return raw_val.strip()

async def analyze_security_headers(domain: str) -> Dict[str, Any]:
    """
    Checks exactly the 8 standard security headers without fabricating a synthetic score.
    Returns status and normalized value for each header.
    """
    url = f"https://{domain}"
    response = await safe_get(url)
    if "error" in response:
        url = f"http://{domain}"
        response = await safe_get(url)
        if "error" in response:
            return {"error": "Could not fetch headers (Target unreachable or offline)"}

    headers = response.get("headers", {})
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    evaluated_headers: Dict[str, Dict[str, Any]] = {}

    for header_name in SECURITY_HEADERS_LIST:
        h_key = header_name.lower()
        if h_key in headers_lower:
            cleaned_val = deduplicate_header_value(headers_lower[h_key])
            evaluated_headers[header_name] = {
                "present": True,
                "value": cleaned_val
            }
        else:
            evaluated_headers[header_name] = {
                "present": False,
                "value": "MISSING"
            }

    return {
        "headers": evaluated_headers
    }
