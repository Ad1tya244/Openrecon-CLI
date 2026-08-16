from typing import Dict, Any
from openrecon.utils.safe_http import safe_get

SECURITY_HEADERS_INFO = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections.",
        "impact": "MitM attacks, Protocol Downgrade attacks, Cookie Hijacking."
    },
    "Content-Security-Policy": {
        "description": "Controls resources the user agent is allowed to load.",
        "impact": "Cross-Site Scripting (XSS), Data Injection, Clickjacking."
    },
    "X-Frame-Options": {
        "description": "Prevents the page from being embedded in frames/iframes.",
        "impact": "Clickjacking (UI Redressing) attacks."
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-sniffing of response content types.",
        "impact": "MIME Sniffing attacks, Drive-by Downloads."
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent with requests.",
        "impact": "Information Leakage (User privacy, internal URL structure)."
    },
    "Permissions-Policy": {
        "description": "Controls which browser features are allowed.",
        "impact": "Abuse of sensitive features (Camera, Microphone, Geolocation)."
    }
}

async def analyze_security_headers(domain: str) -> Dict[str, Any]:
    """
    Analyzes HTTP headers for security posture and provides impact assessment.
    """
    url = f"https://{domain}"
    results = {
        "present_headers": {},
        "missing_headers": [],
        "score": 0
    }
    
    response = await safe_get(url)
    if "error" in response:
        url = f"http://{domain}"
        response = await safe_get(url)
        if "error" in response:
            return {"error": "Could not fetch headers (Target unreachable or offline)"}

    headers = response.get("headers", {})
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for header, info in SECURITY_HEADERS_INFO.items():
        if header.lower() in headers_lower:
            results["present_headers"][header] = {
                "value": headers_lower[header.lower()],
                "status": "Present"
            }
        else:
            results["missing_headers"].append({
                "header": header,
                "description": info["description"],
                "impact": info["impact"]
            })

    total = len(SECURITY_HEADERS_INFO)
    present = len(results["present_headers"])
    results["score"] = int((present / total) * 100) if total > 0 else 0
    
    return results
