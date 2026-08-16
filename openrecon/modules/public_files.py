from typing import Dict, Any
from openrecon.utils.safe_http import safe_get

ALLOWLISTED_FILES = [
    "robots.txt",
    "sitemap.xml",
    "security.txt",
    ".well-known/security.txt",
    "humans.txt",
    "ads.txt"
]

async def check_public_files(domain: str) -> Dict[str, Any]:
    """
    Checks for the existence of standard public files safely without brute forcing.
    """
    base_url = f"https://{domain}"
    results = {
        "found": [],
        "missing": [],
        "interesting_findings": []
    }
    
    for filename in ALLOWLISTED_FILES:
        url = f"{base_url}/{filename}"
        response = await safe_get(url)
        
        if "error" not in response and response.get("status_code") == 200:
            results["found"].append(filename)
            content = response.get("content_text", "")
            
            if filename == "robots.txt":
                if any(x in content for x in ["Disallow: /admin", "Disallow: /control", "Disallow: /api", "Disallow: /backup"]):
                    results["interesting_findings"].append("robots.txt hides sensitive paths (/admin, /api, or /backup)")
            
            if "security.txt" in filename:
                results["interesting_findings"].append("security.txt present (Vulnerability Disclosure Policy defined)")
        else:
            results["missing"].append(filename)
             
    return results
