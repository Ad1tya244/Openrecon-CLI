from typing import Dict, Any, List
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
    Only retains files that actually return HTTP 200 OK.
    """
    base_url = f"https://{domain}"
    found_files: List[str] = []
    
    for filename in ALLOWLISTED_FILES:
        url = f"{base_url}/{filename}"
        response = await safe_get(url)
        
        # Fallback to HTTP if HTTPS fails with error
        if "error" in response:
            url = f"http://{domain}/{filename}"
            response = await safe_get(url)

        if "error" not in response and response.get("status_code") == 200:
            found_files.append(filename)
             
    return {
        "found": found_files
    }
