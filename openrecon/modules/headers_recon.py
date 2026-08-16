from typing import Dict, Any
from openrecon.utils.safe_http import safe_get

async def analyze_headers(domain: str) -> Dict[str, Any]:
    """
    Analyzes HTTP response for status code, server, content-type, content-length,
    redirects, and final URL.
    """
    url = f"https://{domain}"
    results: Dict[str, Any] = {
        "headers": {},
        "server": None,
        "content_type": None,
        "content_length": None,
        "redirects": 0,
        "final_url": None,
        "status_code": None
    }
    
    response_data = await safe_get(url)
    if "error" in response_data:
        # Fallback to HTTP
        url = f"http://{domain}"
        response_data = await safe_get(url)
        if "error" in response_data:
            return {"error": response_data["error"]}

    server_headers = response_data.get("headers", {})
    server_headers_lower = {k.lower(): v for k, v in server_headers.items()}

    results["headers"] = server_headers
    results["status_code"] = response_data.get("status_code")
    results["final_url"] = response_data.get("url")
    results["redirects"] = response_data.get("redirects", 0)
    results["content_length"] = response_data.get("content_length")
    
    if "server" in server_headers_lower:
        results["server"] = server_headers_lower["server"]
    if "content-type" in server_headers_lower:
        results["content_type"] = server_headers_lower["content-type"]
        
    return results
