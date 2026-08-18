from typing import Dict, Any, Optional
from openrecon.utils.safe_http import safe_get

async def analyze_headers(domain: str) -> Dict[str, Any]:
    """
    Analyzes HTTP response for specific evidence-based fields:
    URL, Status Code, Server, Content-Type, Content-Length, HTTP Version,
    Redirects, Location, Final URL, Set-Cookie count, Date, Last-Modified, ETag.
    """
    initial_url = f"https://{domain}"
    response_data = await safe_get(initial_url)
    
    if "error" in response_data:
        # Fallback to HTTP if HTTPS fails completely
        initial_url = f"http://{domain}"
        response_data = await safe_get(initial_url)
        if "error" in response_data:
            return {"error": response_data["error"]}

    headers = response_data.get("headers", {})
    headers_lower = {k.lower(): v for k, v in headers.items()}

    status_code = response_data.get("status_code")
    final_url = response_data.get("url", initial_url)
    redirects = response_data.get("redirects", 0)
    http_ver = response_data.get("http_version", "HTTP/1.1")
    cookies_count = response_data.get("cookies_count", 0)

    server = headers_lower.get("server")
    content_type = headers_lower.get("content-type")
    
    # Only report Content-Length when the server actually sent the Content-Length header
    content_length_hdr = headers_lower.get("content-length")
    content_length = f"{content_length_hdr} bytes" if content_length_hdr is not None else None

    location = headers_lower.get("location")
    date_hdr = headers_lower.get("date")
    last_modified = headers_lower.get("last-modified")
    etag = headers_lower.get("etag")

    cookies_display = None
    if cookies_count > 0:
        cookies_display = f"{cookies_count} set"
    elif "set-cookie" in headers_lower:
        cookies_display = "Present"

    return {
        "url": initial_url,
        "status_code": status_code,
        "server": server,
        "content_type": content_type,
        "content_length": content_length,
        "http_version": http_ver,
        "redirects": redirects if redirects > 0 else 0,
        "location": location if redirects > 0 or (status_code and 300 <= status_code < 400) else None,
        "final_url": final_url,
        "cookies": cookies_display,
        "date": date_hdr,
        "last_modified": last_modified,
        "etag": etag,
        "headers": headers
    }
