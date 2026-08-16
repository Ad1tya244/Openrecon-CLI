import asyncio
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Dict, Any, Optional
import httpx
from openrecon.config import settings

# Constants
MAX_RESPONSE_SIZE = 10 * 1024 * 1024  # 10 MB
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OpenRecon/1.0"
CONNECT_TIMEOUT = settings.SOCKET_TIMEOUT
READ_TIMEOUT = settings.HTTP_TIMEOUT
MAX_REDIRECTS = 3

class SafeHTTPError(Exception):
    pass

def _validate_ip(ip_str: str):
    """
    Raises SafeHTTPError if IP is internal/private/loopback.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise SafeHTTPError(f"Blocked request to internal/private IP: {ip_str}")
        if not ip.is_global:
            raise SafeHTTPError(f"Blocked request to non-global IP: {ip_str}")
    except ValueError:
        raise SafeHTTPError(f"Invalid IP address: {ip_str}")

def _resolve_and_validate(hostname: str) -> str:
    """
    Resolves hostname to IP and validates it against SSRF rules.
    Returns the first valid IP.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        for info in addr_info:
            ip_addr = info[4][0]
            _validate_ip(ip_addr)
            return ip_addr
    except socket.gaierror:
        raise SafeHTTPError(f"Could not resolve hostname: {hostname}")
    except Exception as e:
        if isinstance(e, SafeHTTPError):
            raise
        raise SafeHTTPError(f"Resolution failed: {str(e)}")
    
    raise SafeHTTPError(f"No valid IPs found for resolution of {hostname}")

async def safe_request(method: str, url: str, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Performs a secure HTTP request (GET or HEAD).
    - Validates destination IP (SSRF protection).
    - Enforces size limits.
    - Enforces timeouts.
    - Handles redirects safely.
    """
    retries = 2
    base_delay = 0.5
    timeout = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)

    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
                redirects_left = MAX_REDIRECTS
                current_url = url
                initial_status = None
                
                while redirects_left >= 0:
                    parsed = urlparse(current_url)
                    if not parsed.hostname:
                        raise SafeHTTPError("Invalid URL: missing hostname")
                    
                    # SSRF Check: Resolve and Validate IP
                    target_ip = _resolve_and_validate(parsed.hostname)
                    
                    # Prepare headers
                    headers = {"User-Agent": USER_AGENT, "Host": parsed.hostname}
                    if extra_headers:
                        headers.update(extra_headers)
                        headers["Host"] = parsed.hostname
                    
                    scheme = parsed.scheme or "http"
                    formatted_ip = f"[{target_ip}]" if ":" in target_ip else target_ip
                    
                    request_url = f"{scheme}://{formatted_ip}"
                    if parsed.port:
                        request_url += f":{parsed.port}"
                    if parsed.path:
                        request_url += parsed.path
                    if parsed.query:
                        request_url += f"?{parsed.query}"
    
                    req = client.build_request(method, request_url, headers=headers)
                    response = await client.send(req, stream=True)
                    if initial_status is None:
                        initial_status = response.status_code
                    
                    # Size Limit Check (For GET)
                    content_chunks = []
                    total_size = 0
                    
                    if method == "GET":
                        async for chunk in response.aiter_bytes():
                            total_size += len(chunk)
                            if total_size > MAX_RESPONSE_SIZE:
                                await response.aclose()
                                break
                            content_chunks.append(chunk)
                    else:
                        await response.aclose()
    
                    content = b"".join(content_chunks)
                    content_str = content.decode("utf-8", errors="replace")
    
                    # Handle Redirects
                    if response.is_redirect:
                        next_location = response.headers.get("Location")
                        if not next_location:
                            break 
                            
                        if next_location.startswith("/"):
                            next_location = f"{scheme}://{parsed.hostname}{next_location}"
                        elif not next_location.startswith("http"):
                            next_location = f"{scheme}://{parsed.hostname}/{next_location}"
                        
                        current_url = next_location
                        redirects_left -= 1
                        await response.aclose()
                        continue
                    else:
                        content_len_hdr = response.headers.get("content-length")
                        content_len = int(content_len_hdr) if content_len_hdr and content_len_hdr.isdigit() else total_size
                        return {
                            "status_code": response.status_code,
                            "initial_status": initial_status,
                            "headers": dict(response.headers),
                            "content_text": content_str,
                            "content_length": content_len,
                            "redirects": MAX_REDIRECTS - redirects_left,
                            "url": current_url
                        }
    
                raise SafeHTTPError("Max redirects exceeded")

        except (httpx.ConnectError, httpx.ReadTimeout, httpx.PoolTimeout, httpx.NetworkError, httpx.RemoteProtocolError) as e:
            if attempt < retries - 1:
                await asyncio.sleep(base_delay * (attempt + 1))
                continue
            return {"error": f"Request failed after {retries} attempts: {str(e)}"}
        except Exception as e:
            return {"error": str(e)}
    
    return {"error": "Request failed"}

async def safe_get(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return await safe_request("GET", url, headers)

async def safe_head(url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    return await safe_request("HEAD", url, headers)
