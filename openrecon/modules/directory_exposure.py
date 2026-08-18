import re
import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional, Set
from openrecon.utils.safe_http import safe_get, safe_head

DIRECTORY_LISTING_SIGNATURES = [
    r"<title>\s*Index of\s+",
    r"<h1>\s*Index of\s+",
    r"<title>\s*Directory listing for\s+",
    r"<h2>\s*Directory listing for\s+",
    r"Directory Listing [Ff]or\s+",
    r"<a\s+href=[\"\']\.\./[\"\']>\.\./</a>",
    r"<a\s+href=[\"\']\.\./?[\"\']>\s*Parent Directory\s*</a>",
    r"Parent Directory</a>",
    r"\[To Parent Directory\]",
    r"Volume Serial Number is",
    r"<table summary=[\"\']Directory Listing[\"\']",
]

def is_directory_listing(html_content: str) -> bool:
    """Inspects response body content to determine if it is a genuine directory listing."""
    if not html_content or not isinstance(html_content, str):
        return False
    for sig in DIRECTORY_LISTING_SIGNATURES:
        if re.search(sig, html_content, re.IGNORECASE):
            return True
    return False

def extract_directories_from_url(raw_url: str, domain: str) -> List[str]:
    """
    Extracts and normalizes parent directory paths from a target URL or path.
    Only retains paths belonging to the authorized target domain scope.
    """
    if not raw_url or not isinstance(raw_url, str):
        return []
    raw = raw_url.strip()
    if not raw or raw.startswith("javascript:") or raw.startswith("data:") or raw.startswith("mailto:"):
        return []
    try:
        parsed = urllib.parse.urlparse(raw)
        if parsed.netloc:
            netloc = parsed.netloc.split(":")[0].lower()
            if netloc != domain.lower() and not netloc.endswith("." + domain.lower()):
                return []
                
        path = urllib.parse.unquote(parsed.path).strip()
        path = path.split("?")[0].split("#")[0].strip()
        if not path or path == "/":
            return []
            
        has_trailing_slash = path.endswith("/")
        segments = [s for s in path.strip("/").split("/") if s and s != "."]
        if not segments:
            return []
            
        if has_trailing_slash:
            dir_segments = segments
        else:
            last = segments[-1]
            if "." in last:
                dir_segments = segments[:-1]
            else:
                dir_segments = segments[:-1] if len(segments) > 1 else segments
                
        if not dir_segments:
            return []
            
        dirs = []
        curr = ""
        for seg in dir_segments:
            curr += "/" + seg
            dirs.append(curr + "/")
            
        return dirs
    except Exception:
        return []

async def _discover_target_directories(base_url: str, domain: str) -> Set[str]:
    discovered: Set[str] = set()
    
    # 1. robots.txt
    try:
        resp = await safe_get(f"{base_url}/robots.txt")
        if "error" not in resp and resp.get("status_code") == 200:
            content = resp.get("content_text", "")
            matches = re.findall(r"(?:Disallow|Allow)\s*:\s*([^\s#]+)", content)
            for m in matches:
                for d in extract_directories_from_url(m, domain):
                    discovered.add(d)
    except Exception:
        pass

    # 2. sitemap.xml
    try:
        resp = await safe_get(f"{base_url}/sitemap.xml")
        if "error" not in resp and resp.get("status_code") == 200:
            content = resp.get("content_text", "")
            locs = re.findall(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", content)
            for loc in locs[:50]:
                for d in extract_directories_from_url(loc, domain):
                    discovered.add(d)
    except Exception:
        pass

    # 3. Homepage HTML
    try:
        resp = await safe_get(f"{base_url}/")
        if "error" not in resp and resp.get("status_code") == 200:
            content = resp.get("content_text", "")
            links = re.findall(r'(?:href|src|action|data-src|poster)\s*=\s*["\']([^"\'\s>]+)["\']', content)
            for link in links[:100]:
                for d in extract_directories_from_url(link, domain):
                    discovered.add(d)
    except Exception:
        pass

    return discovered

async def _verify_single_directory(
    path: str,
    base_url: str,
    domain: str,
    semaphore: asyncio.Semaphore
) -> Optional[Dict[str, Any]]:
    async with semaphore:
        url = f"{base_url}{path}"
        head_resp = await safe_head(url)
        
        if "error" in head_resp and base_url.startswith("https://"):
            url_http = f"http://{domain}{path}"
            head_resp_http = await safe_head(url_http)
            if "error" not in head_resp_http:
                head_resp = head_resp_http
                url = url_http
                
        if "error" in head_resp:
            return None
            
        status = head_resp.get("status_code", 0)
        
        # Only HTTP 200 with verified directory listing signature qualifies
        if status == 200:
            get_resp = await safe_get(url)
            if "error" not in get_resp and get_resp.get("status_code") == 200:
                content = get_resp.get("content_text", "")
                if is_directory_listing(content):
                    return {
                        "path": path,
                        "status": "200 EXPOSED",
                        "status_code": 200,
                        "is_exposed": True
                    }
                    
        return None

async def check_directory_exposure(
    domain: str,
    discovered_urls: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Discovers candidate directories from target-derived evidence and tests them internally.
    ONLY returns confirmed exposed directories with verifiable directory listing signatures.
    """
    base_url = f"https://{domain}"
    candidate_paths: Set[str] = set()
    
    if discovered_urls:
        for u in discovered_urls:
            for d in extract_directories_from_url(u, domain):
                candidate_paths.add(d)
                
    passive_dirs = await _discover_target_directories(base_url, domain)
    candidate_paths.update(passive_dirs)
    
    normalized_candidates = []
    seen = set()
    for raw in sorted(list(candidate_paths)):
        p = "/" + raw.strip("/").strip() + "/"
        if p != "//" and p.lower() not in seen:
            seen.add(p.lower())
            normalized_candidates.append(p)
            
    semaphore = asyncio.Semaphore(10)
    tasks = [
        _verify_single_directory(path, base_url, domain, semaphore)
        for path in normalized_candidates
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    findings = []
    for item in results:
        if isinstance(item, dict) and item is not None and item.get("is_exposed"):
            findings.append(item)
            
    findings.sort(key=lambda x: x["path"])
    
    return {
        "findings": findings,
        "total": len(findings)
    }
