import re
import asyncio
import urllib.parse
from typing import Dict, Any, List, Optional, Set
from openrecon.utils.safe_http import safe_head, safe_get

DIRECTORY_LISTING_SIGNATURES = [
    r"<title>\s*Index of\s+",
    r"<h1>\s*Index of\s+",
    r"<title>\s*Directory listing for\s+",
    r"<h2>\s*Directory listing for\s+",
    r"Directory Listing [Ff]or\s+",
    r"<a\s+href=[\"\']\.\./[\"\']>\.\./</a>",
    r"Parent Directory</a>",
    r"\[To Parent Directory\]",
    r"Volume Serial Number is",
    r"<table summary=[\"\']Directory Listing[\"\']",
]

def is_directory_listing(html_content: str) -> bool:
    """
    Inspects response body content to determine if it is a genuine directory listing.
    """
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
    Normalizes query strings, fragments, slashes, and URL encodings.
    Does not convert filenames into directories.
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
                # Filename with extension (e.g. style.css, app.js, file.pdf) -> parent is directory
                dir_segments = segments[:-1]
            else:
                # Action or page without extension (e.g. /admin/login) -> parent is /admin/
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
    """
    Extracts candidate directories exclusively from target-derived evidence:
    - Homepage HTML (<a href>, <link href>, <script src>, <img src>, etc.)
    - robots.txt (Disallow, Allow)
    - sitemap.xml (<loc>)
    """
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
    """
    Verifies a target-derived candidate directory path using:
    HEAD -> 200 OK -> GET -> directory-listing signature check.
    Only confirmed directory listings are returned.
    403, 401, 404, 5xx, and normal 200 pages are ignored.
    """
    async with semaphore:
        url = f"{base_url}{path}"
        head_resp = await safe_head(url)
        
        # HTTP fallback if HTTPS fails with network error
        if "error" in head_resp and base_url.startswith("https://"):
            url_http = f"http://{domain}{path}"
            head_resp_http = await safe_head(url_http)
            if "error" not in head_resp_http:
                head_resp = head_resp_http
                url = url_http
                
        if "error" in head_resp:
            return None
            
        status = head_resp.get("status_code", 0)
        
        # Only proceed to inspect if HEAD returns 200 OK
        if status == 200:
            get_resp = await safe_get(url)
            if "error" not in get_resp and get_resp.get("status_code") == 200:
                content = get_resp.get("content_text", "")
                if is_directory_listing(content):
                    return {
                        "path": path,
                        "status": "Exposed",
                        "status_code": 200,
                        "is_exposed": True,
                        "url": get_resp.get("url", url)
                    }
                    
        return None

async def check_directory_exposure(
    domain: str,
    discovered_urls: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Discovers candidate directories exclusively from target-derived evidence
    (homepage HTML, robots.txt, sitemap.xml, and existing reconnaissance URLs),
    then verifies whether those directories are openly listed.
    Only confirmed exposed directory listings are returned as findings.
    """
    base_url = f"https://{domain}"
    candidate_paths: Set[str] = set()
    
    # 1. Extract from any passed-in reconnaissance URLs
    if discovered_urls:
        for u in discovered_urls:
            for d in extract_directories_from_url(u, domain):
                candidate_paths.add(d)
                
    # 2. Extract from target's robots.txt, sitemap.xml, and homepage HTML
    passive_dirs = await _discover_target_directories(base_url, domain)
    candidate_paths.update(passive_dirs)
    
    # 3. Clean & Deduplicate candidate paths
    normalized_candidates = []
    seen = set()
    for raw in sorted(list(candidate_paths)):
        p = "/" + raw.strip("/").strip() + "/"
        if p != "//" and p.lower() not in seen:
            seen.add(p.lower())
            normalized_candidates.append(p)
            
    # Bound concurrent checks
    semaphore = asyncio.Semaphore(10)
    tasks = [
        _verify_single_directory(path, base_url, domain, semaphore)
        for path in normalized_candidates
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    exposed_findings = []
    for item in results:
        if isinstance(item, dict) and item is not None:
            exposed_findings.append(item)
            
    # Sort alphabetically
    exposed_findings.sort(key=lambda x: x["path"])
    exposed_paths = [f["path"] for f in exposed_findings]
    
    return {
        "exposed_directories": exposed_paths,
        "findings": exposed_findings,
        "paths": exposed_findings,
        "total": len(exposed_findings),
        "candidates_derived": len(normalized_candidates)
    }
