import os
import re
import json
import asyncio
from typing import Dict, Any, List, Optional, Set
from openrecon.utils.safe_http import safe_get

DEFAULT_FINGERPRINTS_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "technologies.json")
)

_DEFAULT_FINGERPRINTS_CACHE: Optional[Dict[str, Any]] = None

CATEGORY_STANDARD_MAP = {
    "web servers": "Web Server",
    "web server": "Web Server",
    "programming languages": "Backend",
    "backend": "Backend",
    "databases": "Backend",
    "ui frameworks": "Frontend",
    "frontend": "Frontend",
    "font scripts": "Frontend",
    "cms": "CMS",
    "web frameworks": "Framework",
    "frameworks": "Framework",
    "framework": "Framework",
    "paas": "Runtime",
    "runtimes": "Runtime",
    "runtime": "Runtime",
    "analytics": "Analytics",
    "javascript libraries": "JavaScript Libraries",
    "javascript graphics": "JavaScript Libraries",
    "cdn": "CDN / Proxy",
    "reverse proxies": "CDN / Proxy",
    "cdn / proxy": "CDN / Proxy",
    "security": "CDN / Proxy",
}

def standardize_category(raw_cat: str) -> str:
    if not raw_cat:
        return "Frontend"
    c_lower = raw_cat.strip().lower()
    return CATEGORY_STANDARD_MAP.get(c_lower, "Frontend")

def load_fingerprints(custom_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Loads technology fingerprints from the authoritative JSON database.
    """
    global _DEFAULT_FINGERPRINTS_CACHE

    target_path = custom_path or DEFAULT_FINGERPRINTS_PATH
    
    if not custom_path and _DEFAULT_FINGERPRINTS_CACHE is not None:
        return _DEFAULT_FINGERPRINTS_CACHE

    if target_path and os.path.isfile(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                techs = data.get("technologies", data)
                if not custom_path and techs:
                    _DEFAULT_FINGERPRINTS_CACHE = techs
                return techs
        except Exception:
            pass

    return {}

def extract_meta_tags(html: str) -> Dict[str, List[str]]:
    """Extracts name/property to content mappings from HTML meta tags."""
    if not html or not isinstance(html, str):
        return {}
    meta_dict: Dict[str, List[str]] = {}
    
    pattern1 = re.compile(r'<meta\s+[^>]*name=[\"\']([^\"\'>]+)[\"\'][^>]*content=[\"\']([^\"\'>]+)[\"\']', re.IGNORECASE)
    pattern2 = re.compile(r'<meta\s+[^>]*content=[\"\']([^\"\'>]+)[\"\'][^>]*name=[\"\']([^\"\'>]+)[\"\']', re.IGNORECASE)
    pattern3 = re.compile(r'<meta\s+[^>]*property=[\"\']([^\"\'>]+)[\"\'][^>]*content=[\"\']([^\"\'>]+)[\"\']', re.IGNORECASE)

    for match in pattern1.finditer(html):
        name, content = match.group(1).lower().strip(), match.group(2).strip()
        meta_dict.setdefault(name, []).append(content)

    for match in pattern2.finditer(html):
        content, name = match.group(1).strip(), match.group(2).lower().strip()
        meta_dict.setdefault(name, []).append(content)

    for match in pattern3.finditer(html):
        prop, content = match.group(1).lower().strip(), match.group(2).strip()
        meta_dict.setdefault(prop, []).append(content)

    return meta_dict

def extract_asset_urls(html: str) -> Dict[str, List[str]]:
    """Extracts script and stylesheet URLs from HTML body."""
    if not html or not isinstance(html, str):
        return {"scripts": [], "css": [], "all_assets": [], "inline_js": []}
        
    script_matches = re.findall(r'<script\s+[^>]*src=[\"\']([^\"\'>\s]+)[\"\']', html, re.IGNORECASE)
    css_matches = re.findall(r'<link\s+[^>]*href=[\"\']([^\"\'>\s]+)[\"\']', html, re.IGNORECASE)
    img_matches = re.findall(r'<img\s+[^>]*src=[\"\']([^\"\'>\s]+)[\"\']', html, re.IGNORECASE)
    inline_js = re.findall(r'<script(?:\s+[^>]*)?>([\s\S]*?)</script>', html, re.IGNORECASE)

    all_assets = []
    all_assets.extend(script_matches)
    all_assets.extend(css_matches)
    all_assets.extend(img_matches)

    return {
        "scripts": script_matches,
        "css": css_matches,
        "all_assets": all_assets,
        "inline_js": inline_js
    }

def identify_technologies(
    headers: Dict[str, Any],
    html: str,
    fingerprints: Optional[Dict[str, Any]] = None,
    url: Optional[str] = None,
    robots_txt: Optional[str] = None
) -> Dict[str, Any]:
    """
    Strictly evidence-based technology identification across:
    HTTP headers, cookies, HTML patterns, meta tags, script references, CSS asset names.
    Does not infer technologies without direct observed evidence.
    """
    if fingerprints is None:
        fingerprints = load_fingerprints()

    headers_lower = {k.lower(): str(v) for k, v in headers.items()} if headers else {}
    set_cookie_val = ""
    for k, v in headers_lower.items():
        if k == "set-cookie" or "cookie" in k:
            set_cookie_val += f" {v}"

    html_str = html or ""
    meta_tags = extract_meta_tags(html_str)
    assets = extract_asset_urls(html_str)
    script_urls = assets["scripts"]
    css_urls = assets["css"]
    inline_js_text = "\n".join(assets["inline_js"])
    url_str = url or ""
    robots_str = robots_txt or ""

    detected_techs: Dict[str, Dict[str, Any]] = {}

    for tech_name, rule in fingerprints.items():
        raw_category = rule.get("category", "Frontend")
        category = standardize_category(raw_category)
        matched = False
        version: Optional[str] = None

        # 1. Header Match (Evidence)
        if "headers" in rule and isinstance(rule["headers"], dict):
            for h_name, pat in rule["headers"].items():
                h_name_lower = h_name.lower()
                if h_name_lower in headers_lower:
                    actual_val = headers_lower[h_name_lower]
                    m = re.search(pat, actual_val, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            version = version or m.group(1).strip()

        # 2. Cookie Match (Evidence)
        if "cookies" in rule:
            cookie_pats = rule["cookies"]
            if isinstance(cookie_pats, list):
                for c_pat in cookie_pats:
                    if re.search(c_pat, set_cookie_val, re.IGNORECASE):
                        matched = True
            elif isinstance(cookie_pats, dict):
                for c_name, c_pat in cookie_pats.items():
                    if re.search(c_name, set_cookie_val, re.IGNORECASE):
                        if c_pat:
                            m = re.search(c_pat, set_cookie_val, re.IGNORECASE)
                            if m:
                                matched = True
                                if m.groups() and m.group(1):
                                    version = version or m.group(1).strip()
                        else:
                            matched = True

        # 3. Meta Tags Match (Evidence)
        if "meta" in rule and isinstance(rule["meta"], dict):
            for m_name, pat in rule["meta"].items():
                m_name_lower = m_name.lower()
                if m_name_lower in meta_tags:
                    for content_val in meta_tags[m_name_lower]:
                        m = re.search(pat, content_val, re.IGNORECASE)
                        if m:
                            matched = True
                            if m.groups() and m.group(1):
                                version = version or m.group(1).strip()

        # 4. Scripts / ScriptSrc Match (Evidence)
        script_patterns = rule.get("scripts") or rule.get("scriptSrc")
        if script_patterns and isinstance(script_patterns, list):
            for pat in script_patterns:
                for s_url in script_urls:
                    m = re.search(pat, s_url, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            version = version or m.group(1).strip()

        # 5. CSS Assets Match (Evidence)
        if "css" in rule and isinstance(rule["css"], list):
            for pat in rule["css"]:
                for c_url in css_urls:
                    m = re.search(pat, c_url, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            version = version or m.group(1).strip()

        # 6. HTML Match (Evidence)
        if "html" in rule and html_str:
            html_pats = rule["html"]
            if isinstance(html_pats, list):
                for h_pat in html_pats:
                    m = re.search(h_pat, html_str, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            version = version or m.group(1).strip()
            elif isinstance(html_pats, str):
                m = re.search(html_pats, html_str, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = version or m.group(1).strip()

        # 7. JavaScript Pattern Match in Inline JS (Evidence)
        if "js" in rule and inline_js_text:
            js_pats = rule["js"]
            if isinstance(js_pats, list):
                for j_pat in js_pats:
                    m = re.search(j_pat, inline_js_text, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            version = version or m.group(1).strip()

        if matched:
            detected_techs[tech_name] = {
                "name": tech_name,
                "version": version,
                "category": category
            }

    # Group into categories
    categories_dict: Dict[str, List[Dict[str, Any]]] = {}
    for tech in detected_techs.values():
        cat = tech["category"]
        if cat not in categories_dict:
            categories_dict[cat] = []
        categories_dict[cat].append(tech)

    return {
        "technologies": list(detected_techs.values()),
        "categories": categories_dict,
        "total_detected": len(detected_techs)
    }

async def analyze_technology(domain: str) -> Dict[str, Any]:
    """Fetches target homepage and inspects technology stack."""
    url = f"https://{domain}"
    response = await safe_get(url)
    if "error" in response:
        url = f"http://{domain}"
        response = await safe_get(url)
        if "error" in response:
            return {"error": "Target unreachable or offline"}

    headers = response.get("headers", {})
    html_content = response.get("content_text", "")
    
    # Try fetching robots.txt for safe additional asset cues
    robots_resp = await safe_get(f"{url.rstrip('/')}/robots.txt")
    robots_text = robots_resp.get("content_text", "") if "error" not in robots_resp else ""

    return identify_technologies(
        headers=headers,
        html=html_content,
        url=response.get("url", url),
        robots_txt=robots_text
    )

# Alias for module registry compatibility
get_tech_fingerprint = analyze_technology
