from openrecon.utils.findings import Finding, Evidence
import os
import re
import json
import asyncio
from typing import Dict, Any, List, Optional, Tuple, Set
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

def map_engine_cats_to_presentation(tech_cats: List[Dict[str, Any]], tech_name: str, fallback_cat: str = "") -> str:
    """Presentation-only mapping from Technology Engine category IDs/names to OpenRecon display categories."""
    name_lower = tech_name.lower().strip()
    
    # Specific overrides (protocols, security policies, web standards, or specific tech roles)
    if name_lower in ("http/3", "open graph", "priority hints", "rss", "amp"):
        return "Web standards / metadata"
    if name_lower in ("hsts", "dnssec", "cloudflare bot management", "onetrust", "ubuntu"):
        return "Security / Infrastructure"
    if name_lower == "ethicalads":
        return "Analytics"
    if name_lower in ("google fonts", "google font api"):
        return "CDN / Proxy"
    if name_lower == "google custom search":
        return "CMS"
        
    for cat in tech_cats:
        # Check by category name first (handles fallback and implies results)
        cat_name = cat.get("name", "")
        if cat_name:
            cn_lower = cat_name.lower().strip()
            if cn_lower in ("web servers", "web server", "reverse proxies", "load balancers"):
                return "Web Server"
            elif cn_lower in ("backend", "databases", "programming languages", "web frameworks", "frameworks", "framework"):
                return "Backend"
            elif cn_lower in ("frontend", "ui frameworks", "javascript frameworks", "page builders", "static site generator", "editors"):
                return "Frontend frameworks/libraries"
            elif cn_lower in ("javascript libraries", "javascript graphics"):
                return "JavaScript Libraries"
            elif cn_lower in ("cms", "blogs", "ecommerce", "message boards", "lms", "wikis", "search engines"):
                return "CMS"
            elif cn_lower in ("analytics", "tag managers", "surveys", "a/b testing", "rum", "browser fingerprinting", "customer data platform", "advertising"):
                return "Analytics"
            elif cn_lower in ("cdn", "proxy", "cdn / proxy", "hosting", "paas", "iaas", "caching", "font scripts"):
                return "CDN / Proxy"
            elif cn_lower in ("security", "infrastructure", "security / infrastructure", "authentication", "ssl/tls certificate authorities", "containers", "operating systems", "privacy"):
                return "Security / Infrastructure"
                
        cat_id = cat.get("id")
        if not cat_id:
            continue
        try:
            cat_id = int(cat_id)
        except Exception:
            continue
            
        if cat_id in (22, 33, 64, 65):
            return "Web Server"
        elif cat_id in (27, 34, 3, 18, 82, 87):
            return "Backend"
        elif cat_id in (12, 66, 51, 57, 20, 26):
            return "Frontend frameworks/libraries"
        elif cat_id in (59, 25):
            return "JavaScript Libraries"
        elif cat_id in (1, 11, 2, 6, 21, 8, 29):
            return "CMS"
        elif cat_id in (10, 42, 73, 74, 78, 83, 97, 76):
            return "Analytics"
        elif cat_id in (31, 88, 62, 63, 23, 17):
            return "CDN / Proxy"
        elif cat_id in (16, 69, 70, 60, 28, 95):
            return "Security / Infrastructure"
            
    # Map raw string category if present (e.g. from fallback rules)
    if fallback_cat:
        fc_lower = fallback_cat.lower().strip()
        if fc_lower in ("web servers", "web server"):
            return "Web Server"
        elif fc_lower in ("backend", "databases", "programming languages", "framework", "web frameworks"):
            return "Backend"
        elif fc_lower in ("frontend", "ui frameworks"):
            return "Frontend frameworks/libraries"
        elif fc_lower in ("javascript libraries", "javascript graphics"):
            return "JavaScript Libraries"
        elif fc_lower in ("cms", "blogs", "ecommerce", "search engines"):
            return "CMS"
        elif fc_lower in ("analytics", "advertising"):
            return "Analytics"
        elif fc_lower in ("cdn", "proxy", "cdn / proxy", "hosting", "font scripts"):
            return "CDN / Proxy"
        elif fc_lower in ("security", "infrastructure", "security / infrastructure", "operating systems", "privacy"):
            return "Security / Infrastructure"
            
    return "Web standards / metadata"
    if name_lower in ("hsts", "dnssec"):
        return "Security / Infrastructure"
        
    for cat in tech_cats:
        # Check by category name first (handles fallback and implies results)
        cat_name = cat.get("name", "")
        if cat_name:
            cn_lower = cat_name.lower().strip()
            if cn_lower in ("web servers", "web server", "reverse proxies", "load balancers"):
                return "Web Server"
            elif cn_lower in ("backend", "databases", "programming languages", "web frameworks", "frameworks", "framework"):
                return "Backend"
            elif cn_lower in ("frontend", "ui frameworks", "font scripts", "javascript frameworks", "page builders", "static site generator", "editors"):
                return "Frontend frameworks/libraries"
            elif cn_lower in ("javascript libraries", "javascript graphics"):
                return "JavaScript Libraries"
            elif cn_lower in ("cms", "blogs", "ecommerce", "message boards", "lms", "wikis"):
                return "CMS"
            elif cn_lower in ("analytics", "tag managers", "surveys", "a/b testing", "rum", "browser fingerprinting", "customer data platform"):
                return "Analytics"
            elif cn_lower in ("cdn", "proxy", "cdn / proxy", "hosting", "paas", "iaas", "caching"):
                return "CDN / Proxy"
            elif cn_lower in ("security", "infrastructure", "security / infrastructure", "authentication", "ssl/tls certificate authorities", "containers"):
                return "Security / Infrastructure"
                
        cat_id = cat.get("id")
        if not cat_id:
            continue
        try:
            cat_id = int(cat_id)
        except Exception:
            continue
            
        if cat_id in (22, 33, 64, 65):
            return "Web Server"
        elif cat_id in (27, 34, 3, 18):
            return "Backend"
        elif cat_id in (12, 66, 51, 57, 20, 17, 26):
            return "Frontend frameworks/libraries"
        elif cat_id in (59, 25):
            return "JavaScript Libraries"
        elif cat_id in (1, 11, 2, 6, 21, 8):
            return "CMS"
        elif cat_id in (10, 42, 73, 74, 78, 83, 97):
            return "Analytics"
        elif cat_id in (31, 88, 62, 63, 23):
            return "CDN / Proxy"
        elif cat_id in (16, 69, 70, 60):
            return "Security / Infrastructure"
            
    # Map raw string category if present (e.g. from fallback rules)
    if fallback_cat:
        fc_lower = fallback_cat.lower().strip()
        if fc_lower in ("web servers", "web server"):
            return "Web Server"
        elif fc_lower in ("backend", "databases", "programming languages", "framework", "web frameworks"):
            return "Backend"
        elif fc_lower in ("frontend", "ui frameworks", "font scripts"):
            return "Frontend frameworks/libraries"
        elif fc_lower in ("javascript libraries", "javascript graphics"):
            return "JavaScript Libraries"
        elif fc_lower in ("cms", "blogs", "ecommerce"):
            return "CMS"
        elif fc_lower == "analytics":
            return "Analytics"
        elif fc_lower in ("cdn", "proxy", "cdn / proxy", "hosting"):
            return "CDN / Proxy"
        elif fc_lower in ("security", "infrastructure", "security / infrastructure"):
            return "Security / Infrastructure"
            
    return "Web standards / metadata"
    if name_lower in ("hsts", "dnssec"):
        return "Security / Infrastructure"
        
    for cat in tech_cats:
        cat_id = cat.get("id")
        if not cat_id:
            continue
        try:
            cat_id = int(cat_id)
        except Exception:
            continue
            
        if cat_id in (22, 33, 64, 65):
            return "Web Server"
        elif cat_id in (27, 34, 3, 18):
            return "Backend"
        elif cat_id in (12, 66, 51, 57, 20, 17, 26):
            return "Frontend frameworks/libraries"
        elif cat_id in (59, 25):
            return "JavaScript Libraries"
        elif cat_id in (1, 11, 2, 6, 21, 8):
            return "CMS"
        elif cat_id in (10, 42, 73, 74, 78, 83, 97):
            return "Analytics"
        elif cat_id in (31, 88, 62, 63, 23):
            return "CDN / Proxy"
        elif cat_id in (16, 69, 70, 60):
            return "Security / Infrastructure"
            
    # Map raw string category if present (e.g. from fallback rules)
    if fallback_cat:
        fc_lower = fallback_cat.lower().strip()
        if fc_lower in ("web servers", "web server"):
            return "Web Server"
        elif fc_lower in ("backend", "databases", "programming languages", "framework", "web frameworks"):
            return "Backend"
        elif fc_lower in ("frontend", "ui frameworks", "font scripts"):
            return "Frontend frameworks/libraries"
        elif fc_lower in ("javascript libraries", "javascript graphics"):
            return "JavaScript Libraries"
        elif fc_lower in ("cms", "blogs", "ecommerce"):
            return "CMS"
        elif fc_lower == "analytics":
            return "Analytics"
        elif fc_lower in ("cdn", "proxy", "cdn / proxy", "hosting"):
            return "CDN / Proxy"
        elif fc_lower in ("security", "infrastructure", "security / infrastructure"):
            return "Security / Infrastructure"
            
    return "Web standards / metadata"
    if name_lower in ("hsts", "dnssec"):
        return "Security / Infrastructure"
        
    for cat in tech_cats:
        cat_id = cat.get("id")
        if not cat_id:
            continue
        try:
            cat_id = int(cat_id)
        except Exception:
            continue
            
        if cat_id in (22, 33, 64, 65):
            return "Web Server"
        elif cat_id in (27, 34, 3, 18):
            return "Backend"
        elif cat_id in (12, 66, 51, 57, 20, 17, 26):
            return "Frontend frameworks/libraries"
        elif cat_id in (59, 25):
            return "JavaScript Libraries"
        elif cat_id in (1, 11, 2, 6, 21, 8):
            return "CMS"
        elif cat_id in (10, 42, 73, 74, 78, 83, 97):
            return "Analytics"
        elif cat_id in (31, 88, 62, 63, 23):
            return "CDN / Proxy"
        elif cat_id in (16, 69, 70, 60):
            return "Security / Infrastructure"
            
    return "Web standards / metadata"

def merge_and_deduplicate_detections(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicates normalized technology names after detection, merging confidence and versions."""
    aliases = {
        "Apache HTTP Server": ["apache", "apache http server"],
        "Vue.js": ["vue", "vue.js"],
        "Nuxt": ["nuxt", "nuxt.js"],
        "React": ["react", "react.js"],
        "Angular": ["angular", "angular.js"],
        "Express": ["express", "express.js"],
        "Node.js": ["node", "node.js"],
        "Tailwind CSS": ["tailwind", "tailwindcss", "tailwind css"],
        "Google Analytics": ["google analytics", "google analytics enhanced ecommerce"]
    }
    
    alias_to_canonical = {}
    for canonical, alias_list in aliases.items():
        for a in alias_list:
            alias_to_canonical[a.lower()] = canonical
            
    merged: Dict[str, Dict[str, Any]] = {}
    
    for item in detections:
        name = item.get("name")
        if not name:
            continue
            
        canonical = alias_to_canonical.get(name.lower(), name)
        ver = item.get("version") or None
        confidence = item.get("confidence", 100)
        evidence = item.get("evidence", [])
        
        if canonical not in merged:
            merged[canonical] = {
                "name": canonical,
                "version": ver,
                "confidence": confidence,
                "categories": item.get("categories", []),
                "category": item.get("category", ""),
                "evidence": list(evidence)
            }
        else:
            if confidence > merged[canonical]["confidence"]:
                merged[canonical]["confidence"] = confidence
            existing_ver = merged[canonical]["version"]
            if not existing_ver or (ver and len(ver) > len(existing_ver)):
                merged[canonical]["version"] = ver
            merged[canonical]["evidence"].extend(evidence)
            
    for canonical in merged:
        merged[canonical]["evidence"] = deduplicate_evidence_list(merged[canonical]["evidence"])
                
    return list(merged.values())

def deduplicate_evidence_list(evidence_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    deduped = []
    for ev in evidence_list:
        eng = ev.get("detection_engine", "technology-engine")
        ev_type = ev.get("type", "unknown")
        src = ev.get("source") or ""
        snip = ev.get("snippet") or ev.get("value") or ev.get("match") or ""
        loc = ev.get("location") or ""
        identity = (eng, ev_type, src, snip, loc)
        if identity not in seen:
            seen.add(identity)
            deduped.append(ev)
    return deduped

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

class TechnologyPattern:
    r"""
    Direct port of Technology engine's pattern parser and version resolver.
    Parses 'regex\;version:\1\;confidence:50\;excludes:Tech' syntax.
    """
    def __init__(self, raw: str):
        self.raw = str(raw)
        parts = self.raw.split(r"\;")
        self.regex_str = parts[0]
        self.version_spec: Optional[str] = None
        self.confidence = 100
        self.excludes: List[str] = []
        
        for p in parts[1:]:
            if ":" in p:
                k, v = p.split(":", 1)
                k = k.strip().lower()
                v = v.strip()
                if k == "version":
                    self.version_spec = v
                elif k == "confidence":
                    try:
                        self.confidence = int(v)
                    except ValueError:
                        self.confidence = 100
                elif k == "excludes":
                    self.excludes.append(v)
        
        try:
            self.regex = re.compile(self.regex_str, re.IGNORECASE)
        except Exception:
            self.regex = re.compile(re.escape(self.regex_str), re.IGNORECASE)

    def match(self, value: str) -> Optional[Tuple[re.Match, Optional[str]]]:
        if not value:
            return None
        m = self.regex.search(value)
        if not m:
            return None
        
        resolved_version = None
        if self.version_spec:
            ver = self.version_spec
            ternary_m = re.search(r'\\(\d+)\?([^:]+):(.*)$', ver)
            if ternary_m:
                idx = int(ternary_m.group(1))
                val = m.group(idx) if idx <= len(m.groups()) and m.group(idx) else None
                ver = ternary_m.group(2) if val else ternary_m.group(3)
                if val and "\\1" in ver:
                    ver = ver.replace(f"\\{idx}", val)
            else:
                for idx, g in enumerate(m.groups(), 1):
                    if g:
                        ver = ver.replace(f"\\{idx}", g)
            ver = re.sub(r'\\\d+', '', ver).strip()
            if ver and len(ver) <= 15:
                try:
                    if int(ver) < 10000:
                        resolved_version = ver
                except ValueError:
                    resolved_version = ver
        elif m.groups():
            for g in m.groups():
                if g and isinstance(g, str):
                    g_clean = g.strip()
                    if re.match(r'^[0-9]+(?:\.[0-9]+)*', g_clean):
                        resolved_version = g_clean
                        break
                    
        return m, resolved_version


def resolve_technology_graph(detected: Dict[str, Dict[str, Any]], all_rules: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Applies Technology-inspired relational rules:
    - 'implies': recursively adds implied technologies with confidence
    - 'excludes': eliminates mutually exclusive/generic technologies
    - 'requires': removes technologies whose mandatory prerequisites are missing
    """
    resolved = dict(detected)
    
    # 1. Resolve Implies recursively
    changed = True
    while changed:
        changed = False
        for name in list(resolved.keys()):
            rule = all_rules.get(name, {})
            implies_list = rule.get("implies", [])
            if isinstance(implies_list, str):
                implies_list = [implies_list]
            for imp_name in implies_list:
                if imp_name not in resolved and imp_name in all_rules:
                    imp_rule = all_rules[imp_name]
                    raw_cat = imp_rule.get("category", "Backend")
                    resolved[imp_name] = {
                        "name": imp_name,
                        "version": None,
                        "category": standardize_category(raw_cat)
                    }
                    changed = True

    # 2. Resolve Excludes
    for name in list(resolved.keys()):
        if name in resolved:
            rule = all_rules.get(name, {})
            excludes_list = rule.get("excludes", [])
            if isinstance(excludes_list, str):
                excludes_list = [excludes_list]
            for exc_name in excludes_list:
                if exc_name in resolved:
                    del resolved[exc_name]

    # 3. Resolve Requires
    for name in list(resolved.keys()):
        rule = all_rules.get(name, {})
        requires_list = rule.get("requires", [])
        if isinstance(requires_list, str):
            requires_list = [requires_list]
        for req_name in requires_list:
            if req_name not in resolved:
                del resolved[name]
                break

    return resolved


def format_dns_for_technology_engine(dns_raw: Optional[Dict[str, Any]]) -> Dict[str, List[str]]:
    wapp_dns = {}
    if not dns_raw:
        return wapp_dns
        
    for rtype in ["TXT", "MX", "NS", "CNAME", "SOA"]:
        raw_vals = dns_raw.get(rtype, [])
        cleaned = []
        for val in raw_vals:
            # Strip TTL if present (e.g. "blah (TTL: 3600)" -> "blah")
            val_str = str(val)
            if " (TTL:" in val_str:
                val_str = val_str.split(" (TTL:")[0].strip()
            
            # For MX, extract only the hostname (e.g. "10 mail.example.com" -> "mail.example.com")
            if rtype == "MX":
                parts = val_str.split()
                if len(parts) > 1:
                    val_str = parts[1].strip()
                elif parts:
                    val_str = parts[0].strip()
            
            # Strip trailing dots from hostnames
            if rtype in ("CNAME", "MX", "NS"):
                val_str = val_str.rstrip(".")
                
            cleaned.append(val_str)
        if cleaned:
            wapp_dns[rtype.lower()] = cleaned
    return wapp_dns


def prepare_technology_items(
    headers: Dict[str, Any],
    html: str,
    url: str,
    dns_records: Optional[Dict[str, Any]] = None,
    css_contents: Optional[List[str]] = None,
    cert_issuer: Optional[str] = None,
    robots_txt: Optional[str] = None,
    text_content: Optional[str] = None
) -> Dict[str, Any]:
    """Prepares structured inputs in the format expected by Technology runner."""
    headers_dict = {}
    cookies_dict = {}
    if headers:
        for k, v in headers.items():
            k_lower = k.lower()
            val_str = str(v)
            if k_lower not in headers_dict:
                headers_dict[k_lower] = []
            headers_dict[k_lower].append(val_str)
            
            # Extract cookies
            if k_lower == "set-cookie":
                for cookie_part in val_str.split(","):
                    cookie_name_val = cookie_part.strip().split(";")[0]
                    if "=" in cookie_name_val:
                        c_name, c_val = cookie_name_val.split("=", 1)
                        c_name = c_name.strip()
                        if c_name not in cookies_dict:
                            cookies_dict[c_name] = []
                        cookies_dict[c_name].append(c_val.strip())

    html_str = html or ""
    meta_dict = {}
    if html_str:
        extracted_metas = extract_meta_tags(html_str)
        for k, vals in extracted_metas.items():
            meta_dict[k.lower()] = vals

    assets = extract_asset_urls(html_str)
    script_srcs = assets.get("scripts", [])
    inline_js = assets.get("inline_js", [])

    return {
        "url": url or "",
        "html": html_str,
        "headers": headers_dict,
        "cookies": cookies_dict,
        "meta": meta_dict,
        "scriptSrc": script_srcs,
        "scripts": inline_js,
        "css": css_contents or [],
        "dns": format_dns_for_technology_engine(dns_records),
        "text": text_content or "",
        "certIssuer": cert_issuer or "",
        "robots": robots_txt or ""
    }


def run_fallback_technology_engine(tech_items: Dict[str, Any], fingerprints: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Python-based fallback matching engine when Node is unavailable."""
    headers_lower = {}
    for k, vals in tech_items.get("headers", {}).items():
        headers_lower[k] = " ".join(vals)
        
    set_cookie_val = " ".join(" ".join(v) for v in tech_items.get("cookies", {}).values())
    html_str = tech_items.get("html", "")
    meta_tags = tech_items.get("meta", {})
    script_urls = tech_items.get("scriptSrc", [])
    css_urls = tech_items.get("css", [])
    inline_js_text = "\n".join(tech_items.get("scripts", []))

    detected_techs: Dict[str, Dict[str, Any]] = {}

    for tech_name, rule in fingerprints.items():
        raw_category = rule.get("category", "Frontend")
        category = standardize_category(raw_category)
        matched = False
        version: Optional[str] = None

        if "headers" in rule and isinstance(rule["headers"], dict):
            for h_name, pat_raw in rule["headers"].items():
                h_name_lower = h_name.lower()
                if h_name_lower in headers_lower:
                    pat = TechnologyPattern(pat_raw)
                    res = pat.match(headers_lower[h_name_lower])
                    if res:
                        matched = True
                        if res[1]:
                            version = version or res[1]

        if "cookies" in rule:
            cookie_pats = rule["cookies"]
            if isinstance(cookie_pats, list):
                for c_raw in cookie_pats:
                    pat = TechnologyPattern(c_raw)
                    res = pat.match(set_cookie_val)
                    if res:
                        matched = True
                        if res[1]:
                            version = version or res[1]
            elif isinstance(cookie_pats, dict):
                for c_name, c_raw in cookie_pats.items():
                    if re.search(c_name, set_cookie_val, re.IGNORECASE):
                        if c_raw:
                            pat = TechnologyPattern(c_raw)
                            res = pat.match(set_cookie_val)
                            if res:
                                matched = True
                                if res[1]:
                                    version = version or res[1]
                        else:
                            matched = True

        if "meta" in rule and isinstance(rule["meta"], dict):
            for m_name, pat_raw in rule["meta"].items():
                m_name_lower = m_name.lower()
                if m_name_lower in meta_tags:
                    pat = TechnologyPattern(pat_raw)
                    for content_val in meta_tags[m_name_lower]:
                        res = pat.match(content_val)
                        if res:
                            matched = True
                            if res[1]:
                                version = version or res[1]

        script_patterns = rule.get("scripts") or rule.get("scriptSrc")
        if script_patterns and isinstance(script_patterns, list):
            for s_raw in script_patterns:
                pat = TechnologyPattern(s_raw)
                for s_url in script_urls:
                    res = pat.match(s_url)
                    if res:
                        matched = True
                        if res[1]:
                            version = version or res[1]

        if "css" in rule and isinstance(rule["css"], list):
            for c_raw in rule["css"]:
                pat = TechnologyPattern(c_raw)
                for c_url in css_urls:
                    res = pat.match(c_url)
                    if res:
                        matched = True
                        if res[1]:
                            version = version or res[1]

        if "html" in rule and html_str:
            html_pats = rule["html"]
            if isinstance(html_pats, list):
                for h_raw in html_pats:
                    pat = TechnologyPattern(h_raw)
                    res = pat.match(html_str)
                    if res:
                        matched = True
                        if res[1]:
                            version = version or res[1]
            elif isinstance(html_pats, str):
                pat = TechnologyPattern(html_pats)
                res = pat.match(html_str)
                if res:
                    matched = True
                    if res[1]:
                        version = version or res[1]

        if "js" in rule and inline_js_text:
            js_pats = rule["js"]
            if isinstance(js_pats, list):
                for j_raw in js_pats:
                    pat = TechnologyPattern(j_raw)
                    res = pat.match(inline_js_text)
                    if res:
                        matched = True
                        if res[1]:
                            version = version or res[1]

        if matched:
            evidence_item = {
                "type": "fallback",
                "source": "Python engine",
                "snippet": f"Matched fallback rules for {tech_name}",
                "detection_engine": "fallback",
                "confidence": 100
            }
            detected_techs[tech_name] = {
                "name": tech_name,
                "version": version,
                "category": category,
                "evidence": [evidence_item]
            }

    # Font Awesome self-hosted detection.
    # Technology engine requires a CDN href containing 'awesome'/'font-awesome'/'fontawesome-free'
    # or a kit.fontawesome.com scriptSrc. Self-hosted deployments commonly use css/all.css
    # (no 'awesome' in path) and expose fas/fa-solid/fa-regular/fa-brands icon classes.
    # These prefixes are structurally unique to Font Awesome 5+/6+ with no false-positive risk.
    # Rule fires only when the Technology JS engine has not already detected Font Awesome.
    if "Font Awesome" not in detected_techs and html_str:
        _fa_patterns = [
            ("class=(?:[\"'])\\s*fa-solid\\b", "FA6 solid"),
            ("class=(?:[\"'])\\s*fa-regular\\b", "FA6 regular"),
            ("class=(?:[\"'])\\s*fa-brands\\b", "FA6 brands"),
            ("class=(?:[\"'])\\s*fas\\b", "FA5 solid"),
            ("class=(?:[\"'])\\s*far\\b", "FA5 regular"),
            ("class=(?:[\"'])\\s*fab\\b", "FA5 brands"),
        ]
        for _fa_pat, _fa_label in _fa_patterns:
            _fa_m = re.search(_fa_pat, html_str, re.IGNORECASE)
            if _fa_m:
                detected_techs["Font Awesome"] = {
                    "name": "Font Awesome",
                    "version": None,
                    "category": standardize_category("UI frameworks"),
                    "evidence": [{
                        "type": "html",
                        "source": "Self-hosted Font Awesome (" + _fa_label + "): " + _fa_m.group(0)[:80],
                        "snippet": _fa_m.group(0)[:80],
                        "detection_engine": "fallback",
                        "confidence": 90,
                    }]
                }
                break

    detected_techs = resolve_technology_graph(detected_techs, fingerprints)
    
    # Map back to Technology engine's expected response format for downstream handling
    res_list = []
    for k, v in detected_techs.items():
        res_list.append({
            "name": v["name"],
            "version": v["version"] or "",
            "categories": [{"name": v["category"]}],
            "evidence": v.get("evidence", [])
        })
    return res_list


TECH_NAME_NORMALIZATION = {
    "nuxt.js": "Nuxt",
    "nuxt": "Nuxt",
    "vue.js": "Vue.js",
    "vue": "Vue.js",
    "react": "React",
    "angular": "Angular",
    "angular.js": "Angular",
    "tailwind css": "Tailwind CSS",
    "tailwindcss": "Tailwind CSS",
    "bootstrap": "Bootstrap",
    "wordpress": "WordPress",
    "jquery": "jQuery",
    "jquery migrate": "jQuery Migrate",
    "modernizr": "Modernizr",
    "ethicalads": "EthicalAds",
    "plausible analytics": "Plausible Analytics",
    "google analytics": "Google Analytics",
    "google custom search": "Google Custom Search",
    "onetrust": "OneTrust",
    "adobe analytics": "Adobe Analytics",
}

def normalize_tech_name(name: str) -> str:
    n_lower = name.lower().strip()
    return TECH_NAME_NORMALIZATION.get(n_lower, name)


def enrich_versions_from_custom_rules(detections: List[Dict[str, Any]], tech_items: Dict[str, Any], fingerprints: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Enriches detections using custom regex patterns from technologies.json for CDN/query versions."""
    for item in detections:
        name = normalize_tech_name(item["name"])
        if not item.get("version"):
            rule = fingerprints.get(name)
            if not rule:
                for k, v in fingerprints.items():
                    if k.lower() == name.lower():
                        rule = v
                        break
            if rule:
                # 1. Scripts
                script_pats = rule.get("scripts") or rule.get("scriptSrc") or []
                for s_raw in script_pats:
                    try:
                        pat = TechnologyPattern(s_raw)
                        for s_url in tech_items.get("scriptSrc", []):
                            m = pat.match(s_url)
                            if m and m[1]:
                                item["version"] = m[1]
                                break
                    except Exception:
                        pass
                    if item.get("version"):
                        break
                
                # 2. CSS
                if not item.get("version") and "css" in rule:
                    for c_raw in rule["css"]:
                        try:
                            pat = TechnologyPattern(c_raw)
                            for c_url in tech_items.get("css", []):
                                m = pat.match(c_url)
                                if m and m[1]:
                                    item["version"] = m[1]
                                    break
                        except Exception:
                            pass
                        if item.get("version"):
                            break
                            
                # 3. HTML
                if not item.get("version") and "html" in rule:
                    html_pats = rule["html"]
                    if isinstance(html_pats, list):
                        for h_raw in html_pats:
                            try:
                                pat = TechnologyPattern(h_raw)
                                m = pat.match(tech_items.get("html", ""))
                                if m and m[1]:
                                    item["version"] = m[1]
                                    break
                            except Exception:
                                pass
                    elif isinstance(html_pats, str):
                        try:
                            pat = TechnologyPattern(html_pats)
                            m = pat.match(tech_items.get("html", ""))
                            if m and m[1]:
                                item["version"] = m[1]
                        except Exception:
                            pass
    return detections


def identify_technologies(
    headers: Dict[str, Any],
    html: str,
    fingerprints: Optional[Dict[str, Any]] = None,
    url: Optional[str] = None,
    robots_txt: Optional[str] = None,
    dns_records: Optional[Dict[str, Any]] = None,
    css_contents: Optional[List[str]] = None,
    cert_issuer: Optional[str] = None,
    text_content: Optional[str] = None
) -> Dict[str, Any]:
    """
    Genuine Technology-powered technology identification running the actual Technology JS engine,
    augmented by OpenRecon's custom technology signatures for backward compatibility.
    """
    import subprocess
    url_str = url or ""
    tech_items = prepare_technology_items(
        headers, html, url_str,
        dns_records=dns_records,
        css_contents=css_contents,
        cert_issuer=cert_issuer,
        robots_txt=robots_txt,
        text_content=text_content
    )

    res = []
    raw_detections = []
    # 1. Run Node-based technology engine
    try:
        runner_path = os.path.join(os.path.dirname(__file__), "technology_runner.js")
        proc = subprocess.run(
            ["node", runner_path],
            input=json.dumps(tech_items),
            capture_output=True,
            text=True,
            check=True
        )
        raw_res = json.loads(proc.stdout)
        if isinstance(raw_res, dict):
            res = raw_res.get("resolved", [])
            raw_detections = raw_res.get("rawDetections", [])
        else:
            res = raw_res
        res = enrich_versions_from_custom_rules(res, tech_items, fingerprints or load_fingerprints())
    except Exception as e:
        pass

    # Map raw_detections directly to their resolved counterparts
    for r in res:
        r_name = r["name"]
        r["evidence"] = []
        for rd in raw_detections:
            if rd["name"].lower() == r_name.lower():
                r["evidence"].append({
                    "type": rd["pattern"]["type"],
                    "source": rd["pattern"]["source"] or rd["pattern"]["value"],
                    "snippet": rd["pattern"]["match"],
                    "detection_engine": "technology-engine",
                    "confidence": rd["pattern"]["confidence"]
                })

    # 2. Run fallback/custom Python engine for full coverage
    fallback_res = run_fallback_technology_engine(tech_items, fingerprints or load_fingerprints())
    
    # 3. Merge results (preserving custom/test signatures)
    res_names_lower = {item["name"].lower() for item in res}
    for item in fallback_res:
        n_lower = item["name"].lower()
        if n_lower not in res_names_lower:
            res.append(item)
            res_names_lower.add(n_lower)

    # 4. Deduplicate and merge aliases after detection
    deduplicated_res = merge_and_deduplicate_detections(res)

    detected_techs: Dict[str, Dict[str, Any]] = {}
    for item in deduplicated_res:
        name = normalize_tech_name(item["name"])
        ver = item.get("version") or None
        tech_cats = item.get("categories", [])
        
        # 5. Presentation-only category mapping
        category = map_engine_cats_to_presentation(tech_cats, name, item.get("category", ""))
            
        detected_techs[name] = {
            "name": name,
            "version": ver,
            "category": category,
            "evidence": item.get("evidence", [])
        }

    # Group into categories
    categories_dict: Dict[str, List[Dict[str, Any]]] = {}
    for tech in detected_techs.values():
        cat = tech["category"]
        if cat not in categories_dict:
            categories_dict[cat] = []
        categories_dict[cat].append(tech)

    findings_list = []
    for tech in detected_techs.values():
        name = tech["name"]
        ver = tech.get("version")
        confidence = tech.get("confidence")
        cat = tech["category"]
        
        ev_list = []
        raw_evs = tech.get("evidence", [])
        for ev in raw_evs:
            eng = ev.get("detection_engine", "technology-engine")
            ev_type = ev.get("type", "unknown")
            src = ev.get("source") or ""
            snip = ev.get("snippet") or ""
            loc = ev.get("location")
            conf = ev.get("confidence", 100)
            
            ev_list.append(Evidence(
                type=ev_type,
                source=src,
                location=loc,
                snippet=snip,
                detection_engine=eng,
                confidence=conf
            ))
            
        inf = "DIRECT"
        if any(e.detection_engine == "fallback" for e in ev_list):
            inf = "FALLBACK"
            
        if not ev_list:
            inf = "RELATIONAL"
            implying = None
            for other_tech in detected_techs.values():
                if other_tech["name"] == name:
                    continue
                other_rule = (fingerprints or load_fingerprints()).get(other_tech["name"], {})
                implies_list = other_rule.get("implies", [])
                if isinstance(implies_list, str):
                    implies_list = [implies_list]
                if any(imp.lower() == name.lower() for imp in implies_list):
                    implying = other_tech["name"]
                    break
            
            if implying:
                ev_list.append(Evidence(
                    type="relational",
                    source=implying,
                    rule="implies",
                    detection_engine="technology-engine",
                    confidence=confidence or 100
                ))
            else:
                ev_list.append(Evidence(
                    type="inferred",
                    source="Technology relationship graph",
                    detection_engine="technology-engine",
                    confidence=confidence or 100
                ))
                inf = "INFERRED"
                
        seen_ids = set()
        unique_ev_list = []
        for e in ev_list:
            ident = e.get_identity()
            if ident not in seen_ids:
                seen_ids.add(ident)
                unique_ev_list.append(e)
                
        findings_list.append(Finding(
            value=name,
            category=cat,
            version=ver,
            confidence=confidence,
            evidence=unique_ev_list,
            inference=inf
        ))

    return {
        "technologies": list(detected_techs.values()),
        "categories": categories_dict,
        "total_detected": len(detected_techs),
        "findings": findings_list
    }


async def analyze_technology(domain: str) -> Dict[str, Any]:
    """
    Fetches target homepage and inspects technology stack across headers, meta tags,
    DOM elements, script URLs, CSS stylesheets, and first-party script banners.
    """
    import urllib.parse
    import asyncio
    base_host = domain.strip().lower()
    if base_host.startswith(("http://", "https://")):
        base_host = urllib.parse.urlparse(base_host).netloc.split(":")[0]

    url = f"https://{base_host}"
    response = await safe_get(url)
    if "error" in response:
        url = f"http://{base_host}"
        response = await safe_get(url)
        if "error" in response:
            return {"error": "Target unreachable or offline"}

    headers = response.get("headers", {})
    html_content = response.get("content_text", "")
    
    # Fetch DNS records in thread pool to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    from openrecon.modules.dns_recon import get_dns_records
    dns_records = await loop.run_in_executor(None, get_dns_records, base_host)
    
    # Extract stylesheet URLs and fetch up to 3 first-party CSS file contents
    assets = extract_asset_urls(html_content)
    first_party_css = []
    seen_css = set()
    for c_url in assets.get("css", []):
        if not c_url or c_url.startswith(("data:", "javascript:", "blob:", "#", "about:")):
            continue
        parsed_c = urllib.parse.urlparse(c_url)
        path_lower = parsed_c.path.lower()
        if not any(path_lower.endswith(ext) for ext in (".css", ".scss", ".sass")) and "stylesheet" not in c_url.lower():
            continue
        resolved = urllib.parse.urljoin(url, c_url)
        parsed_res = urllib.parse.urlparse(resolved)
        c_host = parsed_res.netloc.split(":")[0].lower()
        if (c_host == base_host or c_host.endswith("." + base_host)) and resolved.lower() not in seen_css:
            seen_css.add(resolved.lower())
            first_party_css.append(resolved)
            if len(first_party_css) >= 3:
                break
                
    css_contents = []
    if first_party_css:
        sem_css = asyncio.Semaphore(3)
        async def fetch_css(css_u: str):
            async with sem_css:
                try:
                    css_res = await safe_get(css_u)
                    if css_res.get("status_code") == 200 and css_res.get("content_text"):
                        css_contents.append(css_res["content_text"][:200000])
                except Exception:
                    pass
        await asyncio.gather(*(fetch_css(cu) for cu in first_party_css))
    
    # Fetch SSL details in thread pool
    from openrecon.modules.ssl_recon import analyze_ssl
    ssl_data = await loop.run_in_executor(None, analyze_ssl, base_host)
    cert_issuer = ""
    if isinstance(ssl_data, dict) and "issuer" in ssl_data:
        issuer_org = ssl_data["issuer"].get("organizationName", "")
        issuer_cn = ssl_data["issuer"].get("commonName", "")
        cert_issuer = f"{issuer_org} {issuer_cn}".strip()

    # Extract plain text content (Technology plain text relation)
    no_scripts = re.sub(r'(?i)<script(?:\s+[^>]*)?>[\s\S]*?</script>', ' ', html_content)
    no_styles = re.sub(r'(?i)<style(?:\s+[^>]*)?>[\s\S]*?</style>', ' ', no_scripts)
    text_content = re.sub(r'<[^>]+>', ' ', no_styles)
    text_content = re.sub(r'\s+', ' ', text_content).strip()

    # Try fetching robots.txt for safe additional asset cues
    robots_resp = await safe_get(f"{url.rstrip('/')}/robots.txt")
    robots_text = robots_resp.get("content_text", "") if "error" not in robots_resp else ""

    result = identify_technologies(
        headers=headers,
        html=html_content,
        url=response.get("url", url),
        robots_txt=robots_text,
        dns_records=dns_records,
        css_contents=css_contents,
        cert_issuer=cert_issuer,
        text_content=text_content
    )

    # Inspect first-party scripts for library banners and versions
    assets = extract_asset_urls(html_content)
    first_party_scripts = []
    seen_scripts = set()

    for s_url in assets.get("scripts", []):
        if not s_url or s_url.startswith(("data:", "javascript:", "blob:", "#", "about:")):
            continue
        resolved = urllib.parse.urljoin(url, s_url)
        parsed_s = urllib.parse.urlparse(resolved)
        s_host = parsed_s.netloc.split(":")[0].lower()
        if (s_host == base_host or s_host.endswith("." + base_host)) and resolved.lower() not in seen_scripts:
            seen_scripts.add(resolved.lower())
            first_party_scripts.append(resolved)

    if first_party_scripts:
        sem = asyncio.Semaphore(4)
        async def fetch_script_banner(js_u: str):
            async with sem:
                try:
                    js_res = await safe_get(js_u)
                    if js_res.get("status_code") == 200 and js_res.get("content_text"):
                        code = js_res["content_text"][:30000]
                        # Check banners
                        banner_evidence = []
                        # jQuery
                        jq_m = re.search(r'/\*!?\s*jQuery\s+v([1-3]\.[0-9]+(?:\.[0-9]+)?)\b', code)
                        if jq_m:
                            banner_evidence.append({"name": "jQuery", "version": jq_m.group(1).strip(), "category": "Frontend"})
                        # Bootstrap
                        bs_m = re.search(r'/\*!?\s*Bootstrap\s+v([3-5]\.[0-9]+(?:\.[0-9]+)?)\b', code)
                        if bs_m:
                            banner_evidence.append({"name": "Bootstrap", "version": bs_m.group(1).strip(), "category": "Frontend"})
                        # React
                        r_m = re.search(r'@license\s+React\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b', code)
                        if r_m:
                            banner_evidence.append({"name": "React", "version": r_m.group(1).strip(), "category": "Frontend"})
                        # Vue
                        v_m = re.search(r'/\*!?\s*Vue\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b', code)
                        if v_m:
                            banner_evidence.append({"name": "Vue.js", "version": v_m.group(1).strip(), "category": "Frontend"})
                        # Lodash
                        l_m = re.search(r'/\*!?\s*lodash\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b', code)
                        if l_m:
                            banner_evidence.append({"name": "Lodash", "version": l_m.group(1).strip(), "category": "Frontend"})

                        if banner_evidence:
                            merge_technology_evidence(result, banner_evidence)
                except Exception:
                    pass

        tasks = [fetch_script_banner(u) for u in first_party_scripts[:6]]
        await asyncio.gather(*tasks, return_exceptions=True)

    return result

# Alias for module registry compatibility
get_tech_fingerprint = analyze_technology


def merge_technology_evidence(tech_data: Dict[str, Any], evidence_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merges cross-module technology evidence into the Technology Stack findings.
    Preserves strongest direct observations and merges versions cleanly.
    """
    if not isinstance(tech_data, dict):
        tech_data = {"technologies": [], "categories": {}, "total_detected": 0}

    categories = tech_data.setdefault("categories", {})
    existing_techs = {t["name"].lower(): t for t in tech_data.get("technologies", [])}

    for ev in evidence_list:
        name = ev.get("name")
        if not name:
            continue
        cat = ev.get("category", "Frontend")
        ver = ev.get("version")
        if ver in ("Version unknown", "unknown", "None", "", None):
            ver = None

        name_lower = name.lower()
        if name_lower in existing_techs:
            existing = existing_techs[name_lower]
            if not existing.get("version") and ver:
                existing["version"] = str(ver)
        else:
            new_item = {
                "name": name,
                "version": str(ver) if ver else None,
                "category": cat
            }
            existing_techs[name_lower] = new_item
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(new_item)

    rebuilt_cats: Dict[str, List[Dict[str, Any]]] = {}
    rebuilt_techs: List[Dict[str, Any]] = []
    for t in existing_techs.values():
        rebuilt_techs.append(t)
        c = t.get("category", "Frontend")
        if c not in rebuilt_cats:
            rebuilt_cats[c] = []
        rebuilt_cats[c].append(t)

    tech_data["technologies"] = rebuilt_techs
    tech_data["categories"] = rebuilt_cats
    tech_data["total_detected"] = len(rebuilt_techs)

    findings = tech_data.setdefault("findings", [])
    for ev in evidence_list:
        name = ev.get("name")
        if not name:
            continue
        cat = ev.get("category", "Frontend")
        ver = ev.get("version")
        
        finding = None
        for f in findings:
            if f.value.lower() == name.lower():
                finding = f
                break
                
        if not finding:
            finding = Finding(
                value=name,
                category=cat,
                version=ver,
                confidence=100,
                evidence=[],
                inference="DIRECT"
            )
            findings.append(finding)
            
        if ver and (not finding.version or len(ver) > len(finding.version)):
            finding.version = ver
            
        finding.evidence.append(Evidence(
            type="HTML" if "HTML" in str(ev.get("source", "")) or "generator" in str(ev.get("evidence", "")) else "script",
            source=ev.get("source", "page-intel"),
            snippet=ev.get("evidence", f"Found {name} cross-module marker"),
            detection_engine="endpoint-parser" if "HTML" in str(ev.get("source", "")) or "generator" in str(ev.get("evidence", "")) else "ast-endpoint-parser",
            confidence=100
        ))
        
        seen_ids = set()
        unique_ev = []
        for e in finding.evidence:
            ident = e.get_identity()
            if ident not in seen_ids:
                seen_ids.add(ident)
                unique_ev.append(e)
        finding.evidence = unique_ev

    return tech_data
