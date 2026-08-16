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

def load_fingerprints(custom_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Loads technology fingerprints from the authoritative JSON database.
    Supports loading from an explicit custom path if provided.
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
    """
    Extracts name/property to content mappings from HTML meta tags.
    """
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
    """
    Extracts script, css, image, and link URLs as well as inline JS blocks from HTML body.
    """
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

def _resolve_relationships(
    detected: Dict[str, Dict[str, Any]],
    fingerprints: Dict[str, Any]
) -> Dict[str, Dict[str, Any]]:
    """
    Resolves 'implies', 'requires', and 'excludes' relationships in a cycle-safe manner.
    """
    # 1. Resolve 'implies' recursively with cycle safety
    visited_implies: Set[str] = set()
    queue = list(detected.keys())

    while queue:
        tech = queue.pop(0)
        if tech in visited_implies:
            continue
        visited_implies.add(tech)

        rule = fingerprints.get(tech, {})
        implies = rule.get("implies", [])
        if isinstance(implies, str):
            implies = [implies]

        for imp in implies:
            if imp in fingerprints:
                if imp not in detected:
                    detected[imp] = {
                        "name": imp,
                        "version": None,
                        "category": fingerprints[imp].get("category", "Other")
                    }
                if imp not in visited_implies:
                    queue.append(imp)

    # 2. Resolve 'requires' (if any required technology is absent, drop candidate)
    for tech in list(detected.keys()):
        rule = fingerprints.get(tech, {})
        requires = rule.get("requires", [])
        if isinstance(requires, str):
            requires = [requires]
        for req in requires:
            if req not in detected:
                del detected[tech]
                break

    # 3. Resolve 'excludes' (if candidate excludes another detected tech, remove excluded)
    for tech in list(detected.keys()):
        if tech not in detected:
            continue
        rule = fingerprints.get(tech, {})
        excludes = rule.get("excludes", [])
        if isinstance(excludes, str):
            excludes = [excludes]
        for exc in excludes:
            if exc in detected:
                del detected[exc]

    return detected

def identify_technologies(
    headers: Dict[str, Any],
    html: str,
    fingerprints: Optional[Dict[str, Any]] = None,
    url: Optional[str] = None,
    robots_txt: Optional[str] = None
) -> Dict[str, Any]:
    """
    Passively fingerprints technologies across HTTP headers, cookies, HTML patterns,
    DOM markers, meta tags, script URLs, CSS assets, inline JS, robots.txt, and URL patterns.
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
        category = rule.get("category", "Other")
        matched = False
        version: Optional[str] = None

        # 1. Header Match
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

        # 2. Cookie Match
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

        # 3. Meta Tags Match
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

        # 4. Scripts / ScriptSrc Match
        script_patterns = rule.get("scripts") or rule.get("scriptSrc")
        if script_patterns and isinstance(script_patterns, list):
            for pat in script_patterns:
                for s_url in script_urls:
                    m = re.search(pat, s_url, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            version = version or m.group(1).strip()

        # 5. CSS Assets Match
        if "css" in rule and isinstance(rule["css"], list):
            for pat in rule["css"]:
                for c_url in css_urls:
                    m = re.search(pat, c_url, re.IGNORECASE)
                    if m:
                        matched = True
                        if m.groups() and m.group(1):
                            version = version or m.group(1).strip()

        # 6. HTML / DOM Match
        html_patterns = rule.get("html") or rule.get("dom")
        if html_patterns and isinstance(html_patterns, list):
            for pat in html_patterns:
                m = re.search(pat, html_str, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = version or m.group(1).strip()

        # 7. JavaScript Property / Inline Match
        if "js" in rule and isinstance(rule["js"], list):
            for pat in rule["js"]:
                m = re.search(pat, inline_js_text, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = version or m.group(1).strip()

        # 8. Robots.txt Match
        if "robots" in rule and isinstance(rule["robots"], list) and robots_str:
            for pat in rule["robots"]:
                m = re.search(pat, robots_str, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups() and m.group(1):
                        version = version or m.group(1).strip()

        # 9. URL / Hostname Match
        if "url" in rule and isinstance(rule["url"], list) and url_str:
            for pat in rule["url"]:
                m = re.search(pat, url_str, re.IGNORECASE)
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

    # Resolve relationships for passive findings
    detected_techs = _resolve_relationships(detected_techs, fingerprints)

    categories: Dict[str, List[Dict[str, Any]]] = {}
    tech_list = []

    for tech_name, info in sorted(detected_techs.items(), key=lambda x: x[0].lower()):
        cat = info["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append({
            "name": tech_name,
            "version": info["version"]
        })
        tech_list.append(info)

    return {
        "technologies": tech_list,
        "categories": categories,
        "total": len(tech_list),
        "raw_detected": detected_techs
    }

def collect_probe_paths(fingerprints: Dict[str, Any]) -> List[str]:
    """
    Collects and deduplicates technology-specific probe paths defined in the fingerprint database.
    """
    paths_set: Set[str] = set()
    for rule in fingerprints.values():
        for p in rule.get("paths", []):
            if isinstance(p, str) and p.strip() and p.strip() != "/":
                norm = "/" + p.strip("/").strip()
                if p.endswith("/"):
                    norm += "/"
                paths_set.add(norm)
        for probe in rule.get("probes", []):
            p = probe.get("path")
            if isinstance(p, str) and p.strip() and p.strip() != "/":
                norm = "/" + p.strip("/").strip()
                if p.endswith("/"):
                    norm += "/"
                paths_set.add(norm)
    return sorted(list(paths_set))

def evaluate_active_probes(
    probe_responses: Dict[str, Dict[str, Any]],
    fingerprints: Dict[str, Any],
    root_html: Optional[str] = None
) -> Dict[str, Dict[str, Any]]:
    """
    Evaluates technology-specific active probe responses against probe rules.
    Prevents false positives from wildcard routing / SPA fallbacks.
    """
    active_detected: Dict[str, Dict[str, Any]] = {}
    normalized_root = root_html.strip() if root_html else ""

    for tech_name, rule in fingerprints.items():
        category = rule.get("category", "Other")
        matched = False
        version: Optional[str] = None

        # 1. Explicit Probe Objects
        for probe in rule.get("probes", []):
            path = probe.get("path")
            if not path:
                continue
            norm_path = "/" + path.strip("/").strip()
            if path.endswith("/"):
                norm_path += "/"
                
            resp = probe_responses.get(norm_path)
            if not resp or "error" in resp:
                continue

            status = resp.get("status_code", 0)
            expected_status = probe.get("status")
            if expected_status is not None:
                if isinstance(expected_status, int) and status != expected_status:
                    continue
                elif isinstance(expected_status, list) and status not in expected_status:
                    continue

            content_text = resp.get("content_text", "")
            headers_dict = resp.get("headers", {})
            headers_lower = {k.lower(): str(v) for k, v in headers_dict.items()}

            # Check wildcard / SPA fallback: if probe response is identical to homepage, ignore
            if normalized_root and len(content_text) > 100 and content_text.strip() == normalized_root:
                continue

            # Check negative HTML / signature
            neg_html = probe.get("negative_html", [])
            if any(re.search(pat, content_text, re.IGNORECASE) for pat in neg_html):
                continue

            # Check positive HTML
            pos_html = probe.get("html", [])
            if pos_html and not any(re.search(pat, content_text, re.IGNORECASE) for pat in pos_html):
                continue

            # Check headers
            probe_headers = probe.get("headers", {})
            hdr_match = True
            for h_name, pat in probe_headers.items():
                if h_name.lower() not in headers_lower or not re.search(pat, headers_lower[h_name.lower()], re.IGNORECASE):
                    hdr_match = False
                    break
            if not hdr_match:
                continue

            # If probe has neither html nor headers nor cookies, do not match on status code alone
            if not pos_html and not probe_headers:
                continue

            matched = True
            ver_regex = probe.get("version_regex")
            if ver_regex:
                m = re.search(ver_regex, content_text, re.IGNORECASE)
                if m and m.groups() and m.group(1):
                    version = m.group(1).strip()
            break

        # 2. Probe Paths with Standard Rules
        if not matched and "paths" in rule:
            for path in rule["paths"]:
                norm_path = "/" + path.strip("/").strip()
                if path.endswith("/"):
                    norm_path += "/"
                resp = probe_responses.get(norm_path)
                if resp and "error" not in resp and resp.get("status_code") == 200:
                    content_text = resp.get("content_text", "")
                    if normalized_root and len(content_text) > 100 and content_text.strip() == normalized_root:
                        continue

                    sub_res = identify_technologies(
                        headers=resp.get("headers", {}),
                        html=content_text,
                        fingerprints={tech_name: rule}
                    )
                    sub_detected = sub_res.get("raw_detected", {})
                    if tech_name in sub_detected:
                        matched = True
                        version = sub_detected[tech_name].get("version")
                        break

        if matched:
            active_detected[tech_name] = {
                "name": tech_name,
                "version": version,
                "category": category
            }

    return active_detected

async def get_tech_fingerprint(
    domain: str,
    custom_fingerprints_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs passive fingerprinting and controlled active probe analysis for target domain.
    """
    url = f"https://{domain}"
    response = await safe_get(url)
    if "error" in response:
        url = f"http://{domain}"
        response = await safe_get(url)
        if "error" in response:
            return {"error": "Could not fetch target response (Target unreachable or blocked)"}

    headers = response.get("headers", {})
    html_content = response.get("content_text", "")

    # Passive check of robots.txt for evidence
    robots_content = ""
    try:
        robots_resp = await safe_get(f"{url.rstrip('/')}/robots.txt")
        if "error" not in robots_resp and robots_resp.get("status_code") == 200:
            robots_content = robots_resp.get("content_text", "")
    except Exception:
        pass

    fingerprints = load_fingerprints(custom_fingerprints_path)

    # 1. Passive Identification
    passive_res = identify_technologies(
        headers=headers,
        html=html_content,
        fingerprints=fingerprints,
        url=url,
        robots_txt=robots_content
    )
    detected_techs = dict(passive_res.get("raw_detected", {}))

    # 2. Active Controlled Probing
    probe_paths = collect_probe_paths(fingerprints)
    if probe_paths:
        base_url = url.rstrip("/")
        semaphore = asyncio.Semaphore(10)

        async def _fetch_probe(path: str) -> tuple:
            async with semaphore:
                resp = await safe_get(f"{base_url}{path}")
                if "error" in resp and base_url.startswith("https://"):
                    resp_http = await safe_get(f"http://{domain}{path}")
                    if "error" not in resp_http:
                        resp = resp_http
                return path, resp

        probe_tasks = [_fetch_probe(p) for p in probe_paths]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        probe_responses: Dict[str, Dict[str, Any]] = {}
        for item in probe_results:
            if isinstance(item, tuple) and len(item) == 2:
                p, r = item
                if isinstance(r, dict):
                    probe_responses[p] = r

        # Evaluate Active Probes with root_html wildcard protection
        active_techs = evaluate_active_probes(probe_responses, fingerprints, root_html=html_content)
        
        # Merge active detections
        for name, info in active_techs.items():
            if name not in detected_techs:
                detected_techs[name] = info
            elif not detected_techs[name].get("version") and info.get("version"):
                detected_techs[name]["version"] = info["version"]

    # 3. Resolve Relationships (implies, requires, excludes) with Cycle Protection
    detected_techs = _resolve_relationships(detected_techs, fingerprints)

    # 4. Group into categories
    categories: Dict[str, List[Dict[str, Any]]] = {}
    tech_list = []

    for tech_name, info in sorted(detected_techs.items(), key=lambda x: x[0].lower()):
        cat = info["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append({
            "name": tech_name,
            "version": info["version"]
        })
        tech_list.append(info)

    return {
        "technologies": tech_list,
        "categories": categories,
        "total": len(tech_list)
    }
