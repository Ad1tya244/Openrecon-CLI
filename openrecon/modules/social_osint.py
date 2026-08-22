import re
import urllib.parse
import asyncio
from typing import Dict, Any, List, Set, Optional
from openrecon.utils.safe_http import safe_get

SOCIAL_PATTERNS = {
    "LinkedIn": re.compile(r'https?://(?:[a-z0-9-]+\.)?linkedin\.com/(?:company|in|school|org|groups)/[a-zA-Z0-9_.-]+', re.IGNORECASE),
    "Instagram": re.compile(r'https?://(?:www\.)?instagram\.com/[a-zA-Z0-9_.-]+', re.IGNORECASE),
    "Facebook": re.compile(r'https?://(?:www\.)?facebook\.com/[a-zA-Z0-9_.-]+', re.IGNORECASE),
    "YouTube": re.compile(r'https?://(?:www\.)?youtube\.com/(?:c/|user/|channel/|@)?[a-zA-Z0-9_.-]+', re.IGNORECASE),
    "X": re.compile(r'https?://(?:www\.)?(?:twitter\.com|x\.com)/[a-zA-Z0-9_.-]+', re.IGNORECASE),
    "GitHub": re.compile(r'https?://(?:www\.)?github\.com/[a-zA-Z0-9_.-]+', re.IGNORECASE),
    "Telegram": re.compile(r'https?://(?:t\.me|telegram\.me)/[a-zA-Z0-9_.-]+', re.IGNORECASE),
    "Discord": re.compile(r'https?://(?:www\.)?(?:discord\.gg|discord\.com/invite)/[a-zA-Z0-9_.-]+', re.IGNORECASE),
}

EXCLUDED_PATHS = {
    "linkedin.com": {"jobs", "sharearticle", "sharing", "cws", "share", "post", "c", "pub", "feed", "posts"},
    "instagram.com": {"p", "explore", "developer", "about", "blog", "legal", "terms", "privacy", "static"},
    "facebook.com": {"sharer", "sharer.php", "plugins", "policies", "help", "pages", "group", "groups", "events", "about", "privacy", "terms", "business"},
    "youtube.com": {"t", "embed", "playlist", "watch", "channel", "c", "user", "live", "about", "terms", "privacy", "settings", "feed"},
    "twitter.com": {"intent", "share", "search", "hashtag", "widgets", "tos", "privacy", "i", "settings", "personalization", "home"},
    "x.com": {"intent", "share", "search", "hashtag", "widgets", "tos", "privacy", "i", "settings", "personalization", "home"},
    "github.com": {"features", "pricing", "join", "login", "trending", "explore", "marketplace", "about", "security", "contact", "settings", "collections", "enterprise", "open-source", "orgs", "partners", "resources", "solutions", "topics", "team", "why-github", "customer-stories", "trust-center", "fluidicon.png"},
    "t.me": {"s", "addstickers", "iv", "share"},
    "discord.com": {"invite"},
}

LINK_REGEX = re.compile(r'href=["\']((?!mailto:|tel:|javascript:|#)[^"\' >]+)["\']', re.IGNORECASE)

def normalize_social_url(platform: str, url: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.strip("/")
    
    domain_key = None
    for dk in EXCLUDED_PATHS:
        if dk in parsed.netloc.lower():
            domain_key = dk
            break
            
    if domain_key:
        path_parts = [p for p in path.split("/") if p]
        if path_parts:
            first_part = path_parts[0].lower()
            if first_part in EXCLUDED_PATHS[domain_key]:
                return None
                
    if platform == "LinkedIn":
        if not path:
            return None
        return f"https://www.linkedin.com/{path}"
    elif platform == "Instagram":
        if not path:
            return None
        return f"https://www.instagram.com/{path}"
    elif platform == "Facebook":
        if not path:
            return None
        return f"https://www.facebook.com/{path}"
    elif platform == "YouTube":
        if not path:
            return None
        if path in ("embed", "watch", "playlist"):
            return None
        return f"https://www.youtube.com/{path}"
    elif platform == "X":
        if not path:
            return None
        return f"https://x.com/{path}"
    elif platform == "GitHub":
        if not path:
            return None
        return f"https://github.com/{path}"
    elif platform == "Telegram":
        if not path:
            return None
        return f"https://t.me/{path}"
    elif platform == "Discord":
        if not path:
            return None
        if "invite" in parsed.path:
            return f"https://discord.com/invite/{path.split('/')[-1]}"
        return f"https://discord.gg/{path}"
        
    return url

def classify_profile(platform: str, url: str, target_domain: str, source_url: str) -> tuple:
    url_lower = url.lower()
    target_label = target_domain.split('.')[0].lower()
    source_lower = source_url.lower()
    
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.strip("/")
    path_parts = [p for p in path.split("/") if p]
    handle = path_parts[-1].lower() if path_parts else ""
    
    share_keywords = ["sharer", "sharearticle", "sharing", "share.php", "intent/tweet", "widgets", "sharer.php", "/intent/"]
    if any(k in url_lower for k in share_keywords):
        return ("UNVERIFIED", "Generic social sharing URL or widget.")

    if platform == "LinkedIn":
        if any(k in url_lower for k in ("/company/", "/school/", "/org/", "/groups/")):
            if target_label in handle or target_label in url_lower:
                return ("OFFICIAL_ORGANIZATION", "Official organization school, company, or group page matching target label.")
            if source_lower == f"https://{target_domain}" or source_lower == f"http://{target_domain}":
                return ("OFFICIAL_ORGANIZATION", "Official organization school or company page linked from homepage.")
            return ("OFFICIAL_ORGANIZATION", "Verified organizational profile found on official pages.")
            
        if "/in/" in url_lower:
            dept_keywords = ["dept", "department", "placement", "library", "cell", "office", "admin", "official"]
            if any(k in handle for k in dept_keywords):
                if target_label in handle:
                    return ("OFFICIAL_DEPARTMENT", "Official department or administrative unit page.")
            return ("PERSONAL_ASSOCIATED", "Individual LinkedIn profile associated with the organization.")
            
        return ("UNVERIFIED", "Insufficient evidence of organizational ownership.")

    elif platform == "GitHub":
        if len(path_parts) == 1:
            if handle == target_label:
                return ("OFFICIAL_ORGANIZATION", "Official organization landing repository matching target label.")
            if any(k in handle for k in ("club", "cell", "dept", "department", "team", "project")):
                return ("OFFICIAL_CLUB_OR_CELL", "Official club or organization-linked development team.")
            return ("PERSONAL_ASSOCIATED", "Individual developer profile associated with the organization.")
        return ("UNVERIFIED", "Insufficient evidence of organizational ownership.")

    elif platform == "YouTube":
        if any(k in url_lower for k in ("/embed", "/watch", "/playlist")):
            return ("UNVERIFIED", "YouTube utility or video play link.")
            
        if any(k in url_lower for k in ("/channel/", "/c/", "/user/", "/@")):
            official_keywords = ["media", "channel", "official", "univ", "college", "school"]
            if target_label in handle:
                if any(k in handle for k in official_keywords) or handle == target_label:
                    return ("OFFICIAL_ORGANIZATION", "Official YouTube channel representing the organization.")
                if any(k in handle for k in ("dept", "department", "civil", "cse", "ece", "mca", "mba")):
                    return ("OFFICIAL_DEPARTMENT", "Official department-specific YouTube channel.")
                return ("OFFICIAL_ORGANIZATION", "YouTube channel matching organization handle.")
            if source_lower == f"https://{target_domain}" or source_lower == f"http://{target_domain}":
                return ("OFFICIAL_ORGANIZATION", "Official YouTube channel linked from homepage.")
            return ("PERSONAL_ASSOCIATED", "Individual user channel associated with the organization.")
        return ("UNVERIFIED", "Insufficient evidence of organizational ownership.")

    else:
        event_keywords = ["utsaha", "vaibhava", "fest", "festival", "symposium", "graduation"]
        if any(k in handle for k in event_keywords):
            return ("OFFICIAL_EVENT", "Official event, festival, or symposium profile.")
            
        club_keywords = ["club", "cell", "society", "committee", "rotaract", "ieee", "iete", "sports", "cultural"]
        if any(k in handle for k in club_keywords):
            return ("OFFICIAL_CLUB_OR_CELL", "Official student club or administrative cell profile.")
            
        dept_keywords = ["dept", "department", "civil", "cse", "ece", "mca", "mba", "placement", "library", "admin", "office"]
        if any(k in handle for k in dept_keywords):
            return ("OFFICIAL_DEPARTMENT", "Official department-specific social page.")
            
        if "cv" in handle and target_label in handle:
            return ("OFFICIAL_DEPARTMENT", "Official department-specific social page.")
            
        if handle == target_label or handle == f"{target_label}1" or handle == f"{target_label}official":
            return ("OFFICIAL_ORGANIZATION", "Official organization social profile matching target label.")
            
        if source_lower == f"https://{target_domain}" or source_lower == f"http://{target_domain}":
            if len(handle) < 15 and not any(c.isdigit() for c in handle):
                return ("OFFICIAL_ORGANIZATION", "Official organization social profile linked from homepage.")
            return ("OFFICIAL_ORGANIZATION", "Social profile linked directly from official homepage.")
            
        if len(handle) > 0:
            if target_label in handle:
                return ("PERSONAL_ASSOCIATED", "Individual/associated user account containing organization name.")
            return ("UNVERIFIED", "Unverified external social profile link.")
            
    return ("UNVERIFIED", "Insufficient evidence to verify profile classification.")

def is_internal_url(url: str, target_domain: str, target_label: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.lower()
        if not netloc:
            return True
        if netloc.endswith(target_domain):
            return True
        if len(target_label) > 3 and target_label in netloc:
            return True
    except Exception:
        pass
    return False

async def discover_social_media(target: str) -> Dict[str, Any]:
    """
    Discovers publicly available social media accounts associated with the target domain.
    Crawls up to 40 pages and applies verification/classification rules.
    """
    clean_target = target.strip().lower()
    if clean_target.startswith(("http://", "https://")):
        clean_target = urllib.parse.urlparse(clean_target).netloc
        
    target_domain = clean_target.split(":")[0]
    target_label = target_domain.split('.')[0]
    base_url = f"https://{target_domain}"
    
    res = await safe_get(base_url)
    if res.get("error") or res.get("status_code", 0) >= 400:
        base_url = f"http://{target_domain}"
        res = await safe_get(base_url)
        
    html_content = res.get("content_text", "")
    if not html_content:
        return {"social_profiles": {}, "sources": {}, "classifications": {}, "reasons": {}, "unfiltered_profiles": {}}
        
    discovered_raw: Dict[str, List[tuple]] = {}
    
    def extract_socials_from_text(text: str, source_url: str, is_external: bool = False):
        for platform, pattern in SOCIAL_PATTERNS.items():
            for match in pattern.findall(text):
                normalized = normalize_social_url(platform, match)
                if normalized:
                    if platform not in discovered_raw:
                        discovered_raw[platform] = []
                    discovered_raw[platform].append((normalized, source_url))

    # Extract from home page
    extract_socials_from_text(html_content, base_url, is_external=False)
    
    visited_urls: Set[str] = {base_url, f"{base_url}/"}
    priority_urls: Set[str] = set()
    other_urls: Set[str] = set()
    
    def process_html_links(html: str, source_url: str):
        for link in LINK_REGEX.findall(html):
            link = link.split('#')[0].strip()
            if not link:
                continue
            full_url = urllib.parse.urljoin(source_url, link)
            parsed = urllib.parse.urlparse(full_url)
            if parsed.scheme not in ("http", "https"):
                continue
            norm_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if norm_url in visited_urls:
                continue
            if is_internal_url(norm_url, target_domain, target_label):
                path_lower = parsed.path.lower()
                query_lower = parsed.query.lower()
                if any(path_lower.endswith(ext) for ext in (".jpg", ".jpeg", ".png", ".gif", ".css", ".zip", ".tar", ".gz", ".exe", ".mp4", ".mp3", ".woff", ".woff2", ".ttf", ".pdf")):
                    continue
                priority_keywords = ["faculty", "staff", "department", "dep-", "contact", "admission", "placement", "office", "administration", "people", "directory"]
                if any(k in path_lower or k in query_lower for k in priority_keywords):
                    priority_urls.add(norm_url)
                else:
                    other_urls.add(norm_url)

    # Process home page links
    process_html_links(html_content, base_url)
    
    # Crawl up to 40 pages recursively
    limit = 40
    crawled_count = 1
    
    while crawled_count < limit and (priority_urls or other_urls):
        batch = []
        while len(batch) < 10 and crawled_count + len(batch) < limit:
            if priority_urls:
                batch.append(priority_urls.pop())
            elif other_urls:
                batch.append(other_urls.pop())
            else:
                break
                
        if not batch:
            break
            
        for u in batch:
            visited_urls.add(u)
            
        async def fetch_and_scan(url: str):
            sub_res = await safe_get(url)
            if not sub_res.get("error") and sub_res.get("status_code") == 200:
                sub_html = sub_res.get("content_text", "")
                extract_socials_from_text(sub_html, url, is_external=False)
                process_html_links(sub_html, url)
                
        await asyncio.gather(*(fetch_and_scan(u) for u in batch), return_exceptions=True)
        crawled_count += len(batch)
        
    # Follow cross-platform references from verified profiles (e.g. GitHub org pages)
    github_orgs = []
    for platform, items in list(discovered_raw.items()):
        if platform == "GitHub":
            for url, src in items:
                parsed = urllib.parse.urlparse(url)
                parts = [p for p in parsed.path.split('/') if p]
                if len(parts) == 1:
                    github_orgs.append(url)
                    
    if github_orgs:
        async def fetch_github_socials(url: str):
            sub_res = await safe_get(url)
            if not sub_res.get("error") and sub_res.get("status_code") == 200:
                sub_html = sub_res.get("content_text", "")
                for plat, pat in SOCIAL_PATTERNS.items():
                    for match in pat.findall(sub_html):
                        norm = normalize_social_url(plat, match)
                        if norm:
                            if plat not in discovered_raw:
                                discovered_raw[plat] = []
                            discovered_raw[plat].append((norm, f"Cross-reference from {url}"))
                            
        await asyncio.gather(*(fetch_github_socials(u) for u in github_orgs), return_exceptions=True)

    # Classify, consolidate, and deduplicate
    social_profiles: Dict[str, List[str]] = {}
    unfiltered_profiles: Dict[str, List[str]] = {}
    sources: Dict[str, Dict[str, str]] = {}
    classifications: Dict[str, str] = {}
    reasons: Dict[str, str] = {}
    
    for platform, items in discovered_raw.items():
        seen = set()
        plat_official = []
        plat_unfiltered = []
        plat_sources = {}
        
        for url, src in items:
            url_norm = url.strip()
            if url_norm not in seen:
                seen.add(url_norm)
                plat_unfiltered.append(url_norm)
                plat_sources[url_norm] = src
                
                # Classify
                classification, reason = classify_profile(platform, url_norm, target_domain, src)
                classifications[url_norm] = classification
                reasons[url_norm] = reason
                
                if classification.startswith("OFFICIAL_"):
                    plat_official.append(url_norm)
                    
        # Sort profiles
        plat_official.sort(key=lambda u: (not any(k in u.lower() for k in ("/company/", "/school/", "/org/", "/@")), u))
        plat_unfiltered.sort(key=lambda u: (not any(k in u.lower() for k in ("/company/", "/school/", "/org/", "/@")), u))
        
        if plat_official:
            social_profiles[platform] = plat_official
        if plat_unfiltered:
            unfiltered_profiles[platform] = plat_unfiltered
        sources[platform] = plat_sources
        
    return {
        "social_profiles": social_profiles,
        "sources": sources,
        "classifications": classifications,
        "reasons": reasons,
        "unfiltered_profiles": unfiltered_profiles
    }
