import re
import urllib.parse
import asyncio
from typing import Dict, Any, List, Set
from openrecon.utils.safe_http import safe_get

EMAIL_REGEX = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
LINK_REGEX = re.compile(r'href=["\']((?!mailto:|tel:|javascript:|#)[^"\' >]+)["\']', re.IGNORECASE)

def get_registered_domain_prefix(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) < 2:
        return domain
    # Common 2-letter second-level domains followed by country code
    if len(parts) >= 3 and parts[-2] in ("co", "ac", "gov", "org", "edu", "net", "com", "res") and len(parts[-1]) == 2:
        return parts[-3]
    return parts[-2]

def is_relevant_email(email: str, target_domain: str) -> bool:
    email = email.lower().strip()
    target_domain = target_domain.lower().strip()
    
    parts = email.split('@')
    if len(parts) != 2:
        return False
    username, email_domain = parts
    
    # Exclude hex tokens / keys (>= 32 chars)
    if len(username) >= 32 and all(c in '0123456789abcdef' for c in username):
        return False
        
    # Exclude common long random strings/tokens
    if len(username) > 40:
        return False

    # Exact match or subdomain
    if email_domain == target_domain or email_domain.endswith('.' + target_domain):
        return True
        
    # Check registered domain prefix parity (e.g. bmsit.ac.in -> prefix bmsit matches bmsit.in -> prefix bmsit)
    target_prefix = get_registered_domain_prefix(target_domain)
    email_prefix = get_registered_domain_prefix(email_domain)
    if len(target_prefix) > 3 and target_prefix == email_prefix:
        return True
            
    # Also support sibling domains
    target_parts = target_domain.split('.')
    email_parts = email_domain.split('.')
    if len(email_parts) >= 2:
        parent_domain = ".".join(target_parts[-len(email_parts):])
        if email_domain == parent_domain:
            return True
    return False

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

async def enumerate_emails(target: str) -> Dict[str, Any]:
    """
    Discovers publicly available email addresses associated with the target domain.
    Searches the home page, public files, and crawls key subpages recursively.
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
    emails_found: Dict[str, str] = {}
    
    if not html_content:
        return {"emails": []}
        
    # Extract from home page
    for email in EMAIL_REGEX.findall(html_content):
        if is_relevant_email(email, target_domain):
            emails_found[email.lower().strip()] = base_url
            
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
                # Check for priority keywords
                priority_keywords = ["faculty", "staff", "department", "dep-", "contact", "admission", "placement", "office", "administration", "people", "directory"]
                if any(k in path_lower or k in query_lower for k in priority_keywords):
                    priority_urls.add(norm_url)
                else:
                    other_urls.add(norm_url)

    # Process home page links
    process_html_links(html_content, base_url)
    
    # Check robots.txt and sitemaps
    robots_url = f"{base_url}/robots.txt"
    robots_res = await safe_get(robots_url)
    if not robots_res.get("error") and robots_res.get("status_code") == 200:
        robots_txt = robots_res.get("content_text", "")
        for email in EMAIL_REGEX.findall(robots_txt):
            if is_relevant_email(email, target_domain):
                emails_found[email.lower().strip()] = robots_url
                
        # Parse sitemaps
        sitemap_urls = re.findall(r'Sitemap:\s*(https?://\S+)', robots_txt, re.IGNORECASE)
        for sitemap_url in sitemap_urls:
            sitemap_res = await safe_get(sitemap_url)
            if not sitemap_res.get("error") and sitemap_res.get("status_code") == 200:
                sitemap_xml = sitemap_res.get("content_text", "")
                for loc in re.findall(r'<loc>(https?://[^<]+)</loc>', sitemap_xml, re.IGNORECASE):
                    loc_clean = loc.split('#')[0].strip()
                    parsed_loc = urllib.parse.urlparse(loc_clean)
                    norm_loc = f"{parsed_loc.scheme}://{parsed_loc.netloc}{parsed_loc.path}"
                    if norm_loc in visited_urls:
                        continue
                    if is_internal_url(norm_loc, target_domain, target_label):
                        path_lower = parsed_loc.path.lower()
                        priority_keywords = ["faculty", "staff", "department", "dep-", "contact", "admission", "placement", "office", "administration", "people", "directory"]
                        if any(k in path_lower for k in priority_keywords):
                            priority_urls.add(norm_loc)
                        else:
                            other_urls.add(norm_loc)

    # Recursive crawling up to 40 pages total
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
            
        async def fetch_and_parse(url: str):
            sub_res = await safe_get(url)
            if not sub_res.get("error") and sub_res.get("status_code") == 200:
                sub_html = sub_res.get("content_text", "")
                for email in EMAIL_REGEX.findall(sub_html):
                    if is_relevant_email(email, target_domain):
                        email_lower = email.lower().strip()
                        if email_lower not in emails_found:
                            emails_found[email_lower] = url
                process_html_links(sub_html, url)
                
        await asyncio.gather(*(fetch_and_scan_task := fetch_and_parse(u) for u in batch), return_exceptions=True)
        crawled_count += len(batch)
        
    email_list = [{"value": k, "source": v} for k, v in emails_found.items()]
    email_list.sort(key=lambda x: x["value"])
    
    return {"emails": email_list}
