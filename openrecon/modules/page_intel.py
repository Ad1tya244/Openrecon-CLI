from openrecon.utils.findings import Finding, Evidence
"""
OpenRecon — Page Source Intelligence Module
Inspects HTML metadata, DOM structures, functional forms, inline JavaScript,
and directly referenced first-party JavaScript bundles to discover security-relevant
application endpoints, client-side configurations, internal infrastructure, and technology evidence.

Inspired by the lexical AST/parser and scope control architecture of OpenRecon endpoint scanner.
"""

import re
import json
import asyncio
import urllib.parse
import os
import subprocess
from html.parser import HTMLParser
from typing import Dict, List, Any, Optional, Set, Tuple

from openrecon.utils.safe_http import safe_get

MAX_JS_FILES = 12
MAX_JS_SIZE = 2 * 1024 * 1024  # 2MB
CONCURRENCY_LIMIT = 5

STATIC_ASSET_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".pdf", ".zip", ".tar.gz", ".map"
)

COMMON_JS_LIBRARY_RE = re.compile(
    r"(jquery|lodash|react|vue|angular|bootstrap|moment|d3|chart|select2|slick|fancybox|owl\.carousel|modernizr|mathjax|requirejs|backbone|ember|knockout|typescript|babel|core-js|regenerator-runtime|zone\.js|webpack|vite|next|nuxt|gatsby|jekyll|hugo|wordpress|drupal|joomla|shopify|magento)",
    re.IGNORECASE
)

DEFAULT_EXT_FILTER = {
    ".3g2", ".3gp", ".7z", ".apk", ".arj", ".avi", ".axd", ".bmp", ".csv", ".deb",
    ".dll", ".doc", ".drv", ".eot", ".exe", ".flv", ".gif", ".gifv", ".gz", ".h264",
    ".ico", ".iso", ".jar", ".jpeg", ".jpg", ".lock", ".m4a", ".m4v", ".map", ".mkv",
    ".mov", ".mp3", ".mp4", ".mpeg", ".mpg", ".msi", ".ogg", ".ogm", ".ogv", ".otf",
    ".pdf", ".pkg", ".png", ".ppt", ".psd", ".rar", ".rm", ".rpm", ".svg", ".swf",
    ".sys", ".tar.gz", ".tar", ".tif", ".tiff", ".ttf", ".txt", ".vob", ".wav", ".webm",
    ".webp", ".wmv", ".woff", ".woff2", ".xcf", ".xls", ".xlsx", ".zip"
}

# Regex pageBodyRegex from regex.go
AST_BODY_RE = re.compile(
    r"""(?:("""
    r"""(?:\.{1,2}/[A-Za-z0-9\-_/\\?&@\.?=%]+)"""
    r"""|(?:https?://[A-Za-z0-9_\-\.]+(?:\.{0,2})?/[A-Za-z0-9\-_/\\?&@\.?=%]+)"""
    r"""|(?:/[A-Za-z0-9\-_/\\?&@\.%]+\.(?:aspx?|action|cfm|cgi|do|pl|css|x?html?|js(?:p|on)?|pdf|php5?|py|rss))"""
    r"""|(?:[A-Za-z0-9\-_/\\?&@\.%]+/[A-Za-z0-9/\\-_/\\?&@\.%]+\.(?:aspx?|action|cfm|cgi|do|pl|css|x?html?|js(?:p|on)?|pdf|php5?|py|rss))"""
    r"""))"""
)

# Regex relativeEndpointsRegex from regex.go
AST_JS_RE = re.compile(
    r"""['"\s]("""
    r"""(?:https?://[A-Za-z0-9_\-.]+(?:\:\d{1,5})?)+(?:\.{1,2})?/[A-Za-z0-9/\-_\\.%]+(?:\?[^'"\s]+|#[^'"\s]*)?"""
    r"""|(?:\.{1,2}/)?[a-zA-Z0-9\-_/\\%]+\.(?:aspx?|js(?:on|p)?|html|php5?|action|do)(?:\?[^'"\s]+|#[^'"\s]*)?"""
    r"""|(?:\.{0,2}/)[a-zA-Z0-9\-_/\\%]+(?:/|\\)[a-zA-Z0-9\-_]{3,}(?:\?[^'"\s]+|#[^'"\s]*)?"""
    r"""|(?:\.{0,2})[a-zA-Z0-9\-_/\\%]{3,}/"""
    r""")['"\s]"""
)

def is_filtered_static_extension(path_or_url: str) -> bool:
    """Port of OpenRecon's static file validator extension validation."""
    if not path_or_url:
        return False
    try:
        parsed = urllib.parse.urlparse(path_or_url)
        path_str = parsed.path
    except Exception:
        path_str = path_or_url
    
    # Remove query/hash if basic parsing failed
    path_str = path_str.split("?")[0].split("#")[0]
    _, ext = os.path.splitext(path_str.lower())
    return ext in DEFAULT_EXT_FILTER

def is_common_js_library_file(path_or_url: str) -> bool:
    """Returns True if the path corresponds to a common library JavaScript file (Go port of OpenRecon's common JS library validator)."""
    return bool(COMMON_JS_LIBRARY_RE.search(path_or_url))

def extract_endpoints_via_node_ast(js_code: str) -> List[Dict[str, Any]]:
    """Runs Node.js client_endpoint_engine.js AST endpoint extractor on the script contents."""
    try:
        runner_path = os.path.join(os.path.dirname(__file__), "client_endpoint_engine.js")
        proc = subprocess.run(
            ["node", runner_path],
            input=js_code,
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(proc.stdout)
    except Exception:
        return []

def classify_endpoint(method: str, url_path: str, req_ct: str = "", resp_ct: str = "", soap_action: str = "") -> str:
    """Direct port of OpenRecon's endpoint classification function from endpoints.go."""
    path_lower = url_path.lower()
    method_upper = method.upper()
    
    if soap_action or "soap+xml" in req_ct.lower() or "soap+xml" in resp_ct.lower():
        return "soap"
        
    has_graphql_segment = False
    parts = path_lower.split("/")
    for p in parts:
        if p == "graphql":
            has_graphql_segment = True
            break
            
    if has_graphql_segment or "application/graphql" in req_ct.lower() or "application/graphql" in resp_ct.lower():
        return "graphql"
        
    is_json = "application/json" in req_ct.lower() or "application/json" in resp_ct.lower()
    is_xml = "application/xml" in req_ct.lower() or "application/xml" in resp_ct.lower()
    is_form = "application/x-www-form-urlencoded" in req_ct.lower() or "multipart/form-data" in req_ct.lower()
    
    api_path_segments = ["/api", "/v1", "/v2", "/v3", "/rest", "/rpc", "/jsonrpc", "/.well-known", "/oauth", "/openapi", "/auth"]
    is_api_path = any(seg in path_lower for seg in api_path_segments)
    is_mutating = method_upper in ("POST", "PUT", "DELETE", "PATCH")
    
    if (is_json or is_xml) and (is_mutating or is_api_path):
        return "rest"
    if is_json and method_upper == "GET":
        return "xhr"
    if is_form and is_mutating:
        return "rest"
    if is_api_path:
        return "rest" if is_mutating else "xhr"
        
    return "xhr"


HTTP_NON_PARAM_KEYS = {
    "method", "headers", "body", "data", "params", "url", "mode", "credentials",
    "cache", "type", "datatype", "contenttype", "processdata", "async", "crossdomain",
    "content-type", "authorization", "accept", "x-csrf-token", "x-requested-with",
    "user-agent", "cookie", "cache-control", "pragma", "host", "origin", "referer"
}

LIBRARY_RULES = [
    {
        "name": "jQuery",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]jquery[.-]([1-3]\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*jQuery\s+v([1-3]\.[0-9]+(?:\.[0-9]+)?)\b',
            r'jQuery\.fn\.jquery\s*=\s*["\']([1-3]\.[0-9]+(?:\.[0-9]+)?)[\"\']',
            r'\.fn\.jquery\s*=\s*["\']([1-3]\.[0-9]+(?:\.[0-9]+)?)[\"\']'
        ],
        "presence_patterns": [
            r'\bjquery(?:\.min|\.[a-f0-9]+)?\.js\b',
            r'\bwindow\.jQuery\b',
            r'jQuery\s*=\s*function'
        ]
    },
    {
        "name": "Bootstrap",
        "category": "Frontend",
        "url_version_patterns": [
            r'[/-]bootstrap[.-]([3-5]\.[0-9]+(?:\.[0-9]+)?)(?:\.bundle)?(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*Bootstrap\s+v([3-5]\.[0-9]+(?:\.[0-9]+)?)\b',
            r'bootstrap\.Tooltip\.VERSION\s*=\s*["\']([3-5]\.[0-9.]+)["\']'
        ],
        "presence_patterns": [
            r'\bbootstrap(?:\.bundle|\.min|\.[a-f0-9]+)?\.js\b',
            r'\bwindow\.bootstrap\b'
        ]
    },
    {
        "name": "React",
        "category": "Frontend",
        "url_version_patterns": [
            r'[/-]react[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.production|\.min)?\.js'
        ],
        "content_version_patterns": [
            r'@license\s+React\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
            r'/\*!?\s*React\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
            r'React\.version\s*=\s*["\']([0-9.]+)["\']'
        ],
        "presence_patterns": [
            r'\breact(?:\.production|\.min|\.[a-f0-9]+)?\.js\b',
            r'\bwindow\.React\b'
        ]
    },
    {
        "name": "ReactDOM",
        "category": "Frontend",
        "url_version_patterns": [
            r'[/-]react-dom[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.production|\.min)?\.js'
        ],
        "content_version_patterns": [
            r'@license\s+ReactDOM\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
            r'/\*!?\s*ReactDOM\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\breact-dom(?:\.production|\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "Vue.js",
        "category": "Frontend",
        "url_version_patterns": [
            r'[/-]vue[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.global|\.runtime|\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*Vue\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
            r'Vue\.version\s*=\s*["\']([0-9.]+)["\']'
        ],
        "presence_patterns": [
            r'\bvue(?:\.global|\.runtime|\.min|\.[a-f0-9]+)?\.js\b',
            r'\bwindow\.Vue\b'
        ]
    },
    {
        "name": "Angular",
        "category": "Frontend",
        "url_version_patterns": [
            r'[/-]angular[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*@angular/core\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bng-version\b',
            r'\bwindow\.angular\b'
        ]
    },
    {
        "name": "Lodash",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]lodash[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*lodash\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
            r'/\*!?\s*Lodash\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\blodash(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "Moment.js",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]moment[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*moment\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
            r'/\*!?\s*Moment\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bmoment(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "Axios",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]axios[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*axios\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
            r'/\*!?\s*Axios\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\baxios(?:\.min|\.[a-f0-9]+)?\.js\b',
            r'\bwindow\.axios\b'
        ]
    },
    {
        "name": "Alpine.js",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]alpine[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*Alpine\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\balpine(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "HTMX",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]htmx[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*htmx\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b',
            r'/\*!?\s*HTMX\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bhtmx(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "SweetAlert2",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]sweetalert2[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*SweetAlert2\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bsweetalert2(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "Highcharts",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]highcharts[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*Highcharts\s+JS\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bhighcharts(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "Font Awesome",
        "category": "Frontend",
        "url_version_patterns": [
            r'[/-]fontawesome[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*Font\s+Awesome(?:\s+Free)?\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bfontawesome(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "DOMPurify",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]dompurify[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*DOMPurify\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bdompurify(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "Chart.js",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]chart[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*Chart\.js\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bchart(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "core-js",
        "category": "JavaScript Libraries",
        "url_version_patterns": [
            r'[/-]core-js[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*core-js\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bcore-js(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    },
    {
        "name": "Sentry",
        "category": "Analytics",
        "url_version_patterns": [
            r'[/-]sentry[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.js'
        ],
        "content_version_patterns": [
            r'/\*!?\s*Sentry(?:\s+SDK)?\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b'
        ],
        "presence_patterns": [
            r'\bsentry(?:\.min|\.[a-f0-9]+)?\.js\b'
        ]
    }
]

COMMON_JS_LIBRARY_REGEX = re.compile(
    r'(?i)(?:amplify|quantserve|slideshow|jquery|modernizr|polyfill|vendor|modules|gtm|underscore|tween|retina|selectivizr|cufon|angular|bootstrap|d3|backbone|videojs|google[-_]analytics|material|redux|knockout|datepicker|datetimepicker|ember|react|node[-_]modules|lodash|moment|chart|highcharts|raphael|prototype|mootools|dojo|ext|yui|web[-_]?components|polymer|vue|svelte|next|nuxt|gatsby|express|socket[-_.]?io|axios|superagent|rxjs|ramda|immutable|flux|mobx|relay|apollo|graphql|three|phaser|pixi|babylon|cannon|hammer|howler|gsap|velocity|popper|shepherd|prism|highlight|markdown[-_]?it|core-js|regenerator-runtime|zone\.js|tslib)'
)

def is_common_js_library_file(path: str) -> bool:
    """Adapted from OpenRecon AST helper (IsPathCommonJSLibraryFile)."""
    return bool(COMMON_JS_LIBRARY_REGEX.search(path))


def is_static_asset(path: str) -> bool:
    clean = path.split('?')[0].split('#')[0].lower()
    return clean.endswith(STATIC_ASSET_EXTS)

API_PATH_INDICATORS = (
    "/api/", "/api", "/graphql", "/rest/", "/rest",
    "/auth/", "/auth", "/oauth/", "/oauth",
    "/v1/", "/v2/", "/v3/", "/v4/", "/rpc/", "/data/", "/json/"
)

API_EXTENSIONS = (".json", ".xml", ".graphql", ".gql")

def is_api_endpoint_request(method: str, url: str) -> bool:
    """
    Validates whether an actual client-side network request represents an API endpoint
    rather than a static template partial, static HTML fragment, or navigation URL.
    """
    method = method.upper().strip()
    if method in ("POST", "PUT", "DELETE", "PATCH"):
        return True

    parsed = urllib.parse.urlparse(url)
    path_lower = parsed.path.lower()
    host_lower = parsed.netloc.split(":")[0].lower()

    if host_lower.startswith("api."):
        return True

    if any(ind in path_lower for ind in API_PATH_INDICATORS):
        return True

    if path_lower.endswith(API_EXTENSIONS):
        return True

    if parsed.query and any(q in parsed.query.lower() for q in ("id=", "action=", "query=", "q=", "type=", "filter=")):
        return True

    return False

def is_target_url(url: str, target_domain: str) -> bool:
    """
    Determines if a URL is target-owned (relative path on target or absolute URL on target/subdomain).
    Protocol-relative URLs like '//vimeo.com/...' are properly recognized as external.
    """
    if not url:
        return False
    if url.startswith("//"):
        return is_target_domain("https:" + url, target_domain)
    elif url.startswith("/"):
        return True
    elif url.startswith(("http://", "https://", "ws://", "wss://")):
        return is_target_domain(url, target_domain)
    return False

def is_target_domain(url_or_host: str, target_domain: str) -> bool:
    """
    Validates whether a URL or host belongs to the target domain or its subdomains.
    """
    target_clean = target_domain.lower().strip()
    if target_clean.startswith(("http://", "https://")):
        target_clean = urllib.parse.urlparse(target_clean).netloc.split(":")[0]

    if url_or_host.startswith(("http://", "https://", "ws://", "wss://")):
        parsed = urllib.parse.urlparse(url_or_host)
        host = parsed.netloc.split(":")[0].lower()
    else:
        host = url_or_host.split(":")[0].lower()

    if not host or "." not in host:
        return False

    return host == target_clean or host.endswith("." + target_clean)

def strip_js_comments(code: str) -> str:
    """
    Strips JavaScript block comments (/* ... */) and line comments (// ...)
    while preserving string literals.
    """
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " "
        else:
            return s
    
    # Combined regex matching line comments, block comments, and quoted strings
    pattern = re.compile(
        r'//.*?$|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"' + r"|'(?:\\.|[^'\\])*'" + r'|`(?:\\.|[^`\\])*`',
        re.MULTILINE
    )
    return pattern.sub(replacer, code)

def extract_balanced_call(text: str, open_paren_idx: int) -> Tuple[str, int]:
    """
    Given text and the index of an opening parenthesis '(',
    returns the balanced contents inside the parenthesis and the ending index.
    Properly handles nested parentheses, braces, brackets, and quotes.
    """
    depth = 0
    in_quote = None
    escape = False
    start_pos = open_paren_idx + 1
    
    for i in range(open_paren_idx, len(text)):
        ch = text[i]
        
        if in_quote:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == in_quote:
                in_quote = None
            continue
            
        if ch in ("'", '"', '`'):
            in_quote = ch
            continue
            
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return text[start_pos:i].strip(), i + 1
                
    return "", -1

def extract_params_from_js_block(block: str) -> List[str]:
    """
    Extracts parameter/field names from a JS object string, prioritizing 'body' or 'data' blocks.
    Filters out HTTP headers and internal options.
    """
    params: List[str] = []
    
    payload_m = re.search(r'\b(?:body|data)\s*:\s*(?:JSON\.stringify\s*\(\s*)?\{([^}]+)\}', block, re.DOTALL | re.IGNORECASE)
    search_text = payload_m.group(1) if payload_m else block

    pairs = re.findall(r"['\"`]?([a-zA-Z0-9_$]+)['\"`]?\s*:", search_text)
    for p in pairs:
        p_clean = p.strip()
        if p_clean.lower() not in HTTP_NON_PARAM_KEYS and not p_clean.startswith("__"):
            if p_clean not in params:
                params.append(p_clean)

    return params

def normalize_js_endpoint_url(raw_url: str, configs: Dict[str, str]) -> str:
    """
    Normalizes JS endpoint URLs including template literals and known API_BASE concatenations.
    e.g. `/api/v1/users/${id}` -> `/api/v1/users/{id}`
    e.g. `API_BASE + "/users"` -> `/api/v1/users` (if API_BASE is `/api/v1`)
    """
    raw_url = raw_url.strip()
    if not raw_url:
        return ""
        
    if (raw_url.startswith(("'", '"', '`')) and raw_url.endswith(("'", '"', '`'))) and len(raw_url) >= 2:
        raw_url = raw_url[1:-1].strip()

    if "${" in raw_url:
        raw_url = re.sub(r"\$\{([^}]+)\}", r"{\1}", raw_url)

    concat_m = re.match(r"^(?:API_BASE|apiBase|baseURL|apiUrl)\s*\+\s*['\"`]([^'\"`]+)['\"`]$", raw_url, re.IGNORECASE)
    if concat_m:
        base = configs.get("api_base", "").rstrip("/")
        path = concat_m.group(1).lstrip("/")
        raw_url = f"{base}/{path}" if base else f"/{path}"

    if '"+"' in raw_url or "'+'" in raw_url or "`+`" in raw_url or '" + "' in raw_url or "' + '" in raw_url:
        raw_url = re.sub(r"['\"`]\s*\+\s*['\"`]", "", raw_url)

    return raw_url.strip()

class DOMSourceParser(HTMLParser):
    """
    DOM Parser that inspects HTML elements, attributes, forms, meta tags, and scripts.
    Categorizes elements and attributes with source attribution (Forms, HTMX, Data APIs, Router Links).
    """
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.meta_tags: List[Dict[str, str]] = []
        self.link_tags: List[Dict[str, str]] = []
        self.script_srcs: List[str] = []
        self.inline_scripts: List[str] = []
        self.forms: List[Dict[str, Any]] = []
        self.href_links: List[str] = []
        self.dom_api_endpoints: List[Dict[str, Any]] = []
        self.dom_app_routes: Set[str] = set()
        self.dom_config_refs: Set[str] = set()
        self.framework_markers: List[Dict[str, Any]] = []
        self.data_configs: Dict[str, str] = {}

        self._current_tag = None
        self._current_script = []
        self._current_form = None
        self._current_form_fields = []

    def handle_starttag(self, tag, attrs):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        tag_lower = tag.lower()
        self._current_tag = tag_lower

        # Framework markers & data configs
        for k, v in attrs:
            k_lower = k.lower()
            if k_lower == "ng-version":
                self.framework_markers.append({"name": "Angular", "version": v, "category": "Frontend", "source": f"ng-version attribute: {v}"})
            elif k_lower.startswith("data-v-"):
                self.framework_markers.append({"name": "Vue.js", "version": None, "category": "Frontend", "source": "data-v-* attribute"})
            elif k_lower == "data-reactroot":
                self.framework_markers.append({"name": "React", "version": None, "category": "Frontend", "source": "data-reactroot attribute"})
            elif k_lower == "data-api-base":
                self.data_configs["api_base"] = v
            elif k_lower == "data-backend-url":
                self.data_configs["backend_url"] = v
            elif k_lower == "data-env":
                self.data_configs["environment"] = v

                # HTML5 Media / Content Sinks (OpenRecon HTML sink port)
        if tag_lower == "iframe" and "src" in attr_dict:
            src_val = attr_dict["src"].strip()
            if src_val:
                self.href_links.append(src_val)
        elif tag_lower == "button" and "formaction" in attr_dict:
            formaction_val = attr_dict["formaction"].strip()
            if formaction_val:
                self.dom_api_endpoints.append({
                    "method": attr_dict.get("formmethod", "POST").upper(),
                    "url": formaction_val,
                    "params": [],
                    "display": f"{attr_dict.get('formmethod', 'POST').upper()} {formaction_val}",
                    "source": "HTML_BUTTON_FORMACTION"
                })
        elif tag_lower == "source" and "src" in attr_dict:
            src_val = attr_dict["src"].strip()
            if src_val:
                self.href_links.append(src_val)
        elif tag_lower in ("audio", "video", "img") and "src" in attr_dict:
            src_val = attr_dict["src"].strip()
            if src_val:
                self.href_links.append(src_val)
        elif tag_lower == "meta" and attr_dict.get("http-equiv", "").lower() == "refresh":
            content_val = attr_dict.get("content", "").strip()
            if content_val and "url=" in content_val.lower():
                parts = content_val.lower().split("url=")
                if len(parts) > 1:
                    ref_url = parts[1].strip()
                    if ref_url:
                        self.href_links.append(ref_url)

        elem_id = attr_dict.get("id", "")
        if elem_id == "__next":
            self.framework_markers.append({"name": "Next.js", "version": None, "category": "Framework", "source": "id=__next DOM marker"})
        elif elem_id == "__nuxt":
            self.framework_markers.append({"name": "Nuxt.js", "version": None, "category": "Framework", "source": "id=__nuxt DOM marker"})

        # HTMX Declarative Endpoints (hx-get, hx-post, hx-put, hx-delete, hx-patch)
        htmx_methods = {
            "hx-get": "GET",
            "hx-post": "POST",
            "hx-put": "PUT",
            "hx-delete": "DELETE",
            "hx-patch": "PATCH"
        }
        for hx_attr, hx_method in htmx_methods.items():
            if hx_attr in attr_dict:
                endpoint_val = attr_dict[hx_attr].strip()
                if endpoint_val and is_target_url(endpoint_val, self.base_url) and is_api_endpoint_request(hx_method, endpoint_val):
                    params = []
                    hx_vals = attr_dict.get("hx-vals", "")
                    if hx_vals:
                        try:
                            import json
                            vals_obj = json.loads(hx_vals)
                            if isinstance(vals_obj, dict):
                                params = [str(k) for k in vals_obj.keys() if str(k).lower() not in HTTP_NON_PARAM_KEYS]
                        except Exception:
                            params = [p for p in re.findall(r"""['\"`]?([a-zA-Z0-9_$]+)['\"`]?\s*:""", hx_vals) if p.lower() not in HTTP_NON_PARAM_KEYS]
                    
                    disp = f"{hx_method} {endpoint_val}" if hx_method != "GET" else endpoint_val
                    self.dom_api_endpoints.append({
                        "method": hx_method,
                        "url": endpoint_val,
                        "params": params,
                        "display": disp,
                        "source": "HTML_HTMX"
                    })

        # HTML5 Data API Attributes
        for data_attr in ("data-endpoint", "data-api", "data-action", "data-url"):
            if data_attr in attr_dict:
                data_val = attr_dict[data_attr].strip()
                if data_val and is_target_url(data_val, self.base_url) and is_api_endpoint_request("GET", data_val):
                    self.dom_api_endpoints.append({
                        "method": "GET",
                        "url": data_val,
                        "params": [],
                        "display": data_val,
                        "source": "HTML_DATA_ATTR"
                    })

        # Declarative Router Links (<router-link to="...">, <nuxt-link to="...">)
        if tag_lower in ("router-link", "nuxt-link", "link-to"):
            to_val = attr_dict.get("to") or attr_dict.get("href")
            if to_val and to_val.startswith("/") and not to_val.startswith("//"):
                self.dom_app_routes.add(to_val)

        # Onclick Navigation Handlers
        onclick_val = attr_dict.get("onclick", "")
        if onclick_val:
            m = re.search(r"""(?:location(?:\.href|\.assign)?\s*=\s*|window\.open\s*\(\s*)['"`](/[a-zA-Z0-9_/-]+)['"`]""", onclick_val)
            if m:
                target_path = m.group(1).strip()
                if is_api_endpoint_request("GET", target_path):
                    self.dom_api_endpoints.append({
                        "method": "GET",
                        "url": target_path,
                        "params": [],
                        "display": target_path,
                        "source": "HTML_EVENT_HANDLER"
                    })
                else:
                    self.dom_app_routes.add(target_path)

        # Button formaction sink
        if tag_lower == "button" and "formaction" in attr_dict:
            fa_val = attr_dict["formaction"].strip()
            if fa_val and is_target_url(fa_val, self.base_url):
                fa_method = attr_dict.get("formmethod", "POST").upper()
                if is_api_endpoint_request(fa_method, fa_val):
                    self.dom_api_endpoints.append({
                        "method": fa_method,
                        "url": fa_val,
                        "params": [],
                        "display": f"{fa_method} {fa_val}" if fa_method != "GET" else fa_val,
                        "source": "HTML_BUTTON_FORMACTION"
                    })
                elif APP_ROUTE_PATH_PATTERN.search(fa_val):
                    self.dom_app_routes.add(fa_val)

        # Iframe src sink
        if tag_lower == "iframe" and "src" in attr_dict:
            ifr_val = attr_dict["src"].strip()
            if ifr_val and is_target_url(ifr_val, self.base_url) and not ifr_val.startswith("javascript:"):
                if APP_ROUTE_PATH_PATTERN.search(ifr_val):
                    self.dom_app_routes.add(ifr_val)

        # Meta refresh sink
        if tag_lower == "meta" and attr_dict.get("http-equiv", "").lower() == "refresh":
            content_val = attr_dict.get("content", "")
            url_m = re.search(r'''url\s*=\s*['"]?([^'"\s;>]+)''', content_val, re.IGNORECASE)
            if url_m:
                ref_url = url_m.group(1).strip()
                if is_target_url(ref_url, self.base_url) and APP_ROUTE_PATH_PATTERN.search(ref_url):
                    self.dom_app_routes.add(ref_url)


        # OpenRecon HTML tag parsers
        if tag_lower == "base" and "href" in attr_dict:
            base_href = attr_dict["href"].strip()
            if base_href:
                self.href_links.append(base_href)
        elif tag_lower in ("blockquote", "q", "del", "ins") and "cite" in attr_dict:
            cite_val = attr_dict["cite"].strip()
            if cite_val:
                self.href_links.append(cite_val)
        elif tag_lower == "embed" and "src" in attr_dict:
            src_val = attr_dict["src"].strip()
            if src_val:
                self.href_links.append(src_val)
        elif tag_lower == "object":
            for object_attr in ("data", "codebase"):
                if object_attr in attr_dict:
                    val = attr_dict[object_attr].strip()
                    if val:
                        self.href_links.append(val)
        elif tag_lower in ("body", "table", "tr", "td", "th") and "background" in attr_dict:
            bg_val = attr_dict["background"].strip()
            if bg_val:
                self.href_links.append(bg_val)
        elif tag_lower in ("svg", "image", "use"):
            for href_attr in ("href", "xlink:href"):
                if href_attr in attr_dict:
                    href_val = attr_dict[href_attr].strip()
                    if href_val:
                        self.href_links.append(href_val)
        elif tag_lower == "area" and "ping" in attr_dict:
            ping_val = attr_dict["ping"].strip()
            if ping_val:
                self.href_links.append(ping_val)
        elif tag_lower == "a" and "ping" in attr_dict:
            ping_val = attr_dict["ping"].strip()
            if ping_val:
                self.href_links.append(ping_val)

        if tag_lower == "meta":
            self.meta_tags.append(attr_dict)
        elif tag_lower == "link":
            self.link_tags.append(attr_dict)
            if attr_dict.get("rel") == "service-worker":
                href = attr_dict.get("href")
                if href:
                    self.dom_config_refs.add(href)
        elif tag_lower == "script":
            src = attr_dict.get("src")
            if src:
                self.script_srcs.append(src)
            self._current_script = []
        elif tag_lower == "a":
            href = attr_dict.get("href")
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#", "about:")):
                self.href_links.append(href)
        elif tag_lower == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "POST").upper(),
                "id": attr_dict.get("id", "")
            }
            self._current_form_fields = []
        elif tag_lower in ("input", "textarea", "select"):
            name = attr_dict.get("name")
            inp_type = attr_dict.get("type", "text").lower()
            if self._current_form is not None:
                if inp_type == "file":
                    self._current_form_fields.append("file")
                elif name and name not in self._current_form_fields:
                    self._current_form_fields.append(name)

    def handle_data(self, data):
        if self._current_tag == "script":
            self._current_script.append(data)

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower == "script":
            if self._current_script:
                script_text = "".join(self._current_script).strip()
                if script_text:
                    self.inline_scripts.append(script_text)
            self._current_script = []
            self._current_tag = None
        elif tag_lower == "form":
            if self._current_form is not None:
                self._current_form["fields"] = list(self._current_form_fields)
                self.forms.append(self._current_form)
            self._current_form = None
            self._current_form_fields = []

def filter_functional_forms(forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Retains only meaningful application forms (authentication, registration,
    password reset, file upload, account/profile actions).
    Filters out contact, newsletter, search, and generic feedback forms.
    """
    functional_forms = []
    seen = set()

    for f in forms:
        action = f.get("action", "").strip()
        method = f.get("method", "POST").upper()
        fields = f.get("fields", [])
        fields_lower = [fld.lower() for fld in fields]

        is_auth = any(k in action.lower() for k in ("/login", "/signin", "/auth", "/session", "/oauth"))
        is_auth_fields = any("pass" in fld or "pwd" in fld for fld in fields_lower) and any(u in fld for fld in fields_lower for u in ("user", "email", "login", "uname", "account"))
        is_upload = "file" in fields_lower or any(k in action.lower() for k in ("/upload", "/import"))
        is_register = any(k in action.lower() for k in ("/register", "/signup", "/join", "/create-account"))
        is_reset = any(k in action.lower() for k in ("/reset", "/forgot", "/recover", "/password"))
        is_account = any(k in action.lower() for k in ("/profile", "/account", "/settings", "/billing", "/checkout", "/manage"))

        if is_auth or is_auth_fields or is_upload or is_register or is_reset or is_account:
            clean_action = action if action else "/"
            key = f"{method} {clean_action}"
            if key not in seen:
                seen.add(key)
                functional_forms.append({
                    "method": method,
                    "action": clean_action,
                    "fields": fields
                })

    return functional_forms

APP_ROUTE_PATTERN = re.compile(
    r'/(?:login|logout|signin|signout|signup|register|admin|dashboard|upload|account|settings|profile|portal|reset-password|forgot-password|checkout|billing|manage|auth|oauth|sims|grievance|admissions?|careers?|apply)(?:[/?#._-]|$)',
    re.IGNORECASE
)

# 1. Functional Application Route Keywords (Paths)
# These represent actual interactive application features: auth, admin, management, portals, forms, user consoles
APP_ROUTE_PATH_PATTERN = re.compile(
    r'/(?:'
    r'login|logout|signin|signout|signup|register|'
    r'admin|dashboard|portal|console|panel|manage|'
    r'account|profile|settings|billing|checkout|'
    r'auth|oauth|sso|mfa|'
    r'reset-password|forgot-password|change-password|'
    r'upload|file/upload|import|export|'
    r'sims|grievance|admission-query|apply|enquiry'
    r')(?:[/?#._-]|$)',
    re.IGNORECASE
)

# 2. Subdomain Services & Portals
# Subdomains representing actual applications, portals, management, or authentication services
APP_PORTAL_SUBDOMAIN_PREFIXES = (
    "staff.", "student.", "students.", "results.", "projects.",
    "portal.", "portals.", "app.", "apps.", "admin.", "dashboard.",
    "auth.", "login.", "sso.", "console.", "manage.", "panel.",
    "erp.", "lms.", "vms.", "sims.", "sis.", "secure."
)

# Subdomain prefixes to explicitly IGNORE as non-application / informational / static
NON_APP_SUBDOMAINS = (
    "blog.", "blogs.", "news.", "docs.", "documentation.", "devguide.",
    "wiki.", "peps.", "status.", "jobs.", "donate.", "translations.",
    "mail.", "lists.", "policies.", "privacy.", "static.", "assets.",
    "cdn.", "media.", "images.", "img.", "download.", "downloads."
)

def extract_meaningful_app_routes(hrefs: List[str], base_url: str) -> List[str]:
    """
    Filters HTML href links down to genuine, target-owned application routes and subdomain portals.
    Excludes ordinary navigation, blogs, documentation, jobs, status, and informational pages.
    """
    parsed_base = urllib.parse.urlparse(base_url)
    base_host = parsed_base.netloc.split(":")[0].lower()
    app_routes: Set[str] = set()

    for href in hrefs:
        href_clean = href.strip()
        if not href_clean or is_static_asset(href_clean):
            continue

        resolved = urllib.parse.urljoin(base_url, href_clean)
        parsed_href = urllib.parse.urlparse(resolved)
        host = parsed_href.netloc.split(":")[0].lower()

        if is_target_domain(host, base_host):
            # Target subdomain
            if host != base_host and host.endswith("." + base_host):
                if any(host.startswith(na) for na in NON_APP_SUBDOMAINS):
                    path = parsed_href.path
                    if APP_ROUTE_PATH_PATTERN.search(path):
                        app_routes.add(f"https://{host}{path}")
                elif any(host.startswith(pfx) for pfx in APP_PORTAL_SUBDOMAIN_PREFIXES) or APP_ROUTE_PATH_PATTERN.search(parsed_href.path):
                    path = parsed_href.path if parsed_href.path and parsed_href.path != "/" else "/"
                    if path.count("/") <= 2 and not path.endswith((".html", ".htm", ".pdf")):
                        app_routes.add(f"https://{host}{path}")
                    elif APP_ROUTE_PATH_PATTERN.search(path):
                        app_routes.add(f"https://{host}{path}")
            else:
                path = parsed_href.path
                if APP_ROUTE_PATH_PATTERN.search(path):
                    app_routes.add(path)

    return sorted(list(app_routes))


def extract_oauth_configurations(code: str) -> List[Dict[str, str]]:
    """
    Extracts client-side OAuth 2.0 / OIDC identity provider configurations,
    client IDs, redirect URIs, scopes, and tenant information.
    """
    findings: List[Dict[str, str]] = []
    seen: Set[str] = set()

    oauth_patterns = [
        ("Auth Domain / Issuer", re.compile(r"""\b(?:issuer|authority|authServer|authDomain|auth_domain)\s*[:=]\s*['"`](https?://[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*|[a-zA-Z0-9_.-]+\.(?:auth0\.com|okta\.com|oktapreview\.com|b2clogin\.com|microsoftonline\.com))['"`]""", re.IGNORECASE)),
        ("Auth0 Domain", re.compile(r"""\b(?:domain)\s*[:=]\s*['"`]([a-zA-Z0-9_.-]+\.(?:auth0\.com|okta\.com|oktapreview\.com))['"`]""", re.IGNORECASE)),
        ("OAuth Client ID", re.compile(r"""\b(?:clientId|client_id|appId|app_id|userPoolClientId)\s*[:=]\s*['"`]([a-zA-Z0-9_-]{12,64})['"`]""", re.IGNORECASE)),
        ("OAuth Redirect URI", re.compile(r"""\b(?:redirectUri|redirect_uri|callbackUrl|callback_url|redirect_url)\s*[:=]\s*['"`](https?://[^\s'"`<>]+|/[a-zA-Z0-9_/.-]*)['"`]""", re.IGNORECASE)),
        ("OAuth Scope", re.compile(r"""\b(?:scope|scopes)\s*[:=]\s*['"`](openid[^'"`<>]*)['"`]""", re.IGNORECASE)),
        ("Azure Tenant ID", re.compile(r"""\b(?:tenantId|tenant_id|tenant)\s*[:=]\s*['"`]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"`]""", re.IGNORECASE)),
        ("Keycloak Realm", re.compile(r"""\b(?:realm)\s*[:=]\s*['"`]([a-zA-Z0-9_-]{3,32})['"`]""", re.IGNORECASE))
    ]

    for label, pattern in oauth_patterns:
        for m in pattern.finditer(code):
            val = m.group(1).strip()
            if val.lower() in ("true", "false", "null", "undefined", "localhost", "127.0.0.1", "username", "password"):
                continue
            k = f"{label}: {val}"
            if k not in seen:
                seen.add(k)
                findings.append({"label": label, "value": val, "display": f"{label}: {val}"})

    return findings

def extract_graphql_operations(code: str) -> List[Dict[str, Any]]:
    """
    Extracts GraphQL operation definitions (queries, mutations, subscriptions)
    from client-side JavaScript bundles, Apollo Client, urql, and Relay tags.
    """
    operations: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    pattern = re.compile(
        r'\b(query|mutation|subscription)\s+([a-zA-Z0-9_$]+)(?:\s*\(([^)]*)\))?\s*\{',
        re.IGNORECASE
    )

    for m in pattern.finditer(code):
        op_type = m.group(1).upper()
        op_name = m.group(2).strip()
        raw_vars = m.group(3) or ""
        
        if op_name.lower() in ("true", "false", "null", "undefined", "function", "var", "let", "const"):
            continue

        var_names = []
        if raw_vars:
            var_names = [v.strip().lstrip("$") for v in re.findall(r'\$([a-zA-Z0-9_$]+)', raw_vars)]

        key = f"{op_type} {op_name}"
        if key not in seen:
            seen.add(key)
            disp = f"{op_type} {op_name}"
            if var_names:
                disp += f" ({', '.join(var_names)})"
            operations.append({
                "type": op_type,
                "name": op_name,
                "variables": var_names,
                "display": disp
            })

    return operations

def analyze_javascript_requests(raw_code: str, target_domain: str, source_label: str = "inline script") -> Tuple[List[Dict[str, Any]], List[str], List[str], Dict[str, str], Set[str]]:
    """
    AST-based lexical parsing of JavaScript requests, endpoints, parameters, and configs.
    Supports fetch, axios, jQuery AJAX, XMLHttpRequest, WebSocket, navigator.sendBeacon, EventSource,
    new Request, ky, superagent, ServiceWorkers, and dynamic client-side routers.
    """
    code = strip_js_comments(raw_code)
    api_endpoints: List[Dict[str, Any]] = []
    seen_apis: Set[str] = set()
    app_routes: Set[str] = set()
    websockets: Set[str] = set()
    configs: Dict[str, str] = {}
    config_refs: Set[str] = set()



    # 1. API Configurations
    api_base_pat = re.compile(
        r"""\b(?:API_BASE|API_BASE_URL|apiBase|api_base|apiBaseUrl|api_base_url|baseURL|baseUrl|apiHost|api_host|apiUrl|api_url|apiEndpoint)\s*[:=]\s*['"`](https?://[^\s'"`<>]+|/[a-zA-Z0-9_/.-]*)['"`]""",
        re.IGNORECASE
    )
    for m in api_base_pat.finditer(code):
        val = m.group(1).strip()
        if is_target_url(val, target_domain) and not val.endswith(STATIC_ASSET_EXTS):
            configs["api_base"] = val
            break

    backend_pat = re.compile(
        r"""\b(?:BACKEND_URL|backendUrl|backend_url|SERVER_URL|serverUrl|server_url|API_SERVER|apiServer)\s*[:=]\s*['"`](https?://[^\s'"`<>]+)['"`]""",
        re.IGNORECASE
    )
    for m in backend_pat.finditer(code):
        val = m.group(1).strip()
        if is_target_url(val, target_domain):
            configs["backend_url"] = val
            break

    env_pat = re.compile(
        r"""\b(?:ENVIRONMENT|environment|env|NODE_ENV|app_env|APP_ENV|REACT_APP_ENV|NEXT_PUBLIC_ENV|VITE_ENV)\s*[:=]\s*['"`](staging|production|development|dev|prod|test|testing|sandbox|qa|uat)['"`]""",
        re.IGNORECASE
    )
    env_m = env_pat.search(code)
    if env_m:
        configs["environment"] = env_m.group(1).strip().lower()

    # 2. axios.create({ baseURL: ... })
    for m in re.finditer(r"axios\.create\s*\(", code, re.IGNORECASE):
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        burl_m = re.search(r"""baseURL\s*:\s*['"`]([^'"`]+)['"`]""", call_content, re.IGNORECASE)
        if burl_m and "api_base" not in configs:
            configs["api_base"] = burl_m.group(1).strip()

    # 3. Lexical Function Calls
    # A. fetch(...)
    for m in re.finditer(r"\bfetch\s*\(", code):
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue

        url_match = re.match(r"""^(?:['"`]([^'"`]+)['"`]|`([^`]+)`|([a-zA-Z0-9_$]+\s*\+\s*['"`][^'"`]+['"`])|([a-zA-Z0-9_$]+))""", call_content)
        if url_match:
            raw_url = url_match.group(1) or url_match.group(2) or url_match.group(3) or url_match.group(4) or ""
            url_part = normalize_js_endpoint_url(raw_url, configs)
            opts_part = call_content[url_match.end():]

            if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part):
                method = "GET"
                method_m = re.search(r"""\bmethod\s*:\s*['"]([a-zA-Z]+)['"]""", opts_part, re.IGNORECASE)
                if method_m:
                    method = method_m.group(1).upper()
                elif "body:" in opts_part or "body :" in opts_part:
                    method = "POST"

                if is_api_endpoint_request(method, url_part):
                    params = extract_params_from_js_block(opts_part)
                    key = f"{method} {url_part}"
                    if key not in seen_apis:
                        seen_apis.add(key)
                        disp = f"{method} {url_part}" if method != "GET" else url_part
                        api_endpoints.append({
                            "method": method,
                            "url": url_part,
                            "params": params,
                            "display": disp,
                            "source": "JS_FETCH"
                        })

    # B. navigator.sendBeacon(url, data)
    for m in re.finditer(r"\bnavigator\.sendBeacon\s*\(", code):
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue
        url_match = re.match(r"""^(?:['"`]([^'"`]+)['"`]|`([^`]+)`)""", call_content)
        if url_match:
            raw_url = url_match.group(1) or url_match.group(2) or ""
            url_part = normalize_js_endpoint_url(raw_url, configs)
            if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part) and is_api_endpoint_request("POST", url_part):
                params = extract_params_from_js_block(call_content)
                key = f"POST {url_part}"
                if key not in seen_apis:
                    seen_apis.add(key)
                    api_endpoints.append({
                        "method": "POST",
                        "url": url_part,
                        "params": params,
                        "display": f"POST {url_part}",
                        "source": "JS_BEACON"
                    })

    # C. new EventSource(url) - SSE
    for m in re.finditer(r"\bnew\s+EventSource\s*\(", code):
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue
        url_match = re.match(r"""^(?:['"`]([^'"`]+)['"`]|`([^`]+)`)""", call_content)
        if url_match:
            raw_url = url_match.group(1) or url_match.group(2) or ""
            url_part = normalize_js_endpoint_url(raw_url, configs)
            if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part):
                key = f"GET {url_part}"
                if key not in seen_apis:
                    seen_apis.add(key)
                    api_endpoints.append({
                        "method": "GET",
                        "url": url_part,
                        "params": [],
                        "display": f"{url_part} (SSE)",
                        "source": "JS_EVENTSOURCE"
                    })

    # D. new Request(url, opts)
    for m in re.finditer(r"\bnew\s+Request\s*\(", code):
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue
        url_match = re.match(r"""^(?:['"`]([^'"`]+)['"`]|`([^`]+)`)""", call_content)
        if url_match:
            raw_url = url_match.group(1) or url_match.group(2) or ""
            url_part = normalize_js_endpoint_url(raw_url, configs)
            opts_part = call_content[url_match.end():]
            if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part):
                method_m = re.search(r"""\bmethod\s*:\s*['"]([a-zA-Z]+)['"]""", opts_part, re.IGNORECASE)
                method = method_m.group(1).upper() if method_m else ("POST" if "body:" in opts_part else "GET")
                if is_api_endpoint_request(method, url_part):
                    params = extract_params_from_js_block(opts_part)
                    key = f"{method} {url_part}"
                    if key not in seen_apis:
                        seen_apis.add(key)
                        disp = f"{method} {url_part}" if method != "GET" else url_part
                        api_endpoints.append({
                            "method": method,
                            "url": url_part,
                            "params": params,
                            "display": disp,
                            "source": "JS_REQUEST"
                        })

    # E. axios calls: axios.get, axios.post, axios.put, axios.delete, axios.patch, axios({ ... })
    for m in re.finditer(r"\baxios(?:\.(get|post|put|delete|patch))?\s*\(", code):
        ax_method = m.group(1)
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue

        if ax_method:
            method = ax_method.upper()
            url_match = re.match(r"""^(?:['"`]([^'"`]+)['"`]|`([^`]+)`|([a-zA-Z0-9_$]+\s*\+\s*['"`][^'"`]+['"`]))""", call_content)
            if url_match:
                raw_url = url_match.group(1) or url_match.group(2) or url_match.group(3) or ""
                url_part = normalize_js_endpoint_url(raw_url, configs)
                opts_part = call_content[url_match.end():]
                if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part) and is_api_endpoint_request(method, url_part):
                    params = extract_params_from_js_block(opts_part)
                    key = f"{method} {url_part}"
                    if key not in seen_apis:
                        seen_apis.add(key)
                        disp = f"{method} {url_part}" if method != "GET" else url_part
                        api_endpoints.append({
                            "method": method,
                            "url": url_part,
                            "params": params,
                            "display": disp,
                            "source": "JS_AXIOS"
                        })
        else:
            url_m = re.search(r"""\burl\s*:\s*['"`]([^'"`]+)['"`]""", call_content, re.IGNORECASE)
            if url_m:
                raw_url = url_m.group(1).strip()
                url_part = normalize_js_endpoint_url(raw_url, configs)
                if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part) and is_api_endpoint_request(method, url_part):
                    method_m = re.search(r"""\bmethod\s*:\s*['"]([a-zA-Z]+)['"]""", call_content, re.IGNORECASE)
                    method = method_m.group(1).upper() if method_m else "GET"
                    params = extract_params_from_js_block(call_content)
                    key = f"{method} {url_part}"
                    if key not in seen_apis:
                        seen_apis.add(key)
                        disp = f"{method} {url_part}" if method != "GET" else url_part
                        api_endpoints.append({
                            "method": method,
                            "url": url_part,
                            "params": params,
                            "display": disp,
                            "source": "JS_AXIOS"
                        })

    # F. Modern HTTP Clients: ky & superagent
    for m in re.finditer(r"\b(?:ky|superagent)\.(get|post|put|delete|patch)\s*\(", code):
        method = m.group(1).upper()
        call_content, end_pos = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue
        url_match = re.match(r"""^(?:['"`]([^'"`]+)['"`]|`([^`]+)`)""", call_content)
        if url_match:
            raw_url = url_match.group(1) or url_match.group(2) or ""
            url_part = normalize_js_endpoint_url(raw_url, configs)
            trailing_code = code[end_pos:end_pos+120] if end_pos != -1 else ""
            opts_part = call_content[url_match.end():] + " " + trailing_code
            if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part) and is_api_endpoint_request(method, url_part):
                params = extract_params_from_js_block(opts_part)
                key = f"{method} {url_part}"
                if key not in seen_apis:
                    seen_apis.add(key)
                    disp = f"{method} {url_part}" if method != "GET" else url_part
                    api_endpoints.append({
                        "method": method,
                        "url": url_part,
                        "params": params,
                        "display": disp,
                        "source": "JS_CLIENT"
                    })

    # G. jQuery AJAX: $.ajax({ ... }), $.get, $.post, $.getJSON
    for m in re.finditer(r"(?:\$|jQuery)\.(?:ajax|get|post|getJSON)\s*\(", code):
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue

        url_m = re.search(r"""\burl\s*:\s*['"`]([^'"`]+)['"`]""", call_content, re.IGNORECASE)
        if not url_m:
            url_m = re.match(r"""^(?:['"`]([^'"`]+)['"`]|`([^`]+)`)""", call_content)

        if url_m:
            raw_url = url_m.group(1) or (url_m.group(2) if len(url_m.groups()) > 1 else "") or ""
            url_part = normalize_js_endpoint_url(raw_url, configs)
            if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part):
                method_m = re.search(r"""\b(?:type|method)\s*:\s*['"]([a-zA-Z]+)['"]""", call_content, re.IGNORECASE)
                if method_m:
                    method = method_m.group(1).upper()
                elif ".post(" in m.group(0):
                    method = "POST"
                else:
                    method = "GET"

                if is_api_endpoint_request(method, url_part):
                    params = extract_params_from_js_block(call_content)
                    key = f"{method} {url_part}"
                    if key not in seen_apis:
                        seen_apis.add(key)
                        disp = f"{method} {url_part}" if method != "GET" else url_part
                        api_endpoints.append({
                            "method": method,
                            "url": url_part,
                            "params": params,
                            "display": disp,
                            "source": "JS_JQUERY"
                        })

    # H. XMLHttpRequest: xhr.open(method, url)
    for m in re.finditer(r"\.open\s*\(", code):
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue
        xhr_m = re.match(r"""['"`]([a-zA-Z]+)['"`]\s*,\s*['"`]([^'"`]+)['"`]""", call_content)
        if xhr_m:
            method = xhr_m.group(1).upper()
            raw_url = xhr_m.group(2).strip()
            url_part = normalize_js_endpoint_url(raw_url, configs)
            if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part) and is_api_endpoint_request(method, url_part):
                key = f"{method} {url_part}"
                if key not in seen_apis:
                    seen_apis.add(key)
                    disp = f"{method} {url_part}" if method != "GET" else url_part
                    api_endpoints.append({
                        "method": method,
                        "url": url_part,
                        "params": [],
                        "display": disp,
                        "source": "JS_XHR"
                    })

    # I. WebSocket: new WebSocket("wss://...") or ws config
    for m in re.finditer(r"new\s+WebSocket\s*\(", code):
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue
        ws_m = re.match(r"""['"`](wss?://[^'"`]+)['"`]""", call_content)
        if ws_m:
            ws_url = ws_m.group(1).strip()
            if is_target_url(ws_url, target_domain):
                websockets.add(ws_url)

    for m in re.finditer(r"""\b(?:wsUrl|wsEndpoint|websocket|ws_url|ws_endpoint)\s*[:=]\s*['"`](wss?://[^'"`\s<>]+)['"`]""", code, re.IGNORECASE):
        ws_url = m.group(1).strip()
        if is_target_url(ws_url, target_domain):
            websockets.add(ws_url)

    # J. ServiceWorker and WebWorker registration
    for m in re.finditer(r"\b(?:navigator\.serviceWorker\.register|new\s+Worker)\s*\(", code):
        call_content, _ = extract_balanced_call(code, m.end() - 1)
        if not call_content:
            continue
        url_match = re.match(r"""^(?:['"`]([^'"`]+)['"`]|`([^`]+)`)""", call_content)
        if url_match:
            raw_url = url_match.group(1) or url_match.group(2) or ""
            url_part = normalize_js_endpoint_url(raw_url, configs)
            if url_part and is_target_url(url_part, target_domain):
                config_refs.add(url_part)

    # K. Client-Side Navigation: router.push("/dashboard"), window.location = "/dashboard"
    nav_pat = re.compile(
        r"""\b(?:(?:window\.)?location(?:\.href|\.assign|\.replace)?\s*(?:=\s*|\(\s*)|router\.(?:push|replace)\s*\(\s*|navigate\s*\(\s*|history\.(?:pushState|replaceState)\s*\([^,()]*?,\s*[^,()]*?,\s*)['"`](/(?:login|logout|signin|signout|signup|register|admin|dashboard|upload|account|settings|profile|portal|reset-password|forgot-password|checkout|billing|manage)[a-zA-Z0-9_/-]*)['"`]""",
        re.IGNORECASE
    )
    for m in nav_pat.finditer(code):
        app_routes.add(m.group(1).strip())

        # L. Generalized JSLuice API Path String Extraction
    discovered_urls = {ep["url"] for ep in api_endpoints}
    generic_api_pat = re.compile(
        r'''['"`](/(?:api|v[1-9]|graphql|auth|admin|rest|rpc|service|services|oauth|token|user|users|account|data|webhook|webhooks|query)[a-zA-Z0-9_/-]*)['"`]''',
        re.IGNORECASE
    )
    for m in generic_api_pat.finditer(code):
        raw_path = m.group(1).strip()
        url_part = normalize_js_endpoint_url(raw_path, configs)
        if url_part and url_part not in discovered_urls and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part) and is_api_endpoint_request("GET", url_part):
            key = f"GET {url_part}"
            if key not in seen_apis:
                seen_apis.add(key)
                discovered_urls.add(url_part)
                api_endpoints.append({
                    "method": "GET",
                    "url": url_part,
                    "params": [],
                    "display": url_part,
                    "source": "JS_STRING_LITERAL"
                })

    # 5. Port of technology engine's scriptContentRegexParser / scriptJSFileRegexParser using relativeEndpointsRegex
    js_scraped = []
    for m in AST_JS_RE.finditer(code):
        ep_url = m.group(1).strip()
        ep_url = ep_url.strip("'\"")
        url_part = normalize_js_endpoint_url(ep_url, configs)
        if url_part and is_target_url(url_part, target_domain) and not is_filtered_static_extension(url_part):
            js_scraped.append(url_part)
            
    for url_part in js_scraped:
        fam = classify_endpoint("GET", url_part)
        is_api = (fam in ("rest", "graphql", "soap") or is_api_endpoint_request("GET", url_part))
        if is_api:
            k = f"GET {url_part}"
            if k not in seen_apis:
                seen_apis.add(k)
                api_endpoints.append({
                    "method": "GET",
                    "url": url_part,
                    "params": [],
                    "display": url_part,
                    "class": fam,
                    "source": "JS Regex",
                    "source_label": source_label
                })
        else:
            app_routes.add(url_part)

    # Walk Node AST JSLuice endpoints (run after Python fallback to allow merging params)
    node_eps = extract_endpoints_via_node_ast(raw_code)
    for node_ep in node_eps:
        u = node_ep.get("url", "")
        m = node_ep.get("method", "GET")
        if not u:
            continue
        if not is_target_url(u, target_domain):
            continue
        if is_filtered_static_extension(u):
            continue
        fam = classify_endpoint(m, u)
        params = ["dynamic"] if "{var}" in u or "{" in u else []
        disp = f"{m} {u}"
        k = f"{m} {u}"
        if k not in seen_apis:
            seen_apis.add(k)
            api_endpoints.append({
                "method": m,
                "url": u,
                "display": disp,
                "params": params,
                "class": fam,
                "source": "JSLuice AST",
                "source_label": source_label,
                "expression": node_ep.get("expression")
            })
        else:
            # If already seen, find and update/merge properties
            existing = next((ep for ep in api_endpoints if ep["method"] == m and ep["url"] == u), None)
            if existing:
                if fam:
                    existing["class"] = fam
                for p in params:
                    if p not in existing["params"]:
                        existing["params"].append(p)

    # Deduplicate and merge parameters/sinks for identical method+url
    merged = []
    seen_merged = {}
    for ep in api_endpoints:
        k = (ep["method"], ep["url"])
        if "class" not in ep:
            ep["class"] = classify_endpoint(ep["method"], ep["url"])
        if k in seen_merged:
            # Merge params
            for p in ep.get("params", []):
                if p not in seen_merged[k]["params"]:
                    seen_merged[k]["params"].append(p)
            # If the new ep has a specific class or source, merge/prefer
            if ep.get("class") and seen_merged[k].get("class") in ("xhr", "", None):
                seen_merged[k]["class"] = ep["class"]
        else:
            seen_merged[k] = ep
            merged.append(ep)
            
    # Prune redundant GET APIs if specific method (POST/PUT/DELETE/PATCH) is found for same URL path
    methods_by_url = {}
    for ep in merged:
        u = ep["url"]
        m = ep["method"]
        if u not in methods_by_url:
            methods_by_url[u] = set()
        methods_by_url[u].add(m)
        
    pruned_endpoints = []
    for ep in merged:
        u = ep["url"]
        m = ep["method"]
        if m == "GET" and len(methods_by_url[u]) > 1:
            continue
        pruned_endpoints.append(ep)
        
    api_endpoints = pruned_endpoints

    return api_endpoints, sorted(list(app_routes)), sorted(list(websockets)), configs, config_refs


TOKEN_SIGNATURES: List[Tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
    ("AWS Secret Key Assignment", re.compile(r"""\b(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['"]([0-9a-zA-Z/+=]{40})['"]""", re.IGNORECASE)),
    ("Google / Firebase API Key", re.compile(r'\b(AIzaSy[A-Za-z0-9_-]{33})\b')),
    ("Stripe Publishable Key", re.compile(r'\b(pk_(?:live|test)_[0-9a-zA-Z]{24,})\b')),
    ("Sentry DSN", re.compile(r'\b(https://[a-f0-9]{32}@[a-z0-9.-]+\.ingest\.sentry\.io/[0-9]+)\b', re.IGNORECASE)),
    ("Mapbox Access Token", re.compile(r'\b(pk\.eyJ1[a-zA-Z0-9._-]{50,})\b')),
    ("AWS Cognito Identity Pool ID", re.compile(r'\b((?:us-east-1|us-east-2|us-west-1|us-west-2|eu-west-1|eu-central-1|ap-southeast-1|ap-southeast-2):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b', re.IGNORECASE)),
    ("Slack Incoming Webhook", re.compile(r'\b(https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9A-Za-z]{24})\b')),
    ("Discord Webhook", re.compile(r'\b(https://(?:canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,68})\b')),
    ("Voiceflow Chatbot Project ID", re.compile(r"""\bprojectID\s*:\s*['"]([a-zA-Z0-9_-]{16,36})['"]""", re.IGNORECASE)),
    ("Collect.chat ID", re.compile(r"""\bCollectId\s*=\s*['"]([a-zA-Z0-9_-]{16,36})['"]""", re.IGNORECASE)),
    ("Google Custom Search ID", re.compile(r"""(?:cse\.js\?cx=|cx\s*:\s*['"])([a-zA-Z0-9_:.-]{10,40})""", re.IGNORECASE)),
    ("Intercom App ID", re.compile(r"""\b(?:app_id|appId)\s*:\s*['"]([a-zA-Z0-9]{8,12})['"]""", re.IGNORECASE)),
    ("Hotjar Site ID", re.compile(r"""\bhjid\s*:\s*([0-9]{5,10})""", re.IGNORECASE)),
    ("Private Key Structure", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'))
]

def mask_token(token: str) -> str:
    if token.startswith("https://"):
        return token
    if len(token) <= 8:
        return "***"
    return f"{token[:6]}...{token[-4:]}"

def extract_infrastructure_and_sensitive(text: str, source_label: str, target_domain: str = "") -> Tuple[List[str], List[str], List[str]]:
    """
    Extracts internal hostnames/IPs, cloud storage buckets, and high-confidence client/service credentials.
    """
    internal_hosts: List[str] = []
    cloud_storage: List[str] = []
    sensitive_findings: List[str] = []

    # 1. Private IPv4 Addresses
    internal_ips = re.findall(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b', text)
    for ip in set(internal_ips):
        if ip not in {"127.0.0.1", "0.0.0.0"}:
            internal_hosts.append(ip)

    # 2. Internal / Staging / Dev domains explicitly prefixed with http(s)://
    staging_urls = re.findall(r'\bhttps?://([a-zA-Z0-9_.-]+\.(?:dev|staging|stage|test|internal|local|corp|lan|intranet|priv)(?:\.[a-zA-Z0-9_-]+)?)\b', text, re.IGNORECASE)
    for d in set(staging_urls):
        internal_hosts.append(d)

    # 3. Non-prefixed hostnames ending in internal TLDs (e.g. db01.internal.example, vault.corp)
    internal_tld_hosts = re.findall(r'\b([a-zA-Z0-9_-]+\.[a-zA-Z0-9_.-]+\.(?:internal|corp|lan|intranet|priv))\b', text, re.IGNORECASE)
    for h in set(internal_tld_hosts):
        internal_hosts.append(h)

    # 4. Target staging / dev subdomains (e.g. staging.target.com, dev.target.com)
    if target_domain:
        subdomain_pat = re.compile(r'\bhttps?://([a-zA-Z0-9_.-]+)\b', re.IGNORECASE)
        for h in subdomain_pat.findall(text):
            if is_target_domain(h, target_domain):
                h_lower = h.lower()
                if any(k in h_lower for k in ("staging", "dev-", "-dev", "test-", "-test", "internal-", "-internal", "qa-", "-qa", "uat-", "-uat", "sandbox-", "-sandbox", "stage-", "-stage")):
                    internal_hosts.append(h)

    # 5. Cloud Storage Buckets (S3, GCS, Azure)
    buckets = re.findall(r'\b([a-zA-Z0-9_-]+\.s3\.amazonaws\.com|storage\.googleapis\.com/[a-zA-Z0-9_-]+|[a-zA-Z0-9_-]+\.blob\.core\.windows\.net)\b', text, re.IGNORECASE)
    for b in set(buckets):
        cloud_storage.append(b)

    s3_urls = re.findall(r'\bs3://([a-zA-Z0-9._-]+)\b', text, re.IGNORECASE)
    for s3 in set(s3_urls):
        cloud_storage.append(f"s3://{s3}")

    # 6. Structured Client Tokens & Credential Signatures
    seen_tokens = set()
    for name, pattern in TOKEN_SIGNATURES:
        for m in pattern.finditer(text):
            val = m.group(1) if m.groups() else m.group(0)
            if val not in seen_tokens:
                seen_tokens.add(val)
                token_display = val if "Private Key" not in name else "-----BEGIN PRIVATE KEY-----"
                sensitive_findings.append(f"{name}: {token_display}")

    return sorted(list(set(internal_hosts))), sorted(list(set(cloud_storage))), sensitive_findings

def categorize_static_references(text: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Categorizes static file and debug endpoint references into:
    - Config References (/config/appsettings.json, /manifest.json)
    - API Specifications (/swagger.json, /openapi.yaml, /v2/api-docs)
    - Debug / Monitoring Endpoints (/debug/vars, /actuator, /metrics)
    """
    config_refs: Set[str] = set()
    api_specs: Set[str] = set()
    debug_endpoints: Set[str] = set()

    for m in re.finditer(r'["\'](/(?:config|settings|app-config|env|manifest|appsettings|parameters|config/appsettings)\.(?:json|js|xml|yaml|yml))["\']', text, re.IGNORECASE):
        config_refs.add(m.group(1).strip())

    for m in re.finditer(r'["\'](/(?:swagger|openapi|v[123]/api-docs|api-docs|docs/openapi|swagger/v1/swagger)\.(?:json|yaml|yml))["\']', text, re.IGNORECASE):
        api_specs.add(m.group(1).strip())

    for m in re.finditer(r'["\'](/(?:debug/vars|actuator(?:/health|/info|/metrics|/env)?|metrics|prometheus|__debug__|healthz|readyz))["\']', text, re.IGNORECASE):
        debug_endpoints.add(m.group(1).strip())

    return sorted(list(config_refs)), sorted(list(api_specs)), sorted(list(debug_endpoints))

def extract_source_map_references(js_text: str, js_url: str) -> List[Tuple[str, str]]:
    """
    Extracts sourceMappingURL comments from first-party JavaScript and resolves full URLs.
    """
    maps = []
    for m in re.finditer(r'//[#@]\s*sourceMappingURL\s*=\s*([^\s\'\"]+)', js_text):
        map_ref = m.group(1).strip()
        if not map_ref.startswith("data:"):
            full_map_url = urllib.parse.urljoin(js_url, map_ref)
            parsed = urllib.parse.urlparse(full_map_url)
            display_path = parsed.path or map_ref
            maps.append((display_path, full_map_url))
    return maps

def detect_library_evidence(js_url: str, js_text: str) -> List[Dict[str, Any]]:
    """
    Detects library names and strictly verified versions for `tech` module.
    """
    evidence = []
    seen = set()

    for rule in LIBRARY_RULES:
        name = rule["name"]
        cat = rule["category"]

        # 1. URL Version Pattern
        for pat in rule.get("url_version_patterns", []):
            m = re.search(pat, js_url, re.IGNORECASE)
            if m:
                ver = m.group(1).strip()
                if name not in seen:
                    seen.add(name)
                    evidence.append({
                        "name": name,
                        "category": cat,
                        "version": ver,
                        "source": "page-intel",
                        "evidence": f"Explicit library version in {js_url}"
                    })
                break

        if name in seen:
            continue

        # 2. Content Version Pattern
        for pat in rule.get("content_version_patterns", []):
            m = re.search(pat, js_text, re.IGNORECASE)
            if m:
                ver = m.group(1).strip()
                if name not in seen:
                    seen.add(name)
                    evidence.append({
                        "name": name,
                        "category": cat,
                        "version": ver,
                        "source": "page-intel",
                        "evidence": f"Explicit library banner in {js_url}"
                    })
                break

        if name in seen:
            continue

        # 3. Presence Pattern (Version unknown)
        for pat in rule.get("presence_patterns", []):
            if re.search(pat, js_text, re.IGNORECASE) or re.search(pat, js_url, re.IGNORECASE):
                if name not in seen:
                    seen.add(name)
                    evidence.append({
                        "name": name,
                        "category": cat,
                        "version": None,
                        "source": "page-intel",
                        "evidence": f"Found {name} marker in {js_url}"
                    })
                break

    return evidence

def extract_dom_technology_evidence(parser: DOMSourceParser, html_content: str) -> List[Dict[str, Any]]:
    """
    Extracts technology evidence from HTML DOM meta tags, generator tags, and scripts.
    """
    evidence = []
    seen = set()

    for m in parser.framework_markers:
        name = m["name"]
        if name not in seen:
            seen.add(name)
            evidence.append(m)

    for meta in parser.meta_tags:
        name_attr = meta.get("name", "").lower()
        content_attr = meta.get("content", "")
        if name_attr == "generator" and content_attr:
            gen = content_attr.strip()
            wp_m = re.search(r'WordPress\s*([0-9.]+)?', gen, re.IGNORECASE)
            if wp_m:
                evidence.append({
                    "name": "WordPress",
                    "category": "CMS",
                    "version": wp_m.group(1) if wp_m.group(1) else None,
                    "source": "page-intel",
                    "evidence": f"HTML meta generator: {gen}"
                })
            elif "drupal" in gen.lower():
                d_m = re.search(r'Drupal\s*([0-9.]+)?', gen, re.IGNORECASE)
                evidence.append({
                    "name": "Drupal",
                    "category": "CMS",
                    "version": d_m.group(1) if d_m.group(1) else None,
                    "source": "page-intel",
                    "evidence": f"HTML meta generator: {gen}"
                })
            elif "joomla" in gen.lower():
                j_m = re.search(r'Joomla!\s*([0-9.]+)?', gen, re.IGNORECASE)
                evidence.append({
                    "name": "Joomla",
                    "category": "CMS",
                    "version": j_m.group(1) if j_m.group(1) else None,
                    "source": "page-intel",
                    "evidence": f"HTML meta generator: {gen}"
                })

    for src in parser.script_srcs:
        for rule in LIBRARY_RULES:
            name = rule["name"]
            cat = rule["category"]
            for pat in rule.get("url_version_patterns", []):
                m = re.search(pat, src, re.IGNORECASE)
                if m:
                    ver = m.group(1).strip()
                    if name not in seen:
                        seen.add(name)
                        evidence.append({
                            "name": name,
                            "category": cat,
                            "version": ver,
                            "source": "page-intel",
                            "evidence": f"Script src version in {src}"
                        })

    return evidence

async def analyze_page_intel(target: str) -> Dict[str, Any]:
    """
    Analyzes the target's root HTML page, inline JavaScript, and referenced first-party JavaScript
    to discover concrete application intelligence, configuration, and technology evidence.
    """
    clean_target = target.strip().lower()
    if clean_target.startswith(("http://", "https://")):
        clean_target = urllib.parse.urlparse(clean_target).netloc

    base_host = clean_target.split(":")[0]
    base_url = f"https://{clean_target}"

    # 1. Fetch Root HTML
    res = await safe_get(base_url)
    if res.get("error") or res.get("status_code", 0) >= 400:
        if base_url.startswith("https://"):
            base_url = f"http://{base_host}"
            res = await safe_get(base_url)

    html_content = res.get("content_text", "")
    if not html_content:
        return {
            "target": target,
            "forms": [],
            "api_references": [],
            "application_paths": [],
            "client_config": {},
            "websockets": [],
            "config_references": [],
            "api_specifications": [],
            "debug_endpoints": [],
            "source_maps": [],
            "internal_hosts": [],
            "cloud_storage": [],
            "sensitive_references": [],
            "graphql_operations": [],
            "oauth_configurations": [],
            "technology_evidence": []
        }

    # 2. Parse HTML DOM
    dom_parser = DOMSourceParser(base_url)
    try:
        dom_parser.feed(html_content)
    except Exception:
        pass

    # Extract Functional Forms, DOM Tech Evidence, and Routes
    forms = filter_functional_forms(dom_parser.forms)
    tech_evidence = extract_dom_technology_evidence(dom_parser, html_content)
    href_app_routes = extract_meaningful_app_routes(dom_parser.href_links, base_url)

    # Port of technology engine's bodyScrapeEndpointsParser using pageBodyRegex
    body_scraped = []
    for m in AST_BODY_RE.finditer(html_content):
        ep_url = m.group(1).strip()
        if ep_url and is_target_url(ep_url, base_url) and not is_filtered_static_extension(ep_url):
            body_scraped.append(ep_url)

    all_endpoints: List[Dict[str, Any]] = []
    seen_endpoints: Set[str] = set()
    all_graphql_ops: List[Dict[str, Any]] = []
    seen_graphql_ops: Set[str] = set()
    all_oauth_configs: List[Dict[str, str]] = []
    seen_oauth: Set[str] = set()
    all_app_routes: Set[str] = set(href_app_routes)
    all_websockets: Set[str] = set()
    all_configs: Dict[str, str] = dict(dom_parser.data_configs)
    all_config_refs: Set[str] = set(dom_parser.dom_config_refs)

    # Merge DOM discovered API endpoints (HTMX, data-endpoint attributes)
    for ep in dom_parser.dom_api_endpoints:
        k = f"{ep.get('method', 'GET')} {ep.get('url', '')}"
        if k not in seen_endpoints:
            seen_endpoints.add(k)
            all_endpoints.append(ep)

    # Merge body scraped endpoints
    for ep_url in body_scraped:
        fam = classify_endpoint("GET", ep_url)
        is_api = (fam in ("rest", "graphql", "soap") or is_api_endpoint_request("GET", ep_url))
        if is_api:
            k = f"GET {ep_url}"
            if k not in seen_endpoints:
                seen_endpoints.add(k)
                all_endpoints.append({
                    "method": "GET",
                    "url": ep_url,
                    "params": [],
                    "display": ep_url,
                    "class": fam,
                    "source": "Body Regex"
                })
        else:
            if APP_ROUTE_PATTERN.search(ep_url) or is_target_domain(ep_url, base_host):
                all_app_routes.add(ep_url)

    for route in dom_parser.dom_app_routes:
        if APP_ROUTE_PATTERN.search(route) or is_target_domain(route, base_host):
            all_app_routes.add(route)
    all_api_specs: Set[str] = set()
    all_debug_endpoints: Set[str] = set()
    all_internal_hosts: Set[str] = set()
    all_cloud_storage: Set[str] = set()
    sensitive_refs: List[str] = []
    found_source_map_refs: List[Tuple[str, str]] = []

    # Link tag references (manifest, openapi, swagger)
    for link in dom_parser.link_tags:
        rel = link.get("rel", "").lower()
        href = link.get("href", "").strip()
        if href:
            full_link = urllib.parse.urljoin(base_url, href)
            parsed_link = urllib.parse.urlparse(full_link)
            disp_path = parsed_link.path if parsed_link.netloc == base_host else full_link
            if "manifest" in rel or "manifest" in href:
                all_config_refs.add(disp_path)
            elif any(k in rel or k in href for k in ("openapi", "swagger", "api-docs")):
                all_api_specs.add(disp_path)

    # Static file and debug endpoint references in HTML
    h_cfg, h_spec, h_dbg = categorize_static_references(html_content)
    all_config_refs.update(h_cfg)
    all_api_specs.update(h_spec)
    all_debug_endpoints.update(h_dbg)

    # 3. Contextual Analysis of Inline JavaScript
    for idx, inl_text in enumerate(dom_parser.inline_scripts):
        if not inl_text or len(inl_text) < 10:
            continue
        apis, routes, ws, cfgs, crefs = analyze_javascript_requests(inl_text, base_host, f"inline script #{idx+1}")
        all_config_refs.update(crefs)
        for ep in apis:
            ep_key = f"{ep.get('method')} {ep.get('url')}"
            if ep_key not in seen_endpoints:
                seen_endpoints.add(ep_key)
                all_endpoints.append(ep)
        for r in routes:
            all_app_routes.add(r)
        for w in ws:
            all_websockets.add(w)
        for ck, cv in cfgs.items():
            if ck not in all_configs:
                all_configs[ck] = cv

        i_cfg, i_spec, i_dbg = categorize_static_references(inl_text)
        all_config_refs.update(i_cfg)
        all_api_specs.update(i_spec)
        all_debug_endpoints.update(i_dbg)

        hosts, buckets, sens = extract_infrastructure_and_sensitive(inl_text, f"inline script #{idx+1}", base_host)
        for h in hosts:
            all_internal_hosts.add(h)
        for b in buckets:
            all_cloud_storage.add(b)
        for s in sens:
            if s not in sensitive_refs:
                sensitive_refs.append(s)

    # 4. Resolve and Retrieve Directly Referenced First-Party JavaScript Files ONLY
    resolved_scripts: List[str] = []
    seen_scripts: Set[str] = set()
    for s_src in dom_parser.script_srcs:
        if not s_src or s_src.startswith(("data:", "javascript:", "blob:", "#", "about:")):
            continue
        if is_common_js_library_file(s_src):
            continue
        full_u = urllib.parse.urljoin(base_url, s_src)
        parsed_su = urllib.parse.urlparse(full_u)
        if parsed_su.scheme in ("http", "https") and parsed_su.netloc:
            # Filter FIRST-PARTY target scripts ONLY
            if is_target_domain(full_u, base_host):
                clean_u = urllib.parse.urlunparse((parsed_su.scheme, parsed_su.netloc, parsed_su.path, "", parsed_su.query, ""))
                if clean_u.lower() not in seen_scripts:
                    seen_scripts.add(clean_u.lower())
                    resolved_scripts.append(clean_u)

    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def fetch_and_analyze_script(js_url: str):
        async with sem:
            try:
                js_res = await safe_get(js_url)
                if js_res.get("status_code") == 200 and js_res.get("content_text"):
                    text = js_res["content_text"][:MAX_JS_SIZE]
                    parsed_u = urllib.parse.urlparse(js_url)
                    script_display_path = parsed_u.path or js_url

                    # Contextual JS Analysis (Target-Centric)
                    apis, routes, ws, cfgs, crefs = analyze_javascript_requests(text, base_host, js_url)
                    all_config_refs.update(crefs)
                    for ep in apis:
                        ep_key = f"{ep.get('method')} {ep.get('url')}"
                        if ep_key not in seen_endpoints:
                            seen_endpoints.add(ep_key)
                            all_endpoints.append(ep)
                    for r in routes:
                        all_app_routes.add(r)
                    for w in ws:
                        all_websockets.add(w)
                    for ck, cv in cfgs.items():
                        if ck not in all_configs:
                            all_configs[ck] = cv

                    # Static references
                    j_cfg, j_spec, j_dbg = categorize_static_references(text)
                    all_config_refs.update(j_cfg)
                    all_api_specs.update(j_spec)
                    all_debug_endpoints.update(j_dbg)

                    # Source Maps
                    maps = extract_source_map_references(text, js_url)
                    for sm in maps:
                        found_source_map_refs.append(sm)

                    # Technology evidence for `tech`
                    lib_ev = detect_library_evidence(js_url, text)
                    for ev in lib_ev:
                        tech_evidence.append(ev)

                    # Infrastructure and Sensitive References
                    hosts, buckets, sens = extract_infrastructure_and_sensitive(text, script_display_path, base_host)
                    for h in hosts:
                        all_internal_hosts.add(h)
                    for b in buckets:
                        all_cloud_storage.add(b)
                    for s in sens:
                        if s not in sensitive_refs:
                            sensitive_refs.append(s)
            except Exception:
                pass

    tasks = [fetch_and_analyze_script(u) for u in resolved_scripts[:MAX_JS_FILES]]
    await asyncio.gather(*tasks, return_exceptions=True)

    # 5. Verify Source Maps (Only report accessible ones)
    verified_source_maps: List[str] = []

    for display_path, map_url in found_source_map_refs[:5]:
        try:
            map_res = await safe_get(map_url)
            if map_res.get("status_code") == 200 and map_res.get("content_text"):
                try:
                    map_json = json.loads(map_res["content_text"])
                    if isinstance(map_json, dict) and ("sources" in map_json or "mappings" in map_json or "version" in map_json):
                        sources_content = map_json.get("sourcesContent")
                        has_content = bool(sources_content and isinstance(sources_content, list) and any(sources_content))
                        if has_content:
                            verified_source_maps.append(f"{display_path} (ACCESSIBLE, SOURCES PRESENT)")
                        else:
                            verified_source_maps.append(f"{display_path} (ACCESSIBLE)")
                except Exception:
                    pass
        except Exception:
            pass

    api_urls = {ep.get("url") for ep in all_endpoints}
    filtered_app_routes = [r for r in all_app_routes if r not in api_urls]

    # Build Structured Findings list of Finding dataclass instances
    findings_list = []

    # 1. Forms
    for f in forms:
        clean_action = f.get("action", "")
        method = f.get("method", "POST")
        fields = f.get("fields", [])
        fields_str = f" ({', '.join(fields)})" if fields else ""
        findings_list.append(Finding(
            value=f"{method} {clean_action}{fields_str}",
            category="Functional Form",
            confidence=100,
            evidence=[Evidence(
                type="HTML",
                source="HTML body",
                location=f"form#{f.get('id')}" if f.get('id') else "form",
                snippet=f'<form action="{clean_action}" method="{method}">',
                detection_engine="endpoint-parser"
            )]
        ))

    # 2. API Endpoints
    for ep in all_endpoints:
        m = ep.get("method", "GET")
        u = ep.get("url", "")
        disp = ep.get("display") or f"{m} {u}"
        params = ep.get("params", [])
        if params:
            disp = f"{disp} ({', '.join(params)})"
            
        eng = "endpoint-parser"
        ev_type = "HTML"
        src = "HTML body"
        expr = None
        
        if ep.get("source") == "JSLuice AST":
            eng = "ast-endpoint-parser"
            ev_type = "JavaScript"
            src = ep.get("source_label", "script")
            expr = ep.get("expression")
        elif ep.get("source") == "JS Regex":
            eng = "ast-endpoint-parser"
            ev_type = "regex"
            src = ep.get("source_label", "script")
        elif ep.get("source") == "Body Regex":
            eng = "endpoint-parser"
            ev_type = "regex"
            src = "HTML body"
            expr = "Regex pageBodyRegex" 
            
        findings_list.append(Finding(
            value=disp,
            category="API Endpoint",
            confidence=100,
            evidence=[Evidence(
                type=ev_type,
                source=src,
                location=expr,
                snippet=expr or disp,
                detection_engine=eng
            )]
        ))

    # 3. Application Routes
    for route in filtered_app_routes:
        findings_list.append(Finding(
            value=route,
            category="Application Route",
            confidence=100,
            evidence=[Evidence(
                type="HTML",
                source="HTML body",
                location="href",
                snippet=f'<a href="{route}">',
                detection_engine="endpoint-parser"
            )]
        ))

    # 4. WebSockets
    for ws in all_websockets:
        findings_list.append(Finding(
            value=ws,
            category="WebSocket/SSE",
            confidence=100,
            evidence=[Evidence(
                type="JavaScript",
                source="script",
                snippet=f'new WebSocket("{ws}")',
                detection_engine="ast-endpoint-parser"
            )]
        ))

    # 5. OAuth configurations
    for o in all_oauth_configs:
        findings_list.append(Finding(
            value=o.get("display", ""),
            category="OAuth Configuration",
            confidence=100,
            evidence=[Evidence(
                type="JavaScript",
                source="script",
                location=o.get("label"),
                snippet=o.get("display"),
                detection_engine="endpoint-parser"
            )]
        ))

    # 6. Sensitive References
    for s in sensitive_refs:
        name_part = s.split(":")[0] if ":" in s else "Token"
        val_part = s.split(":", 1)[1].strip() if ":" in s else s
        masked_val = mask_token(val_part) if "Private Key" not in name_part else "-----BEGIN PRIVATE KEY-----"
        findings_list.append(Finding(
            value=f"{name_part}: {masked_val}",
            category="Exposed Token",
            confidence=100,
            evidence=[Evidence(
                type="JavaScript",
                source="script",
                location=name_part,
                snippet=f"{name_part}: {masked_val}",
                detection_engine="endpoint-parser"
            )]
        ))

    # Stably merge and deduplicate findings
    deduped_findings = []
    seen_f = {}
    for f in findings_list:
        k = (f.category, f.value)
        if k not in seen_f:
            seen_f[k] = Finding(
                value=f.value,
                category=f.category,
                version=f.version,
                confidence=f.confidence,
                evidence=list(f.evidence),
                inference=f.inference or "DIRECT"
            )
        else:
            seen_f[k].evidence.extend(f.evidence)
            
    for f in seen_f.values():
        seen_ev = set()
        unique_ev = []
        for e in f.evidence:
            ident = e.get_identity()
            if ident not in seen_ev:
                seen_ev.add(ident)
                unique_ev.append(e)
        f.evidence = unique_ev
        deduped_findings.append(f)

    return {
        "target": target,
        "forms": forms,
        "api_references": all_endpoints,
        "application_paths": sorted(list(filtered_app_routes)),
        "client_config": all_configs,
        "websockets": sorted(list(all_websockets)),
        "config_references": sorted(list(all_config_refs)),
        "api_specifications": sorted(list(all_api_specs)),
        "debug_endpoints": sorted(list(all_debug_endpoints)),
        "source_maps": verified_source_maps,
        "internal_hosts": sorted(list(all_internal_hosts)),
        "cloud_storage": sorted(list(all_cloud_storage)),
        "sensitive_references": sensitive_refs,
        "graphql_operations": all_graphql_ops,
        "oauth_configurations": all_oauth_configs,
        "technology_evidence": tech_evidence,
        "findings": deduped_findings
    }
