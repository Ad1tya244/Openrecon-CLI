import asyncio
from typing import Dict, Any, List, Optional
from openrecon.utils.safe_http import safe_get

ALLOWLISTED_FILES = [
    "robots.txt",
    "sitemap.xml",
    "security.txt",
    ".well-known/security.txt",
    "humans.txt",
    "ads.txt"
]

async def check_public_files(domain: str) -> Dict[str, Any]:
    """
    Checks for the existence of standard public files safely without brute forcing.
    Only retains files that actually return HTTP 200 OK.
    """
    base_url = f"https://{domain}"
    sem = asyncio.Semaphore(3)

    async def check_file(filename: str) -> Optional[str]:
        async with sem:
            url = f"{base_url}/{filename}"
            response = await safe_get(url)
            
            # Fallback to HTTP if HTTPS fails with error
            if "error" in response:
                url = f"http://{domain}/{filename}"
                response = await safe_get(url)

            if "error" not in response and response.get("status_code") == 200:
                return filename
            return None

    tasks = [check_file(filename) for filename in ALLOWLISTED_FILES]
    results = await asyncio.gather(*tasks)
    found_files = [f for f in results if f is not None]
             
    return {
        "found": found_files
    }
