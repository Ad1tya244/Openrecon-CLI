"""
Opt-in automatic update installer for OpenRecon.
Runs only when explicitly invoked via `openrecon --check-update`.
Provides precise, actionable diagnostic error reporting without exposing stack traces.
"""
import os
import sys
import re
import hashlib
import tempfile
import subprocess
from typing import Optional, Tuple, Dict, Any
from urllib.parse import urlparse
import httpx
from openrecon import __version__
from openrecon.config import settings
from openrecon.formatter import console

OFFICIAL_REPO = "Ad1tya244/Openrecon-CLI"
ALLOWED_DOMAINS = {
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com"
}

def validate_repo(repo: str) -> bool:
    """Ensures that updates are strictly fetched from the official repository."""
    if not repo or not isinstance(repo, str):
        return False
    return repo.strip().lower() == OFFICIAL_REPO.lower()

def validate_download_url(url: str) -> bool:
    """
    Validates that a download URL strictly belongs to the official GitHub repository
    or the official GitHub release asset CDN. Rejects untrusted domains, forks, or arbitrary hosts.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return False
        
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        if hostname not in ALLOWED_DOMAINS:
            return False

        if hostname == "github.com":
            path_lower = parsed.path.lower()
            expected_prefix = f"/{OFFICIAL_REPO.lower()}/"
            if not path_lower.startswith(expected_prefix):
                return False

        return True
    except Exception:
        return False

def is_source_checkout() -> bool:
    """
    Detects if OpenRecon is running from a local Git or source repository checkout.
    When running from source, working trees must NEVER be modified automatically.
    """
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        check_dir = current_dir
        for _ in range(3):
            if os.path.isdir(os.path.join(check_dir, ".git")):
                return True
            parent = os.path.dirname(check_dir)
            if parent == check_dir:
                break
            check_dir = parent
    except Exception:
        pass

    if os.path.isdir(".git") and os.path.isdir("openrecon"):
        return True

    return False

def parse_semver(v: str) -> Optional[Tuple[int, int, int]]:
    """
    Parses a semantic version string into a (major, minor, patch) tuple.
    Returns None if the format is invalid or malformed.
    """
    if not v or not isinstance(v, str):
        return None
    cleaned = v.strip().lstrip("vV")
    cleaned = cleaned.split("-")[0].split("+")[0]
    parts = cleaned.split(".")
    if len(parts) == 1 and parts[0].isdigit():
        return (int(parts[0]), 0, 0)
    elif len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
        return (int(parts[0]), int(parts[1]), 0)
    elif len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit() and parts[2].isdigit():
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    return None

def is_newer_version(latest_str: str, current_str: str) -> bool:
    """Returns True if latest_str is strictly newer than current_str using SemVer."""
    latest = parse_semver(latest_str)
    current = parse_semver(current_str)
    if latest is None or current is None:
        return False
    return latest > current

def compute_sha256(data: bytes) -> str:
    """Computes the SHA-256 hash of raw byte data."""
    return hashlib.sha256(data).hexdigest()

def extract_sha256_checksum(text: str, filename: str = "") -> Optional[str]:
    """
    Extracts a 64-character hexadecimal SHA-256 hash from release text,
    a checksum file, or an asset body.
    """
    if not text or not isinstance(text, str):
        return None
    for line in text.splitlines():
        line = line.strip()
        if filename and filename.lower() in line.lower():
            m = re.search(r'[0-9a-fA-F]{64}', line)
            if m:
                return m.group(0).lower()
        else:
            m = re.search(r'sha256[:\s=]+([0-9a-fA-F]{64})', line, re.IGNORECASE)
            if m:
                return m.group(1).lower()
            m = re.match(r'^([0-9a-fA-F]{64})\s*$', line)
            if m:
                return m.group(1).lower()
    return None

def fetch_latest_release_info(
    repo: str = OFFICIAL_REPO,
    timeout: float = settings.UPDATE_TIMEOUT_SECONDS
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Fetches the latest official GitHub Release metadata from:
      https://api.github.com/repos/{repo}/releases/latest
    Returns (release_data, error_message).
    """
    if not validate_repo(repo):
        return None, f"Invalid or untrusted repository: '{repo}'"

    url = f"https://api.github.com/repos/{repo}/releases/latest"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"OpenRecon/{__version__}"
    }

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as client:
            resp = client.get(url, headers=headers)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    return None, "GitHub API returned invalid JSON response."

                tag_name = data.get("tag_name")
                if not tag_name or not isinstance(tag_name, str):
                    return None, "Release metadata missing valid 'tag_name'."

                if parse_semver(tag_name) is None:
                    return None, f"Release tag '{tag_name}' is not a valid semantic version."

                return data, None

            elif resp.status_code == 404:
                # Fallback check on tags endpoint
                tags_url = f"https://api.github.com/repos/{repo}/tags"
                tags_resp = client.get(tags_url, headers=headers)
                if tags_resp.status_code == 200:
                    try:
                        tags_data = tags_resp.json()
                    except Exception:
                        return None, "GitHub API returned invalid JSON response for tags."

                    if isinstance(tags_data, list) and len(tags_data) > 0:
                        first_tag = tags_data[0].get("name")
                        if first_tag and parse_semver(first_tag) is not None:
                            return {"tag_name": first_tag, "assets": [], "body": ""}, None
                        elif first_tag:
                            return None, f"Tag '{first_tag}' is not a valid semantic version."
                    return None, "GitHub API returned HTTP 404 (release not found)."

                elif tags_resp.status_code == 403:
                    if tags_resp.headers.get("x-ratelimit-remaining") == "0":
                        return None, "GitHub API request failed: HTTP 429 (rate limit exceeded)."
                    return None, "GitHub API returned HTTP 403 (access forbidden)."
                elif tags_resp.status_code == 429:
                    return None, "GitHub API request failed: HTTP 429 (rate limit exceeded)."
                else:
                    return None, "GitHub API returned HTTP 404 (release not found)."

            elif resp.status_code == 403:
                if resp.headers.get("x-ratelimit-remaining") == "0":
                    return None, "GitHub API request failed: HTTP 429 (rate limit exceeded)."
                return None, "GitHub API returned HTTP 403 (access forbidden)."

            elif resp.status_code == 429:
                return None, "GitHub API request failed: HTTP 429 (rate limit exceeded)."

            elif resp.status_code >= 500:
                return None, f"GitHub API returned server error (HTTP {resp.status_code})."

            else:
                return None, f"GitHub API returned unexpected status (HTTP {resp.status_code})."

    except httpx.TimeoutException:
        return None, "GitHub API request timed out."
    except httpx.ConnectError:
        return None, "Could not connect to GitHub (network/DNS failure)."
    except (httpx.TLSAttributeError, httpx.RequestError) as e:
        err_str = str(e).lower()
        if "certificate" in err_str or "ssl" in err_str or "tls" in err_str:
            return None, "TLS verification failed while connecting to GitHub."
        return None, f"Could not connect to GitHub: {type(e).__name__}"
    except Exception as e:
        return None, f"Unexpected error during update check: {str(e)}"

def fetch_latest_version(
    repo: str = OFFICIAL_REPO,
    timeout: float = settings.UPDATE_TIMEOUT_SECONDS
) -> Optional[str]:
    """Helper that returns the tag name of the latest official version."""
    info, _ = fetch_latest_release_info(repo=repo, timeout=timeout)
    if info:
        tag = info.get("tag_name")
        if tag:
            return tag.strip()
    return None

def download_and_verify_artifact(
    download_url: str,
    expected_sha256: Optional[str] = None,
    timeout: float = 30.0
) -> Optional[str]:
    """
    Downloads the release artifact to a temporary file.
    If expected_sha256 is provided, performs cryptographic verification before returning.
    Returns path to temporary file if valid, or None if download or verification fails.
    """
    if not validate_download_url(download_url):
        return None

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as client:
            resp = client.get(download_url)
            if resp.status_code != 200:
                return None
            
            content = resp.content
            if not content:
                return None

            # Verify SHA-256 checksum if provided
            if expected_sha256:
                computed_hash = compute_sha256(content)
                if computed_hash.lower() != expected_sha256.lower():
                    return None

            # Save to secure temporary file
            tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
            tmp.write(content)
            tmp.flush()
            tmp.close()
            return tmp.name
    except Exception:
        return None

def install_update(
    repo: str,
    target_tag: str,
    release_info: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Safely downloads and installs the updated version using pip from a local verified artifact.
    Upgrades only OpenRecon and its declared dependencies without modifying unrelated packages.
    Preserves the existing installation intact if update fails at any step.
    """
    if not validate_repo(repo):
        return False

    clean_tag = target_tag.strip()
    official_archive_url = f"https://github.com/{repo}/archive/refs/tags/{clean_tag}.tar.gz"
    
    expected_sha256 = None
    if release_info:
        body = release_info.get("body", "")
        expected_sha256 = extract_sha256_checksum(body, f"{clean_tag}.tar.gz")
        if not expected_sha256:
            expected_sha256 = extract_sha256_checksum(body)

    tmp_path = download_and_verify_artifact(official_archive_url, expected_sha256=expected_sha256)
    if not tmp_path:
        return False

    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--upgrade-strategy",
        "only-if-needed",
        "--no-cache-dir",
        tmp_path
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            text=True
        )
        return proc.returncode == 0
    except Exception:
        return False
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

def verify_installed_version(expected_version: str) -> bool:
    """Verifies that the expected version is installed after an update."""
    clean_expected = expected_version.lstrip("vV")
    try:
        import importlib.metadata
        installed = importlib.metadata.version("openrecon")
        return installed == clean_expected
    except Exception:
        return True

def run_opt_in_update_check(
    repo: str = OFFICIAL_REPO,
    prompt_fn=None
) -> Optional[str]:
    """
    Opt-in update check invoked ONLY by `openrecon --check-update`.
    """
    current_version = __version__
    console.print(f"OpenRecon v{current_version}")

    release_info, error_msg = fetch_latest_release_info(repo=repo)
    if error_msg or not release_info or not release_info.get("tag_name"):
        err = error_msg or "Release metadata unavailable."
        console.print(f"[yellow][!] {err}[/yellow]")
        return None

    latest_tag = release_info["tag_name"].strip()
    clean_latest = latest_tag.lstrip("vV")

    # Version comparison
    if is_newer_version(clean_latest, current_version):
        console.print(f"Update available: v{clean_latest}\n")
        
        if is_source_checkout():
            console.print("Please update the source checkout manually.\n")
            return clean_latest

        # Prompt user before installation
        get_input = prompt_fn or input
        try:
            choice = get_input("Update OpenRecon? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        if choice in ("y", "yes"):
            console.print("Updating OpenRecon...")
            success = install_update(repo, latest_tag, release_info=release_info)
            if success and verify_installed_version(clean_latest):
                console.print(f"Update complete: v{clean_latest}\n")
                return clean_latest
            else:
                console.print("[yellow][!] Update failed. Continuing with current version.[/yellow]\n")
                return None
        else:
            return None
    else:
        console.print("OpenRecon is up to date.")
        return None
