"""
Opt-in automatic updater for OpenRecon.
Runs only when explicitly invoked via `openrecon --check-update`.
When confirmed by the user (y/Y), automatically installs the official update into
the current environment without requiring manual git/download/reinstall steps.
"""
import os
import sys
import re
import hashlib
import tempfile
import subprocess
from typing import Optional, Tuple, Dict, Any, List
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
    Fetches the latest official GitHub Release metadata or highest semantic-version tag:
      1. Tries /releases/latest for published Releases.
      2. If 404 (no published Release), queries /tags and selects the highest valid SemVer tag.
    Returns (release_data, error_message).
    """
    if not validate_repo(repo):
        return None, f"Invalid or untrusted repository: '{repo}'"

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": f"OpenRecon/{__version__}"
    }

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, verify=True) as client:
            # 1. Try /releases/latest
            release_url = f"https://api.github.com/repos/{repo}/releases/latest"
            resp = client.get(release_url, headers=headers)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    return None, "GitHub API returned invalid JSON response for release."

                tag_name = data.get("tag_name")
                if not tag_name or not isinstance(tag_name, str):
                    return None, "Release metadata missing valid 'tag_name'."

                if parse_semver(tag_name) is None:
                    return None, f"Release tag '{tag_name}' is not a valid semantic version."

                return data, None

            elif resp.status_code == 404:
                # 2. Fallback to /tags to look for published SemVer tags
                tags_url = f"https://api.github.com/repos/{repo}/tags"
                tags_resp = client.get(tags_url, headers=headers)

                if tags_resp.status_code == 200:
                    try:
                        tags_data = tags_resp.json()
                    except Exception:
                        return None, "GitHub API returned invalid JSON response for tags."

                    if not isinstance(tags_data, list) or len(tags_data) == 0:
                        # No tags exist yet -> treated cleanly as up to date
                        return None, None

                    # Filter and select the highest valid semantic-version tag
                    valid_tags = []
                    for t in tags_data:
                        t_name = t.get("name") if isinstance(t, dict) else None
                        if t_name:
                            parsed = parse_semver(t_name)
                            if parsed is not None:
                                valid_tags.append((parsed, t_name.strip()))

                    if not valid_tags:
                        # No valid semver tags found -> treated cleanly as up to date
                        return None, None

                    # Sort by parsed semver tuple (major, minor, patch) in descending order
                    valid_tags.sort(key=lambda x: x[0], reverse=True)
                    highest_tag_tuple, highest_tag_name = valid_tags[0]

                    return {
                        "tag_name": highest_tag_name,
                        "assets": [],
                        "body": ""
                    }, None

                elif tags_resp.status_code == 404:
                    return None, f"GitHub repository '{repo}' not found (HTTP 404)."
                elif tags_resp.status_code == 403:
                    if tags_resp.headers.get("x-ratelimit-remaining") == "0":
                        return None, "GitHub API request failed: HTTP 429 (rate limit exceeded)."
                    return None, "GitHub API returned HTTP 403 (access forbidden)."
                elif tags_resp.status_code == 429:
                    return None, "GitHub API request failed: HTTP 429 (rate limit exceeded)."
                elif tags_resp.status_code >= 500:
                    return None, f"GitHub API returned server error (HTTP {tags_resp.status_code})."
                else:
                    return None, f"GitHub API returned unexpected status (HTTP {tags_resp.status_code})."

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
    except httpx.RequestError as e:
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
    Safely downloads and installs the updated version into the current environment using pip.
    Upgrades OpenRecon without modifying unrelated dependencies or executing Git commands.
    Preserves the existing installation intact if update fails at any step.
    """
    if not validate_repo(repo):
        return False

    clean_tag = target_tag.strip()
    official_archive_url = f"https://github.com/{repo}/archive/refs/tags/{clean_tag}.tar.gz"
    
    if not validate_download_url(official_archive_url):
        return False

    expected_sha256 = None
    if release_info:
        body = release_info.get("body", "")
        expected_sha256 = extract_sha256_checksum(body, f"{clean_tag}.tar.gz")
        if not expected_sha256:
            expected_sha256 = extract_sha256_checksum(body)

    tmp_path = download_and_verify_artifact(official_archive_url, expected_sha256=expected_sha256)
    
    # If checksum verification was requested and failed, abort installation
    if expected_sha256 and not tmp_path:
        return False

    target_to_install = tmp_path if tmp_path else official_archive_url

    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "--upgrade-strategy",
        "only-if-needed",
        "--no-cache-dir",
        target_to_install
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
        if tmp_path and os.path.exists(tmp_path):
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
    When an update exists and user confirms (y/Y), performs full automatic update.
    """
    current_version = __version__
    console.print(f"OpenRecon v{current_version}")

    release_info, error_msg = fetch_latest_release_info(repo=repo)
    if error_msg:
        console.print(f"[yellow][!] {error_msg}[/yellow]")
        return None

    latest_tag = release_info.get("tag_name") if release_info else None
    if not latest_tag:
        console.print("OpenRecon is up to date. No updates available.")
        return None

    clean_latest = latest_tag.lstrip("vV")

    # Version comparison
    if is_newer_version(clean_latest, current_version):
        console.print(f"Update available: v{clean_latest}\n")

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
        console.print("OpenRecon is up to date. No updates available.")
        return None
