"""
Centralized Version and Change Management for OpenRecon.
"""
import os
import json
from typing import Tuple, Optional

MAJOR_VERSION = 1
DEFAULT_VERSION_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data", "version.json")
)

def calculate_version(change_count: int) -> str:
    """
    Calculates semantic version from change count using the formula:
      major = 1
      minor = change_count // 10
      patch = change_count % 10
      version = f"{major}.{minor}.{patch}"
    """
    if change_count < 0:
        change_count = 0
    major = MAJOR_VERSION
    minor = change_count // 10
    patch = change_count % 10
    return f"{major}.{minor}.{patch}"

def get_change_count(custom_path: Optional[str] = None) -> int:
    """
    Reads the current change counter from the authoritative persistence file.
    """
    filepath = custom_path or DEFAULT_VERSION_FILE
    if filepath and os.path.isfile(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                return int(data.get("change_count", 0))
        except Exception:
            pass
    return 0

def get_version(custom_path: Optional[str] = None) -> str:
    """
    Returns the semantic version corresponding to the current change counter.
    """
    filepath = custom_path or DEFAULT_VERSION_FILE
    if filepath and os.path.isfile(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                count = int(data.get("change_count", 0))
                # Always ensure version matches calculated version
                return calculate_version(count)
        except Exception:
            pass
    return calculate_version(0)

def set_change_count(count: int, custom_path: Optional[str] = None) -> Tuple[int, str]:
    """
    Explicitly sets the change counter and writes the updated state to persistence.
    """
    filepath = custom_path or DEFAULT_VERSION_FILE
    count = max(0, count)
    version = calculate_version(count)
    
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump({"change_count": count, "version": version}, f, indent=2)
        f.write("\n")
        
    return count, version

def increment_change_count(custom_path: Optional[str] = None) -> Tuple[int, str]:
    """
    Increments the change counter by 1, calculates the new version,
    and persists the update. Returns (new_change_count, new_version).
    """
    current = get_change_count(custom_path)
    new_count = current + 1
    return set_change_count(new_count, custom_path)

# Module-level exports
CHANGE_COUNT = get_change_count()
__version__ = get_version()
