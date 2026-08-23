import re
import ipaddress
from typing import Optional
from dataclasses import dataclass

@dataclass
class ValidationResult:
    is_valid: bool
    input_type: str = "unknown"  # 'domain', 'ipv4', 'email', 'invalid'
    normalized_input: Optional[str] = None
    error_message: Optional[str] = None
    is_public: bool = False

def validate_target(target: str) -> ValidationResult:
    """
    Validates and normalizes target input.
    Accepts: Domain, IPv4, Email.
    Rejects: URLs, Private/Internal IPs/Domains, Wildcards, Ports.
    
    Security:
    - No DNS resolution used (prevents timing attacks / DNS rebinding during validation).
    - Strict regex allowlists.
    - Uses ipaddress for robust IP parsing.
    """
    if not target:
        return ValidationResult(is_valid=False, error_message="Input cannot be empty.")

    # 1. Normalize
    target = target.strip().lower()

    # 2. Reject URLs (Protocol, Path, Port characters)
    if "://" in target:
        return ValidationResult(
            is_valid=False,
            error_message="URLs are not accepted. Please provide a domain name."
        )
    
    # Check for path separators or params
    if any(char in target for char in ['/', '\\', '?', '#']):
        return ValidationResult(
            is_valid=False,
            error_message="Paths and query parameters are not accepted. Please provide a domain or IP only."
        )
    
    # Check for ports (colon)
    if ':' in target:
        return ValidationResult(
            is_valid=False,
            error_message="Ports are not accepted. Please specify only the target domain or IPv4."
        )
         
    # Check for wildcards
    if '*' in target:
        return ValidationResult(
            is_valid=False,
            error_message="Wildcards are not accepted."
        )

    # 3. Try IPv4
    try:
        ip = ipaddress.IPv4Address(target)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return ValidationResult(
                is_valid=False, 
                input_type="ipv4", 
                error_message=f"Restricted or private IP range '{target}' is not allowed for OSINT."
            )
        return ValidationResult(
            is_valid=False,
            input_type="ipv4",
            error_message="IPv4 targets are not accepted. Please provide a domain name."
        )
    except ipaddress.AddressValueError:
        pass

    # 4. Try Email
    if '@' in target:
        return ValidationResult(
            is_valid=False,
            input_type="email",
            error_message="Email targets are not accepted. Please provide a domain name."
        )

    # 5. Try Domain
    domain_pattern = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')
    
    if domain_pattern.match(target):
        if target in ('localhost', 'local') or target.endswith('.local') or target.endswith('.internal') or target.endswith('.lan'):
            return ValidationResult(
                is_valid=False, 
                input_type="domain", 
                error_message="Local or internal domain rejected."
            )
            
        return ValidationResult(
            is_valid=True, 
            input_type="domain", 
            normalized_input=target, 
            is_public=True
        )

    return ValidationResult(
        is_valid=False, 
        input_type="invalid", 
        error_message="Invalid target format. Must be a valid public Domain."
    )
