import ssl
import socket
import datetime
from typing import Dict, Any, List, Tuple, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa
from openrecon.config import settings

def extract_key_details(pubkey) -> Tuple[str, str]:
    """Extracts genuine key type and key size from public key object."""
    if isinstance(pubkey, rsa.RSAPublicKey):
        return "RSA", f"{pubkey.key_size}-bit"
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        curve_name = getattr(pubkey.curve, "name", "EC")
        return f"EC ({curve_name})", f"{pubkey.key_size}-bit"
    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
        return "Ed25519", "256-bit"
    elif isinstance(pubkey, ed448.Ed448PublicKey):
        return "Ed448", "448-bit"
    elif isinstance(pubkey, dsa.DSAPublicKey):
        return "DSA", f"{pubkey.key_size}-bit"
    return type(pubkey).__name__, "Unknown"

def match_hostname(hostname: str, san_list: List[str], common_name: Optional[str] = None) -> bool:
    """
    Validates requested hostname against certificate SANs per RFC 6125.
    Falls back to Subject Common Name only if SANs are absent.
    """
    h = hostname.lower().strip().rstrip(".")
    candidates = san_list if san_list else ([common_name] if common_name else [])
    
    for cand in candidates:
        if not cand:
            continue
        c = cand.lower().strip().rstrip(".")
        if c == h:
            return True
        if c.startswith("*."):
            base = c[2:]
            if h.endswith("." + base):
                prefix = h[:-len("." + base)]
                if "." not in prefix and len(prefix) > 0:
                    return True
    return False

def verify_cert_chain(domain: str, port: int = 443) -> str:
    """Verifies certificate chain against system/default CA trust store."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=settings.SOCKET_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as _:
                return "VERIFIED"
    except ssl.SSLCertVerificationError as e:
        err_msg = str(e).lower()
        if "self-signed" in err_msg or "self signed" in err_msg:
            return "SELF-SIGNED"
        elif "unable to get local issuer certificate" in err_msg or "incomplete" in err_msg:
            return "INCOMPLETE"
        elif "certificate has expired" in err_msg:
            return "EXPIRED"
        elif "hostname" in err_msg:
            return "HOSTNAME_MISMATCH"
        else:
            return "UNTRUSTED"
    except Exception:
        return "UNKNOWN"

def analyze_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Retrieves and analyzes the SSL certificate of the target via standard TLS handshake.
    Validates requested hostname against SANs and verifies trust chain.
    """
    chain_status = verify_cert_chain(domain, port)

    # Establish unverified handshake to inspect certificate metadata regardless of trust
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((domain, port), timeout=settings.SOCKET_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as conn:
                der_cert = conn.getpeercert(binary_form=True)
                if not der_cert:
                    return {"valid": False, "error": "No certificate presented by host"}

                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                
                subject = {attr.oid._name: attr.value for attr in cert.subject}
                issuer = {attr.oid._name: attr.value for attr in cert.issuer}
                
                # Subject Alternative Names (SANs)
                sans: List[str] = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = [name.value for name in san_ext.value if hasattr(name, 'value')]
                except Exception:
                    pass

                cn = subject.get("commonName")
                hostname_valid = match_hostname(domain, sans, cn)

                valid_from = cert.not_valid_before_utc
                valid_to = cert.not_valid_after_utc
                
                now = datetime.datetime.now(datetime.timezone.utc)
                days_remaining = (valid_to - now).days
                is_expired = days_remaining < 0
                
                is_overall_valid = (not is_expired) and hostname_valid
                
                signature_algorithm = cert.signature_algorithm_oid._name
                
                # Key details
                pubkey = cert.public_key()
                key_type, key_size = extract_key_details(pubkey)

                # Cipher & Protocol from live connection
                cipher_info = conn.cipher()
                cipher_name = cipher_info[0] if cipher_info and len(cipher_info) > 0 else None
                tls_version = conn.version() or (cipher_info[1] if cipher_info and len(cipher_info) > 1 else None)

                status_label = "VALID"
                if is_expired:
                    status_label = "EXPIRED"
                elif not hostname_valid:
                    status_label = "INVALID (Hostname mismatch)"
                elif chain_status in ("UNTRUSTED", "SELF-SIGNED"):
                    status_label = "INVALID"

                return {
                    "valid": is_overall_valid,
                    "status_label": status_label,
                    "is_expired": is_expired,
                    "hostname_valid": hostname_valid,
                    "days_remaining": days_remaining,
                    "chain_status": chain_status,
                    "version": cert.version.name,
                    "key_type": key_type,
                    "key_size": key_size,
                    "subject": subject,
                    "issuer": issuer,
                    "subject_alt_names": sans,
                    "signature_algorithm": signature_algorithm,
                    "valid_from": valid_from.isoformat(),
                    "valid_until": valid_to.isoformat(),
                    "serial_number": str(cert.serial_number),
                    "cipher": cipher_name,
                    "protocol": tls_version
                }

    except socket.timeout:
        return {"valid": False, "error": "SSL handshake connection timed out"}
    except Exception as e:
        return {"valid": False, "error": str(e)}
