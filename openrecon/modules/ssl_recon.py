import ssl
import socket
import datetime
from typing import Dict, Any, List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from openrecon.config import settings

def analyze_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Retrieves and analyzes the SSL certificate of the target.
    Performs a standard handshake without sending application data.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        sock = socket.create_connection((domain, port), timeout=settings.SOCKET_TIMEOUT)
        
        with context.wrap_socket(sock, server_hostname=domain) as conn:
            der_cert = conn.getpeercert(binary_form=True)
            if not der_cert:
                return {"valid": False, "error": "No certificate found"}

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

            valid_from = cert.not_valid_before_utc
            valid_to = cert.not_valid_after_utc
            
            now = datetime.datetime.now(datetime.timezone.utc)
            days_remaining = (valid_to - now).days
            is_expired = days_remaining < 0
            
            signature_algorithm = cert.signature_algorithm_oid._name

            return {
                "valid": not is_expired,
                "is_expired": is_expired,
                "days_remaining": days_remaining,
                "subject": subject,
                "issuer": issuer,
                "subject_alt_names": sans,
                "version": cert.version.name,
                "signature_algorithm": signature_algorithm,
                "valid_from": valid_from.isoformat(),
                "valid_until": valid_to.isoformat(),
                "serial_number": str(cert.serial_number),
                "cipher_suite": conn.cipher()
            }

    except socket.timeout:
        return {"valid": False, "error": "SSL handshake connection timed out"}
    except Exception as e:
        return {"valid": False, "error": str(e)}
