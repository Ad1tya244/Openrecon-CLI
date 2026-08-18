import unittest
from unittest.mock import patch, MagicMock
from openrecon.modules.ssl_recon import analyze_ssl, extract_key_details, verify_cert_chain, match_hostname
from openrecon.formatter import render_ssl
from cryptography.hazmat.primitives.asymmetric import rsa, ec

class TestSSLRecon(unittest.TestCase):
    def test_key_details_extraction(self):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
        k_type, k_size = extract_key_details(rsa_key)
        self.assertEqual(k_type, "RSA")
        self.assertEqual(k_size, "2048-bit")

        ec_key = ec.generate_private_key(ec.SECP256R1()).public_key()
        k_type, k_size = extract_key_details(ec_key)
        self.assertIn("EC", k_type)
        self.assertEqual(k_size, "256-bit")

    def test_rfc6125_san_hostname_validation(self):
        # Exact match
        self.assertTrue(match_hostname("example.com", ["example.com", "www.example.com"]))
        self.assertTrue(match_hostname("www.example.com", ["example.com", "www.example.com"]))

        # Wildcard match: *.example.com matches sub.example.com, but NOT example.com or a.b.example.com
        self.assertTrue(match_hostname("api.example.com", ["*.example.com"]))
        self.assertFalse(match_hostname("example.com", ["*.example.com"]))
        self.assertFalse(match_hostname("deep.sub.example.com", ["*.example.com"]))

        # Mismatch: requested host python.org with cert only covering www.python.org
        self.assertFalse(match_hostname("python.org", ["www.python.org"]))
        self.assertTrue(match_hostname("python.org", ["www.python.org", "python.org"]))

        # Fallback to CN only when SANs empty
        self.assertTrue(match_hostname("example.com", [], common_name="example.com"))
        self.assertFalse(match_hostname("example.com", [], common_name="other.com"))

    def test_render_ssl_output(self):
        data = {
            "valid": True,
            "status_label": "VALID",
            "chain_status": "VERIFIED",
            "version": "v3",
            "key_type": "RSA",
            "key_size": "2048-bit",
            "issuer": "DigiCert Global Root G2 (DigiCert Inc)",
            "subject": "example.com",
            "valid_from": "2023-01-01T00:00:00",
            "valid_until": "2024-01-01T00:00:00",
            "days_remaining": 150,
            "serial_number": "123456789",
            "signature_algorithm": "sha256WithRSAEncryption",
            "subject_alt_names": ["example.com", "www.example.com"],
            "cipher": "TLS_AES_256_GCM_SHA384",
            "protocol": "TLSv1.3"
        }
        render_ssl(data)

if __name__ == "__main__":
    unittest.main()
