import unittest
from unittest.mock import patch, AsyncMock
import asyncio
from openrecon.modules.security_headers_recon import analyze_security_headers, deduplicate_header_value
from openrecon.formatter import render_security_headers

class TestSecurityHeadersRecon(unittest.TestCase):
    def test_duplicate_header_deduplication(self):
        self.assertEqual(deduplicate_header_value("nosniff, nosniff"), "nosniff")
        self.assertEqual(deduplicate_header_value("nosniff,nosniff, nosniff"), "nosniff")
        self.assertEqual(deduplicate_header_value("SAMEORIGIN"), "SAMEORIGIN")
        self.assertEqual(deduplicate_header_value("max-age=31536000; includeSubDomains"), "max-age=31536000; includeSubDomains")

    def test_security_headers_evaluation(self):
        mock_resp = {
            "headers": {
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-frame-options": "SAMEORIGIN",
                "x-content-type-options": "nosniff, nosniff"
            }
        }
        with patch("openrecon.modules.security_headers_recon.safe_get", new_callable=AsyncMock, return_value=mock_resp):
            res = asyncio.run(analyze_security_headers("example.com"))
            
            headers = res["headers"]
            self.assertTrue(headers["Strict-Transport-Security"]["present"])
            self.assertEqual(headers["Strict-Transport-Security"]["value"], "max-age=31536000; includeSubDomains")
            self.assertTrue(headers["X-Frame-Options"]["present"])
            
            # Verify deduplicated value
            self.assertTrue(headers["X-Content-Type-Options"]["present"])
            self.assertEqual(headers["X-Content-Type-Options"]["value"], "nosniff")

            self.assertFalse(headers["Content-Security-Policy"]["present"])
            self.assertEqual(headers["Content-Security-Policy"]["value"], "MISSING")
            self.assertFalse(headers["Cross-Origin-Opener-Policy"]["present"])
            self.assertEqual(headers["Cross-Origin-Opener-Policy"]["value"], "MISSING")

            # Verify no score exists
            self.assertNotIn("score", res)

    def test_render_security_headers_output(self):
        data = {
            "headers": {
                "Strict-Transport-Security": {"present": True, "value": "max-age=31536000"},
                "Content-Security-Policy": {"present": False, "value": "MISSING"},
                "X-Frame-Options": {"present": True, "value": "DENY"},
                "X-Content-Type-Options": {"present": True, "value": "nosniff"},
                "Referrer-Policy": {"present": False, "value": "MISSING"},
                "Permissions-Policy": {"present": False, "value": "MISSING"},
                "Cross-Origin-Opener-Policy": {"present": False, "value": "MISSING"},
                "Cross-Origin-Resource-Policy": {"present": False, "value": "MISSING"}
            }
        }
        render_security_headers(data)

if __name__ == "__main__":
    unittest.main()
