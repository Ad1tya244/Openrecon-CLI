import unittest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from openrecon.modules.subdomain_recon import (
    normalize_subdomain,
    enumerate_subdomains,
    MAX_SUBDOMAINS
)
from openrecon.formatter import render_subdomains

class TestSubdomainNormalization(unittest.TestCase):
    def test_apex_domain_excluded(self):
        self.assertIsNone(normalize_subdomain("example.com", "example.com"))
        self.assertIsNone(normalize_subdomain("example.com.", "example.com"))
        self.assertIsNone(normalize_subdomain("EXAMPLE.COM", "example.com"))
        self.assertIsNone(normalize_subdomain("bmsit.ac.in", "bmsit.ac.in"))
        self.assertIsNone(normalize_subdomain("  bmsit.ac.in.  ", "bmsit.ac.in"))

    def test_wildcard_handling(self):
        self.assertIsNone(normalize_subdomain("*.example.com", "example.com"))
        self.assertIsNone(normalize_subdomain("*example.com", "example.com"))
        self.assertEqual(normalize_subdomain("*.api.example.com", "example.com"), "api.example.com")
        self.assertEqual(normalize_subdomain("*api.example.com", "example.com"), "api.example.com")
        self.assertEqual(normalize_subdomain("*.dev.bmsit.ac.in", "bmsit.ac.in"), "dev.bmsit.ac.in")

    def test_valid_subdomains(self):
        self.assertEqual(normalize_subdomain("admin.example.com", "example.com"), "admin.example.com")
        self.assertEqual(normalize_subdomain("ADMIN.EXAMPLE.COM", "example.com"), "admin.example.com")
        self.assertEqual(normalize_subdomain("  api.example.com.  ", "example.com"), "api.example.com")
        self.assertEqual(normalize_subdomain("'vpn.example.com'", "example.com"), "vpn.example.com")

    def test_no_artificial_www_generation(self):
        self.assertEqual(normalize_subdomain("svasthya.bmsit.ac.in", "bmsit.ac.in"), "svasthya.bmsit.ac.in")
        self.assertNotEqual(normalize_subdomain("svasthya.bmsit.ac.in", "bmsit.ac.in"), "www.svasthya.bmsit.ac.in")
        # Genuinely passed www hostnames are preserved exactly as passed
        self.assertEqual(normalize_subdomain("www.bmsit.ac.in", "bmsit.ac.in"), "www.bmsit.ac.in")
        self.assertEqual(normalize_subdomain("www.projects.bmsit.ac.in", "bmsit.ac.in"), "www.projects.bmsit.ac.in")

    def test_nested_subdomains_preserved(self):
        self.assertEqual(normalize_subdomain("foo.bar.example.com", "example.com"), "foo.bar.example.com")
        self.assertEqual(normalize_subdomain("a.b.c.example.com", "example.com"), "a.b.c.example.com")
        self.assertEqual(normalize_subdomain("deep.nested.sub.domain.example.com", "example.com"), "deep.nested.sub.domain.example.com")

    def test_unrelated_domain_rejected(self):
        self.assertIsNone(normalize_subdomain("evil.com", "example.com"))
        self.assertIsNone(normalize_subdomain("notexample.com", "example.com"))
        self.assertIsNone(normalize_subdomain("example.com.attacker.com", "example.com"))
        self.assertIsNone(normalize_subdomain("example.org", "example.com"))
        self.assertIsNone(normalize_subdomain("", "example.com"))
        self.assertIsNone(normalize_subdomain(None, "example.com"))

    def test_max_subdomains_50_cap_and_exact_count(self):
        mock_candidates = [f"sub{i}.example.com" for i in range(100)]
        with patch("openrecon.modules.subdomain_recon._fetch_source_safe", new_callable=AsyncMock, return_value=mock_candidates):
            res = asyncio.run(enumerate_subdomains("example.com"))
            subdomains = res["subdomains"]
            total = res["total"]
            
            self.assertEqual(len(subdomains), 50)
            self.assertEqual(total, 50)
            self.assertEqual(MAX_SUBDOMAINS, 50)

    def test_render_subdomains_output(self):
        data = {
            "subdomains": [
                {"hostname": "admission.example.com"},
                {"hostname": "alumni.example.com"}
            ],
            "total": 2
        }
        render_subdomains(data)

if __name__ == "__main__":
    unittest.main()
