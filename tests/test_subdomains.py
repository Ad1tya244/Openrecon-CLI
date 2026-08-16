import unittest
import asyncio
from unittest.mock import AsyncMock, patch
from openrecon.modules.subdomain_recon import (
    normalize_subdomain,
    enumerate_subdomains,
    MAX_SUBDOMAINS
)

class TestSubdomainNormalization(unittest.TestCase):
    def test_apex_domain_excluded(self):
        self.assertIsNone(normalize_subdomain("example.com", "example.com"))
        self.assertIsNone(normalize_subdomain("example.com.", "example.com"))
        self.assertIsNone(normalize_subdomain("EXAMPLE.COM", "example.com"))
        self.assertIsNone(normalize_subdomain("bmsit.ac.in", "bmsit.ac.in"))
        self.assertIsNone(normalize_subdomain("  bmsit.ac.in.  ", "bmsit.ac.in"))

    def test_wildcard_handling(self):
        # Wildcard on apex resolves to apex -> excluded
        self.assertIsNone(normalize_subdomain("*.example.com", "example.com"))
        self.assertIsNone(normalize_subdomain("*example.com", "example.com"))
        # Wildcard on nested subdomain -> extracts valid subdomain
        self.assertEqual(normalize_subdomain("*.api.example.com", "example.com"), "api.example.com")
        self.assertEqual(normalize_subdomain("*api.example.com", "example.com"), "api.example.com")
        self.assertEqual(normalize_subdomain("*.dev.bmsit.ac.in", "bmsit.ac.in"), "dev.bmsit.ac.in")

    def test_valid_subdomains(self):
        self.assertEqual(normalize_subdomain("admin.example.com", "example.com"), "admin.example.com")
        self.assertEqual(normalize_subdomain("ADMIN.EXAMPLE.COM", "example.com"), "admin.example.com")
        self.assertEqual(normalize_subdomain("  api.example.com.  ", "example.com"), "api.example.com")
        self.assertEqual(normalize_subdomain("'vpn.example.com'", "example.com"), "vpn.example.com")

    def test_no_artificial_www_generation(self):
        # Normalization MUST NEVER manufacture www. variants
        self.assertEqual(normalize_subdomain("svasthya.bmsit.ac.in", "bmsit.ac.in"), "svasthya.bmsit.ac.in")
        self.assertNotEqual(normalize_subdomain("svasthya.bmsit.ac.in", "bmsit.ac.in"), "www.svasthya.bmsit.ac.in")
        # Genuinely passed www hostnames are preserved exactly as passed
        self.assertEqual(normalize_subdomain("www.bmsit.ac.in", "bmsit.ac.in"), "www.bmsit.ac.in")
        self.assertEqual(normalize_subdomain("www.projects.bmsit.ac.in", "bmsit.ac.in"), "www.projects.bmsit.ac.in")

    def test_distinct_hostnames_preserved(self):
        # If both variants exist in source, they remain distinct and neither is manufactured from the other
        raw_list = ["svasthya.bmsit.ac.in", "www.svasthya.bmsit.ac.in"]
        results = [normalize_subdomain(r, "bmsit.ac.in") for r in raw_list]
        self.assertEqual(results, ["svasthya.bmsit.ac.in", "www.svasthya.bmsit.ac.in"])

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

    def test_exact_deduplication_and_sorting(self):
        raw_list = [
            "ADMIN.example.com",
            "admin.example.com",
            "*.api.example.com",
            "api.example.com",
            "example.com",
            "foo.bar.example.com",
            "evil.com"
        ]
        target = "example.com"
        results = set()
        for r in raw_list:
            norm = normalize_subdomain(r, target)
            if norm:
                results.add(norm)
        
        sorted_results = sorted(list(results))
        expected = ["admin.example.com", "api.example.com", "foo.bar.example.com"]
        self.assertEqual(sorted_results, expected)


class TestSubdomainMultiSourceAndResilience(unittest.IsolatedAsyncioTestCase):
    @patch("openrecon.modules.subdomain_recon._fetch_certspotter")
    @patch("openrecon.modules.subdomain_recon._fetch_rapiddns")
    @patch("openrecon.modules.subdomain_recon._fetch_urlscan")
    @patch("openrecon.modules.subdomain_recon._fetch_crt_sh")
    @patch("openrecon.modules.subdomain_recon._fetch_hackertarget")
    @patch("openrecon.modules.subdomain_recon._fetch_wayback")
    @patch("openrecon.modules.subdomain_recon._fetch_anubis")
    @patch("openrecon.modules.subdomain_recon._check_dns_resolution")
    async def test_multi_source_merging_and_attribution(
        self, mock_dns, mock_anubis, mock_wb, mock_ht, mock_crt, mock_urlscan, mock_rapid, mock_cs
    ):
        mock_cs.return_value = ["api.example.com", "cert.example.com"]
        mock_rapid.return_value = ["api.example.com", "rapid.example.com"]
        mock_urlscan.return_value = ["web.example.com"]
        mock_crt.return_value = ["cert.example.com", "crt.example.com"]
        mock_ht.return_value = ["ht.example.com"]
        mock_wb.return_value = ["archive.example.com"]
        mock_anubis.return_value = ["anubis.example.com"]

        mock_dns.return_value = {"resolves": True, "ips": ["1.2.3.4"]}

        result = await enumerate_subdomains("example.com")
        
        self.assertEqual(result["count"], 8)
        self.assertEqual(len(result["subdomains"]), 8)
        self.assertFalse(result["limit_reached"])
        
        # Verify attribution for multi-source entry
        api_entry = next(s for s in result["subdomains"] if s["hostname"] == "api.example.com")
        self.assertIn("certspotter", api_entry["sources"])
        self.assertIn("rapiddns", api_entry["sources"])

        cert_entry = next(s for s in result["subdomains"] if s["hostname"] == "cert.example.com")
        self.assertIn("certspotter", cert_entry["sources"])
        self.assertIn("crt_sh", cert_entry["sources"])

    @patch("openrecon.modules.subdomain_recon._fetch_certspotter")
    @patch("openrecon.modules.subdomain_recon._fetch_rapiddns")
    @patch("openrecon.modules.subdomain_recon._fetch_urlscan")
    @patch("openrecon.modules.subdomain_recon._fetch_crt_sh")
    @patch("openrecon.modules.subdomain_recon._fetch_hackertarget")
    @patch("openrecon.modules.subdomain_recon._fetch_wayback")
    @patch("openrecon.modules.subdomain_recon._fetch_anubis")
    @patch("openrecon.modules.subdomain_recon._check_dns_resolution")
    async def test_dns_does_not_add_or_remove_entries(
        self, mock_dns, mock_anubis, mock_wb, mock_ht, mock_crt, mock_urlscan, mock_rapid, mock_cs
    ):
        mock_cs.return_value = ["active.example.com", "inactive.example.com"]
        mock_rapid.return_value = []
        mock_urlscan.return_value = []
        mock_crt.return_value = []
        mock_ht.return_value = []
        mock_wb.return_value = []
        mock_anubis.return_value = []

        async def fake_dns(hostname, resolver):
            if hostname == "active.example.com":
                return {"resolves": True, "ips": ["93.184.216.34"]}
            # inactive does not resolve
            return {"resolves": False, "ips": []}

        mock_dns.side_effect = fake_dns

        result = await enumerate_subdomains("example.com")
        # Both hostnames must be in the result list regardless of resolution
        self.assertEqual(result["count"], 2)
        self.assertEqual(len(result["subdomains"]), 2)
        
        active_sub = next(s for s in result["subdomains"] if s["hostname"] == "active.example.com")
        self.assertTrue(active_sub["resolves"])
        
        inactive_sub = next(s for s in result["subdomains"] if s["hostname"] == "inactive.example.com")
        self.assertFalse(inactive_sub["resolves"])

    @patch("openrecon.modules.subdomain_recon._fetch_certspotter")
    @patch("openrecon.modules.subdomain_recon._fetch_rapiddns")
    @patch("openrecon.modules.subdomain_recon._fetch_urlscan")
    @patch("openrecon.modules.subdomain_recon._fetch_crt_sh")
    @patch("openrecon.modules.subdomain_recon._fetch_hackertarget")
    @patch("openrecon.modules.subdomain_recon._fetch_wayback")
    @patch("openrecon.modules.subdomain_recon._fetch_anubis")
    @patch("openrecon.modules.subdomain_recon._check_dns_resolution")
    async def test_max_subdomains_50_cap(
        self, mock_dns, mock_anubis, mock_wb, mock_ht, mock_crt, mock_urlscan, mock_rapid, mock_cs
    ):
        # Generate 75 unique subdomains
        large_list = [f"sub{i}.example.com" for i in range(75)]
        mock_cs.return_value = large_list
        mock_rapid.return_value = []
        mock_urlscan.return_value = []
        mock_crt.return_value = []
        mock_ht.return_value = []
        mock_wb.return_value = []
        mock_anubis.return_value = []

        mock_dns.return_value = {"resolves": True, "ips": ["1.2.3.4"]}

        result = await enumerate_subdomains("example.com")
        self.assertTrue(result["limit_reached"])
        self.assertEqual(result["count"], 50)
        self.assertEqual(len(result["subdomains"]), 50)
        self.assertEqual(result["total_discovered"], 75)

if __name__ == "__main__":
    unittest.main()
