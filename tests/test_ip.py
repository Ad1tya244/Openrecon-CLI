import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
from openrecon.modules.ip_hosting_asn import get_domain_intelligence, normalize_provider, clean_asn_info
from openrecon.formatter import render_ip_asn

class TestIPHostingASN(unittest.TestCase):
    def test_provider_normalization(self):
        self.assertEqual(normalize_provider("Cloudflare, Inc."), "Cloudflare")
        self.assertEqual(normalize_provider("Amazon.com, Inc."), "Amazon AWS")
        self.assertEqual(normalize_provider("Google LLC"), "Google Cloud")
        self.assertEqual(normalize_provider("DigitalOcean, LLC"), "DigitalOcean")

    def test_clean_asn_info(self):
        info = clean_asn_info("AS13335 Cloudflare, Inc.", isp="Cloudflare, Inc.")
        self.assertEqual(info["asn"], "AS13335")
        self.assertEqual(info["org"], "Cloudflare, Inc.")

    def test_domain_intelligence_resolution(self):
        mock_a_rdata = MagicMock()
        mock_a_rdata.to_text.return_value = "93.184.216.34"
        mock_a = [mock_a_rdata]

        mock_aaaa_rdata = MagicMock()
        mock_aaaa_rdata.to_text.return_value = "2606:2800:220:1:248:1893:25c8:1946"
        mock_aaaa = [mock_aaaa_rdata]

        def mock_resolve(domain, rtype):
            if rtype == "A":
                return mock_a
            if rtype == "AAAA":
                return mock_aaaa
            raise Exception("No record")

        mock_ip_api = {
            "status": "success",
            "city": "Norwell",
            "countryCode": "US",
            "isp": "EDGECAST",
            "org": "Verizon Digital Media Services",
            "as": "AS15133 MCI Communications Services, Inc. d/b/a Verizon Business"
        }

        with patch("dns.resolver.Resolver.resolve", side_effect=mock_resolve), \
             patch("openrecon.modules.ip_hosting_asn.get_ip_data", new_callable=AsyncMock, return_value=mock_ip_api):
            res = asyncio.run(get_domain_intelligence("example.com"))
            
            self.assertEqual(res["primary_ip"], "93.184.216.34")
            self.assertEqual(res["ipv6"], "2606:2800:220:1:248:1893:25c8:1946")
            self.assertEqual(res["asn"], "AS15133")
            self.assertEqual(res["location"], "Norwell, US")

    def test_render_ip_output(self):
        data = {
            "primary_ip": "93.184.216.34",
            "ipv6": "2606:2800:220:1:248:1893:25c8:1946",
            "additional_ips": ["93.184.216.35"],
            "location": "Norwell, US",
            "isp": "EDGECAST",
            "asn": "AS15133",
            "provider": "EdgeCast",
            "hosting_type": "CDN / Edge Network"
        }
        render_ip_asn(data)

if __name__ == "__main__":
    unittest.main()
