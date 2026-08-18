import unittest
from unittest.mock import patch, MagicMock
from openrecon.modules.dns_recon import get_dns_records
from openrecon.formatter import render_dns

class TestDNSRecon(unittest.TestCase):
    def test_dns_records_extraction_and_ttl(self):
        mock_a = MagicMock()
        mock_a.ttl = 300
        mock_a_rdata = MagicMock()
        mock_a_rdata.address = "93.184.216.34"
        mock_a.__iter__.return_value = [mock_a_rdata]

        mock_aaaa = MagicMock()
        mock_aaaa.ttl = 300
        mock_aaaa_rdata = MagicMock()
        mock_aaaa_rdata.address = "2606:2800:220:1:248:1893:25c8:1946"
        mock_aaaa.__iter__.return_value = [mock_aaaa_rdata]

        mock_cname = MagicMock()
        mock_cname.ttl = 300
        mock_cname_rdata = MagicMock()
        mock_cname_rdata.target = "example.com."
        mock_cname.__iter__.return_value = [mock_cname_rdata]

        mock_mx = MagicMock()
        mock_mx.ttl = 3600
        mock_mx_rdata = MagicMock()
        mock_mx_rdata.preference = 10
        mock_mx_rdata.exchange = "mail.example.com."
        mock_mx.__iter__.return_value = [mock_mx_rdata]

        mock_ns = MagicMock()
        mock_ns.ttl = 86400
        mock_ns_rdata = MagicMock()
        mock_ns_rdata.target = "ns1.example.com."
        mock_ns.__iter__.return_value = [mock_ns_rdata]

        mock_soa = MagicMock()
        mock_soa.ttl = 300
        mock_soa_rdata = MagicMock()
        mock_soa_rdata.mname = "ns1.example.com."
        mock_soa_rdata.serial = 2026010101
        mock_soa_rdata.refresh = 7200
        mock_soa_rdata.retry = 3600
        mock_soa_rdata.expire = 1209600
        mock_soa_rdata.minimum = 300
        mock_soa.__iter__.return_value = [mock_soa_rdata]

        mock_txt = MagicMock()
        mock_txt.ttl = 300
        mock_txt_rdata = MagicMock()
        mock_txt_rdata.strings = [b"v=spf1 ", b"include:_spf.google.com ", b"~all"]
        mock_txt.__iter__.return_value = [mock_txt_rdata]

        def mock_resolve(domain, rtype):
            mapping = {
                "A": mock_a,
                "AAAA": mock_aaaa,
                "CNAME": mock_cname,
                "MX": mock_mx,
                "NS": mock_ns,
                "SOA": mock_soa,
                "TXT": mock_txt
            }
            return mapping[rtype]

        with patch("dns.resolver.Resolver.resolve", side_effect=mock_resolve):
            res = get_dns_records("example.com")
            
            self.assertIn("93.184.216.34 (TTL: 300)", res["A"])
            self.assertIn("2606:2800:220:1:248:1893:25c8:1946 (TTL: 300)", res["AAAA"])
            self.assertIn("example.com → example.com. (TTL: 300)", res["CNAME"])
            self.assertIn("10 mail.example.com. (TTL: 3600)", res["MX"])
            self.assertIn("ns1.example.com. (TTL: 86400)", res["NS"])
            self.assertIn("ns1.example.com. (Serial: 2026010101, Refresh: 7200, Retry: 3600, Expire: 1209600, Min TTL: 300)", res["SOA"])
            self.assertIn("v=spf1 include:_spf.google.com ~all", res["TXT"])

    def test_render_dns_output(self):
        sample_data = {
            "A": ["93.184.216.34 (TTL: 300)"],
            "AAAA": ["2606:2800::1 (TTL: 300)"],
            "CNAME": ["www.example.com → example.com. (TTL: 300)"],
            "MX": ["10 mail.example.com. (TTL: 3600)"],
            "NS": ["ns1.example.com. (TTL: 86400)"],
            "SOA": ["ns1.example.com. (Serial: 2026010101, Refresh: 7200, Retry: 3600, Expire: 1209600, Min TTL: 300)"],
            "TXT": ["v=spf1 -all"]
        }
        # Should render cleanly without exception
        render_dns(sample_data)

if __name__ == "__main__":
    unittest.main()
