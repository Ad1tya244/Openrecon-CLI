import unittest
from unittest.mock import patch, MagicMock
from openrecon.modules.dns_recon import get_dns_records
from openrecon.formatter import render_dns
import dns.resolver
import io
from rich.console import Console

class TestDNSRecon(unittest.TestCase):
    def test_dns_all_records_extraction_and_ttl(self):
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
        mock_cname.ttl = 600
        mock_cname_rdata = MagicMock()
        mock_cname_rdata.target = "cdn.example.com."
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

        mock_caa = MagicMock()
        mock_caa.ttl = 3600
        mock_caa_rdata = MagicMock()
        mock_caa_rdata.flags = 0
        mock_caa_rdata.tag = b"issue"
        mock_caa_rdata.value = b"letsencrypt.org"
        mock_caa.__iter__.return_value = [mock_caa_rdata]

        mock_srv = MagicMock()
        mock_srv.ttl = 120
        mock_srv_rdata = MagicMock()
        mock_srv_rdata.priority = 10
        mock_srv_rdata.weight = 20
        mock_srv_rdata.port = 5060
        mock_srv_rdata.target = "sip.example.com."
        mock_srv.__iter__.return_value = [mock_srv_rdata]

        mock_ptr = MagicMock()
        mock_ptr.ttl = 1800
        mock_ptr_rdata = MagicMock()
        mock_ptr_rdata.target = "host.example.com."
        mock_ptr.__iter__.return_value = [mock_ptr_rdata]

        def mock_resolve(qname, rtype):
            qname_str = str(qname)
            if rtype == "A":
                return mock_a
            elif rtype == "AAAA":
                return mock_aaaa
            elif rtype == "CNAME":
                return mock_cname
            elif rtype == "MX":
                return mock_mx
            elif rtype == "NS":
                return mock_ns
            elif rtype == "SOA":
                return mock_soa
            elif rtype == "TXT":
                return mock_txt
            elif rtype == "CAA":
                return mock_caa
            elif rtype == "SRV":
                if "_sip._tcp" in qname_str:
                    return mock_srv
                raise dns.resolver.NXDOMAIN()
            elif rtype == "PTR":
                return mock_ptr
            raise dns.resolver.NoAnswer()

        with patch("dns.resolver.Resolver.resolve", side_effect=mock_resolve):
            res = get_dns_records("example.com")
            
            self.assertIn("93.184.216.34 (TTL: 300)", res["A"])
            self.assertIn("2606:2800:220:1:248:1893:25c8:1946 (TTL: 300)", res["AAAA"])
            self.assertIn("cdn.example.com. (TTL: 600)", res["CNAME"])
            self.assertIn("10 mail.example.com. (TTL: 3600)", res["MX"])
            self.assertIn("ns1.example.com. (TTL: 86400)", res["NS"])
            self.assertIn("ns1.example.com. (Serial: 2026010101, Refresh: 7200, Retry: 3600, Expire: 1209600, Min TTL: 300)", res["SOA"])
            self.assertIn("v=spf1 include:_spf.google.com ~all", res["TXT"])
            self.assertIn('0 issue "letsencrypt.org" (TTL: 3600)', res["CAA"])
            self.assertIn('_sip._tcp 10 20 5060 sip.example.com. (TTL: 120)', res["SRV"])
            self.assertIn('93.184.216.34 -> host.example.com. (TTL: 1800)', res["PTR"])

    def test_dns_absent_records_and_null_mx(self):
        # Test Null MX and absence of AAAA, CNAME, CAA, SRV, PTR
        mock_a = MagicMock()
        mock_a.ttl = 60
        mock_a_rdata = MagicMock()
        mock_a_rdata.address = "13.200.101.137"
        mock_a.__iter__.return_value = [mock_a_rdata]

        mock_mx = MagicMock()
        mock_mx.ttl = 3600
        mock_mx_rdata = MagicMock()
        mock_mx_rdata.preference = 0
        mock_mx_rdata.exchange = "."
        mock_mx.__iter__.return_value = [mock_mx_rdata]

        def mock_resolve(qname, rtype):
            if rtype == "A":
                return mock_a
            elif rtype == "MX":
                return mock_mx
            raise dns.resolver.NXDOMAIN()

        with patch("dns.resolver.Resolver.resolve", side_effect=mock_resolve):
            res = get_dns_records("example.com")
            
            self.assertEqual(res["A"], ["13.200.101.137 (TTL: 60)"])
            self.assertEqual(res["MX"], ["0 . (TTL: 3600)"])
            self.assertEqual(res["AAAA"], [])
            self.assertEqual(res["CNAME"], [])
            self.assertEqual(res["CAA"], [])
            self.assertEqual(res["SRV"], [])
            self.assertEqual(res["PTR"], [])

    def test_dns_render_formatting(self):
        sample_data = {
            "A": ["13.200.101.137 (TTL: 60)"],
            "AAAA": [],
            "CNAME": [],
            "MX": ["1 aspmx.l.google.com. (TTL: 3600)"],
            "NS": ["ns1.example.com. (TTL: 21600)"],
            "SOA": ["ns1.example.com. (Serial: 0, Refresh: 10800, Retry: 3600, Expire: 604800, Min TTL: 1800)"],
            "TXT": ["v=spf1 include:_spf.google.com ~all"],
            "CAA": [],
            "SRV": [],
            "PTR": []
        }

        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)
        with patch("openrecon.formatter.console", test_console):
            render_dns(sample_data)
        
        output = buf.getvalue()
        self.assertIn("A                13.200.101.137 (TTL: 60)", output)
        self.assertIn("AAAA             No AAAA records", output)
        self.assertIn("CNAME            No CNAME record", output)
        self.assertIn("MX               1 aspmx.l.google.com. (TTL: 3600)", output)
        self.assertIn("NS               ns1.example.com. (TTL: 21600)", output)
        self.assertIn("SOA              ns1.example.com. (Serial: 0, Refresh: 10800, Retry: 3600,", output)
        self.assertIn("TXT              v=spf1 include:_spf.google.com ~all", output)
        self.assertIn("CAA              No CAA records", output)
        self.assertIn("SRV              No SRV records", output)
        self.assertIn("PTR              No PTR records", output)

if __name__ == "__main__":
    unittest.main()
