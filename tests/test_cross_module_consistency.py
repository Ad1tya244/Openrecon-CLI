import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
from openrecon.modules.dns_recon import get_dns_records
from openrecon.modules.email_recon import analyze_email_security
from openrecon.modules.ip_hosting_asn import get_domain_intelligence
from openrecon.modules.ssl_recon import match_hostname
from openrecon.modules.security_headers_recon import deduplicate_header_value
from openrecon.modules.subdomain_recon import normalize_subdomain
from openrecon.modules.public_files import check_public_files
from openrecon.modules.directory_exposure import is_directory_listing
from openrecon.modules.port_recon import parse_service_version
from openrecon.modules.whois_recon import parse_whois_data

class TestCrossModuleConsistency(unittest.TestCase):
    def test_dns_and_email_spf_consistency(self):
        # When DNS returns a specific SPF record, Email Security must analyze that exact same record
        raw_spf_record = "v=spf1 ip4:199.15.212.0/22 include:_spf.google.com include:spf1.mcsv.net -all"
        txt_records = [
            "google-site-verification=abc12345",
            raw_spf_record,
            "MS=ms70274184"
        ]
        
        res = analyze_email_security("example.com", txt_records=txt_records)
        spf = res["spf"]
        
        self.assertEqual(spf["record"], "PRESENT")
        self.assertEqual(spf["status"], "STRICT")
        self.assertEqual(spf["value"], raw_spf_record)
        self.assertEqual(spf["final_qualifier"], "-all")
        self.assertEqual(spf["includes"], ["_spf.google.com", "spf1.mcsv.net"])
        
        # Verify no external/unrelated includes were injected
        self.assertNotIn("mail.zendesk.com", spf["includes"])
        self.assertNotIn("_spf.salesforce.com", spf["includes"])

    def test_dns_and_email_dmarc_consistency(self):
        # DMARC must come from _dmarc.<domain>
        mock_dmarc_rdata = MagicMock()
        mock_dmarc_rdata.strings = [b"v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:rua@example.com"]
        mock_dmarc_txt = MagicMock()
        mock_dmarc_txt.__iter__.return_value = [mock_dmarc_rdata]

        with patch("dns.resolver.Resolver.resolve", return_value=mock_dmarc_txt):
            res = analyze_email_security("example.com", txt_records=["v=spf1 -all"])
            dmarc = res["dmarc"]
            self.assertEqual(dmarc["record"], "PRESENT")
            self.assertEqual(dmarc["policy"], "reject")
            self.assertEqual(dmarc["subdomain_policy"], "reject")
            self.assertEqual(dmarc["rua"], "mailto:rua@example.com")
            self.assertEqual(dmarc["percentage"], "100%")

    def test_dns_and_infrastructure_ip_consistency(self):
        # Infrastructure primary IP and additional IPs must match DNS A and AAAA records
        dns_ipv4 = ["104.16.133.229", "104.16.132.229"]
        dns_ipv6 = ["2606:4700::6810:85e5", "2606:4700::6810:84e5"]

        def mock_resolve(domain, rtype):
            mock_ans = MagicMock()
            if rtype == "A":
                items = []
                for ip in dns_ipv4:
                    rdata = MagicMock()
                    rdata.to_text.return_value = ip
                    items.append(rdata)
                mock_ans.__iter__.return_value = items
                return mock_ans
            elif rtype == "AAAA":
                items = []
                for ip in dns_ipv6:
                    rdata = MagicMock()
                    rdata.to_text.return_value = ip
                    items.append(rdata)
                mock_ans.__iter__.return_value = items
                return mock_ans
            raise Exception("No records")

        with patch("dns.resolver.Resolver.resolve", side_effect=mock_resolve), \
             patch("openrecon.modules.ip_hosting_asn.get_ip_data", new_callable=AsyncMock, return_value={"status": "fail"}):
            
            res = asyncio.run(get_domain_intelligence("example.com"))
            
            self.assertEqual(res["primary_ip"], dns_ipv4[0])
            self.assertEqual(res["additional_ips"], [dns_ipv4[1]])
            self.assertEqual(res["ipv6"], dns_ipv6[0])

    def test_tls_hostname_validation_strictness(self):
        # python.org must NOT match a cert covering only www.python.org
        self.assertFalse(match_hostname("python.org", ["www.python.org"]))
        self.assertTrue(match_hostname("python.org", ["python.org", "www.python.org"]))
        self.assertTrue(match_hostname("www.python.org", ["*.python.org"]))
        self.assertFalse(match_hostname("python.org", ["*.python.org"]))

    def test_http_duplicate_header_deduplication(self):
        self.assertEqual(deduplicate_header_value("nosniff, nosniff"), "nosniff")
        self.assertEqual(deduplicate_header_value("SAMEORIGIN, SAMEORIGIN"), "SAMEORIGIN")
        self.assertEqual(deduplicate_header_value("max-age=31536000; includeSubDomains"), "max-age=31536000; includeSubDomains")

    def test_public_files_http_200_only(self):
        async def mock_safe_get(url):
            if "robots.txt" in url:
                return {"status_code": 200}
            elif "sitemap.xml" in url:
                return {"status_code": 404}
            elif "security.txt" in url:
                return {"status_code": 403}
            return {"status_code": 500}

        with patch("openrecon.modules.public_files.safe_get", side_effect=mock_safe_get):
            res = asyncio.run(check_public_files("example.com"))
            self.assertEqual(res["found"], ["robots.txt"])
            self.assertNotIn("sitemap.xml", res["found"])
            self.assertNotIn("security.txt", res["found"])

    def test_directory_exposure_normal_200_not_exposed(self):
        normal_page = "<html><body><h1>Welcome to our site</h1><p>Normal content</p></body></html>"
        self.assertFalse(is_directory_listing(normal_page))

        apache_listing = "<html><head><title>Index of /data</title></head><body><h1>Index of /data</h1><a href='../'>Parent Directory</a></body></html>"
        self.assertTrue(is_directory_listing(apache_listing))

    def test_subdomain_normalization_and_apex_exclusion(self):
        self.assertIsNone(normalize_subdomain("example.com", "example.com"))
        self.assertIsNone(normalize_subdomain("otherdomain.com", "example.com"))
        self.assertEqual(normalize_subdomain("api.example.com", "example.com"), "api.example.com")
        self.assertEqual(normalize_subdomain("*.dev.example.com", "example.com"), "dev.example.com")

    def test_whois_nameservers_not_in_output(self):
        raw_whois = """
        Domain Name: EXAMPLE.COM
        Registry Domain ID: 2336799_DOMAIN_COM-VRSN
        Registrar: RESERVED-Internet Assigned Numbers Authority
        Registrar IANA ID: 376
        Creation Date: 1995-08-14T04:00:00Z
        Updated Date: 2026-08-14T07:01:00Z
        Name Server: A.IANA-SERVERS.NET
        Name Server: B.IANA-SERVERS.NET
        """
        data = parse_whois_data(raw_whois)
        self.assertEqual(data["registrar"], "RESERVED-Internet Assigned Numbers Authority")
        self.assertEqual(data["registry_domain_id"], "2336799_DOMAIN_COM-VRSN")
        self.assertEqual(data["registrar_iana_id"], "376")
        # Ensure nameservers are not captured in whois data dict
        self.assertNotIn("nameservers", data)
        self.assertNotIn("name_servers", data)

    def test_port_version_non_guessing(self):
        # Ports without banner evidence must have version=None
        self.assertIsNone(parse_service_version("FTP", None))
        self.assertIsNone(parse_service_version("SSH", None))
        self.assertIsNone(parse_service_version("HTTP", None))
        self.assertEqual(parse_service_version("SSH", "SSH-2.0-OpenSSH_9.2p1"), "OpenSSH 9.2p1")

if __name__ == "__main__":
    unittest.main()
