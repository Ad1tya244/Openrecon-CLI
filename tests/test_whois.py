import unittest
from openrecon.modules.whois_recon import parse_whois_data, is_redacted_value
from openrecon.formatter import render_whois

class TestWhoisRecon(unittest.TestCase):
    def test_genuine_whois_parsing(self):
        sample_whois = """
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://www.iana.org
Updated Date: 2023-08-14T07:01:38Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2024-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
Registrar IANA ID: 376
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Organization: Internet Assigned Numbers Authority
Registrant State/Province: CA
Registrant Country: US
Name Server: A.IANA-SERVERS.NET
"""
        parsed = parse_whois_data(sample_whois)
        self.assertEqual(parsed["registrar"], "RESERVED-Internet Assigned Numbers Authority")
        self.assertEqual(parsed["registry_domain_id"], "2336799_DOMAIN_COM-VRSN")
        self.assertEqual(parsed["registrar_iana_id"], "376")
        self.assertEqual(parsed["creation_date"], "1995-08-14T04:00:00Z")
        self.assertEqual(parsed["updated_date"], "2023-08-14T07:01:38Z")
        self.assertEqual(parsed["expiration_date"], "2024-08-13T04:00:00Z")
        self.assertGreater(parsed["age_years"], 25)
        self.assertIn("clientDeleteProhibited", parsed["status"])
        self.assertEqual(parsed["registrant"], "Internet Assigned Numbers Authority")

    def test_privacy_redacted_filtering(self):
        sample_redacted = """
Domain Name: PRIVATETARGET.COM
Registrar: Namecheap
Creation Date: 2020-01-01
Registrant Organization: REDACTED FOR PRIVACY
Registrant Name: Privacy service provided by Withheld for Privacy ehf
"""
        parsed = parse_whois_data(sample_redacted)
        self.assertIsNone(parsed["registrant"])

        self.assertTrue(is_redacted_value("REDACTED FOR PRIVACY"))
        self.assertTrue(is_redacted_value("WhoisGuard Protected"))
        self.assertTrue(is_redacted_value("Contact Privacy Inc. Customer 12345"))
        self.assertTrue(is_redacted_value("GDPR Masked"))
        self.assertFalse(is_redacted_value("Google LLC"))

    def test_render_whois_output(self):
        data = {
            "registrar": "GoDaddy.com, LLC",
            "registry_domain_id": "12345_COM",
            "registrar_iana_id": "146",
            "creation_date": "2010-05-20",
            "updated_date": "2023-05-20",
            "expiration_date": "2025-05-20",
            "age_years": 13.5,
            "status": ["clientTransferProhibited"],
            "registrant": "Example Corp"
        }
        render_whois(data)

if __name__ == "__main__":
    unittest.main()
