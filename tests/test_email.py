import unittest
from unittest.mock import patch, MagicMock
from openrecon.modules.email_recon import analyze_email_security
from openrecon.formatter import render_email

class TestEmailSecurityRecon(unittest.TestCase):
    def test_single_valid_spf_record_with_multiple_includes(self):
        txt_records = [
            "google-site-verification=12345",
            "v=spf1 include:_spf.google.com include:spf.mandrillapp.com -all",
            "facebook-domain-verification=abcde"
        ]
        res = analyze_email_security("example.com", txt_records=txt_records)
        spf = res["spf"]
        
        self.assertEqual(spf["record"], "PRESENT")
        self.assertEqual(spf["status"], "STRICT")
        self.assertEqual(spf["value"], "v=spf1 include:_spf.google.com include:spf.mandrillapp.com -all")
        self.assertEqual(spf["final_qualifier"], "-all")
        self.assertEqual(spf["includes"], ["_spf.google.com", "spf.mandrillapp.com"])

    def test_multiple_spf_records_returns_invalid(self):
        txt_records = [
            "v=spf1 include:_spf.google.com -all",
            "v=spf1 include:mailgun.org ~all"
        ]
        res = analyze_email_security("example.com", txt_records=txt_records)
        spf = res["spf"]
        
        self.assertEqual(spf["record"], "INVALID")
        self.assertIn("INVALID", spf["status"])
        self.assertIsNone(spf["value"])
        self.assertIsNone(spf["final_qualifier"])
        self.assertEqual(spf["includes"], [])

    def test_spf_qualifiers_mapping(self):
        # Strict (-all)
        res_strict = analyze_email_security("example.com", txt_records=["v=spf1 ip4:1.2.3.4 -all"])
        self.assertEqual(res_strict["spf"]["status"], "STRICT")
        self.assertEqual(res_strict["spf"]["final_qualifier"], "-all")

        # Softfail (~all)
        res_soft = analyze_email_security("example.com", txt_records=["v=spf1 include:_spf.google.com ~all"])
        self.assertEqual(res_soft["spf"]["status"], "SOFTFAIL")
        self.assertEqual(res_soft["spf"]["final_qualifier"], "~all")

        # Neutral (?all)
        res_neutral = analyze_email_security("example.com", txt_records=["v=spf1 include:test.com ?all"])
        self.assertEqual(res_neutral["spf"]["status"], "NEUTRAL")
        self.assertEqual(res_neutral["spf"]["final_qualifier"], "?all")

        # Over-permissive (+all)
        res_over = analyze_email_security("example.com", txt_records=["v=spf1 +all"])
        self.assertEqual(res_over["spf"]["status"], "OVER-PERMISSIVE")
        self.assertEqual(res_over["spf"]["final_qualifier"], "+all")

        # Redirect (redirect=)
        res_redirect = analyze_email_security("example.com", txt_records=["v=spf1 redirect=icann.org"])
        self.assertEqual(res_redirect["spf"]["status"], "REDIRECT")
        self.assertIsNone(res_redirect["spf"]["final_qualifier"])

    def test_no_spf_record_returns_missing(self):
        res = analyze_email_security("example.com", txt_records=["google-site-verification=xyz"])
        spf = res["spf"]
        self.assertEqual(spf["record"], "MISSING")
        self.assertEqual(spf["status"], "MISSING")
        self.assertIsNone(spf["value"])
        self.assertIsNone(spf["final_qualifier"])
        self.assertEqual(spf["includes"], [])

    def test_no_cross_record_merging(self):
        # Ensure mechanisms in non-SPF TXT records are never merged
        txt_records = [
            "v=spf1 include:_spf.google.com -all",
            "include:_spf.salesforce.com",
            "mail.zendesk.com"
        ]
        res = analyze_email_security("example.com", txt_records=txt_records)
        spf = res["spf"]
        self.assertEqual(spf["includes"], ["_spf.google.com"])
        self.assertEqual(spf["value"], "v=spf1 include:_spf.google.com -all")

    def test_render_email_output(self):
        data = {
            "spf": {
                "record": "PRESENT",
                "status": "STRICT",
                "value": "v=spf1 include:_spf.google.com include:spf.mandrillapp.com -all",
                "final_qualifier": "-all",
                "includes": ["_spf.google.com", "spf.mandrillapp.com"]
            },
            "dmarc": {
                "record": "PRESENT",
                "policy": "reject",
                "subdomain_policy": "reject",
                "rua": "mailto:dmarc@example.com",
                "percentage": "100%"
            },
            "dkim": {
                "status": "NOT ENUMERATED"
            }
        }
        render_email(data)

if __name__ == "__main__":
    unittest.main()
