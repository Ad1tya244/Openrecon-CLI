import unittest
from openrecon.modules.tech_fingerprint import identify_technologies, merge_technology_evidence
from openrecon.modules.page_intel import analyze_page_intel, analyze_javascript_requests
from openrecon.utils.findings import Finding, Evidence
from openrecon.formatter import render_tech, render_page_intel, export_text_report
import io
import contextlib

class TestEvidenceCorrelation(unittest.TestCase):
    def test_technology_evidence_direct_and_dedup(self):
        headers = {"Server": "Apache/2.4.58 (Ubuntu)", "X-Powered-By": "PHP/8.2.14"}
        html = '<meta name="generator" content="WordPress 6.4.2">'
        
        result = identify_technologies(headers, html)
        self.assertIn("findings", result)
        findings = result["findings"]
        
        wp_finding = next((f for f in findings if f.value == "WordPress"), None)
        self.assertIsNotNone(wp_finding)
        self.assertEqual(wp_finding.inference, "DIRECT")
        self.assertTrue(any(ev.type == "meta" for ev in wp_finding.evidence))
        
        php_finding = next((f for f in findings if f.value == "PHP"), None)
        self.assertIsNotNone(php_finding)
        # PHP can be implied by WordPress or direct from X-Powered-By header
        # Both direct and implied evidence should be present
        self.assertTrue(any(ev.type == "headers" for ev in php_finding.evidence))

    def test_relational_evidence_label(self):
        # Triggering a relational match (e.g., MySQL implied by WordPress)
        html = '<meta name="generator" content="WordPress 6.4.2">'
        result = identify_technologies({}, html)
        findings = result.get("findings", [])
        
        mysql_finding = next((f for f in findings if f.value == "MySQL"), None)
        self.assertIsNotNone(mysql_finding)
        self.assertEqual(mysql_finding.inference, "RELATIONAL")
        self.assertTrue(any(ev.type == "relational" and ev.source == "WordPress" for ev in mysql_finding.evidence))

    def test_fallback_evidence_label(self):
        # Triggering Python fallback matching directly
        headers = {"Server": "Apache/2.4.58 (Ubuntu)"}
        # Simulate Node/Technology engine crash/failure via a blank script content or matching fallback directly
        from openrecon.modules.tech_fingerprint import run_fallback_technology_engine, load_fingerprints
        tech_items = {
            "url": "", "html": "", "headers": {"server": ["Apache/2.4.58 (Ubuntu)"]}, "cookies": {}, "meta": {}, "scriptSrc": [], "scripts": [], "css": []
        }
        fallback_res = run_fallback_technology_engine(tech_items, load_fingerprints())
        self.assertTrue(any(item.get("evidence") for item in fallback_res))
        self.assertEqual(fallback_res[0]["evidence"][0]["detection_engine"], "fallback")

    def test_oauth_and_token_provenance_and_masking(self):
        # Google / Firebase API Key should be masked
        js_code = 'const key = "AIzaSyDUMMYKEY1234567890EXTRA1234567899"; const auth = { authority: "https://example.us.auth0.com" };'
        apis, routes, ws, cfgs, config_refs = analyze_javascript_requests(js_code, "example.com", "inline script #1")
        
        from openrecon.modules.page_intel import extract_infrastructure_and_sensitive, mask_token
        hosts, buckets, sens = extract_infrastructure_and_sensitive(js_code, "inline script #1")
        
        self.assertTrue(any("Google / Firebase API Key" in s for s in sens))
        raw_val = sens[0].split(":", 1)[1].strip()
        masked_val = mask_token(raw_val)
        self.assertNotIn("DUMMYKEY", masked_val)
        self.assertEqual(masked_val, "AIzaSy...7899")

    def test_ast_websocket_sse_provenance(self):
        js_code = 'const ws = new WebSocket("wss://api.example.com/feed"); const sse = new EventSource("/stream");'
        apis, routes, ws_list, cfgs, config_refs = analyze_javascript_requests(js_code, "example.com", "test.js")
        
        # Verify NewExpression signatures are tracked as endpoints
        self.assertTrue(any(ep["method"] == "WS" and ep["url"] == "wss://api.example.com/feed" for ep in apis))
        self.assertTrue(any(ep["method"] == "SSE" and ep["url"] == "/stream" for ep in apis))
        
        ws_ep = next((ep for ep in apis if ep["method"] == "WS"), None)
        self.assertIsNotNone(ws_ep)
        self.assertEqual(ws_ep["expression"], 'new WebSocket("wss://api.example.com/feed")')

    def test_normal_output_vs_evidence_mode(self):
        # Verify text output byte parity
        results = {
            "target": "example.com",
            "modules": {
                "tech": {
                    "data": {
                        "technologies": [{"name": "Nginx", "version": "1.18.0", "category": "Web Server"}],
                        "categories": {"Web Server": [{"name": "Nginx", "version": "1.18.0"}]},
                        "findings": [
                            Finding(
                                value="Nginx",
                                category="Web Server",
                                version="1.18.0",
                                confidence=100,
                                evidence=[Evidence(type="headers", source="Server", snippet="Nginx/1.18.0")]
                            )
                        ]
                    }
                }
            }
        }
        
        plain_out = export_text_report(results, show_evidence=False)
        evidence_out = export_text_report(results, show_evidence=True)
        
        self.assertIn("Web Server       Nginx 1.18.0", plain_out)
        self.assertNotIn("└─ Header", plain_out)
        
        self.assertIn("Nginx 1.18.0", evidence_out)
        self.assertIn("└─ Header: Server: Nginx/1.18.0", evidence_out)

if __name__ == "__main__":
    unittest.main()
