import unittest
from unittest.mock import patch, MagicMock
from openrecon.modules.tech_fingerprint import identify_technologies
from openrecon.modules.page_intel import analyze_javascript_requests

class TestFailureInjectionFallbacks(unittest.TestCase):

    def test_fallback_on_node_failure(self):
        # 1. Simulate Node/Technology engine runner failure (raising exception in subprocess.run)
        headers = {"server": "Apache/2.4.58"}
        html = "<html><body><meta name='generator' content='WordPress 6.2'></body></html>"
        url = "https://example.com/"

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Node.js not available")
            
            # Verify OpenRecon automatically falls back and still returns detections
            detections = identify_technologies(headers, html, url=url)
            
            # Verify useful technology detections are still returned via Python fallback
            names = [d["name"] for d in detections.get("technologies", [])]
            self.assertIn("WordPress", names)
            self.assertIn("Apache HTTP Server", names)

    def test_fallback_does_not_overwrite_primary(self):
        # 2. Verify fallback results do not overwrite higher-confidence primary results.
        headers = {"server": "Apache/2.4.58"}
        html = "<html><body></body></html>"
        url = "https://example.com/"

        # Mock primary engine output to return a specific version
        primary_mock_output = [
            {"name": "Apache HTTP Server", "version": "2.4.58-primary", "categories": [{"name": "Web Server"}]}
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=json_dumps_helper(primary_mock_output))
            
            detections = identify_technologies(headers, html, url=url)
            techs = detections.get("technologies", [])
            names = [d["name"] for d in techs]
            self.assertIn("Apache HTTP Server", names)
            
            apache_tech = next((d for d in techs if d["name"] == "Apache HTTP Server"), None)
            self.assertIsNotNone(apache_tech)
            # Verify it kept the higher-confidence/specific version from the primary engine
            self.assertEqual(apache_tech["version"], "2.4.58-primary")

    def test_jsluice_fallback_on_ast_failure(self):
        # 3. Simulate AST parsing failure/malformed JavaScript.
        js_code = "fetch('/api/v1/users'); malformed ### syntax --- error";
        
        with patch("openrecon.modules.page_intel.extract_endpoints_via_node_ast") as mock_ast:
            # Mock AST parser returning empty list (representing failure/empty results)
            mock_ast.return_value = []
            
            # Verify the lexical endpoint extractor still discovers valid endpoints
            apis, _, _, _, _ = analyze_javascript_requests(js_code, "example.com")
            endpoints = [ep["url"] for ep in apis]
            self.assertIn("/api/v1/users", endpoints)

    def test_jsluice_fallback_deduplication(self):
        # 4. Verify results are deduplicated against AST results.
        js_code = "fetch('/api/v1/users');"
        
        # AST returns the exact same endpoint
        ast_mock_output = [{"method": "GET", "url": "/api/v1/users"}]
        
        with patch("openrecon.modules.page_intel.extract_endpoints_via_node_ast") as mock_ast:
            mock_ast.return_value = ast_mock_output
            
            apis, _, _, _, _ = analyze_javascript_requests(js_code, "example.com")
            # Verify no duplicate entries for the same endpoint
            endpoints = [ep["url"] for ep in apis]
            self.assertEqual(endpoints.count("/api/v1/users"), 1)

    def test_jsluice_fallback_filters_third_party_and_static(self):
        # 5. Verify third-party/static-resource URLs remain filtered.
        js_code = """
        fetch("https://thirdparty.com/api/v1/users");
        fetch("/api/v1/document.pdf");
        """
        
        with patch("openrecon.modules.page_intel.extract_endpoints_via_node_ast") as mock_ast:
            mock_ast.return_value = [] # AST fails or returns nothing
            
            apis, _, _, _, _ = analyze_javascript_requests(js_code, "example.com")
            endpoints = [ep["url"] for ep in apis]
            # Verify filters still applied on fallback detections
            self.assertNotIn("https://thirdparty.com/api/v1/users", endpoints)
            self.assertNotIn("/api/v1/document.pdf", endpoints)

    def test_normal_operation_no_unnecessary_fallback_clash(self):
        # 6. Verify no duplicate output occurs when both engines discover the same evidence under normal operation.
        js_code = "fetch('/api/v1/users');"
        
        apis, _, _, _, _ = analyze_javascript_requests(js_code, "example.com")
        endpoints = [ep["url"] for ep in apis]
        self.assertEqual(endpoints.count("/api/v1/users"), 1)

def json_dumps_helper(obj):
    import json
    return json.dumps(obj)

if __name__ == "__main__":
    unittest.main()
