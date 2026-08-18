import unittest
from openrecon.modules.tech_fingerprint import (
    identify_technologies,
    extract_meta_tags,
    extract_asset_urls,
    standardize_category
)
from openrecon.formatter import render_tech

class TestTechFingerprintEvidenceBased(unittest.TestCase):
    def test_header_evidence_matching(self):
        headers = {
            "server": "nginx/1.18.0",
            "x-powered-by": "PHP/8.1.2"
        }
        res = identify_technologies(headers=headers, html="")
        tech_names = [t["name"].lower() for t in res["technologies"]]
        
        self.assertIn("nginx", tech_names)
        self.assertIn("php", tech_names)

        nginx_tech = next(t for t in res["technologies"] if t["name"].lower() == "nginx")
        self.assertEqual(nginx_tech["version"], "1.18.0")
        self.assertEqual(nginx_tech["category"], "Web Server")

        php_tech = next(t for t in res["technologies"] if t["name"].lower() == "php")
        self.assertEqual(php_tech["version"], "8.1.2")
        self.assertEqual(php_tech["category"], "Backend")

    def test_meta_and_script_evidence_matching(self):
        html = """
        <html>
        <head>
            <meta name="generator" content="WordPress 6.2.2" />
            <script src="/wp-content/themes/theme/main.js"></script>
            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        </head>
        <body>
        </body>
        </html>
        """
        res = identify_technologies(headers={}, html=html)
        tech_names = [t["name"].lower() for t in res["technologies"]]
        
        self.assertIn("wordpress", tech_names)
        self.assertIn("jquery", tech_names)

        wp_tech = next(t for t in res["technologies"] if t["name"].lower() == "wordpress")
        self.assertEqual(wp_tech["version"], "6.2.2")
        self.assertEqual(wp_tech["category"], "CMS")

    def test_category_standardization(self):
        self.assertEqual(standardize_category("web servers"), "Web Server")
        self.assertEqual(standardize_category("programming languages"), "Backend")
        self.assertEqual(standardize_category("ui frameworks"), "Frontend")
        self.assertEqual(standardize_category("cms"), "CMS")
        self.assertEqual(standardize_category("web frameworks"), "Framework")
        self.assertEqual(standardize_category("paas"), "Runtime")
        self.assertEqual(standardize_category("analytics"), "Analytics")
        self.assertEqual(standardize_category("javascript libraries"), "JavaScript Libraries")
        self.assertEqual(standardize_category("cdn"), "CDN / Proxy")

    def test_render_tech_output(self):
        data = {
            "categories": {
                "Web Server": [{"name": "Nginx", "version": "1.18.0"}],
                "Backend": [{"name": "PHP", "version": "8.1"}],
                "CMS": [{"name": "WordPress", "version": "6.2"}],
                "JavaScript Libraries": [{"name": "jQuery", "version": "3.6.0"}]
            }
        }
        render_tech(data)

if __name__ == "__main__":
    unittest.main()
