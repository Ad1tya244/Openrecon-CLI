import unittest
from unittest.mock import patch, AsyncMock
import io
import asyncio
from openrecon.modules.directory_exposure import (
    is_directory_listing,
    extract_directories_from_url,
    check_directory_exposure
)
from openrecon.formatter import render_directories, console
from rich.console import Console

class TestDirectoryExposure(unittest.TestCase):
    def test_signature_detection_apache_and_nginx(self):
        apache_html = "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><hr><pre><a href=\"../\">../</a></pre></body></html>"
        nginx_html = "<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1><hr><pre><a href=\"../\">../</a></pre></body></html>"
        python_simple_http = "<html><head><title>Directory listing for /</title></head><body><h2>Directory listing for /</h2><hr><ul><li><a href=\"file.txt\">file.txt</a></li></ul></body></html>"
        iis_html = "<html><body><h2>Directory Listing -- /backup/</h2><hr><pre><A HREF=\"/parent\">[To Parent Directory]</A></pre></body></html>"

        self.assertTrue(is_directory_listing(apache_html))
        self.assertTrue(is_directory_listing(nginx_html))
        self.assertTrue(is_directory_listing(python_simple_http))
        self.assertTrue(is_directory_listing(iis_html))

    def test_non_exposed_pages_rejected(self):
        normal_200_html = "<html><head><title>Welcome to Careers</title></head><body><h1>Careers at Company</h1><p>Check out our open roles!</p></body></html>"
        error_403_html = "<html><head><title>403 Forbidden</title></head><body><h1>Access Denied</h1></body></html>"
        error_401_html = "<html><head><title>401 Unauthorized</title></head><body><h1>Authorization Required</h1></body></html>"
        error_404_html = "<html><head><title>404 Not Found</title></head><body><h1>Page Not Found</h1></body></html>"

        self.assertFalse(is_directory_listing(normal_200_html))
        self.assertFalse(is_directory_listing(error_403_html))
        self.assertFalse(is_directory_listing(error_401_html))
        self.assertFalse(is_directory_listing(error_404_html))
        self.assertFalse(is_directory_listing(""))
        self.assertFalse(is_directory_listing(None))

    def test_extract_directories_from_url(self):
        dirs1 = extract_directories_from_url("https://example.com/assets/css/style.css", "example.com")
        self.assertIn("/assets/", dirs1)
        self.assertIn("/assets/css/", dirs1)

        dirs2 = extract_directories_from_url("/uploads/2026/01/image.png", "example.com")
        self.assertIn("/uploads/", dirs2)
        self.assertIn("/uploads/2026/", dirs2)

        # Off-target domain must be ignored
        dirs_external = extract_directories_from_url("https://evil.com/assets/lib.js", "example.com")
        self.assertEqual(dirs_external, [])

    def test_exposure_filtering_only_retains_confirmed_listings(self):
        # Setup mock:
        # /uploads/ -> 200 with Apache index (EXPOSED)
        # /careers/ -> 200 normal page (NOT EXPOSED)
        # /admin/   -> 403 (NOT EXPOSED)
        # /secret/  -> 401 (NOT EXPOSED)
        # /missing/ -> 404 (NOT EXPOSED)

        async def mock_safe_head(url):
            if "/uploads/" in url:
                return {"status_code": 200}
            elif "/careers/" in url:
                return {"status_code": 200}
            elif "/admin/" in url:
                return {"status_code": 403}
            elif "/secret/" in url:
                return {"status_code": 401}
            return {"status_code": 404}

        async def mock_safe_get(url):
            if "/uploads/" in url:
                return {
                    "status_code": 200,
                    "content_text": "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1><a href='../'>../</a></body></html>"
                }
            elif "/careers/" in url:
                return {
                    "status_code": 200,
                    "content_text": "<html><head><title>Careers</title></head><body><h1>Open Jobs</h1></body></html>"
                }
            elif "/robots.txt" in url:
                return {
                    "status_code": 200,
                    "content_text": "Disallow: /uploads/\nDisallow: /careers/\nDisallow: /admin/\nDisallow: /secret/\nDisallow: /missing/"
                }
            return {"status_code": 404, "content_text": "Not found"}

        with patch("openrecon.modules.directory_exposure.safe_head", side_effect=mock_safe_head), \
             patch("openrecon.modules.directory_exposure.safe_get", side_effect=mock_safe_get):
            
            res = asyncio.run(check_directory_exposure("example.com"))
            
            findings = res["findings"]
            # Only /uploads/ should be in findings!
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["path"], "/uploads/")
            self.assertEqual(findings[0]["status"], "200 EXPOSED")
            self.assertTrue(findings[0]["is_exposed"])

    def test_zero_findings_exact_output(self):
        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)

        with patch("openrecon.formatter.console", test_console):
            render_directories({"findings": [], "total": 0})
            
        output = buf.getvalue()
        self.assertIn("[+] Directory Exposure", output)
        self.assertIn("No exposed directories found.", output)
        self.assertNotIn("200 OK", output)
        self.assertNotIn("403 Forbidden", output)

    def test_confirmed_findings_output(self):
        buf = io.StringIO()
        test_console = Console(file=buf, force_terminal=False, no_color=True, highlight=False)

        data = {
            "findings": [
                {"path": "/backup/", "status": "200 EXPOSED", "is_exposed": True},
                {"path": "/uploads/", "status": "200 EXPOSED", "is_exposed": True}
            ],
            "total": 2
        }

        with patch("openrecon.formatter.console", test_console):
            render_directories(data)
            
        output = buf.getvalue()
        self.assertIn("[+] Directory Exposure", output)
        self.assertIn("/backup/", output)
        self.assertIn("/uploads/", output)
        self.assertIn("200 EXPOSED", output)
        self.assertNotIn("No exposed directories found.", output)
        self.assertNotIn("200 OK", output)

if __name__ == "__main__":
    unittest.main()
