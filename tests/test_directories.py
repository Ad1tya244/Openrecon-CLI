import unittest
import asyncio
from unittest.mock import patch
from openrecon.modules.directory_exposure import (
    is_directory_listing,
    extract_directories_from_url,
    _discover_target_directories,
    check_directory_exposure
)

class TestDirectoryExposurePurePassive(unittest.TestCase):
    def test_no_wordlist_in_module(self):
        # Verify that wordlists, dictionaries, and wordlist loaders are removed
        import openrecon.modules.directory_exposure as dir_mod
        self.assertFalse(hasattr(dir_mod, "DEFAULT_DIRECTORY_WORDLIST"))
        self.assertFalse(hasattr(dir_mod, "load_directory_wordlist"))
        self.assertFalse(hasattr(dir_mod, "OPENRECON_DIR_WORDLIST"))

    def test_path_extraction_from_file_urls_and_normalization(self):
        domain = "target.com"
        
        # Files produce their containing parent directory
        self.assertEqual(extract_directories_from_url("https://target.com/css/main.css", domain), ["/css/"])
        self.assertEqual(extract_directories_from_url("https://target.com/js/app.js", domain), ["/js/"])
        self.assertEqual(extract_directories_from_url("https://target.com/uploads/report.pdf", domain), ["/uploads/"])
        self.assertEqual(extract_directories_from_url("https://target.com/admin/login", domain), ["/admin/"])
        self.assertEqual(extract_directories_from_url("/assets/", domain), ["/assets/"])
        
        # Query strings, hashes, encodings
        self.assertEqual(extract_directories_from_url("/images/logo.png?v=123#top", domain), ["/images/"])
        self.assertEqual(extract_directories_from_url("/my%20files/doc.pdf", domain), ["/my files/"])
        
        # Deeply nested directories
        self.assertEqual(
            extract_directories_from_url("/assets/vendor/js/bundle.min.js", domain),
            ["/assets/", "/assets/vendor/", "/assets/vendor/js/"]
        )

        # Root files do not produce directory candidates
        self.assertEqual(extract_directories_from_url("/index.html", domain), [])
        self.assertEqual(extract_directories_from_url("/robots.txt", domain), [])
        self.assertEqual(extract_directories_from_url("/", domain), [])

        # Unrelated domains are strictly rejected
        self.assertEqual(extract_directories_from_url("https://evil.com/admin/login", domain), [])
        self.assertEqual(extract_directories_from_url("https://attacker.org/css/style.css", domain), [])

    def test_directory_listing_signature_detection(self):
        apache_html = "<html><head><title>Index of /uploads</title></head><body><h1>Index of /uploads</h1></body></html>"
        nginx_html = "<html><head><title>Index of /static/</title></head><body><hr><pre><a href='../'>../</a><br></pre></body></html>"
        python_html = "<html><head><title>Directory listing for /files/</title></head><body><h2>Directory listing for /files/</h2></body></html>"
        iis_html = "<html><body><pre>[To Parent Directory]</pre></body></html>"
        normal_html = "<html><head><title>Welcome to Target</title></head><body><h1>Home Page</h1><p>Articles and parent directory information.</p></body></html>"

        self.assertTrue(is_directory_listing(apache_html))
        self.assertTrue(is_directory_listing(nginx_html))
        self.assertTrue(is_directory_listing(python_html))
        self.assertTrue(is_directory_listing(iis_html))
        self.assertFalse(is_directory_listing(normal_html))
        self.assertFalse(is_directory_listing(""))
        self.assertFalse(is_directory_listing(None))


class TestDirectoryScannerAsync(unittest.IsolatedAsyncioTestCase):
    async def test_evidence_extraction_and_active_verification(self):
        domain = "target.com"
        
        # Target HTML with various URL-bearing tags
        homepage_html = """
        <html>
        <head>
            <link rel="stylesheet" href="/css/main.css">
            <script src="/js/app.js"></script>
        </head>
        <body>
            <a href="/admin/login">Admin</a>
            <img src="/images/logo.png?v=2">
            <source src="/media/intro.mp4">
            <a href="https://target.com/docs/guide.pdf">Docs</a>
            <a href="https://external.com/out-of-scope/file.js">External</a>
        </body>
        </html>
        """
        
        robots_txt = """
        User-agent: *
        Disallow: /restricted-area/
        Allow: /public-assets/style.css
        """
        
        sitemap_xml = """
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://target.com/downloads/setup.exe</loc></url>
        </urlset>
        """

        mock_head_responses = {
            "https://target.com/css/": {"status_code": 403},
            "https://target.com/js/": {"status_code": 404},
            "https://target.com/admin/": {"status_code": 401},
            "https://target.com/images/": {"status_code": 200},
            "https://target.com/media/": {"status_code": 200},
            "https://target.com/docs/": {"status_code": 200},
            "https://target.com/restricted-area/": {"status_code": 403},
            "https://target.com/public-assets/": {"status_code": 404},
            "https://target.com/downloads/": {"status_code": 404},
            "https://target.com/uploads/": {"status_code": 200}
        }

        mock_get_responses = {
            "https://target.com/": {
                "status_code": 200,
                "content_text": homepage_html,
                "url": "https://target.com/"
            },
            "https://target.com/robots.txt": {
                "status_code": 200,
                "content_text": robots_txt,
                "url": "https://target.com/robots.txt"
            },
            "https://target.com/sitemap.xml": {
                "status_code": 200,
                "content_text": sitemap_xml,
                "url": "https://target.com/sitemap.xml"
            },
            "https://target.com/images/": {
                "status_code": 200,
                "content_text": "<html><head><title>Welcome</title></head><body>Normal non-listing page</body></html>",
                "url": "https://target.com/images/"
            },
            "https://target.com/media/": {
                "status_code": 200,
                "content_text": "<html><head><title>Index of /media</title></head><body><h1>Index of /media</h1><a href='../'>Parent Directory</a></body></html>",
                "url": "https://target.com/media/"
            },
            "https://target.com/docs/": {
                "status_code": 200,
                "content_text": "<html><head><title>Index of /docs</title></head><body><h1>Index of /docs</h1></body></html>",
                "url": "https://target.com/docs/"
            },
            "https://target.com/uploads/": {
                "status_code": 200,
                "content_text": "<html><head><title>Directory listing for /uploads/</title></head><body><h2>Directory listing for /uploads/</h2></body></html>",
                "url": "https://target.com/uploads/"
            }
        }

        async def mock_safe_head(url, headers=None):
            return mock_head_responses.get(url, {"status_code": 404})

        async def mock_safe_get(url, headers=None):
            return mock_get_responses.get(url, {"status_code": 404, "content_text": ""})

        with patch("openrecon.modules.directory_exposure.safe_head", side_effect=mock_safe_head), \
             patch("openrecon.modules.directory_exposure.safe_get", side_effect=mock_safe_get):
            result = await check_directory_exposure(
                domain,
                discovered_urls=["https://target.com/uploads/test.pdf"]
            )

        exposed_dirs = result["exposed_directories"]
        findings = result["findings"]
        finding_paths = [f["path"] for f in findings]

        # 404s (/js/, /public-assets/, /downloads/) must be silently discarded
        self.assertNotIn("/js/", finding_paths)
        self.assertNotIn("/public-assets/", finding_paths)
        self.assertNotIn("/downloads/", finding_paths)

        # 403s and 401s (/css/, /admin/, /restricted-area/) must be silently discarded (not reported as exposed)
        self.assertNotIn("/css/", finding_paths)
        self.assertNotIn("/admin/", finding_paths)
        self.assertNotIn("/restricted-area/", finding_paths)

        # Normal 200 OK page (/images/) must NOT be reported as exposed directory
        self.assertNotIn("/images/", finding_paths)

        # Out-of-scope external paths must never be probed
        self.assertNotIn("/out-of-scope/", finding_paths)

        # Only confirmed directory listings must be reported
        self.assertIn("/media/", exposed_dirs)
        self.assertIn("/docs/", exposed_dirs)
        self.assertIn("/uploads/", exposed_dirs)

        # Total count must match exposed findings length exactly
        self.assertEqual(result["total"], 3)
        self.assertEqual(len(findings), 3)

if __name__ == "__main__":
    unittest.main()
