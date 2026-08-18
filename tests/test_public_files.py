import unittest
from unittest.mock import patch, AsyncMock
import asyncio
from openrecon.modules.public_files import check_public_files
from openrecon.formatter import render_public_files

class TestPublicFilesRecon(unittest.TestCase):
    def test_only_200_ok_files_returned(self):
        async def mock_get(url):
            if "robots.txt" in url:
                return {"status_code": 200, "content_text": "User-agent: *\nDisallow: /admin"}
            elif "security.txt" in url:
                return {"status_code": 200, "content_text": "Contact: mailto:security@example.com"}
            elif "sitemap.xml" in url:
                return {"status_code": 404}
            return {"error": "Connection error"}

        with patch("openrecon.modules.public_files.safe_get", side_effect=mock_get):
            res = asyncio.run(check_public_files("example.com"))
            self.assertIn("robots.txt", res["found"])
            self.assertIn("security.txt", res["found"])
            self.assertNotIn("sitemap.xml", res["found"])

    def test_render_public_files_output(self):
        data = {
            "found": ["robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt"]
        }
        render_public_files(data)

if __name__ == "__main__":
    unittest.main()
