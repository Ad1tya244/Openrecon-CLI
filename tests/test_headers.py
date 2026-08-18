import unittest
from unittest.mock import patch, AsyncMock
import asyncio
from openrecon.modules.headers_recon import analyze_headers
from openrecon.formatter import render_headers

class TestHeadersRecon(unittest.TestCase):
    def test_headers_extraction(self):
        mock_response = {
            "status_code": 200,
            "url": "https://example.com/",
            "redirects": 0,
            "http_version": "HTTP/2",
            "cookies_count": 2,
            "headers": {
                "server": "nginx/1.18.0",
                "content-type": "text/html; charset=utf-8",
                "content-length": "12580",
                "date": "Tue, 18 Aug 2026 07:00:00 GMT",
                "last-modified": "Mon, 17 Aug 2026 12:00:00 GMT",
                "etag": '"654321-abcd"',
                "set-cookie": "session=xyz; path=/"
            }
        }

        with patch("openrecon.modules.headers_recon.safe_get", new_callable=AsyncMock, return_value=mock_response):
            res = asyncio.run(analyze_headers("example.com"))
            
            self.assertEqual(res["status_code"], 200)
            self.assertEqual(res["server"], "nginx/1.18.0")
            self.assertEqual(res["content_type"], "text/html; charset=utf-8")
            self.assertEqual(res["content_length"], "12580 bytes")
            self.assertEqual(res["http_version"], "HTTP/2")
            self.assertEqual(res["redirects"], 0)
            self.assertEqual(res["cookies"], "2 set")
            self.assertEqual(res["date"], "Tue, 18 Aug 2026 07:00:00 GMT")
            self.assertEqual(res["last_modified"], "Mon, 17 Aug 2026 12:00:00 GMT")
            self.assertEqual(res["etag"], '"654321-abcd"')

    def test_unknown_http_version_not_guessed(self):
        mock_response = {
            "status_code": 200,
            "url": "https://example.com/",
            "redirects": 0,
            "http_version": None,
            "cookies_count": 0,
            "headers": {
                "server": "Apache"
            }
        }

        with patch("openrecon.modules.headers_recon.safe_get", new_callable=AsyncMock, return_value=mock_response):
            res = asyncio.run(analyze_headers("example.com"))
            self.assertIsNone(res["http_version"])
            self.assertIsNone(res["content_length"])

    def test_render_headers_output(self):
        data = {
            "url": "https://example.com",
            "status_code": 200,
            "server": "nginx/1.18.0",
            "content_type": "text/html",
            "content_length": "12580 bytes",
            "http_version": "HTTP/1.1",
            "redirects": 0,
            "final_url": "https://example.com/",
            "cookies": "2 set",
            "date": "Tue, 18 Aug 2026 07:00:00 GMT"
        }
        render_headers(data)

if __name__ == "__main__":
    unittest.main()
