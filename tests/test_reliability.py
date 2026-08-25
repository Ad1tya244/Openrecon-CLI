import asyncio
import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import httpx
from openrecon.utils.safe_http import safe_get, FAILED_HTTP_HOSTS
from openrecon.modules.public_files import check_public_files

class TestNetworkReliability(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        # Reset the cached failed hosts before each test
        FAILED_HTTP_HOSTS.clear()

    @patch("openrecon.utils.safe_http._resolve_and_validate")
    @patch("httpx.AsyncClient.send")
    async def test_connect_timeout_retry(self, mock_send, mock_resolve):
        mock_resolve.return_value = "1.1.1.1"

        # Simulate ConnectTimeout on first attempt, success on second
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.headers = httpx.Headers({})
        mock_response.cookies = httpx.Cookies()
        mock_response.http_version = "HTTP/1.1"
        mock_response.is_redirect = False
        mock_response.aclose = AsyncMock()

        # Set up aiter_bytes for stream check
        async def mock_aiter_bytes():
            yield b"content"
        mock_response.aiter_bytes = mock_aiter_bytes

        req = httpx.Request("GET", "https://example.com/test-timeout")
        mock_send.side_effect = [
            httpx.ConnectTimeout("Connection timed out", request=req),
            mock_response
        ]

        # Temporarily speed up the delay for test speed
        with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
            res = await safe_get("https://example.com/test-timeout")
            self.assertEqual(res.get("status_code"), 200)
            self.assertEqual(mock_send.call_count, 2)
            mock_sleep.assert_called_once()

    @patch("openrecon.utils.safe_http._resolve_and_validate")
    @patch("httpx.AsyncClient.send")
    async def test_waf_403_classification(self, mock_send, mock_resolve):
        mock_resolve.return_value = "1.1.1.1"

        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 403
        mock_response.headers = httpx.Headers({"server": "awselb/2.0"})
        mock_response.cookies = httpx.Cookies()
        mock_response.is_redirect = False
        mock_response.aclose = AsyncMock()

        mock_send.return_value = mock_response

        res = await safe_get("https://example.com/blocked")
        self.assertIn("error", res)
        self.assertEqual(res.get("error_type"), "INACCESSIBLE")
        self.assertEqual(res.get("status_code"), 403)

    @patch("openrecon.utils.safe_http._resolve_and_validate")
    @patch("httpx.AsyncClient.send")
    async def test_http_fallback_caching(self, mock_send, mock_resolve):
        mock_resolve.return_value = "1.1.1.1"

        req = httpx.Request("GET", "http://offline-target.com/file")
        mock_send.side_effect = httpx.ConnectError("Connection refused", request=req)

        # First request to HTTP scheme (simulating fallback)
        res1 = await safe_get("http://offline-target.com/file")
        self.assertIn("error", res1)
        self.assertEqual(res1.get("error_type"), "CONNECTION_FAILURE")
        self.assertIn("offline-target.com", FAILED_HTTP_HOSTS)

        # Reset mock send call count
        mock_send.reset_mock()

        # Second request to HTTP scheme on same host should be cached
        res2 = await safe_get("http://offline-target.com/another-file")
        self.assertIn("error", res2)
        self.assertEqual(res2.get("error_type"), "CACHED_HTTP_FAILURE")
        mock_send.assert_not_called()

    @patch("openrecon.modules.public_files.safe_get")
    async def test_concurrent_public_files_execution(self, mock_safe_get):
        # Mock safe_get to return 200 OK
        mock_safe_get.return_value = {"status_code": 200}

        # Run check_public_files which should query all allowlisted files
        res = await check_public_files("example.com")
        self.assertEqual(len(res["found"]), 6)
        self.assertEqual(mock_safe_get.call_count, 6)

if __name__ == "__main__":
    unittest.main()
