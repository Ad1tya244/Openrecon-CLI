import unittest
from unittest.mock import patch, AsyncMock
import asyncio
from openrecon.modules.port_recon import parse_service_version, scan_ports
from openrecon.formatter import render_ports

class TestPortRecon(unittest.TestCase):
    def test_banner_version_parsing(self):
        self.assertEqual(parse_service_version("SSH", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"), "OpenSSH 9.2p1")
        self.assertEqual(parse_service_version("FTP", "220 (vsFTPd 3.0.3)"), "vsFTPd 3.0.3")
        self.assertEqual(parse_service_version("SMTP", "220 mail.example.com ESMTP Postfix"), "Postfix")
        self.assertIsNone(parse_service_version("HTTP", ""))
        self.assertIsNone(parse_service_version("HTTPS", None))

    def test_no_banner_means_no_version_guessed(self):
        self.assertIsNone(parse_service_version("FTP", None))
        self.assertIsNone(parse_service_version("FTP", ""))
        self.assertIsNone(parse_service_version("SSH", None))
        self.assertIsNone(parse_service_version("SMTP", None))
        self.assertIsNone(parse_service_version("MySQL", None))

    def test_scan_ports_mock(self):
        mock_open = [
            {"port": 21, "service": "FTP", "version": None, "banner": None},
            {"port": 22, "service": "SSH", "version": "OpenSSH 9.2p1", "banner": "SSH-2.0-OpenSSH_9.2p1"},
            {"port": 80, "service": "HTTP", "version": None, "banner": None},
            {"port": 443, "service": "HTTPS", "version": None, "banner": None}
        ]
        with patch("openrecon.modules.port_recon.check_port_with_banner", side_effect=lambda domain, port: next((p for p in mock_open if p["port"] == port), None)):
            res = asyncio.run(scan_ports("example.com"))
            self.assertEqual(len(res["open_ports"]), 4)
            self.assertEqual(res["open_ports"][0]["service"], "FTP")
            self.assertIsNone(res["open_ports"][0]["version"])
            self.assertEqual(res["open_ports"][1]["service"], "SSH")
            self.assertEqual(res["open_ports"][1]["version"], "OpenSSH 9.2p1")

    def test_render_ports_output(self):
        data = {
            "open_ports": [
                {"port": 21, "service": "FTP", "version": None},
                {"port": 22, "service": "SSH", "version": "OpenSSH 9.2p1"},
                {"port": 80, "service": "HTTP", "version": None},
                {"port": 443, "service": "HTTPS", "version": None}
            ]
        }
        render_ports(data)

if __name__ == "__main__":
    unittest.main()
