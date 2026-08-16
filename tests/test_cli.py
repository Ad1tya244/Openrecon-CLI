import unittest
import importlib
from openrecon.utils.input_validator import validate_target
from openrecon.modules import MODULE_REGISTRY
from openrecon.cli import build_parser

class TestOpenReconValidator(unittest.TestCase):
    def test_valid_domain(self):
        res = validate_target("example.com")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.input_type, "domain")
        self.assertEqual(res.normalized_input, "example.com")

    def test_valid_subdomain(self):
        res = validate_target("api.sub.example.com")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.input_type, "domain")

    def test_valid_ipv4(self):
        res = validate_target("8.8.8.8")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.input_type, "ipv4")
        self.assertEqual(res.normalized_input, "8.8.8.8")

    def test_private_ipv4_rejected(self):
        for ip in ["127.0.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1"]:
            res = validate_target(ip)
            self.assertFalse(res.is_valid)
            self.assertIn("Restricted or private IP", res.error_message)

    def test_url_rejected(self):
        res = validate_target("https://example.com/test")
        self.assertFalse(res.is_valid)
        self.assertIn("URLs are not accepted", res.error_message)

    def test_wildcard_rejected(self):
        res = validate_target("*.example.com")
        self.assertFalse(res.is_valid)
        self.assertIn("Wildcards are not accepted", res.error_message)

    def test_localhost_rejected(self):
        res = validate_target("localhost")
        self.assertFalse(res.is_valid)

class TestModuleRegistry(unittest.TestCase):
    def test_all_modules_importable(self):
        expected_modules = [
            "dns", "whois", "ssl", "headers", "security-headers",
            "subdomains", "tech", "ports", "ip",
            "public-files", "directories"
        ]
        for key in expected_modules:
            self.assertIn(key, MODULE_REGISTRY)
            meta = MODULE_REGISTRY[key]
            mod = importlib.import_module(meta["module"])
            func = getattr(mod, meta["func"])
            self.assertTrue(callable(func))

class TestCLIParser(unittest.TestCase):
    def setUp(self):
        self.parser = build_parser()

    def test_scan_syntax(self):
        args = self.parser.parse_args(["example.com"])
        self.assertEqual(args.target, "example.com")
        self.assertIsNone(args.module)
        self.assertIsNone(args.output)

    def test_module_selection_syntax(self):
        args = self.parser.parse_args(["example.com", "-m", "dns,ssl,tech"])
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.module, "dns,ssl,tech")

    def test_output_file_syntax(self):
        args = self.parser.parse_args(["example.com", "-o", "results.json"])
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.output, "results.json")

    def test_list_modules_argument(self):
        args = self.parser.parse_args(["list-modules"])
        self.assertEqual(args.target, "list-modules")

    def test_timeout_argument(self):
        args = self.parser.parse_args(["example.com", "-t", "45"])
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.timeout, 45.0)

if __name__ == "__main__":
    unittest.main()
