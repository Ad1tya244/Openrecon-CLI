import unittest
import importlib
import io
import os
from unittest.mock import patch
from openrecon.config import settings
from openrecon.utils.input_validator import validate_target
from openrecon.modules import MODULE_REGISTRY
from openrecon.cli import (
    build_parser,
    resolve_modules,
    print_unknown_module_error,
    format_modules_help,
    validate_output_path,
    print_unsupported_output_error
)
from openrecon.formatter import export_text_report

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
            "dns", "whois", "ssl", "email", "headers", "security-headers",
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
        self.assertEqual(args.timeout, 60.0)

    def test_module_selection_syntax(self):
        args = self.parser.parse_args(["example.com", "-m", "dns,ssl,tech"])
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.module, "dns,ssl,tech")

    def test_output_file_syntax(self):
        args = self.parser.parse_args(["example.com", "-o", "results.txt"])
        self.assertEqual(args.target, "example.com")
        self.assertEqual(args.output, "results.txt")

    def test_list_modules_argument(self):
        args = self.parser.parse_args(["list-modules"])
        self.assertEqual(args.target, "list-modules")

    def test_default_timeout_is_60_seconds(self):
        """Verify default module timeout is exactly 60.0s."""
        self.assertEqual(settings.MODULE_TIMEOUT, 60.0)
        args = self.parser.parse_args(["example.com"])
        self.assertEqual(args.timeout, 60.0)

    def test_timeout_override(self):
        """Verify --timeout overrides the default correctly."""
        args1 = self.parser.parse_args(["example.com", "-t", "120"])
        self.assertEqual(args1.timeout, 120.0)

        args2 = self.parser.parse_args(["example.com", "--timeout", "15"])
        self.assertEqual(args2.timeout, 15.0)

    def test_help_displays_default_60s_timeout(self):
        """Verify --help displays (default: 60s)."""
        help_output = self.parser.format_help()
        self.assertIn("default: 60s", help_output)

    def test_timeout_help_not_unnecessarily_wrapped(self):
        """Verify that -t, --timeout TIMEOUT description appears on the same line in --help."""
        help_output = self.parser.format_help()
        lines = [line for line in help_output.splitlines() if "--timeout" in line]
        self.assertEqual(len(lines), 1, "Expected single line containing --timeout option")
        self.assertIn("Timeout per module in seconds (default: 60s)", lines[0])

    def test_output_help_on_single_line(self):
        """Verify that -o, --output OUTPUT description appears on the same line in --help."""
        help_output = self.parser.format_help()
        lines = [line for line in help_output.splitlines() if "--output" in line]
        self.assertEqual(len(lines), 1, "Expected single line containing --output option")
        self.assertIn("Save scan results to a text file (.txt only)", lines[0])

    def test_txt_output_accepted(self):
        """Verify .txt output filenames are accepted."""
        is_valid, ext = validate_output_path("report.txt")
        self.assertTrue(is_valid)
        self.assertEqual(ext, ".txt")

        is_valid, ext = validate_output_path("/path/to/scan_results.TXT")
        self.assertTrue(is_valid)

    def test_json_and_non_txt_output_rejected(self):
        """Verify .json and other non-.txt filenames are rejected."""
        is_valid, ext = validate_output_path("results.json")
        self.assertFalse(is_valid)
        self.assertEqual(ext, ".json")

        is_valid, ext = validate_output_path("results.csv")
        self.assertFalse(is_valid)
        self.assertEqual(ext, ".csv")

        is_valid, ext = validate_output_path("results")
        self.assertFalse(is_valid)

        # Test error printing
        with io.StringIO() as buf, patch("sys.stderr", buf):
            print_unsupported_output_error(".json")
            err_output = buf.getvalue()
            self.assertIn("Unsupported output format: .json", err_output)
            self.assertIn("OpenRecon supports only .txt output files.", err_output)

    def test_help_does_not_advertise_json(self):
        """Verify --help only advertises .txt and does not mention .json."""
        help_output = self.parser.format_help()
        self.assertIn("Save scan results to a text file (.txt only)", help_output)
        self.assertNotIn(".json", help_output)

    def test_txt_output_formatting_unchanged(self):
        """Verify text report exporter produces valid formatted output."""
        mock_results = {
            "target": "example.com",
            "modules": {
                "dns": {
                    "module": "DNS",
                    "status": "success",
                    "data": {"A": ["93.184.216.34"]}
                }
            }
        }
        report = export_text_report(mock_results, elapsed_seconds=0.5, module_count=1)
        self.assertIn("OpenRecon", report)
        self.assertIn("example.com", report)
        self.assertIn("93.184.216.34", report)

    def test_help_lists_every_registered_module(self):
        """Verify that every currently registered module identifier appears in --help output."""
        help_output = self.parser.format_help()
        for mod_key in MODULE_REGISTRY.keys():
            self.assertIn(mod_key, help_output, f"Module '{mod_key}' missing from --help output!")

    def test_every_displayed_identifier_accepted(self):
        """Verify that every identifier displayed in help is accepted by resolve_modules()."""
        for mod_key in MODULE_REGISTRY.keys():
            selected, unknown = resolve_modules(mod_key)
            self.assertEqual(unknown, [], f"Module identifier '{mod_key}' rejected by resolve_modules!")
            self.assertEqual(selected, [mod_key])

    def test_multiple_modules_selection(self):
        """Verify comma-separated module selection works cleanly."""
        selected, unknown = resolve_modules("dns,ssl,tech")
        self.assertEqual(selected, ["dns", "ssl", "tech"])
        self.assertEqual(unknown, [])

    def test_invalid_module_produces_unknown_error(self):
        """Verify invalid module names produce unknown error and contain valid registered module names."""
        selected, unknown = resolve_modules("invalid_module_xyz")
        self.assertEqual(unknown, ["invalid_module_xyz"])
        
        # Test error printing
        with io.StringIO() as buf, patch("sys.stderr", buf):
            print_unknown_module_error(unknown)
            err_output = buf.getvalue()
            self.assertIn("invalid_module_xyz", err_output)
            for mod_key in MODULE_REGISTRY.keys():
                self.assertIn(mod_key, err_output)

    def test_no_unregistered_modules_in_help(self):
        """Verify that help output does not contain invented module names."""
        help_str = format_modules_help()
        module_lines = [l for l in help_str.splitlines() if l.startswith("  ")]
        displayed_keys = [l.strip().split()[0] for l in module_lines]
        self.assertEqual(set(displayed_keys), set(MODULE_REGISTRY.keys()))

if __name__ == "__main__":
    unittest.main()
