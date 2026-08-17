import unittest
import tempfile
import os
import hashlib
import httpx
from unittest.mock import patch, MagicMock
from openrecon import __version__
from openrecon.updater import (
    OFFICIAL_REPO,
    parse_semver,
    is_newer_version,
    validate_repo,
    validate_download_url,
    compute_sha256,
    extract_sha256_checksum,
    is_source_checkout,
    fetch_latest_release_info,
    fetch_latest_version,
    download_and_verify_artifact,
    install_update,
    verify_installed_version,
    run_opt_in_update_check
)
from openrecon.cli import build_parser, main

class TestOptInUpdaterReleaseWorkflow(unittest.TestCase):
    def test_version_comparison_and_malformed(self):
        """Test semantic version parsing and comparison resilience."""
        self.assertEqual(parse_semver("1.4.0"), (1, 4, 0))
        self.assertEqual(parse_semver("v1.4.5"), (1, 4, 5))
        self.assertEqual(parse_semver("V2.0.0-beta"), (2, 0, 0))
        self.assertEqual(parse_semver("3.1"), (3, 1, 0))
        self.assertIsNone(parse_semver("invalid_version"))
        self.assertIsNone(parse_semver(""))
        self.assertIsNone(parse_semver(None))

    def test_no_update_available_output(self):
        """Test when current version equals latest version (already up to date)."""
        mock_release = {"tag_name": f"v{__version__}", "body": ""}
        with patch("openrecon.updater.fetch_latest_release_info", return_value=(mock_release, None)):
            res = run_opt_in_update_check()
            self.assertIsNone(res)

    def test_no_releases_or_tags_treated_as_up_to_date(self):
        """Test when repo exists but has no releases or tags yet, treated as up to date."""
        mock_resp_release = MagicMock(status_code=404)
        mock_resp_tags = MagicMock(status_code=200, json=lambda: [])

        with patch("httpx.Client.get", side_effect=[mock_resp_release, mock_resp_tags]):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertIsNone(err)

    def test_official_repository_validation(self):
        """Test that only the official repository is accepted."""
        self.assertTrue(validate_repo("Ad1tya244/Openrecon-CLI"))
        self.assertTrue(validate_repo("ad1tya244/openrecon-cli"))
        self.assertFalse(validate_repo("attacker/Openrecon-CLI"))
        self.assertFalse(validate_repo("malicious-repo"))
        self.assertFalse(validate_repo(""))

        data, err = fetch_latest_release_info(repo="attacker/repo")
        self.assertIsNone(data)
        self.assertIn("Invalid or untrusted repository", err)

    def test_valid_published_release_detection(self):
        """Test fetching a valid published GitHub Release from /releases/latest first."""
        mock_resp = MagicMock(status_code=200, json=lambda: {"tag_name": "v2.0.0", "body": "Notes"})
        with patch("httpx.Client.get", return_value=mock_resp):
            data, err = fetch_latest_release_info()
            self.assertIsNone(err)
            self.assertIsNotNone(data)
            self.assertEqual(data["tag_name"], "v2.0.0")

    def test_fallback_to_tags_selects_highest_semver(self):
        """Test fallback to /tags when no Release exists, selecting the highest valid SemVer tag."""
        mock_resp_release = MagicMock(status_code=404)
        mock_resp_tags = MagicMock(
            status_code=200,
            json=lambda: [
                {"name": "v1.0.0"},
                {"name": "v1.5.4"},
                {"name": "v1.2.0"},
                {"name": "unstable-build"},
                {"name": "v0.9.9"}
            ]
        )

        with patch("httpx.Client.get", side_effect=[mock_resp_release, mock_resp_tags]):
            data, err = fetch_latest_release_info()
            self.assertIsNone(err)
            self.assertIsNotNone(data)
            self.assertEqual(data["tag_name"], "v1.5.4")

    def test_fallback_to_tags_no_valid_semver_tags_treated_as_up_to_date(self):
        """Test that tags without valid semver are ignored and treated cleanly as up to date."""
        mock_resp_release = MagicMock(status_code=404)
        mock_resp_tags = MagicMock(status_code=200, json=lambda: [{"name": "nightly-123"}, {"name": "experimental"}])

        with patch("httpx.Client.get", side_effect=[mock_resp_release, mock_resp_tags]):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertIsNone(err)

    def test_repository_not_found_on_github(self):
        """Test diagnostic error when repository itself returns 404 on both endpoints."""
        mock_resp_release = MagicMock(status_code=404)
        mock_resp_tags = MagicMock(status_code=404)

        with patch("httpx.Client.get", side_effect=[mock_resp_release, mock_resp_tags]):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertIn("not found (HTTP 404)", err)

    def test_malicious_and_untrusted_download_url_rejection(self):
        """Test that download URLs outside the official repository are rejected."""
        valid_url = f"https://github.com/{OFFICIAL_REPO}/archive/refs/tags/v1.5.0.tar.gz"
        self.assertTrue(validate_download_url(valid_url))
        self.assertTrue(validate_download_url("https://objects.githubusercontent.com/github-production-release-asset/123"))

        self.assertFalse(validate_download_url("http://github.com/Ad1tya244/Openrecon-CLI/archive/refs/tags/v1.5.0.tar.gz"))
        self.assertFalse(validate_download_url("https://github.com/evil-attacker/Openrecon-CLI/archive/refs/tags/v1.5.0.tar.gz"))
        self.assertFalse(validate_download_url("https://malicious-site.com/payload.tar.gz"))
        self.assertFalse(validate_download_url("ftp://github.com/Ad1tya244/Openrecon-CLI"))
        self.assertFalse(validate_download_url(""))

    def test_prompt_user_confirmation_yes_installs(self):
        """Test that entering 'y' / 'Y' triggers installation and verification."""
        mock_release = {"tag_name": "v99.0.0", "body": ""}
        with patch("openrecon.updater.fetch_latest_release_info", return_value=(mock_release, None)), \
             patch("openrecon.updater.is_source_checkout", return_value=False), \
             patch("openrecon.updater.install_update", return_value=True) as mock_install, \
             patch("openrecon.updater.verify_installed_version", return_value=True) as mock_verify:
            res = run_opt_in_update_check(prompt_fn=lambda _: "y")
            self.assertEqual(res, "99.0.0")
            mock_install.assert_called_once()
            mock_verify.assert_called_once()

    def test_prompt_user_confirmation_no_or_enter_skips(self):
        """Test that entering 'n', 'N', or pressing Enter (blank) skips installation cleanly."""
        mock_release = {"tag_name": "v99.0.0", "body": ""}
        with patch("openrecon.updater.fetch_latest_release_info", return_value=(mock_release, None)), \
             patch("openrecon.updater.is_source_checkout", return_value=False), \
             patch("openrecon.updater.install_update") as mock_install:
            
            res_n = run_opt_in_update_check(prompt_fn=lambda _: "n")
            self.assertIsNone(res_n)
            mock_install.assert_not_called()

            res_N = run_opt_in_update_check(prompt_fn=lambda _: "N")
            self.assertIsNone(res_N)
            mock_install.assert_not_called()

            res_empty = run_opt_in_update_check(prompt_fn=lambda _: "")
            self.assertIsNone(res_empty)
            mock_install.assert_not_called()

    def test_source_checkout_protection_prompts_manual_update(self):
        """Test that running from a source checkout never touches files and prompts manual update."""
        mock_release = {"tag_name": "v99.0.0", "body": ""}
        with patch("openrecon.updater.fetch_latest_release_info", return_value=(mock_release, None)), \
             patch("openrecon.updater.is_source_checkout", return_value=True), \
             patch("openrecon.updater.install_update") as mock_install:
            res = run_opt_in_update_check()
            self.assertEqual(res, "99.0.0")
            mock_install.assert_not_called()

    def test_diagnostic_error_timeout(self):
        """Test diagnostic error for request timeout."""
        with patch("httpx.Client.get", side_effect=httpx.TimeoutException("Timeout")):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertEqual(err, "GitHub API request timed out.")

    def test_diagnostic_error_dns_network_failure(self):
        """Test diagnostic error for DNS/connection failure."""
        with patch("httpx.Client.get", side_effect=httpx.ConnectError("DNS resolution failed")):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertEqual(err, "Could not connect to GitHub (network/DNS failure).")

    def test_diagnostic_error_http_403(self):
        """Test diagnostic error for HTTP 403."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.headers = {"x-ratelimit-remaining": "10"}

        with patch("httpx.Client.get", return_value=mock_resp):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertIn("HTTP 403", err)

    def test_diagnostic_error_http_429(self):
        """Test diagnostic error for rate limit exceeded (HTTP 429)."""
        mock_resp = MagicMock(status_code=429)
        with patch("httpx.Client.get", return_value=mock_resp):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertIn("HTTP 429 (rate limit exceeded)", err)

    def test_diagnostic_error_http_500_502_503(self):
        """Test diagnostic error for GitHub server errors."""
        for code in (500, 502, 503):
            mock_resp = MagicMock(status_code=code)
            with patch("httpx.Client.get", return_value=mock_resp):
                data, err = fetch_latest_release_info()
                self.assertIsNone(data)
                self.assertIn(f"HTTP {code}", err)

    def test_diagnostic_error_malformed_json(self):
        """Test diagnostic error when GitHub returns invalid JSON."""
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.side_effect = ValueError("Invalid JSON")

        with patch("httpx.Client.get", return_value=mock_resp):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertIn("invalid JSON", err)

    def test_diagnostic_error_missing_tag_name(self):
        """Test diagnostic error when release metadata lacks tag_name."""
        mock_resp = MagicMock(status_code=200, json=lambda: {"id": 12345})
        with patch("httpx.Client.get", return_value=mock_resp):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertIn("tag_name", err)

    def test_diagnostic_error_invalid_version(self):
        """Test diagnostic error when tag_name is not valid semantic version."""
        mock_resp = MagicMock(status_code=200, json=lambda: {"tag_name": "nightly_build_xyz"})
        with patch("httpx.Client.get", return_value=mock_resp):
            data, err = fetch_latest_release_info()
            self.assertIsNone(data)
            self.assertIn("not a valid semantic version", err)

    def test_normal_commands_make_zero_network_calls(self):
        """Verify that normal commands (openrecon, --help, list-modules) make zero updater calls."""
        with patch("openrecon.updater.fetch_latest_release_info") as mock_fetch, \
             patch("openrecon.updater.run_opt_in_update_check") as mock_update:
            
            with self.assertRaises(SystemExit):
                main([])
            mock_fetch.assert_not_called()
            mock_update.assert_not_called()

            with self.assertRaises(SystemExit):
                main(["--help"])
            mock_fetch.assert_not_called()
            mock_update.assert_not_called()

            with self.assertRaises(SystemExit):
                main(["list-modules"])
            mock_fetch.assert_not_called()
            mock_update.assert_not_called()

    def test_version_flag_makes_zero_network_requests(self):
        """Test that --version executes immediately with zero network calls."""
        with patch("openrecon.updater.run_opt_in_update_check") as mock_update:
            parser = build_parser()
            with self.assertRaises(SystemExit):
                parser.parse_args(["--version"])
            mock_update.assert_not_called()

if __name__ == "__main__":
    unittest.main()
