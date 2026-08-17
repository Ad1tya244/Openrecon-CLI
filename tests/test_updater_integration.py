"""
Complete isolated integration test suite for the OpenRecon opt-in automatic updater.
Verifies interactive prompting, automatic package installation, and isolated checks.
"""
import unittest
import tempfile
import os
import shutil
import tarfile
import hashlib
import sys
import httpx
from unittest.mock import patch, MagicMock
from openrecon import __version__
from openrecon.updater import (
    OFFICIAL_REPO,
    parse_semver,
    is_newer_version,
    validate_download_url,
    compute_sha256,
    download_and_verify_artifact,
    install_update,
    verify_installed_version,
    fetch_latest_version,
    run_opt_in_update_check
)
from openrecon.cli import build_parser, main

class TestUpdaterIntegrationLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared_temp = tempfile.mkdtemp()
        pkg_dir = os.path.join(cls.shared_temp, "test_pkg")
        os.makedirs(os.path.join(pkg_dir, "openrecon"), exist_ok=True)
        
        with open(os.path.join(pkg_dir, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write("""[build-system]
requires = ["setuptools>=61.0"]
build-backend = "setuptools.build_meta"

[project]
name = "openrecon"
version = "99.0.0"
dependencies = []

[project.scripts]
openrecon = "openrecon:main"
""")
        with open(os.path.join(pkg_dir, "openrecon", "__init__.py"), "w", encoding="utf-8") as f:
            f.write('__version__ = "99.0.0"\ndef main(): print("openrecon v99.0.0")\n')

        cls.tar_path = os.path.join(cls.shared_temp, "openrecon-99.0.0.tar.gz")
        with tarfile.open(cls.tar_path, "w:gz") as tar:
            tar.add(pkg_dir, arcname="openrecon-99.0.0")

        with open(cls.tar_path, "rb") as f:
            cls.tar_bytes = f.read()
        cls.tar_sha256 = hashlib.sha256(cls.tar_bytes).hexdigest()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.shared_temp):
            shutil.rmtree(cls.shared_temp, ignore_errors=True)

    def test_complete_opt_in_lifecycle(self):
        """
        Full opt-in lifecycle test:
        1. Query mock v99.0.0 release
        2. Prompt user: confirm 'y'
        3. Automatically download & install artifact
        4. Verify version reporting
        """
        target_version = "99.0.0"
        mock_release = {
            "tag_name": f"v{target_version}",
            "body": f"Release v{target_version}\nSHA256: {self.tar_sha256}\n"
        }

        mock_resp = MagicMock(status_code=200, content=self.tar_bytes)

        with patch("openrecon.updater.fetch_latest_release_info", return_value=(mock_release, None)), \
             patch("httpx.Client.get", return_value=mock_resp), \
             patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_subproc, \
             patch("openrecon.updater.verify_installed_version", return_value=True):
            
            res = run_opt_in_update_check(prompt_fn=lambda _: "y")
            self.assertEqual(res, target_version)
            mock_subproc.assert_called_once()

    def test_checksum_mismatch_rejection(self):
        """Verify that corrupted or tampered artifacts are rejected and cleaned up."""
        mock_resp = MagicMock(status_code=200, content=self.tar_bytes)

        with patch("httpx.Client.get", return_value=mock_resp):
            valid_url = f"https://github.com/{OFFICIAL_REPO}/archive/refs/tags/v99.0.0.tar.gz"
            wrong_hash = "0" * 64
            downloaded = download_and_verify_artifact(valid_url, expected_sha256=wrong_hash)
            self.assertIsNone(downloaded, "Corrupted artifact was not rejected!")

    def test_malicious_untrusted_url_rejection(self):
        """Verify that untrusted domains, protocols, and fork repositories are rejected."""
        self.assertFalse(validate_download_url("https://malicious-domain.com/openrecon.tar.gz"))
        self.assertFalse(validate_download_url("http://github.com/Ad1tya244/Openrecon-CLI/v1.1.0.tar.gz"))
        self.assertFalse(validate_download_url("https://github.com/evil-fork/Openrecon-CLI/v1.1.0.tar.gz"))
        self.assertFalse(validate_download_url(""))

    def test_normal_scan_makes_zero_network_calls(self):
        """Verify that normal scan execution never contacts GitHub."""
        with patch("openrecon.updater.fetch_latest_release_info") as mock_fetch, \
             patch("openrecon.updater.run_opt_in_update_check") as mock_update, \
             patch("openrecon.cli.execute_scan", return_value=0) as mock_scan:
            with self.assertRaises(SystemExit):
                main(["example.com"])
            mock_fetch.assert_not_called()
            mock_update.assert_not_called()

if __name__ == "__main__":
    unittest.main()
