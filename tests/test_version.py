import unittest
import tempfile
import os
import json
from openrecon.version import (
    calculate_version,
    get_change_count,
    get_version,
    set_change_count,
    increment_change_count,
    DEFAULT_VERSION_FILE,
    __version__ as version_module_version,
    CHANGE_COUNT as version_module_change_count
)
import openrecon
import openrecon.cli
import openrecon.formatter

class TestVersioningSystem(unittest.TestCase):
    def test_version_calculation_formula(self):
        # 0 -> 0.0.0
        self.assertEqual(calculate_version(0), "0.0.0")
        # 1 -> 0.0.1
        self.assertEqual(calculate_version(1), "0.0.1")
        # 9 -> 0.0.9
        self.assertEqual(calculate_version(9), "0.0.9")
        # 10 -> 0.1.0
        self.assertEqual(calculate_version(10), "0.1.0")
        # 11 -> 0.1.1
        self.assertEqual(calculate_version(11), "0.1.1")
        # 19 -> 0.1.9
        self.assertEqual(calculate_version(19), "0.1.9")
        # 20 -> 0.2.0
        self.assertEqual(calculate_version(20), "0.2.0")
        # Additional boundary cases
        self.assertEqual(calculate_version(25), "0.2.5")
        self.assertEqual(calculate_version(99), "0.9.9")
        self.assertEqual(calculate_version(100), "1.0.0")
        self.assertEqual(calculate_version(199), "1.9.9")
        self.assertEqual(calculate_version(200), "2.0.0")
        self.assertEqual(calculate_version(217), "2.1.7")
        self.assertEqual(calculate_version(999), "9.9.9")

    def test_persistence_and_file_loading(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            json.dump({"change_count": 114, "version": "1.1.4"}, f)
            f_path = f.name

        try:
            self.assertEqual(get_change_count(f_path), 114)
            self.assertEqual(get_version(f_path), "1.1.4")

            # Increment count in custom file
            new_count, new_ver = increment_change_count(f_path)
            self.assertEqual(new_count, 115)
            self.assertEqual(new_ver, "1.1.5")
            self.assertEqual(get_change_count(f_path), 115)
            self.assertEqual(get_version(f_path), "1.1.5")

            # Set explicit count in custom file
            set_count, set_ver = set_change_count(120, f_path)
            self.assertEqual(set_count, 120)
            self.assertEqual(set_ver, "1.2.0")
            self.assertEqual(get_change_count(f_path), 120)
            self.assertEqual(get_version(f_path), "1.2.0")
        finally:
            os.unlink(f_path)

    def test_authoritative_persistence_file_exists(self):
        self.assertTrue(os.path.isfile(DEFAULT_VERSION_FILE))
        current_count = get_change_count()
        current_version = get_version()
        self.assertGreaterEqual(current_count, 0)
        self.assertEqual(current_version, calculate_version(current_count))

    def test_centralized_version_synchronization_across_modules(self):
        authoritative_ver = get_version()
        # Verify openrecon package export
        self.assertEqual(openrecon.__version__, authoritative_ver)
        # Verify CLI parser and formatter use the same source
        self.assertEqual(openrecon.cli.__version__, authoritative_ver)
        self.assertEqual(openrecon.formatter.__version__, authoritative_ver)

if __name__ == "__main__":
    unittest.main()
