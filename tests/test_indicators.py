
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from validate_indicators import (
    is_valid_indicator,
    validate_indicators,
)


class TestIndicatorValidation(unittest.TestCase):

    def test_valid_ip(self):
        indicator = {
            "type": "ip-dst",
            "value": "192.0.2.10"
        }
        self.assertTrue(is_valid_indicator(indicator))

    def test_invalid_ip(self):
        indicator = {
            "type": "ip-dst",
            "value": "999.999.999.999"
        }
        self.assertFalse(is_valid_indicator(indicator))

    def test_valid_domain(self):
        indicator = {
            "type": "domain",
            "value": "malware.example"
        }
        self.assertTrue(is_valid_indicator(indicator))

    def test_invalid_url(self):
        indicator = {
            "type": "url",
            "value": "not-a-valid-url"
        }
        self.assertFalse(is_valid_indicator(indicator))

    def test_duplicate_ip(self):
        indicators = [
            {"type": "ip-dst", "value": "192.0.2.10"},
            {"type": "ip-dst", "value": "192.0.2.10"}
        ]

        result = validate_indicators(indicators)
        self.assertEqual(len(result), 1)

    def test_case_insensitive_domain_duplicate(self):
        indicators = [
            {"type": "domain", "value": "malware.example"},
            {"type": "domain", "value": "MALWARE.EXAMPLE"}
        ]

        result = validate_indicators(indicators)
        self.assertEqual(len(result), 1)

    def test_empty_indicator_list(self):
        result = validate_indicators([])
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
