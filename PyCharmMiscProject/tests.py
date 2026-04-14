import unittest
import os
from unittest.mock import patch
from analyzer import analyze_qr_data, check_heuristics, RiskLevel, calculate_shannon_entropy

class TestQRSecurity(unittest.TestCase):

    def test_plain_text(self):
        """Tests if the system correctly identifies non-URLs."""
        result = analyze_qr_data("Hello World, this is a test.")
        self.assertEqual(result.status, "SAFE")
        self.assertEqual(result.level, RiskLevel.SAFE)

    def test_fuzzy_heuristics(self):
        """Tests the Levenshtein distance typosquatting logic."""
        self.assertTrue(check_heuristics("www.secure-paypa1-login.com", "/auth"))
        self.assertTrue(check_heuristics("www.micr0soft-support.net", "/login"))
        self.assertFalse(check_heuristics("www.paypal.com", "/home"))

    def test_http_warning(self):
        """Tests if unencrypted HTTP connections are flagged."""
        result = analyze_qr_data("http://www.example.com")
        self.assertEqual(result.status, "WARNING")
        self.assertEqual(result.level, RiskLevel.WARNING)

    def test_shannon_entropy(self):
        """Tests if the mathematical heuristic catches randomized/DGA URLs."""
        # Standard safe path should have low entropy
        safe_entropy = calculate_shannon_entropy("/login/user")
        self.assertTrue(safe_entropy < 4.0)

        # We must use a very long string with many unique characters to mathematically exceed 4.0
        massive_random_string = "/aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5xA9bC8dE7"
        malicious_entropy = calculate_shannon_entropy(massive_random_string)
        self.assertTrue(malicious_entropy > 4.0)

    # Inject a fake API key so the engine doesn't skip the test
    @patch.dict(os.environ, {"GOOGLE_SAFE_BROWSING_KEY": "FAKE_TEST_KEY_123"})
    @patch('analyzer.http_session.post')
    def test_google_safe_browsing_mock(self, mock_post):
        """
        Enterprise Testing: Mocks the Google API to test if the system
        handles 'THREAT_FOUND' correctly without making real internet calls.
        """
        # Fake the JSON response from Google to pretend we found malware
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"matches": [{"threatType": "MALWARE"}]}

        result = analyze_qr_data("https://www.known-malware-site.com")

        self.assertEqual(result.status, "MALICIOUS")
        self.assertEqual(result.level, RiskLevel.MALICIOUS)
        self.assertIn("Google Safe Browsing", result.message)


if __name__ == "__main__":
    unittest.main()