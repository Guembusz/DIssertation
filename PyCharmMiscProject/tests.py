import unittest
from analyzer import analyze_qr_data, check_heuristics, RiskLevel


class TestQRSecurity(unittest.TestCase):

    def test_plain_text(self):
        """Tests if the system correctly identifies non-URLs."""
        result = analyze_qr_data("Hello World, this is a test.")
        self.assertEqual(result.status, "SAFE")
        self.assertEqual(result.level, RiskLevel.SAFE)

    def test_fuzzy_heuristics(self):
        """Tests the Levenshtein distance typosquatting logic."""
        # paypa1 instead of paypal
        self.assertTrue(check_heuristics("www.secure-paypa1-login.com", "/auth"))

        # micr0soft instead of microsoft
        self.assertTrue(check_heuristics("www.micr0soft-support.net", "/login"))

        # Legitimate brand should NOT flag the heuristic check
        self.assertFalse(check_heuristics("www.paypal.com", "/home"))

    def test_http_warning(self):
        """Tests if unencrypted HTTP connections are flagged."""
        result = analyze_qr_data("http://www.example.com")
        self.assertEqual(result.status, "WARNING")
        self.assertEqual(result.level, RiskLevel.WARNING)


if __name__ == "__main__":
    unittest.main()