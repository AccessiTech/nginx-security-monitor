import unittest
import os
import sys

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mitigation import mitigate_threat


class TestMitigation(unittest.TestCase):

    def test_mitigate_threat_ddos(self):
        """Test mitigation for DDoS pattern"""
        result = mitigate_threat("DDoS")
        self.assertEqual(result, "DDoS mitigation tactics applied.")

    def test_mitigate_threat_sql_injection(self):
        """Test mitigation for SQL Injection pattern"""
        result = mitigate_threat("SQL Injection")
        self.assertEqual(result, "SQL injection mitigation tactics applied.")

    def test_mitigate_threat_xss(self):
        """Test mitigation for XSS pattern"""
        result = mitigate_threat("XSS")
        self.assertEqual(result, "XSS mitigation tactics applied.")

    def test_mitigate_threat_unknown_pattern(self):
        """Test mitigation for unknown/unrecognized pattern"""
        result = mitigate_threat("Unknown Attack")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_empty_string(self):
        """Test mitigation with empty string pattern"""
        result = mitigate_threat("")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_none_pattern(self):
        """Test mitigation with None pattern"""
        result = mitigate_threat(None)
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_case_sensitivity_ddos_lowercase(self):
        """Test mitigation with lowercase ddos pattern"""
        result = mitigate_threat("ddos")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_case_sensitivity_sql_lowercase(self):
        """Test mitigation with lowercase sql injection pattern"""
        result = mitigate_threat("sql injection")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_case_sensitivity_xss_lowercase(self):
        """Test mitigation with lowercase xss pattern"""
        result = mitigate_threat("xss")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_with_extra_whitespace(self):
        """Test mitigation with patterns containing extra whitespace"""
        result = mitigate_threat(" DDoS ")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_partial_match_ddos(self):
        """Test mitigation with partial DDoS pattern match"""
        result = mitigate_threat("DDoS Attack")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_partial_match_sql(self):
        """Test mitigation with partial SQL injection pattern match"""
        result = mitigate_threat("SQL Injection Attempt")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_partial_match_xss(self):
        """Test mitigation with partial XSS pattern match"""
        result = mitigate_threat("XSS Vulnerability")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_numeric_pattern(self):
        """Test mitigation with numeric pattern"""
        result = mitigate_threat("12345")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_special_characters(self):
        """Test mitigation with special characters in pattern"""
        result = mitigate_threat("@#$%^&*()")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_similar_patterns(self):
        """Test mitigation with patterns similar to known ones"""
        test_cases = [
            ("DDOS", "No specific mitigation tactics available for this pattern."),
            (
                "SQLInjection",
                "No specific mitigation tactics available for this pattern.",
            ),
            (
                "Cross-Site Scripting",
                "No specific mitigation tactics available for this pattern.",
            ),
            (
                "DDoS attack",
                "No specific mitigation tactics available for this pattern.",
            ),
            (
                "SQL injection",
                "No specific mitigation tactics available for this pattern.",
            ),
        ]

        for pattern, expected in test_cases:
            with self.subTest(pattern=pattern):
                result = mitigate_threat(pattern)
                self.assertEqual(result, expected)

    def test_mitigate_threat_unicode_pattern(self):
        """Test mitigation with unicode characters in pattern"""
        result = mitigate_threat("DDōS")
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_long_pattern(self):
        """Test mitigation with very long pattern string"""
        long_pattern = "A" * 1000
        result = mitigate_threat(long_pattern)
        self.assertEqual(
            result, "No specific mitigation tactics available for this pattern."
        )

    def test_mitigate_threat_return_types(self):
        """Test that all mitigation functions return strings"""
        test_patterns = ["DDoS", "SQL Injection", "XSS", "Unknown", "", None]

        for pattern in test_patterns:
            with self.subTest(pattern=pattern):
                result = mitigate_threat(pattern)
                self.assertIsInstance(result, str)
                self.assertGreater(len(result), 0)  # Should not return empty strings

    def test_mitigate_threat_all_known_patterns(self):
        """Test all known patterns in a single comprehensive test"""
        known_patterns = {
            "DDoS": "DDoS mitigation tactics applied.",
            "SQL Injection": "SQL injection mitigation tactics applied.",
            "XSS": "XSS mitigation tactics applied.",
        }

        for pattern, expected_result in known_patterns.items():
            with self.subTest(pattern=pattern):
                result = mitigate_threat(pattern)
                self.assertEqual(result, expected_result)

                # Verify the result contains the pattern name (case-insensitive check)
                self.assertIn(pattern.lower(), result.lower())

                # Verify it mentions mitigation
                self.assertIn("mitigation", result.lower())

    def test_mitigate_threat_edge_cases_input_types(self):
        """Test mitigation with different input types that might be passed"""
        # Test with non-string types that can be converted to string
        test_cases = [
            (123, "No specific mitigation tactics available for this pattern."),
            (True, "No specific mitigation tactics available for this pattern."),
            (False, "No specific mitigation tactics available for this pattern."),
            ([], "No specific mitigation tactics available for this pattern."),
            ({}, "No specific mitigation tactics available for this pattern."),
        ]

        for pattern, expected in test_cases:
            with self.subTest(pattern=pattern):
                result = mitigate_threat(pattern)
                self.assertEqual(result, expected)

    def test_mitigate_threat_consistency(self):
        """Test that multiple calls with same pattern return consistent results"""
        patterns = ["DDoS", "SQL Injection", "XSS", "Unknown Pattern"]

        for pattern in patterns:
            with self.subTest(pattern=pattern):
                result1 = mitigate_threat(pattern)
                result2 = mitigate_threat(pattern)
                result3 = mitigate_threat(pattern)

                # All results should be identical
                self.assertEqual(result1, result2)
                self.assertEqual(result2, result3)
                self.assertEqual(result1, result3)


if __name__ == "__main__":
    unittest.main()
