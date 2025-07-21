import unittest
import os
import sys
from unittest.mock import patch

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pattern_detector import PatternDetector


class TestPatternDetector(unittest.TestCase):

    def setUp(self):
        self.detector = PatternDetector()
        self.sample_logs = [
            {
                "ip_address": "192.168.1.100",
                "timestamp": "19/Jul/2025:14:30:25 +0000",
                "request": "GET /admin/login HTTP/1.1",
                "status_code": "200",
                "user_agent": "Mozilla/5.0",
                "raw_line": '192.168.1.100 - - [19/Jul/2025:14:30:25 +0000] "GET /admin/login HTTP/1.1" 200 1234',
            },
            {
                "ip_address": "192.168.1.101",
                "timestamp": "19/Jul/2025:14:30:26 +0000",
                "request": "POST /login HTTP/1.1",
                "status_code": "401",
                "user_agent": "Mozilla/5.0",
                "raw_line": '192.168.1.101 - - [19/Jul/2025:14:30:26 +0000] "POST /login HTTP/1.1" 401 567',
            },
            {
                "ip_address": "192.168.1.102",
                "timestamp": "19/Jul/2025:14:30:27 +0000",
                "request": "GET /index.php?id=1' UNION SELECT * FROM users-- HTTP/1.1",
                "status_code": "200",
                "user_agent": "sqlmap/1.0",
                "raw_line": '192.168.1.102 - - [19/Jul/2025:14:30:27 +0000] "GET /index.php?id=1\' UNION SELECT * FROM users-- HTTP/1.1" 200 890',
            },
            {
                "ip_address": "192.168.1.103",
                "timestamp": "19/Jul/2025:14:30:28 +0000",
                "request": "GET /search?q=<script>alert('xss')</script> HTTP/1.1",
                "status_code": "200",
                "user_agent": "Mozilla/5.0",
                "raw_line": "192.168.1.103 - - [19/Jul/2025:14:30:28 +0000] \"GET /search?q=<script>alert('xss')</script> HTTP/1.1\" 200 345",
            },
            {
                "ip_address": "192.168.1.104",
                "timestamp": "19/Jul/2025:14:30:29 +0000",
                "request": "GET /../../../etc/passwd HTTP/1.1",
                "status_code": "404",
                "user_agent": "curl/7.68.0",
                "raw_line": '192.168.1.104 - - [19/Jul/2025:14:30:29 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 123',
            },
        ]

    def test_detect_patterns(self):
        """Test basic pattern detection"""
        self.detector.detect_patterns(self.sample_logs)
        detected_patterns = self.detector.get_detected_patterns()

        self.assertIsInstance(detected_patterns, list)
        self.assertGreater(len(detected_patterns), 0)

        # Check for specific pattern types
        pattern_types = [pattern.get("type") for pattern in detected_patterns]
        self.assertIn("SQL Injection", pattern_types)
        self.assertIn("XSS Attack", pattern_types)
        self.assertIn("Directory Traversal", pattern_types)
        self.assertIn("Suspicious User Agent", pattern_types)

    def test_get_detected_patterns(self):
        """Test getting detected patterns after detection"""
        self.detector.detect_patterns(self.sample_logs)
        patterns = self.detector.get_detected_patterns()

        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 0)

    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection"""
        sql_logs = [
            {
                "ip_address": "192.168.1.100",
                "timestamp": "19/Jul/2025:14:30:25 +0000",
                "request": "GET /index.php?id=1' UNION SELECT * FROM users-- HTTP/1.1",
                "status_code": "200",
                "user_agent": "Mozilla/5.0",
                "raw_line": "GET /index.php?id=1' UNION SELECT * FROM users-- HTTP/1.1",
            }
        ]

        self.detector.detect_patterns(sql_logs)
        patterns = self.detector.get_detected_patterns()
        sql_patterns = [p for p in patterns if p.get("type") == "SQL Injection"]

        self.assertGreater(len(sql_patterns), 0)
        self.assertEqual(sql_patterns[0]["ip"], "192.168.1.100")
        self.assertEqual(sql_patterns[0]["severity"], "HIGH")

    def test_xss_detection(self):
        """Test XSS attack pattern detection"""
        xss_logs = [
            {
                "ip_address": "192.168.1.101",
                "timestamp": "19/Jul/2025:14:30:25 +0000",
                "request": "GET /search?q=<script>alert('xss')</script> HTTP/1.1",
                "status_code": "200",
                "user_agent": "Mozilla/5.0",
                "raw_line": "GET /search?q=<script>alert('xss')</script> HTTP/1.1",
            }
        ]

        self.detector.detect_patterns(xss_logs)
        patterns = self.detector.get_detected_patterns()
        xss_patterns = [p for p in patterns if p.get("type") == "XSS Attack"]

        self.assertGreater(len(xss_patterns), 0)
        self.assertEqual(xss_patterns[0]["ip"], "192.168.1.101")
        self.assertEqual(xss_patterns[0]["severity"], "HIGH")

    def test_directory_traversal_detection(self):
        """Test directory traversal pattern detection"""
        traversal_logs = [
            {
                "ip_address": "192.168.1.102",
                "timestamp": "19/Jul/2025:14:30:25 +0000",
                "request": "GET /../../../etc/passwd HTTP/1.1",
                "status_code": "404",
                "user_agent": "curl/7.68.0",
                "raw_line": "GET /../../../etc/passwd HTTP/1.1",
            }
        ]

        self.detector.detect_patterns(traversal_logs)
        patterns = self.detector.get_detected_patterns()
        traversal_patterns = [
            p for p in patterns if p.get("type") == "Directory Traversal"
        ]

        self.assertGreater(len(traversal_patterns), 0)
        self.assertEqual(traversal_patterns[0]["ip"], "192.168.1.102")
        self.assertEqual(traversal_patterns[0]["severity"], "MEDIUM")

    def test_brute_force_detection(self):
        """Test brute force attack detection"""
        # Create multiple failed login attempts from same IP
        brute_force_logs = []
        for i in range(15):  # More than threshold (10)
            brute_force_logs.append(
                {
                    "ip_address": "192.168.1.200",
                    "timestamp": f"19/Jul/2025:14:30:{25+i:02d} +0000",
                    "request": "POST /login HTTP/1.1",
                    "status_code": "401",
                    "user_agent": "Mozilla/5.0",
                    "raw_line": f'192.168.1.200 - - [19/Jul/2025:14:30:{25+i:02d} +0000] "POST /login HTTP/1.1" 401 567',
                }
            )

        self.detector.detect_patterns(brute_force_logs)
        patterns = self.detector.get_detected_patterns()
        brute_force_patterns = [
            p for p in patterns if p.get("type") == "Brute Force Attack"
        ]

        self.assertGreater(len(brute_force_patterns), 0)
        self.assertEqual(brute_force_patterns[0]["ip"], "192.168.1.200")
        self.assertEqual(brute_force_patterns[0]["severity"], "HIGH")

    def test_suspicious_user_agent_detection(self):
        """Test suspicious user agent detection"""
        suspicious_logs = [
            {
                "ip_address": "192.168.1.103",
                "timestamp": "19/Jul/2025:14:30:25 +0000",
                "request": "GET / HTTP/1.1",
                "status_code": "200",
                "user_agent": "sqlmap/1.0",
                "raw_line": '192.168.1.103 - - [19/Jul/2025:14:30:25 +0000] "GET / HTTP/1.1" 200 1234',
            }
        ]

        self.detector.detect_patterns(suspicious_logs)
        patterns = self.detector.get_detected_patterns()
        suspicious_patterns = [
            p for p in patterns if p.get("type") == "Suspicious User Agent"
        ]

        self.assertGreater(len(suspicious_patterns), 0)
        self.assertEqual(suspicious_patterns[0]["ip"], "192.168.1.103")
        self.assertEqual(suspicious_patterns[0]["severity"], "MEDIUM")

    def test_suspicious_scanning_detection(self):
        """Test suspicious scanning (404 errors) detection"""
        scanning_logs = [
            {
                "ip_address": "192.168.1.104",
                "timestamp": "19/Jul/2025:14:30:25 +0000",
                "request": "GET /admin/config.php HTTP/1.1",
                "status_code": "404",
                "user_agent": "Mozilla/5.0",
                "raw_line": '192.168.1.104 - - [19/Jul/2025:14:30:25 +0000] "GET /admin/config.php HTTP/1.1" 404 123',
            }
        ]

        self.detector.detect_patterns(scanning_logs)
        patterns = self.detector.get_detected_patterns()
        scanning_patterns = [
            p for p in patterns if p.get("type") == "Suspicious Scanning"
        ]

        self.assertGreater(len(scanning_patterns), 0)
        self.assertEqual(scanning_patterns[0]["ip"], "192.168.1.104")
        self.assertEqual(scanning_patterns[0]["severity"], "LOW")

    def test_pattern_summary(self):
        """Test pattern summary generation"""
        self.detector.detect_patterns(self.sample_logs)
        summary = self.detector.get_pattern_summary()

        self.assertIsInstance(summary, dict)
        self.assertIn("total_threats", summary)
        self.assertIn("by_type", summary)
        self.assertIn("by_severity", summary)
        self.assertIn("top_attacking_ips", summary)

        self.assertGreater(summary["total_threats"], 0)

    def test_pattern_summary_empty(self):
        """Test pattern summary when no patterns detected"""
        # Don't detect any patterns - test empty case
        summary = self.detector.get_pattern_summary()

        # Should return empty dict when no patterns detected
        self.assertEqual(summary, {})

    def test_ddos_detection_threshold_exceeded(self):
        """Test DDoS detection when threshold is exceeded"""
        # Create logs that will exceed the threshold
        ddos_logs = []
        threshold = self.detector.config["thresholds"]["requests_per_ip_per_minute"]

        # Create enough requests to exceed threshold
        for i in range(threshold + 2):
            log_entry = {
                "ip": "192.168.1.100",
                "timestamp": "2024-01-01 12:00:00",
                "method": "GET",
                "uri": f"/test{i}",
                "status": "200",
                "size": "1024",
                "user_agent": "TestBot",
            }
            ddos_logs.append(log_entry)

        self.detector.detect_patterns(ddos_logs)

        # Should have detected DDoS pattern
        patterns = self.detector.get_detected_patterns()
        ddos_patterns = [p for p in patterns if p["type"] == "DDoS Attempt"]
        self.assertGreater(len(ddos_patterns), 0)

        # Check that severity is HIGH
        self.assertTrue(any(p["severity"] == "HIGH" for p in ddos_patterns))

    def test_load_custom_patterns(self):
        """Test loading custom patterns"""
        custom_patterns = {
            "sql_injection": [r"drop\s+table"],
            "xss_patterns": [r"onerror\s*="],
            "thresholds": {"requests_per_ip_per_minute": 50},
        }

        self.detector.load_custom_patterns(custom_patterns)

        # Verify patterns were added
        self.assertIn(r"drop\s+table", self.detector.sql_injection_patterns)
        self.assertIn(r"onerror\s*=", self.detector.xss_patterns)
        self.assertEqual(
            self.detector.config["thresholds"]["requests_per_ip_per_minute"], 50
        )

    def test_empty_logs(self):
        """Test detection with empty log list"""
        self.detector.detect_patterns([])
        patterns = self.detector.get_detected_patterns()

        self.assertIsInstance(patterns, list)
        self.assertEqual(len(patterns), 0)

    def test_malformed_logs(self):
        """Test detection with malformed log entries"""
        malformed_logs = [
            {"ip_address": "192.168.1.100"},  # Missing required fields
            {},  # Empty entry
            None,  # None entry
        ]

        # Should not crash and return empty list
        self.detector.detect_patterns(malformed_logs)
        patterns = self.detector.get_detected_patterns()

        self.assertIsInstance(patterns, list)

    def test_config_loading(self):
        """Test configuration loading"""
        # Test default config when no file provided
        detector_no_config = PatternDetector()
        self.assertIn("thresholds", detector_no_config.config)

        # Test with non-existent config file
        detector_bad_config = PatternDetector("/non/existent/path.json")
        self.assertIn("thresholds", detector_bad_config.config)

    def test_config_loading_exception(self):
        """Test config loading with invalid JSON file"""
        import tempfile

        # Create a temporary file with invalid JSON
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content")
            temp_path = f.name

        try:
            # This should fall back to default config due to exception
            detector = PatternDetector(temp_path)
            self.assertIn("thresholds", detector.config)
        finally:
            os.unlink(temp_path)

    def test_custom_patterns_with_errors(self):
        """Test custom pattern loading with various error conditions"""
        detector = PatternDetector()

        # Test with invalid custom patterns structure
        invalid_patterns = "not a dict"
        detector.load_custom_patterns(invalid_patterns)  # Should handle gracefully

        # Test custom pattern detection with patterns loaded
        custom_patterns = {
            "custom_test_pattern": {"patterns": ["badbot"], "severity": "HIGH"},
            "sql_injection": ["evil_sql"],
            "xss_patterns": ["evil_xss"],
            "suspicious_user_agents": ["evil_agent"],
            "thresholds": {"brute_force_threshold": 10},
        }
        detector.load_custom_patterns(custom_patterns)

        # Test detection with custom patterns
        test_log = {
            "ip_address": "192.168.1.200",
            "timestamp": "19/Jul/2025:14:30:30 +0000",
            "request": "GET /test?param=badbot HTTP/1.1",
            "status_code": "200",
            "user_agent": "testbot",
            "raw_line": '192.168.1.200 - - [19/Jul/2025:14:30:30 +0000] "GET /test?param=badbot HTTP/1.1" 200 123',
        }

        detector.detect_patterns([test_log])
        patterns = detector.get_detected_patterns()

        # Should find the custom pattern
        custom_detections = [p for p in patterns if "Custom Pattern" in p["type"]]
        self.assertTrue(len(custom_detections) > 0)

    def test_custom_patterns_exception_handling(self):
        """Test exception handling in custom pattern detection"""
        detector = PatternDetector()

        # Set up patterns that will cause an exception during detection
        bad_patterns = {
            "custom_bad": {
                "patterns": ["[invalid_regex"],  # Invalid regex
                "severity": "HIGH",
            }
        }
        detector.load_custom_patterns(bad_patterns)

        test_log = {
            "ip_address": "192.168.1.201",
            "timestamp": "19/Jul/2025:14:30:31 +0000",
            "request": "GET /test HTTP/1.1",
            "status_code": "200",
            "user_agent": "testbot",
            "raw_line": '192.168.1.201 - - [19/Jul/2025:14:30:31 +0000] "GET /test HTTP/1.1" 200 123',
        }

        # Should handle the regex exception gracefully
        detector.detect_patterns([test_log])
        # Should not crash

    def test_load_custom_patterns_exception_logging(self):
        """Test exception logging in load_custom_patterns method"""
        detector = PatternDetector()

        # Mock the logging to capture the exception
        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = mock_get_logger.return_value

            # Force an exception by providing an object that will fail when
            # trying to access it like a dictionary
            class BadObject:
                def __contains__(self, key):
                    raise ValueError("Forced exception for testing")

            invalid_data = BadObject()

            # This should trigger the exception handling in load_custom_patterns
            detector.load_custom_patterns(invalid_data)

            # Check that the logger was called with error message
            mock_get_logger.assert_called_with("nginx-security-monitor.patterns")
            mock_logger.error.assert_called_once()

            # Verify the error message format
            call_args = mock_logger.error.call_args[0][0]
            self.assertIn("Failed to load custom patterns:", call_args)


if __name__ == "__main__":
    unittest.main()
