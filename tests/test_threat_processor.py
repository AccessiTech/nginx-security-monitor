#!/usr/bin/env python3
"""
Tests for ThreatProcessor module
"""

import unittest
from unittest.mock import patch, MagicMock, call
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from threat_processor import ThreatProcessor


class TestThreatProcessor(unittest.TestCase):
    """Test cases for ThreatProcessor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {"auto_mitigation": True}
        self.mock_logger = MagicMock()
        self.mock_pattern_detector = MagicMock()
        self.mock_mitigation_function = MagicMock()
        self.mock_plugin_system = MagicMock()

        self.processor = ThreatProcessor(
            config=self.config,
            logger=self.mock_logger,
            pattern_detector=self.mock_pattern_detector,
            mitigation_function=self.mock_mitigation_function,
            plugin_system=self.mock_plugin_system,
        )

    def test_init(self):
        """Test ThreatProcessor initialization."""
        self.assertEqual(self.processor.config, self.config)
        self.assertEqual(self.processor.logger, self.mock_logger)
        self.assertEqual(self.processor.pattern_detector, self.mock_pattern_detector)
        self.assertEqual(
            self.processor.mitigation_function, self.mock_mitigation_function
        )
        self.assertEqual(self.processor.plugin_system, self.mock_plugin_system)

    def test_process_log_entries_with_threats(self):
        """Test processing log entries with detected threats."""
        # Set up log entries
        log_entries = [
            {
                "ip_address": "192.168.1.100",
                "timestamp": "2025-01-01T12:00:00",
                "request": "/admin/login.php",
                "status_code": "200",
                "user_agent": "Mozilla/5.0",
                "raw_line": "sample log line 1",
            },
            {
                "ip_address": "10.0.0.1",
                "timestamp": "2025-01-01T12:01:00",
                "request": "/api/users",
                "status_code": "404",
                "user_agent": "curl/7.68.0",
                "raw_line": "sample log line 2",
            },
        ]

        # Set up threat detections
        threats_detected = [
            [{"type": "sql_injection", "pattern": "DROP TABLE"}],
            [{"type": "brute_force", "pattern": "multiple failed logins"}],
        ]

        self.mock_pattern_detector.detect_threats.side_effect = threats_detected
        self.mock_plugin_system.run_threat_detection_plugins.side_effect = [
            {"confidence": 0.9, "additional_info": "High confidence SQL injection"},
            {"confidence": 0.7, "additional_info": "Possible brute force"},
        ]
        self.mock_mitigation_function.return_value = {
            "status": "success",
            "action": "blocked",
        }

        result = self.processor.process_log_entries(log_entries)

        # Check that pattern detector was called for each entry
        self.assertEqual(self.mock_pattern_detector.detect_threats.call_count, 2)

        # Check that plugin system was called for each threat
        self.assertEqual(
            self.mock_plugin_system.run_threat_detection_plugins.call_count, 2
        )

        # Check that mitigation was applied for high/critical threats
        # Only the first threat (SQL injection = critical) should trigger mitigation
        # The second threat (brute_force with 404 status = medium) should not
        self.assertEqual(self.mock_mitigation_function.call_count, 1)

        # Check result structure
        self.assertEqual(len(result), 2)

        # Check first threat enrichment
        first_threat = result[0]
        self.assertEqual(first_threat["type"], "sql_injection")
        self.assertEqual(first_threat["source_ip"], "192.168.1.100")
        self.assertEqual(first_threat["timestamp"], "2025-01-01T12:00:00")
        self.assertEqual(first_threat["request_uri"], "/admin/login.php")
        self.assertEqual(first_threat["status_code"], "200")
        self.assertEqual(first_threat["user_agent"], "Mozilla/5.0")
        self.assertEqual(
            first_threat["severity"], "critical"
        )  # SQL injection is critical
        self.assertEqual(first_threat["confidence"], 0.9)

        # Check second threat enrichment
        second_threat = result[1]
        self.assertEqual(second_threat["type"], "brute_force")
        self.assertEqual(second_threat["source_ip"], "10.0.0.1")
        self.assertEqual(
            second_threat["severity"], "medium"
        )  # Brute force with 404 status

    def test_process_log_entries_no_threats(self):
        """Test processing log entries with no threats detected."""
        log_entries = [
            {
                "ip_address": "192.168.1.100",
                "timestamp": "2025-01-01T12:00:00",
                "request": "/index.html",
                "status_code": "200",
            }
        ]

        # No threats detected
        self.mock_pattern_detector.detect_threats.return_value = []

        result = self.processor.process_log_entries(log_entries)

        # Should return empty list
        self.assertEqual(result, [])

        # Plugin system should not be called
        self.mock_plugin_system.run_threat_detection_plugins.assert_not_called()

        # Mitigation should not be called
        self.mock_mitigation_function.assert_not_called()

    def test_process_log_entries_auto_mitigation_disabled(self):
        """Test processing with auto mitigation disabled."""
        self.processor.config["auto_mitigation"] = False

        log_entries = [
            {"ip_address": "192.168.1.100", "request": "/admin", "status_code": "200"}
        ]

        self.mock_pattern_detector.detect_threats.return_value = [
            {"type": "sql_injection", "pattern": "UNION SELECT"}
        ]
        self.mock_plugin_system.run_threat_detection_plugins.return_value = {}

        result = self.processor.process_log_entries(log_entries)

        # Should still detect threats
        self.assertEqual(len(result), 1)

        # But mitigation should not be called
        self.mock_mitigation_function.assert_not_called()

    def test_process_log_entries_exception_handling(self):
        """Test exception handling during log entry processing."""
        log_entries = [
            {"ip_address": "192.168.1.100", "request": "/test1"},
            {"ip_address": "10.0.0.1", "request": "/test2"},
        ]

        # First entry causes exception, second succeeds
        self.mock_pattern_detector.detect_threats.side_effect = [
            Exception("Pattern detection failed"),
            [{"type": "xss", "pattern": "<script>"}],
        ]
        self.mock_plugin_system.run_threat_detection_plugins.return_value = {}

        result = self.processor.process_log_entries(log_entries)

        # Should process the second entry despite first failing
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "xss")

        # Should log the error
        self.mock_logger.error.assert_called_with(
            f"Error processing log entry {log_entries[0]}: Pattern detection failed"
        )

    def test_enrich_threat_complete(self):
        """Test threat enrichment with complete log entry."""
        threat = {
            "type": "sql_injection",
            "pattern": "UNION SELECT",
            "matched_text": "' UNION SELECT * FROM users",
        }

        log_entry = {
            "ip_address": "203.0.113.1",
            "timestamp": "2025-01-01T15:30:00",
            "request": "/api/search?q=test' UNION SELECT",
            "status_code": "200",
            "user_agent": "curl/7.68.0",
            "raw_line": "Full log line here",
        }

        with patch.object(self.processor, "_get_geolocation_info") as mock_geo:
            mock_geo.return_value = {
                "country": "United States",
                "city": "New York",
                "isp": "Example ISP",
            }

            enriched = self.processor._enrich_threat(threat, log_entry)

            # Check original threat data is preserved
            self.assertEqual(enriched["type"], "sql_injection")
            self.assertEqual(enriched["pattern"], "UNION SELECT")

            # Check enriched data
            self.assertEqual(enriched["source_ip"], "203.0.113.1")
            self.assertEqual(enriched["timestamp"], "2025-01-01T15:30:00")
            self.assertEqual(
                enriched["request_uri"], "/api/search?q=test' UNION SELECT"
            )
            self.assertEqual(enriched["status_code"], "200")
            self.assertEqual(enriched["user_agent"], "curl/7.68.0")
            self.assertEqual(enriched["raw_log"], "Full log line here")
            self.assertEqual(enriched["severity"], "critical")
            self.assertEqual(enriched["geolocation"]["country"], "United States")

    def test_enrich_threat_minimal_log_entry(self):
        """Test threat enrichment with minimal log entry."""
        threat = {"type": "unknown_threat"}
        log_entry = {}  # Empty log entry

        with patch.object(self.processor, "_get_geolocation_info") as mock_geo:
            mock_geo.return_value = None

            enriched = self.processor._enrich_threat(threat, log_entry)

            # Check defaults are used
            self.assertEqual(enriched["source_ip"], "unknown")
            self.assertEqual(enriched["timestamp"], "")
            self.assertEqual(enriched["request_uri"], "")
            self.assertEqual(enriched["status_code"], "")
            self.assertEqual(enriched["user_agent"], "")
            self.assertEqual(enriched["raw_log"], "")
            self.assertEqual(enriched["severity"], "medium")  # Default severity
            self.assertNotIn("geolocation", enriched)

    def test_assess_threat_severity_critical(self):
        """Test severity assessment for critical threats."""
        threat = {"type": "sql_injection"}
        log_entry = {"status_code": "200"}

        severity = self.processor._assess_threat_severity(threat, log_entry)
        self.assertEqual(severity, "critical")

        # Test other critical types
        for threat_type in ["command_injection", "path_traversal"]:
            threat = {"type": threat_type}
            severity = self.processor._assess_threat_severity(threat, log_entry)
            self.assertEqual(severity, "critical")

    def test_assess_threat_severity_high(self):
        """Test severity assessment for high severity threats."""
        threat = {"type": "xss"}
        log_entry = {"status_code": "200"}

        severity = self.processor._assess_threat_severity(threat, log_entry)
        self.assertEqual(severity, "high")

        # Test other high severity types
        for threat_type in ["csrf", "file_inclusion"]:
            threat = {"type": threat_type}
            severity = self.processor._assess_threat_severity(threat, log_entry)
            self.assertEqual(severity, "high")

    def test_assess_threat_severity_brute_force_escalation(self):
        """Test severity assessment for brute force with successful status codes."""
        # Successful brute force (high severity)
        threat = {"type": "brute_force"}
        log_entry = {"status_code": "200"}

        severity = self.processor._assess_threat_severity(threat, log_entry)
        self.assertEqual(severity, "high")

        # Failed brute force (medium severity)
        log_entry = {"status_code": "401"}
        severity = self.processor._assess_threat_severity(threat, log_entry)
        self.assertEqual(severity, "medium")

    def test_assess_threat_severity_dos_scanning(self):
        """Test severity assessment for DoS and scanning attacks."""
        # Test DoS with different status codes
        threat = {"type": "dos"}

        # Successful DoS
        log_entry = {"status_code": "200"}
        severity = self.processor._assess_threat_severity(threat, log_entry)
        self.assertEqual(severity, "high")

        # Failed DoS
        log_entry = {"status_code": "403"}
        severity = self.processor._assess_threat_severity(threat, log_entry)
        self.assertEqual(severity, "medium")

    def test_assess_threat_severity_low_threats(self):
        """Test severity assessment for low severity threats."""
        low_threat_types = ["suspicious_user_agent", "unusual_request"]

        for threat_type in low_threat_types:
            threat = {"type": threat_type}
            log_entry = {"status_code": "404"}  # Use failed status to avoid escalation

            severity = self.processor._assess_threat_severity(threat, log_entry)
            self.assertEqual(severity, "low")

    def test_assess_threat_severity_status_code_escalation(self):
        """Test severity escalation based on successful status codes."""
        # Medium threat with successful status code should become high
        threat = {"type": "unknown_medium_threat"}
        log_entry = {"status_code": "200"}

        # Mock the default severity as medium
        with patch.object(
            self.processor,
            "_assess_threat_severity",
            wraps=self.processor._assess_threat_severity,
        ):
            severity = self.processor._assess_threat_severity(threat, log_entry)
            # Since unknown_medium_threat gets default 'medium', and 200 status escalates medium to high
            self.assertEqual(severity, "high")

        # Low threat with successful status code should become medium
        threat = {"type": "suspicious_user_agent"}
        severity = self.processor._assess_threat_severity(threat, log_entry)
        self.assertEqual(severity, "medium")  # Escalated from low

    def test_assess_threat_severity_default(self):
        """Test default severity assessment."""
        threat = {"type": "unknown_threat_type"}
        log_entry = {"status_code": "404"}

        severity = self.processor._assess_threat_severity(threat, log_entry)
        self.assertEqual(severity, "medium")  # Default severity

    def test_get_geolocation_info_success(self):
        """Test geolocation lookup with valid IP."""
        ip_address = "8.8.8.8"

        geo_info = self.processor._get_geolocation_info(ip_address)

        # Should return mock geolocation data
        expected = {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
        self.assertEqual(geo_info, expected)

    def test_get_geolocation_info_invalid_ip(self):
        """Test geolocation lookup with invalid IP."""
        # Test with None
        geo_info = self.processor._get_geolocation_info(None)
        self.assertIsNone(geo_info)

        # Test with 'unknown'
        geo_info = self.processor._get_geolocation_info("unknown")
        self.assertIsNone(geo_info)

        # Test with empty string
        geo_info = self.processor._get_geolocation_info("")
        self.assertIsNone(geo_info)

    def test_get_geolocation_info_exception(self):
        """Test geolocation lookup with exception."""
        with patch.object(self.processor, "logger") as mock_logger:
            # Patch the IP address parsing method to force an exception
            with patch.object(
                self.processor,
                "_parse_ip_address",
                side_effect=Exception("IP parsing error"),
            ):
                result = self.processor._get_geolocation_info("8.8.8.8")

                # Should return None when exception occurs
                self.assertIsNone(result)

                # Should log the exception
                mock_logger.debug.assert_called_once_with(
                    "Failed to get geolocation for 8.8.8.8: IP parsing error"
                )

    def test_apply_mitigation_high_severity(self):
        """Test applying mitigation for high severity threats."""
        threat = {
            "type": "sql_injection",
            "severity": "high",
            "source_ip": "192.168.1.100",
        }

        self.mock_mitigation_function.return_value = {
            "status": "success",
            "action": "blocked",
        }

        self.processor._apply_mitigation(threat)

        # Should call mitigation function
        self.mock_mitigation_function.assert_called_once_with("sql_injection")

        # Should log success
        self.mock_logger.info.assert_called_with(
            "Applied mitigation for sql_injection: {'status': 'success', 'action': 'blocked'}"
        )

    def test_apply_mitigation_critical_severity(self):
        """Test applying mitigation for critical severity threats."""
        threat = {
            "type": "command_injection",
            "severity": "critical",
            "source_ip": "10.0.0.1",
        }

        self.mock_mitigation_function.return_value = {
            "status": "success",
            "action": "emergency_block",
        }

        self.processor._apply_mitigation(threat)

        # Should call mitigation function
        self.mock_mitigation_function.assert_called_once_with("command_injection")

    def test_apply_mitigation_low_severity(self):
        """Test not applying mitigation for low severity threats."""
        threat = {
            "type": "suspicious_user_agent",
            "severity": "low",
            "source_ip": "192.168.1.100",
        }

        self.processor._apply_mitigation(threat)

        # Should not call mitigation function for low severity
        self.mock_mitigation_function.assert_not_called()

    def test_apply_mitigation_medium_severity(self):
        """Test not applying mitigation for medium severity threats."""
        threat = {
            "type": "unknown_threat",
            "severity": "medium",
            "source_ip": "192.168.1.100",
        }

        self.processor._apply_mitigation(threat)

        # Should not call mitigation function for medium severity
        self.mock_mitigation_function.assert_not_called()

    def test_apply_mitigation_no_function(self):
        """Test mitigation when no mitigation function is provided."""
        # Create processor without mitigation function
        processor_no_mitigation = ThreatProcessor(
            config=self.config,
            logger=self.mock_logger,
            pattern_detector=self.mock_pattern_detector,
            mitigation_function=None,
            plugin_system=self.mock_plugin_system,
        )

        threat = {"type": "sql_injection", "severity": "critical"}

        # Should not raise an exception
        processor_no_mitigation._apply_mitigation(threat)

        # No logging should occur (no mitigation function to call)
        self.mock_logger.info.assert_not_called()

    def test_apply_mitigation_exception(self):
        """Test exception handling during mitigation application."""
        threat = {"type": "xss", "severity": "high"}

        self.mock_mitigation_function.side_effect = Exception("Mitigation failed")

        self.processor._apply_mitigation(threat)

        # Should log the error
        self.mock_logger.error.assert_called_with(
            "Failed to apply mitigation for threat: Mitigation failed"
        )

    def test_get_threat_statistics(self):
        """Test getting threat statistics."""
        stats = self.processor.get_threat_statistics()

        # Should return expected structure
        expected_stats = {
            "total_threats": 0,
            "threats_by_type": {},
            "threats_by_severity": {},
            "blocked_ips": 0,
            "rate_limited_ips": 0,
        }

        self.assertEqual(stats, expected_stats)

    def test_integration_full_workflow(self):
        """Test the complete threat processing workflow."""
        log_entries = [
            {
                "ip_address": "192.168.1.100",
                "timestamp": "2025-01-01T12:00:00",
                "request": "/admin/login.php?user=admin&pass=' OR 1=1--",
                "status_code": "200",
                "user_agent": "Mozilla/5.0",
                "raw_line": "Complete log entry",
            }
        ]

        # Set up detection results
        detected_threats = [
            {
                "type": "sql_injection",
                "pattern": "OR 1=1",
                "matched_text": "' OR 1=1--",
                "confidence": 0.95,
            }
        ]

        self.mock_pattern_detector.detect_threats.return_value = detected_threats
        self.mock_plugin_system.run_threat_detection_plugins.return_value = {
            "risk_score": 9.5,
            "attack_vector": "web_application",
        }
        self.mock_mitigation_function.return_value = {
            "status": "success",
            "action": "ip_blocked",
            "duration": "24h",
        }

        # Process the log entries
        threats = self.processor.process_log_entries(log_entries)

        # Verify the complete workflow
        self.assertEqual(len(threats), 1)

        threat = threats[0]
        self.assertEqual(threat["type"], "sql_injection")
        self.assertEqual(threat["source_ip"], "192.168.1.100")
        self.assertEqual(threat["severity"], "critical")
        self.assertEqual(threat["confidence"], 0.95)
        self.assertEqual(threat["risk_score"], 9.5)
        self.assertEqual(threat["attack_vector"], "web_application")

        # Verify all components were called
        self.mock_pattern_detector.detect_threats.assert_called_once()
        self.mock_plugin_system.run_threat_detection_plugins.assert_called_once()
        self.mock_mitigation_function.assert_called_once_with("sql_injection")

        # Verify logging
        self.mock_logger.info.assert_called_with(
            "Applied mitigation for sql_injection: {'status': 'success', 'action': 'ip_blocked', 'duration': '24h'}"
        )


if __name__ == "__main__":
    unittest.main()
