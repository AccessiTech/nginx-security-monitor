#!/usr/bin/env python3
"""
Tests for AlertManager module
"""

import unittest
from unittest.mock import patch, MagicMock, call
import sys
import os
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from alert_manager import AlertManager


class TestAlertManager(unittest.TestCase):
    """Test cases for AlertManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "email_service": {"enabled": True, "to_address": "admin@example.com"},
            "sms_service": {"enabled": False},
        }
        self.mock_logger = MagicMock()
        self.alert_manager = AlertManager(self.config, self.mock_logger)

    def test_init(self):
        """Test AlertManager initialization."""
        self.assertEqual(self.alert_manager.config, self.config)
        self.assertEqual(self.alert_manager.logger, self.mock_logger)

    @patch("alert_manager.send_email_alert")
    @patch("alert_manager.send_sms_alert")
    def test_send_threat_alert_email_enabled(self, mock_sms, mock_email):
        """Test sending threat alert with email enabled."""
        pattern = {
            "type": "SQL Injection",
            "ip": "192.168.1.100",
            "timestamp": "2025-01-01T12:00:00",
            "severity": "HIGH",
        }
        mitigation_results = [
            {"status": "success", "action": "blocked"},
            {"status": "failed", "action": "rate_limit"},
        ]

        self.alert_manager.send_threat_alert(pattern, mitigation_results)

        # Check email was sent
        mock_email.assert_called_once()
        email_args = mock_email.call_args[0][0]
        self.assertEqual(email_args["subject"], "NGINX Security Alert: SQL Injection")
        self.assertIn("SQL Injection", email_args["body"])
        self.assertIn("192.168.1.100", email_args["body"])

        # Check SMS was not sent (disabled in config)
        mock_sms.assert_not_called()

        # Check logging
        self.mock_logger.info.assert_called_with("Threat alert sent via email")

    @patch("alert_manager.send_email_alert")
    @patch("alert_manager.send_sms_alert")
    def test_send_threat_alert_sms_enabled(self, mock_sms, mock_email):
        """Test sending threat alert with SMS enabled."""
        # Enable SMS in config
        self.alert_manager.config["sms_service"]["enabled"] = True

        pattern = {"type": "Brute Force", "ip": "10.0.0.1", "severity": "CRITICAL"}
        mitigation_results = []

        self.alert_manager.send_threat_alert(pattern, mitigation_results)

        # Both email and SMS should be sent
        mock_email.assert_called_once()
        mock_sms.assert_called_once()

        # Check logging
        expected_calls = [
            call("Threat alert sent via email"),
            call("Threat alert sent via SMS"),
        ]
        self.mock_logger.info.assert_has_calls(expected_calls)

    @patch("alert_manager.send_email_alert")
    def test_send_threat_alert_email_disabled(self, mock_email):
        """Test threat alert when email is disabled."""
        self.alert_manager.config["email_service"]["enabled"] = False

        pattern = {"type": "XSS"}
        mitigation_results = []

        self.alert_manager.send_threat_alert(pattern, mitigation_results)

        # Email should not be sent
        mock_email.assert_not_called()

    @patch("alert_manager.send_email_alert")
    def test_send_threat_alert_exception_handling(self, mock_email):
        """Test exception handling in send_threat_alert."""
        mock_email.side_effect = Exception("Email service down")

        pattern = {"type": "Test"}
        mitigation_results = []

        self.alert_manager.send_threat_alert(pattern, mitigation_results)

        # Check error was logged
        self.mock_logger.error.assert_called_with(
            "Failed to send threat alert: Email service down"
        )

    @patch("alert_manager.send_email_alert")
    @patch("alert_manager.datetime")
    def test_send_emergency_alert(self, mock_datetime, mock_email):
        """Test sending emergency alert."""
        mock_datetime.now.return_value.isoformat.return_value = "2025-01-01T12:00:00"

        critical_threats = [
            {"type": "File Modification", "description": "Config file changed"},
            {"type": "Process Injection", "description": "Suspicious process"},
        ]

        self.alert_manager.send_emergency_alert(critical_threats)

        # Check email was sent with correct details
        mock_email.assert_called_once()
        email_args = mock_email.call_args[0][0]
        self.assertEqual(
            email_args["subject"], "🚨 CRITICAL: Security Monitor Service Under Attack"
        )
        self.assertIn("2 critical threats detected", email_args["pattern"]["request"])
        self.assertIn("CRITICAL THREATS DETECTED: 2", email_args["body"])
        self.assertIn("File Modification", email_args["body"])
        self.assertIn("Process Injection", email_args["body"])

        # Check logging
        self.mock_logger.info.assert_called_with("Emergency alert sent")

    @patch("alert_manager.send_email_alert")
    def test_send_emergency_alert_email_disabled(self, mock_email):
        """Test emergency alert when email is disabled."""
        self.alert_manager.config["email_service"]["enabled"] = False

        self.alert_manager.send_emergency_alert([])

        # Email should not be sent
        mock_email.assert_not_called()

    @patch("alert_manager.send_email_alert")
    def test_send_emergency_alert_exception_handling(self, mock_email):
        """Test exception handling in send_emergency_alert."""
        mock_email.side_effect = Exception("Network error")

        self.alert_manager.send_emergency_alert([])

        # Check error was logged
        self.mock_logger.error.assert_called_with(
            "Failed to send emergency alert: Network error"
        )

    @patch("alert_manager.send_email_alert")
    def test_send_service_threat_alert(self, mock_email):
        """Test sending service threat alert."""
        high_threats = [
            {"type": "Memory Corruption", "description": "Buffer overflow detected"},
            {
                "type": "Privilege Escalation",
                "description": "Unauthorized access attempt",
            },
        ]

        self.alert_manager.send_service_threat_alert(high_threats)

        # Check email was sent
        mock_email.assert_called_once()
        email_args = mock_email.call_args[0][0]
        self.assertEqual(
            email_args["subject"], "⚠️ Security Monitor Service Threats Detected"
        )
        self.assertEqual(email_args["pattern"]["severity"], "HIGH")
        self.assertIn("2 high-severity threats", email_args["pattern"]["request"])
        self.assertIn("HIGH-SEVERITY THREATS: 2", email_args["body"])

        # Check logging
        self.mock_logger.info.assert_called_with("Service threat alert sent")

    @patch("alert_manager.send_email_alert")
    def test_send_service_threat_alert_exception_handling(self, mock_email):
        """Test exception handling in send_service_threat_alert."""
        mock_email.side_effect = Exception("SMTP error")

        self.alert_manager.send_service_threat_alert([])

        # Check error was logged
        self.mock_logger.error.assert_called_with(
            "Failed to send service threat alert: SMTP error"
        )

    @patch("alert_manager.send_email_alert")
    def test_send_integration_alert(self, mock_email):
        """Test sending security integration alert."""
        threats = [
            {
                "source": "fail2ban",
                "type": "IP Block",
                "description": "Multiple failed logins",
            },
            {
                "source": "suricata",
                "type": "Network Intrusion",
                "description": "Suspicious traffic",
            },
            {
                "source": "fail2ban",
                "type": "Rate Limit",
                "description": "Too many requests",
            },
        ]

        self.alert_manager.send_integration_alert(threats)

        # Check email was sent
        mock_email.assert_called_once()
        email_args = mock_email.call_args[0][0]
        self.assertEqual(
            email_args["subject"], "🔒 Security Framework Alert: 3 threats detected"
        )
        # Check that both sources are mentioned (order may vary due to set())
        request_content = email_args["pattern"]["request"]
        self.assertIn("fail2ban", request_content)
        self.assertIn("suricata", request_content)
        self.assertIn("THREATS DETECTED BY SECURITY TOOLS: 3", email_args["body"])

        # Check logging
        self.mock_logger.info.assert_called_with("Security integration alert sent")

    @patch("alert_manager.send_email_alert")
    def test_send_integration_alert_exception_handling(self, mock_email):
        """Test exception handling in send_integration_alert."""
        mock_email.side_effect = Exception("Connection timeout")

        self.alert_manager.send_integration_alert([])

        # Check error was logged
        self.mock_logger.error.assert_called_with(
            "Failed to send integration alert: Connection timeout"
        )

    def test_create_threat_alert_body_with_pattern_and_mitigation(self):
        """Test threat alert body creation with pattern and mitigation results."""
        pattern = {
            "type": "SQL Injection",
            "ip": "192.168.1.100",
            "timestamp": "2025-01-01T12:00:00",
            "severity": "HIGH",
        }
        mitigation_results = [
            {"status": "success", "action": "blocked"},
            {"status": "success", "action": "logged"},
            {"status": "failed", "action": "rate_limit"},
        ]

        body = self.alert_manager._create_threat_alert_body(pattern, mitigation_results)

        self.assertIn("SQL Injection", body)
        self.assertIn("192.168.1.100", body)
        self.assertIn("2025-01-01T12:00:00", body)
        self.assertIn("HIGH", body)
        self.assertIn("3 countermeasure(s) applied", body)
        self.assertIn("2 successful response(s)", body)

    def test_create_threat_alert_body_missing_fields(self):
        """Test threat alert body creation with missing pattern fields."""
        pattern = {}  # Empty pattern
        mitigation_results = []

        body = self.alert_manager._create_threat_alert_body(pattern, mitigation_results)

        self.assertIn("Unknown", body)  # Default values
        self.assertIn("UNKNOWN", body)
        self.assertIn("0 countermeasure(s) applied", body)
        self.assertIn("0 successful response(s)", body)

    @patch("alert_manager.socket.gethostname")
    @patch("alert_manager.datetime")
    def test_create_emergency_alert_body(self, mock_datetime, mock_hostname):
        """Test emergency alert body creation."""
        mock_datetime.now.return_value.strftime.return_value = "2025-01-01 12:00:00"
        mock_hostname.return_value = "security-server-01"

        threats = [
            {
                "type": "File Tampering",
                "description": "Critical system file modified",
                "severity": "CRITICAL",
            },
            {
                "type": "Memory Corruption",
                "description": "Buffer overflow detected",
                "severity": "HIGH",
            },
        ]

        body = self.alert_manager._create_emergency_alert_body(threats)

        self.assertIn("CRITICAL THREATS DETECTED: 2", body)
        self.assertIn("File Tampering", body)
        self.assertIn("Memory Corruption", body)
        self.assertIn("Critical system file modified", body)
        self.assertIn("Buffer overflow detected", body)
        self.assertIn("2025-01-01 12:00:00", body)
        self.assertIn("security-server-01", body)
        self.assertIn("IMMEDIATE ACTION REQUIRED", body)

    @patch("alert_manager.datetime")
    def test_create_service_threat_alert_body(self, mock_datetime):
        """Test service threat alert body creation."""
        mock_datetime.now.return_value.strftime.return_value = "2025-01-01 12:00:00"

        threats = [
            {
                "type": "Privilege Escalation",
                "description": "Unauthorized access attempt",
            },
            {"type": "Code Injection"},  # Missing description
        ]

        body = self.alert_manager._create_service_threat_alert_body(threats)

        self.assertIn("HIGH-SEVERITY THREATS: 2", body)
        self.assertIn("Privilege Escalation: Unauthorized access attempt", body)
        self.assertIn("Code Injection: No description", body)
        self.assertIn("2025-01-01 12:00:00", body)
        self.assertIn("Recommended Actions", body)

    def test_create_integration_alert_body(self):
        """Test integration alert body creation."""
        threats = [
            {
                "source": "fail2ban",
                "severity": "HIGH",
                "description": "Multiple failed login attempts",
                "src_ip": "192.168.1.100",
                "timestamp": "2025-01-01T12:00:00",
            },
            {
                "source": "suricata",
                "severity": "MEDIUM",
                "description": "Suspicious network traffic",
                "src_ip": "10.0.0.1",
            },
            {
                "source": "fail2ban",
                "description": "Rate limit exceeded",  # Missing severity and other fields
            },
        ]

        body = self.alert_manager._create_integration_alert_body(threats)

        self.assertIn("THREATS DETECTED BY SECURITY TOOLS: 3", body)
        self.assertIn("FAIL2BAN (2 threats)", body)
        self.assertIn("SURICATA (1 threats)", body)
        self.assertIn("[HIGH] Multiple failed login attempts", body)
        self.assertIn("Source IP: 192.168.1.100", body)
        self.assertIn("Time: 2025-01-01T12:00:00", body)
        self.assertIn("[MEDIUM] Suspicious network traffic", body)
        self.assertIn("[UNKNOWN] Rate limit exceeded", body)
        self.assertIn("RECOMMENDED ACTIONS", body)

    def test_create_integration_alert_body_many_threats(self):
        """Test integration alert body with many threats (should truncate)."""
        threats = []
        for i in range(10):  # Create 10 threats from same source
            threats.append(
                {"source": "fail2ban", "description": f"Threat {i}", "severity": "HIGH"}
            )

        body = self.alert_manager._create_integration_alert_body(threats)

        self.assertIn("FAIL2BAN (10 threats)", body)
        self.assertIn(
            "... and 5 more threats", body
        )  # Should show only first 5, mention remaining 5

    def test_create_simple_threat_alert_body(self):
        """Test the _create_simple_threat_alert_body method (single threat)."""
        threat = {
            "type": "XSS Attack",
            "source_ip": "203.0.113.1",
            "timestamp": "2025-01-01T15:30:00",
            "severity": "MEDIUM",
        }

        body = self.alert_manager._create_simple_threat_alert_body(threat)

        self.assertIn("XSS Attack", body)
        self.assertIn("203.0.113.1", body)
        self.assertIn("2025-01-01T15:30:00", body)
        self.assertIn("MEDIUM", body)
        self.assertIn("Automated countermeasures applied", body)

    def test_create_simple_threat_alert_body_ip_fallback(self):
        """Test simple threat alert body with IP field fallback."""
        threat = {
            "type": "DDoS",
            "ip": "198.51.100.1",  # Should use this if source_ip not present
            "severity": "HIGH",
        }

        body = self.alert_manager._create_simple_threat_alert_body(threat)

        self.assertIn("198.51.100.1", body)

    def test_create_simple_threat_alert_body_defaults(self):
        """Test simple threat alert body with missing fields using defaults."""
        threat = {}  # Empty threat

        body = self.alert_manager._create_simple_threat_alert_body(threat)

        self.assertIn("Unknown", body)  # Default type and IP
        self.assertIn("UNKNOWN", body)  # Default severity


if __name__ == "__main__":
    unittest.main()
