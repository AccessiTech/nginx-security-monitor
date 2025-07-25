#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive tests for the email alert functionality.

These tests verify:
1. Email configuration loading
2. Email sending with various configurations
3. HTML and text body generation
4. Attachment handling (single and multiple)
5. SMTP error handling and retries
6. Fallback notifications
7. Security and edge cases
"""

import os
import unittest
import tempfile
import yaml
import smtplib
from unittest.mock import patch, MagicMock, mock_open
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from nginx_security_monitor.email_alert import (
    load_email_config,
    send_email_alert,
    create_text_alert_body,
    create_html_alert_body,
)


class TestEmailAlert(unittest.TestCase):
    """Test email alert functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.sample_alert = {
            "subject": "Security Alert: Suspicious Activity Detected",
            "recipient": "admin@example.com",
            "pattern": {
                "type": "Brute Force Attack",
                "severity": "HIGH",
                "ip": "192.168.1.100",
                "request": "POST /admin/login HTTP/1.1",
            },
            "timestamp": "2025-01-20 15:30:00",
            "details": "Multiple failed login attempts detected",
            "affected_service": "SSH",
            "location": "/var/log/auth.log",
        }

    def test_load_email_config_success(self):
        """Test successful email configuration loading."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = os.path.join(temp_dir, "email_config.yaml")
            config_data = {
                "email_service": {
                    "enabled": True,
                    "smtp_server": "smtp.example.com",
                    "smtp_port": 587,
                    "username": "alerts@example.com",
                    "password": "secret123",
                    "from_address": "alerts@example.com",
                    "to_address": "admin@example.com",
                    "use_tls": True,
                }
            }

            with open(config_file, "w") as f:
                yaml.dump(config_data, f)

            with patch("nginx_security_monitor.email_alert.ConfigManager") as mock_cm:
                mock_cm.get_instance.return_value.get.return_value = config_file

                result = load_email_config(config_file)
                expected = config_data["email_service"]
                self.assertEqual(result, expected)

    def test_load_email_config_default_path(self):
        """Test email configuration loading with default path from ConfigManager."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = os.path.join(temp_dir, "email_config.yaml")
            config_data = {
                "email_service": {"enabled": True, "smtp_server": "smtp.example.com"}
            }

            with open(config_file, "w") as f:
                yaml.dump(config_data, f)

            with patch("nginx_security_monitor.email_alert.ConfigManager") as mock_cm:
                mock_cm.get_instance.return_value.get.return_value = config_file

                # Call without config_path parameter to trigger default path logic
                result = load_email_config()
                expected = config_data["email_service"]
                self.assertEqual(result, expected)

    def test_load_email_config_file_not_found(self):
        """Test email configuration loading when file doesn't exist."""
        with patch("nginx_security_monitor.email_alert.ConfigManager") as mock_cm:
            mock_cm.get_instance.return_value.get.return_value = (
                "/nonexistent/config.yaml"
            )

            with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
                result = load_email_config("/nonexistent/config.yaml")
                self.assertEqual(result, {})
                mock_logging.error.assert_called_once()

    def test_load_email_config_invalid_yaml(self):
        """Test email configuration loading with invalid YAML."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = os.path.join(temp_dir, "invalid_config.yaml")

            with open(config_file, "w") as f:
                f.write("invalid: yaml: content: [")  # Invalid YAML

            with patch("nginx_security_monitor.email_alert.ConfigManager") as mock_cm:
                mock_cm.get_instance.return_value.get.return_value = config_file

                with patch(
                    "nginx_security_monitor.email_alert.logging"
                ) as mock_logging:
                    result = load_email_config(config_file)
                    self.assertEqual(result, {})
                    mock_logging.error.assert_called_once()

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    def test_send_email_alert_disabled(self, mock_cm, mock_load_config):
        """Test email sending when alerts are disabled."""
        mock_load_config.return_value = {"enabled": False}
        mock_cm.get_instance.return_value.get.return_value = False

        with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
            result = send_email_alert(self.sample_alert)
            self.assertIsNone(result)
            mock_logging.getLogger.return_value.info.assert_called_with(
                "Email alerts are disabled"
            )

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    def test_send_email_alert_missing_config(self, mock_cm, mock_load_config):
        """Test email sending with missing configuration."""
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value
        mock_cm_instance.get.side_effect = lambda key, default=None: {
            "alert_system.email.enabled": True,
            "alert_system.email.from_address": None,
            "alert_system.email.to_address": None,
        }.get(key, default)

        with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
            result = send_email_alert(self.sample_alert)
            self.assertIsNone(result)
            mock_logging.getLogger.return_value.error.assert_called_with(
                "Missing email configuration"
            )

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    def test_send_email_alert_success(
        self, mock_text_body, mock_html_body, mock_smtp, mock_cm, mock_load_config
    ):
        """Test successful email sending."""
        # Mock configuration
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value
        mock_cm_instance.get.side_effect = lambda key, default=None: {
            "alert_system.email.enabled": True,
            "alert_system.email.from_address": "alerts@example.com",
            "alert_system.email.to_address": "admin@example.com",
            "alert_system.email.smtp_server": "smtp.example.com",
            "alert_system.email.smtp_port": 587,
            "alert_system.email.username": "alerts@example.com",
            "alert_system.email.password": "secret123",
            "alert_system.email.use_tls": True,
            "alert_system.email.retry_count": 3,
            "alert_system.email.retry_delay": 2,
            "alert_system.email.debug_level": 0,
        }.get(key, default)

        # Mock body creation
        mock_text_body.return_value = "Text alert body"
        mock_html_body.return_value = "<html>HTML alert body</html>"

        # Mock SMTP
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
            result = send_email_alert(self.sample_alert)

            # Verify SMTP calls
            mock_smtp.assert_called_once_with("smtp.example.com", 587)
            mock_server.set_debuglevel.assert_called_once_with(0)
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once_with("alerts@example.com", "secret123")
            mock_server.send_message.assert_called_once()

            # Verify success log
            mock_logging.getLogger.return_value.info.assert_called_with(
                "Email alert sent successfully to admin@example.com"
            )

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    def test_send_email_alert_with_invalid_attachments(
        self, mock_text_body, mock_html_body, mock_smtp, mock_cm, mock_load_config
    ):
        """Test email sending with invalid attachment files."""
        # Mock configuration
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value
        mock_cm_instance.get.side_effect = lambda key, default=None: {
            "alert_system.email.enabled": True,
            "alert_system.email.from_address": "alerts@example.com",
            "alert_system.email.to_address": "admin@example.com",
            "alert_system.email.smtp_server": "smtp.example.com",
            "alert_system.email.smtp_port": 587,
            "alert_system.email.retry_count": 1,
        }.get(key, default)

        # Mock body creation
        mock_text_body.return_value = "Text alert body"
        mock_html_body.return_value = "<html>HTML alert body</html>"

        # Mock SMTP
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        # Add invalid attachments to alert
        alert_with_invalid_attachments = self.sample_alert.copy()
        alert_with_invalid_attachments["attachments"] = [
            "/nonexistent/file1.txt",
            "/nonexistent/file2.txt",
        ]

        with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
            result = send_email_alert(alert_with_invalid_attachments)

            # Verify error was logged for attachment failures
            mock_logging.getLogger.return_value.error.assert_called()

            # Verify email was still sent despite attachment failures
            mock_server.send_message.assert_called_once()

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    def test_send_email_alert_with_invalid_single_attachment(
        self, mock_text_body, mock_html_body, mock_smtp, mock_cm, mock_load_config
    ):
        """Test email sending with invalid single attachment file."""
        # Mock configuration
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value
        mock_cm_instance.get.side_effect = lambda key, default=None: {
            "alert_system.email.enabled": True,
            "alert_system.email.from_address": "alerts@example.com",
            "alert_system.email.to_address": "admin@example.com",
            "alert_system.email.smtp_server": "smtp.example.com",
            "alert_system.email.smtp_port": 587,
            "alert_system.email.retry_count": 1,
        }.get(key, default)

        # Mock body creation
        mock_text_body.return_value = "Text alert body"
        mock_html_body.return_value = "<html>HTML alert body</html>"

        # Mock SMTP
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        # Add invalid single attachment to alert
        alert_with_invalid_attachment = self.sample_alert.copy()
        alert_with_invalid_attachment["attachment"] = "/nonexistent/file.txt"

        with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
            result = send_email_alert(alert_with_invalid_attachment)

            # Verify error was logged for attachment failure
            mock_logging.getLogger.return_value.error.assert_called()

            # Verify email was still sent despite attachment failure
            mock_server.send_message.assert_called_once()

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    def test_send_email_alert_with_attachments(
        self, mock_text_body, mock_html_body, mock_smtp, mock_cm, mock_load_config
    ):
        """Test email sending with multiple attachments."""
        # Create test files
        with tempfile.TemporaryDirectory() as temp_dir:
            attachment1 = os.path.join(temp_dir, "log1.txt")
            attachment2 = os.path.join(temp_dir, "log2.txt")

            with open(attachment1, "w") as f:
                f.write("Log content 1")
            with open(attachment2, "w") as f:
                f.write("Log content 2")

            # Mock configuration
            mock_load_config.return_value = {"enabled": True}
            mock_cm_instance = mock_cm.get_instance.return_value
            mock_cm_instance.get.side_effect = lambda key, default=None: {
                "alert_system.email.enabled": True,
                "alert_system.email.from_address": "alerts@example.com",
                "alert_system.email.to_address": "admin@example.com",
                "alert_system.email.smtp_server": "smtp.example.com",
                "alert_system.email.smtp_port": 587,
                "alert_system.email.retry_count": 1,
            }.get(key, default)

            # Mock body creation
            mock_text_body.return_value = "Text alert body"
            mock_html_body.return_value = "<html>HTML alert body</html>"

            # Mock SMTP
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            # Add attachments to alert
            alert_with_attachments = self.sample_alert.copy()
            alert_with_attachments["attachments"] = [attachment1, attachment2]

            result = send_email_alert(alert_with_attachments)

            # Verify SMTP calls
            mock_server.send_message.assert_called_once()
        """Test email sending with multiple attachments."""
        # Create test files
        with tempfile.TemporaryDirectory() as temp_dir:
            attachment1 = os.path.join(temp_dir, "log1.txt")
            attachment2 = os.path.join(temp_dir, "log2.txt")

            with open(attachment1, "w") as f:
                f.write("Log content 1")
            with open(attachment2, "w") as f:
                f.write("Log content 2")

            # Mock configuration
            mock_load_config.return_value = {"enabled": True}
            mock_cm_instance = mock_cm.get_instance.return_value
            mock_cm_instance.get.side_effect = lambda key, default=None: {
                "alert_system.email.enabled": True,
                "alert_system.email.from_address": "alerts@example.com",
                "alert_system.email.to_address": "admin@example.com",
                "alert_system.email.smtp_server": "smtp.example.com",
                "alert_system.email.smtp_port": 587,
                "alert_system.email.retry_count": 1,
            }.get(key, default)

            # Mock body creation
            mock_text_body.return_value = "Text alert body"
            mock_html_body.return_value = "<html>HTML alert body</html>"

            # Mock SMTP
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            # Add attachments to alert
            alert_with_attachments = self.sample_alert.copy()
            alert_with_attachments["attachments"] = [attachment1, attachment2]

            result = send_email_alert(alert_with_attachments)

            # Verify SMTP calls
            mock_server.send_message.assert_called_once()

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    def test_send_email_alert_single_attachment(
        self, mock_text_body, mock_html_body, mock_smtp, mock_cm, mock_load_config
    ):
        """Test email sending with single attachment (backward compatibility)."""
        # Create test file
        with tempfile.TemporaryDirectory() as temp_dir:
            attachment = os.path.join(temp_dir, "log.txt")

            with open(attachment, "w") as f:
                f.write("Log content")

            # Mock configuration
            mock_load_config.return_value = {"enabled": True}
            mock_cm_instance = mock_cm.get_instance.return_value
            mock_cm_instance.get.side_effect = lambda key, default=None: {
                "alert_system.email.enabled": True,
                "alert_system.email.from_address": "alerts@example.com",
                "alert_system.email.to_address": "admin@example.com",
                "alert_system.email.smtp_server": "smtp.example.com",
                "alert_system.email.smtp_port": 587,
                "alert_system.email.retry_count": 1,
            }.get(key, default)

            # Mock body creation
            mock_text_body.return_value = "Text alert body"
            mock_html_body.return_value = "<html>HTML alert body</html>"

            # Mock SMTP
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            # Add single attachment to alert
            alert_with_attachment = self.sample_alert.copy()
            alert_with_attachment["attachment"] = attachment

            result = send_email_alert(alert_with_attachment)

            # Verify SMTP calls
            mock_server.send_message.assert_called_once()

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    @patch("time.sleep")
    def test_send_email_alert_retry_logic(
        self,
        mock_sleep,
        mock_text_body,
        mock_html_body,
        mock_smtp,
        mock_cm,
        mock_load_config,
    ):
        """Test email retry logic with exponential backoff."""
        # Mock configuration
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value
        mock_cm_instance.get.side_effect = lambda key, default=None: {
            "alert_system.email.enabled": True,
            "alert_system.email.from_address": "alerts@example.com",
            "alert_system.email.to_address": "admin@example.com",
            "alert_system.email.smtp_server": "smtp.example.com",
            "alert_system.email.smtp_port": 587,
            "alert_system.email.retry_count": 3,
            "alert_system.email.retry_delay": 1,
        }.get(key, default)

        # Mock body creation
        mock_text_body.return_value = "Text alert body"
        mock_html_body.return_value = "<html>HTML alert body</html>"

        # Mock SMTP to fail first two attempts, succeed on third
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        mock_server.send_message.side_effect = [
            smtplib.SMTPException("Connection failed"),
            smtplib.SMTPException("Auth failed"),
            None,  # Success on third attempt
        ]

        with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
            result = send_email_alert(self.sample_alert)

            # Verify retries
            self.assertEqual(mock_server.send_message.call_count, 3)
            self.assertEqual(mock_sleep.call_count, 2)  # Sleep between retries

            # Verify final success log
            mock_logging.getLogger.return_value.info.assert_called_with(
                "Email alert sent successfully to admin@example.com"
            )

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    @patch("time.sleep")
    def test_send_email_alert_all_retries_fail(
        self,
        mock_sleep,
        mock_text_body,
        mock_html_body,
        mock_smtp,
        mock_cm,
        mock_load_config,
    ):
        """Test email sending when all retry attempts fail."""
        # Mock configuration
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value
        mock_cm_instance.get.side_effect = lambda key, default=None: {
            "alert_system.email.enabled": True,
            "alert_system.email.from_address": "alerts@example.com",
            "alert_system.email.to_address": "admin@example.com",
            "alert_system.email.smtp_server": "smtp.example.com",
            "alert_system.email.smtp_port": 587,
            "alert_system.email.retry_count": 3,
            "alert_system.email.retry_delay": 1,
        }.get(key, default)

        # Mock body creation
        mock_text_body.return_value = "Text alert body"
        mock_html_body.return_value = "<html>HTML alert body</html>"

        # Mock SMTP to always fail
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        mock_server.send_message.side_effect = smtplib.SMTPException(
            "Persistent failure"
        )

        with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
            result = send_email_alert(self.sample_alert)

            # Verify all retries attempted
            self.assertEqual(mock_server.send_message.call_count, 3)
            self.assertEqual(mock_sleep.call_count, 2)  # Sleep between retries

            # Verify failure log
            mock_logging.getLogger.return_value.error.assert_called_with(
                "Failed to send email alert after 3 attempts"
            )

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    @patch("time.sleep")
    def test_send_email_alert_fallback_notification(
        self,
        mock_sleep,
        mock_text_body,
        mock_html_body,
        mock_smtp,
        mock_cm,
        mock_load_config,
    ):
        """Test fallback notification when all retry attempts fail."""
        # Mock configuration
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value
        mock_cm_instance.get.side_effect = lambda key, default=None: {
            "alert_system.email.enabled": True,
            "alert_system.email.from_address": "alerts@example.com",
            "alert_system.email.to_address": "admin@example.com",
            "alert_system.email.smtp_server": "smtp.example.com",
            "alert_system.email.smtp_port": 587,
            "alert_system.email.retry_count": 1,
            "alert_system.email.fallback_enabled": True,
            "alert_system.email.fallback_address": "backup@example.com",
        }.get(key, default)

        # Mock body creation
        mock_text_body.return_value = "Text alert body"
        mock_html_body.return_value = "<html>HTML alert body</html>"

        # Mock SMTP to always fail
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        mock_server.send_message.side_effect = smtplib.SMTPException(
            "Persistent failure"
        )

        with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
            result = send_email_alert(self.sample_alert)

            # Verify fallback notification was attempted
            mock_logging.getLogger.return_value.info.assert_called_with(
                "Attempting to send to fallback address: backup@example.com"
            )

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    @patch("time.sleep")
    def test_send_email_alert_fallback_error(
        self,
        mock_sleep,
        mock_text_body,
        mock_html_body,
        mock_smtp,
        mock_cm,
        mock_load_config,
    ):
        """Test fallback notification error handling."""
        # Mock configuration with exception in fallback logic
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value

        def config_side_effect(key, default=None):
            config_map = {
                "alert_system.email.enabled": True,
                "alert_system.email.from_address": "alerts@example.com",
                "alert_system.email.to_address": "admin@example.com",
                "alert_system.email.smtp_server": "smtp.example.com",
                "alert_system.email.smtp_port": 587,
                "alert_system.email.retry_count": 1,
                "alert_system.email.fallback_enabled": True,
            }
            if key == "alert_system.email.fallback_address":
                raise Exception("Config error")
            return config_map.get(key, default)

        mock_cm_instance.get.side_effect = config_side_effect

        # Mock body creation
        mock_text_body.return_value = "Text alert body"
        mock_html_body.return_value = "<html>HTML alert body</html>"

        # Mock SMTP to always fail
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server
        mock_server.send_message.side_effect = smtplib.SMTPException(
            "Persistent failure"
        )

        with patch("nginx_security_monitor.email_alert.logging") as mock_logging:
            result = send_email_alert(self.sample_alert)

            # Verify fallback error was logged
            mock_logging.getLogger.return_value.error.assert_called_with(
                "Fallback notification failed: Config error"
            )

    def test_create_text_alert_body_complete(self):
        """Test text alert body creation with complete alert details."""
        result = create_text_alert_body(self.sample_alert)

        # Verify key information is included
        self.assertIn("Security Alert", result)
        self.assertIn("Brute Force Attack", result)
        self.assertIn("HIGH", result)
        self.assertIn("192.168.1.100", result)
        self.assertIn("2025-01-20 15:30:00", result)
        self.assertIn("POST /admin/login", result)

    def test_create_text_alert_body_minimal(self):
        """Test text alert body creation with minimal alert details."""
        minimal_alert = {
            "pattern": "Suspicious Activity",
            "timestamp": "2025-01-20 15:30:00",
        }

        result = create_text_alert_body(minimal_alert)

        # Verify basic structure is maintained
        self.assertIn("Security Alert", result)
        self.assertIn("Suspicious Activity", result)
        self.assertIn("2025-01-20 15:30:00", result)

    def test_create_html_alert_body_complete(self):
        """Test HTML alert body creation with complete alert details."""
        result = create_html_alert_body(self.sample_alert)

        # Verify HTML structure
        self.assertIn("<html>", result)
        self.assertIn("</html>", result)
        self.assertIn("<body", result)  # May have style attributes
        self.assertIn("</body>", result)

        # Verify content - detailed alert with pattern dict
        self.assertIn("Security Alert", result)
        self.assertIn("Brute Force Attack", result)
        self.assertIn("HIGH", result)
        self.assertIn("192.168.1.100", result)
        self.assertIn("2025-01-20 15:30:00", result)

        # Verify styling is applied
        self.assertIn("style=", result)

    def test_create_html_alert_body_minimal(self):
        """Test HTML alert body creation with minimal alert details."""
        minimal_alert = {"pattern": "Test Alert", "timestamp": "2025-01-20 15:30:00"}

        result = create_html_alert_body(minimal_alert)

        # Verify HTML structure is maintained
        self.assertIn("<html>", result)
        self.assertIn("</html>", result)
        self.assertIn("Test Alert", result)
        self.assertIn("2025-01-20 15:30:00", result)

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    def test_send_email_alert_no_tls(
        self, mock_text_body, mock_html_body, mock_smtp, mock_cm, mock_load_config
    ):
        """Test email sending without TLS."""
        # Mock configuration without TLS
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value
        mock_cm_instance.get.side_effect = lambda key, default=None: {
            "alert_system.email.enabled": True,
            "alert_system.email.from_address": "alerts@example.com",
            "alert_system.email.to_address": "admin@example.com",
            "alert_system.email.smtp_server": "smtp.example.com",
            "alert_system.email.smtp_port": 25,
            "alert_system.email.use_tls": False,
            "alert_system.email.retry_count": 1,
        }.get(key, default)

        # Mock body creation
        mock_text_body.return_value = "Text alert body"
        mock_html_body.return_value = "<html>HTML alert body</html>"

        # Mock SMTP
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = send_email_alert(self.sample_alert)

        # Verify TLS was not called
        mock_server.starttls.assert_not_called()
        # Verify message was still sent
        mock_server.send_message.assert_called_once()

    @patch("nginx_security_monitor.email_alert.load_email_config")
    @patch("nginx_security_monitor.email_alert.ConfigManager")
    @patch("nginx_security_monitor.email_alert.smtplib.SMTP")
    @patch("nginx_security_monitor.email_alert.create_html_alert_body")
    @patch("nginx_security_monitor.email_alert.create_text_alert_body")
    def test_send_email_alert_no_auth(
        self, mock_text_body, mock_html_body, mock_smtp, mock_cm, mock_load_config
    ):
        """Test email sending without authentication."""
        # Mock configuration without auth
        mock_load_config.return_value = {"enabled": True}
        mock_cm_instance = mock_cm.get_instance.return_value
        mock_cm_instance.get.side_effect = lambda key, default=None: {
            "alert_system.email.enabled": True,
            "alert_system.email.from_address": "alerts@example.com",
            "alert_system.email.to_address": "admin@example.com",
            "alert_system.email.smtp_server": "localhost",
            "alert_system.email.smtp_port": 25,
            "alert_system.email.username": None,
            "alert_system.email.password": None,
            "alert_system.email.retry_count": 1,
        }.get(key, default)

        # Mock body creation
        mock_text_body.return_value = "Text alert body"
        mock_html_body.return_value = "<html>HTML alert body</html>"

        # Mock SMTP
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        result = send_email_alert(self.sample_alert)

        # Verify login was not called
        mock_server.login.assert_not_called()
        # Verify message was still sent
        mock_server.send_message.assert_called_once()

    def test_create_html_alert_body_with_special_characters(self):
        """Test HTML alert body creation with special characters that need escaping."""
        alert_with_special_chars = {
            "pattern": 'SQL Injection with <script>alert("xss")</script>',
            "timestamp": "2025-01-20 15:30:00",
        }

        result = create_html_alert_body(alert_with_special_chars)

        # Verify HTML structure
        self.assertIn("<html>", result)
        self.assertIn("</html>", result)

        # Verify content is included (though may be escaped)
        self.assertIn("SQL Injection", result)
        self.assertIn("2025-01-20 15:30:00", result)


if __name__ == "__main__":
    unittest.main()
