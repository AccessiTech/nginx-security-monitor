import unittest
from unittest.mock import patch, MagicMock, mock_open
import yaml

from nginx_security_monitor.email_alert import send_email_alert, load_email_config
from nginx_security_monitor.sms_alert import send_sms_alert


class TestAlerts(unittest.TestCase):

    @patch("nginx_security_monitor.email_alert.load_email_config")
    def test_send_email_alert(self, mock_load_config):
        # Mock email configuration
        mock_load_config.return_value = {
            "enabled": True,
            "from_address": "alert@example.com",
            "to_address": "admin@example.com",
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "username": "alert@example.com",
            "password": "password",
            "use_tls": True,
        }

        alert_details = {
            "subject": "Test Alert",
            "message": "This is a test email alert.",
            "recipient": "test@example.com",
        }

        # Mock the SMTP context manager to avoid actual email sending
        with patch("smtplib.SMTP") as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            # The function should run without errors when properly configured
            result = send_email_alert(alert_details)

            # Function returns None on success or failure, so just check it doesn't crash
            self.assertIsNone(result)

    def test_send_sms_alert(self):
        alert_details = {
            "message": "This is a test SMS alert.",
            "recipient": "+1234567890",
        }

        # The SMS function should run without crashing
        result = send_sms_alert(alert_details)
        # The current implementation returns True for success
        self.assertTrue(result)

    def test_send_sms_alert_exception_handling(self):
        """Test SMS alert exception handling by mocking a failure."""
        alert_details = {
            "message": "This is a test SMS alert.",
            "recipient": "+1234567890",
        }

        # Mock print to capture the exception handling
        with patch("builtins.print") as mock_print:
            # Patch the print statement that would normally execute to raise an exception
            def print_side_effect(*args, **kwargs):
                if "Sending SMS" in str(args[0]):
                    raise Exception("SMS service unavailable")
                return None

            mock_print.side_effect = print_side_effect

            # Should return False when an exception occurs
            result = send_sms_alert(alert_details)
            self.assertFalse(result)

            # Check that the error message was printed
            self.assertTrue(
                any(
                    "Failed to send SMS:" in str(call)
                    for call in mock_print.call_args_list
                )
            )

    def test_create_text_alert_body_with_dict_pattern(self):
        """Test text alert body creation with dict pattern."""
        from nginx_security_monitor.email_alert import create_text_alert_body
        from datetime import datetime

        alert_details = {
            "pattern": {
                "type": "SQL Injection",
                "ip": "192.168.1.100",
                "severity": "HIGH",
                "request": "GET /admin?id=1' OR 1=1--",
            },
            "timestamp": "2024-01-01T12:00:00",
        }

        body = create_text_alert_body(alert_details)

        self.assertIn("SQL Injection", body)
        self.assertIn("192.168.1.100", body)
        self.assertIn("HIGH", body)
        self.assertIn("2024-01-01T12:00:00", body)
        self.assertIn("GET /admin?id=1' OR 1=1--", body)

    def test_create_html_alert_body_with_dict_pattern(self):
        """Test HTML alert body creation with dict pattern."""
        from nginx_security_monitor.email_alert import create_html_alert_body

        alert_details = {
            "pattern": {
                "type": "XSS Attack",
                "ip": "10.0.0.50",
                "severity": "MEDIUM",
                "request": "GET /search?q=<script>alert(1)</script>",
            },
            "timestamp": "2024-01-01T15:30:00",
        }

        body = create_html_alert_body(alert_details)

        self.assertIn("XSS Attack", body)
        self.assertIn("10.0.0.50", body)
        self.assertIn("MEDIUM", body)
        self.assertIn("#fd7e14", body)  # Orange color for MEDIUM severity
        self.assertIn("2024-01-01T15:30:00", body)
        self.assertIn("<script>alert(1)</script>", body)

    def test_create_html_alert_body_with_low_severity(self):
        """Test HTML alert body creation with LOW severity for color coverage."""
        from nginx_security_monitor.email_alert import create_html_alert_body

        alert_details = {
            "pattern": {
                "type": "Suspicious Request",
                "ip": "172.16.0.10",
                "severity": "LOW",
                "request": "GET /admin",
            }
        }

        body = create_html_alert_body(alert_details)

        self.assertIn("Suspicious Request", body)
        self.assertIn("#ffc107", body)  # Yellow color for LOW severity

    def test_create_html_alert_body_with_unknown_severity(self):
        """Test HTML alert body creation with unknown severity for default color coverage."""
        from nginx_security_monitor.email_alert import create_html_alert_body

        alert_details = {
            "pattern": {
                "type": "Unknown Threat",
                "ip": "203.0.113.1",
                "severity": "UNKNOWN_SEVERITY",
                "request": "POST /api/data",
            }
        }

        body = create_html_alert_body(alert_details)

        self.assertIn("Unknown Threat", body)
        self.assertIn("#6c757d", body)  # Default gray color for unknown severity

    # Email Alert Tests - Enhanced Coverage

    def test_load_email_config_success(self):
        """Test successful email config loading."""
        mock_config = {
            "email_service": {
                "enabled": True,
                "from_address": "test@example.com",
                "to_address": "admin@example.com",
                "smtp_server": "smtp.example.com",
                "smtp_port": 587,
                "username": "test@example.com",
                "password": "password123",
                "use_tls": True,
            }
        }

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("yaml.safe_load", return_value=mock_config):
                config = load_email_config("/test/path/settings.yaml")

                expected = mock_config["email_service"]
                self.assertEqual(config, expected)

    def test_load_email_config_file_not_found(self):
        """Test email config loading when file doesn't exist."""
        with patch("builtins.open", side_effect=FileNotFoundError("File not found")):
            with patch("logging.error") as mock_log:
                config = load_email_config("/nonexistent/path.yaml")

                self.assertEqual(config, {})
                mock_log.assert_called_once()

    def test_load_email_config_yaml_error(self):
        """Test email config loading with YAML parsing error."""
        with patch("builtins.open", mock_open(read_data="invalid: yaml: content:")):
            with patch("yaml.safe_load", side_effect=yaml.YAMLError("Invalid YAML")):
                with patch("logging.error") as mock_log:
                    config = load_email_config("/test/path.yaml")

                    self.assertEqual(config, {})
                    mock_log.assert_called_once()

    def test_load_email_config_no_email_service(self):
        """Test email config loading when email_service section is missing."""
        mock_config = {"other_service": {"enabled": True}}

        with patch("builtins.open", mock_open(read_data=yaml.dump(mock_config))):
            with patch("yaml.safe_load", return_value=mock_config):
                config = load_email_config("/test/path.yaml")

                self.assertEqual(config, {})

    @patch("nginx_security_monitor.email_alert.load_email_config")
    def test_send_email_alert_disabled(self, mock_load_config):
        """Test send_email_alert when email is disabled."""
        mock_load_config.return_value = {"enabled": False}

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            result = send_email_alert({"subject": "Test"})

            self.assertIsNone(result)
            mock_logger.info.assert_called_with("Email alerts are disabled")

    @patch("nginx_security_monitor.email_alert.load_email_config")
    def test_send_email_alert_missing_sender(self, mock_load_config):
        """Test send_email_alert with missing sender configuration."""
        mock_load_config.return_value = {
            "enabled": True,
            "to_address": "admin@example.com",
            # Missing from_address and username
        }

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            result = send_email_alert({"subject": "Test"})

            self.assertIsNone(result)
            mock_logger.error.assert_called_with("Missing email configuration")

    @patch("nginx_security_monitor.email_alert.load_email_config")
    def test_send_email_alert_missing_recipient(self, mock_load_config):
        """Test send_email_alert with missing recipient configuration."""
        mock_load_config.return_value = {
            "enabled": True,
            "from_address": "sender@example.com",
            # Missing to_address
        }

        alert_details = {
            "subject": "Test Alert"
            # Missing recipient
        }

        with patch("logging.getLogger") as mock_get_logger:
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            result = send_email_alert(alert_details)

            self.assertIsNone(result)
            mock_logger.error.assert_called_with("Missing email configuration")

    @patch("nginx_security_monitor.email_alert.load_email_config")
    def test_send_email_alert_with_custom_config_path(self, mock_load_config):
        """Test send_email_alert with custom config path."""
        mock_load_config.return_value = {
            "enabled": True,
            "from_address": "sender@example.com",
            "to_address": "recipient@example.com",
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "use_tls": True,
        }

        alert_details = {"subject": "Test Alert", "message": "Test message"}

        with patch("smtplib.SMTP") as mock_smtp, patch(
            "nginx_security_monitor.email_alert.create_html_alert_body",
            return_value="<html>Test</html>",
        ), patch(
            "nginx_security_monitor.email_alert.create_text_alert_body",
            return_value="Test text",
        ):

            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            result = send_email_alert(alert_details, config_path="/custom/config.yaml")

            # Should call load_email_config with custom path
            mock_load_config.assert_called_with("/custom/config.yaml")
            self.assertIsNone(result)

    @patch("nginx_security_monitor.email_alert.load_email_config")
    def test_send_email_alert_smtp_exception(self, mock_load_config):
        """Test send_email_alert with SMTP connection error."""
        mock_load_config.return_value = {
            "enabled": True,
            "from_address": "sender@example.com",
            "to_address": "recipient@example.com",
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
            "use_tls": True,
        }

        alert_details = {"subject": "Test Alert", "message": "Test message"}

        with patch(
            "smtplib.SMTP", side_effect=Exception("SMTP connection failed")
        ), patch(
            "nginx_security_monitor.email_alert.create_html_alert_body",
            return_value="<html>Test</html>",
        ), patch(
            "nginx_security_monitor.email_alert.create_text_alert_body",
            return_value="Test text",
        ), patch(
            "logging.getLogger"
        ) as mock_get_logger:

            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            result = send_email_alert(alert_details)

            self.assertIsNone(result)
            # Should log the error
            mock_logger.error.assert_called()

    @patch("nginx_security_monitor.email_alert.load_email_config")
    def test_send_email_alert_fallback_username_as_sender(self, mock_load_config):
        """Test send_email_alert using username as sender when from_address is missing."""
        mock_load_config.return_value = {
            "enabled": True,
            "username": "user@example.com",  # No from_address, should use username
            "to_address": "recipient@example.com",
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
        }

        alert_details = {"subject": "Test Alert", "message": "Test message"}

        with patch("smtplib.SMTP") as mock_smtp, patch(
            "nginx_security_monitor.email_alert.create_html_alert_body",
            return_value="<html>Test</html>",
        ), patch(
            "nginx_security_monitor.email_alert.create_text_alert_body",
            return_value="Test text",
        ):

            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            result = send_email_alert(alert_details)

            self.assertIsNone(result)
            # Verify SMTP was called (meaning username was used as sender)
            mock_smtp.assert_called_once()

    @patch("nginx_security_monitor.email_alert.load_email_config")
    def test_send_email_alert_recipient_from_alert_details(self, mock_load_config):
        """Test send_email_alert using recipient from alert_details over config."""
        mock_load_config.return_value = {
            "enabled": True,
            "from_address": "sender@example.com",
            "to_address": "config_recipient@example.com",  # Should be overridden
            "smtp_server": "smtp.example.com",
        }

        alert_details = {
            "subject": "Test Alert",
            "recipient": "alert_recipient@example.com",  # This should take precedence
            "message": "Test message",
        }

        with patch("smtplib.SMTP") as mock_smtp, patch(
            "nginx_security_monitor.email_alert.create_html_alert_body",
            return_value="<html>Test</html>",
        ), patch(
            "nginx_security_monitor.email_alert.create_text_alert_body",
            return_value="Test text",
        ):

            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server

            result = send_email_alert(alert_details)

            self.assertIsNone(result)
            # Verify SMTP was called successfully
            mock_smtp.assert_called_once()


if __name__ == "__main__":
    unittest.main()
