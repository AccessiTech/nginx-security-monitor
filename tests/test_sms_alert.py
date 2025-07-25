#!/usr/bin/env python3
"""
Comprehensive tests for SMS Alert module
"""

import unittest
from unittest.mock import patch, MagicMock, call
import time

from nginx_security_monitor.sms_alert import (
    send_sms_alert,
    send_via_twilio,
    send_via_aws_sns,
)


class TestSMSAlert(unittest.TestCase):
    """Test cases for SMS Alert functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.basic_alert = {
            "message": "Test security alert",
            "recipient": "+1234567890",
        }

        self.config_alert = {
            "message": "Security breach detected in system XYZ",
            "severity": "high",
            "timestamp": "2024-01-15T10:30:00Z",
        }

    def test_send_sms_alert_basic_compatibility(self):
        """Test basic SMS alert sending with recipient and message."""
        result = send_sms_alert(self.basic_alert)
        self.assertTrue(result)

    def test_send_sms_alert_basic_exception(self):
        """Test basic SMS alert exception handling."""
        alert_details = {"message": "Test message", "recipient": "+1234567890"}

        # Create a more targeted mock that only fails on the first print call
        def print_side_effect(*args, **kwargs):
            if "Sending SMS" in str(args[0]):
                raise Exception("Network error")
            # Allow the error print to work normally

        with patch("builtins.print", side_effect=print_side_effect) as mock_print:
            result = send_sms_alert(alert_details)
            self.assertFalse(result)
            # Verify both print calls were attempted
            self.assertEqual(mock_print.call_count, 2)

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    def test_send_sms_alert_disabled(self, mock_config_manager):
        """Test SMS alert when SMS is disabled."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": False
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config

        with patch("nginx_security_monitor.sms_alert.logging.getLogger") as mock_logger:
            mock_log = MagicMock()
            mock_logger.return_value = mock_log

            result = send_sms_alert(self.config_alert)

            self.assertFalse(result)
            mock_log.info.assert_called_with("SMS alerts are disabled")

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    def test_send_sms_alert_no_recipient(self, mock_config_manager):
        """Test SMS alert when no recipient is specified."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": True,
            "alert_system.sms.default_recipient": "",
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config

        with patch("nginx_security_monitor.sms_alert.logging.getLogger") as mock_logger:
            mock_log = MagicMock()
            mock_logger.return_value = mock_log

            alert_without_recipient = {"message": "Test alert"}
            result = send_sms_alert(alert_without_recipient)

            self.assertFalse(result)
            mock_log.error.assert_called_with("No SMS recipient specified")

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    def test_send_sms_alert_message_truncation(self, mock_config_manager):
        """Test message truncation when message exceeds max length."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": True,
            "alert_system.sms.provider": "dummy",
            "alert_system.sms.max_length": 50,
            "alert_system.sms.retry_count": 1,
            "alert_system.sms.default_recipient": "+1234567890",
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config

        with patch("nginx_security_monitor.sms_alert.logging.getLogger") as mock_logger:
            mock_log = MagicMock()
            mock_logger.return_value = mock_log

            long_message_alert = {
                "message": "This is a very long message that exceeds the maximum length limit and should be truncated"
            }

            result = send_sms_alert(long_message_alert)

            self.assertTrue(result)
            # Check that the logged message is truncated
            logged_calls = mock_log.info.call_args_list
            self.assertTrue(any("..." in str(call) for call in logged_calls))

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    def test_send_sms_alert_dummy_provider(self, mock_config_manager):
        """Test SMS sending with dummy provider."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": True,
            "alert_system.sms.provider": "dummy",
            "alert_system.sms.retry_count": 1,
            "alert_system.sms.default_recipient": "+1234567890",
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config

        with patch("nginx_security_monitor.sms_alert.logging.getLogger") as mock_logger:
            mock_log = MagicMock()
            mock_logger.return_value = mock_log

            result = send_sms_alert(self.config_alert)

            self.assertTrue(result)
            # Check that dummy SMS was logged
            mock_log.info.assert_called()
            logged_message = str(mock_log.info.call_args)
            self.assertIn("[DUMMY SMS]", logged_message)

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    @patch("nginx_security_monitor.sms_alert.send_via_twilio")
    def test_send_sms_alert_twilio_provider(
        self, mock_send_twilio, mock_config_manager
    ):
        """Test SMS sending with Twilio provider."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": True,
            "alert_system.sms.provider": "twilio",
            "alert_system.sms.api_key": "test_account_sid",
            "alert_system.sms.api_secret": "test_auth_token",
            "alert_system.sms.from_number": "+0987654321",
            "alert_system.sms.retry_count": 1,
            "alert_system.sms.default_recipient": "+1234567890",
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config
        mock_send_twilio.return_value = True

        result = send_sms_alert(self.config_alert)

        self.assertTrue(result)
        mock_send_twilio.assert_called_once_with(
            "test_account_sid",
            "test_auth_token",
            "+0987654321",
            "+1234567890",
            "Security breach detected in system XYZ",
        )

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    @patch("nginx_security_monitor.sms_alert.send_via_aws_sns")
    def test_send_sms_alert_aws_sns_provider(self, mock_send_aws, mock_config_manager):
        """Test SMS sending with AWS SNS provider."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": True,
            "alert_system.sms.provider": "aws_sns",
            "alert_system.sms.api_key": "test_access_key",
            "alert_system.sms.api_secret": "test_secret_key",
            "alert_system.sms.retry_count": 1,
            "alert_system.sms.default_recipient": "+1234567890",
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config
        mock_send_aws.return_value = True

        result = send_sms_alert(self.config_alert)

        self.assertTrue(result)
        mock_send_aws.assert_called_once_with(
            "test_access_key",
            "test_secret_key",
            "+1234567890",
            "Security breach detected in system XYZ",
        )

    @patch("time.sleep")
    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    def test_send_sms_alert_retry_logic(self, mock_config_manager, mock_sleep):
        """Test SMS retry logic with exponential backoff."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": True,
            "alert_system.sms.provider": "dummy",
            "alert_system.sms.retry_count": 3,
            "alert_system.sms.retry_delay": 2,
            "alert_system.sms.default_recipient": "+1234567890",
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config

        with patch("nginx_security_monitor.sms_alert.logging.getLogger") as mock_logger:
            mock_log = MagicMock()
            mock_logger.return_value = mock_log

            # Make logging.info raise an exception to simulate dummy provider failure
            mock_log.info.side_effect = Exception("SMS service down")

            result = send_sms_alert(self.config_alert)

            self.assertFalse(result)
            # Check that sleep was called with exponential backoff (2, 4)
            expected_calls = [call(2), call(4)]
            mock_sleep.assert_has_calls(expected_calls)
            # Check that all attempts were logged
            self.assertEqual(
                mock_log.error.call_count, 4
            )  # 3 attempt errors + 1 final error

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    def test_send_sms_alert_recipient_priority(self, mock_config_manager):
        """Test recipient priority: alert details > default config."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": True,
            "alert_system.sms.provider": "dummy",
            "alert_system.sms.retry_count": 1,
            "alert_system.sms.default_recipient": "+0000000000",
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config

        # This alert has a recipient, so it should use the basic path
        alert_with_recipient = {"message": "Test alert", "recipient": "+1111111111"}

        # The alert has both message and recipient, so it uses the basic compatibility path
        result = send_sms_alert(alert_with_recipient)
        self.assertTrue(result)

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    def test_send_sms_alert_default_message(self, mock_config_manager):
        """Test default message when no message provided."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": True,
            "alert_system.sms.provider": "dummy",
            "alert_system.sms.retry_count": 1,
            "alert_system.sms.default_recipient": "+1234567890",
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config

        with patch("nginx_security_monitor.sms_alert.logging.getLogger") as mock_logger:
            mock_log = MagicMock()
            mock_logger.return_value = mock_log

            alert_no_message = {}
            result = send_sms_alert(alert_no_message)

            self.assertTrue(result)
            # Check that default message was used
            logged_message = str(mock_log.info.call_args)
            self.assertIn("Security alert: Check your system", logged_message)

    def test_send_via_twilio_missing_package(self):
        """Test Twilio SMS when package is not installed."""
        with patch("importlib.util.find_spec", return_value=None):
            with patch(
                "nginx_security_monitor.sms_alert.logging.getLogger"
            ) as mock_logger:
                mock_log = MagicMock()
                mock_logger.return_value = mock_log

                result = send_via_twilio("sid", "token", "+1111", "+2222", "test")

                self.assertFalse(result)
                mock_log.error.assert_called_with(
                    "Twilio package not installed. Install with: pip install twilio"
                )

    @patch("importlib.util.find_spec")
    def test_send_via_twilio_success(self, mock_find_spec):
        """Test successful Twilio SMS sending."""
        # Mock that twilio package is available
        mock_find_spec.return_value = MagicMock()

        # Mock the entire twilio.rest module and Client class
        with patch.dict(
            "sys.modules", {"twilio": MagicMock(), "twilio.rest": MagicMock()}
        ):
            # Import after mocking sys.modules
            import sys

            mock_client = MagicMock()
            mock_message = MagicMock()
            mock_message.sid = "SM123456789"
            mock_client.messages.create.return_value = mock_message

            # Mock the Client class
            sys.modules["twilio.rest"].Client = MagicMock(return_value=mock_client)

            with patch(
                "nginx_security_monitor.sms_alert.logging.getLogger"
            ) as mock_logger:
                mock_log = MagicMock()
                mock_logger.return_value = mock_log

                result = send_via_twilio(
                    "test_sid", "test_token", "+1111", "+2222", "Test message"
                )

                self.assertTrue(result)
                mock_client.messages.create.assert_called_once_with(
                    body="Test message", from_="+1111", to="+2222"
                )
                mock_log.info.assert_called_with(
                    "SMS sent via Twilio. SID: SM123456789"
                )

    @patch("importlib.util.find_spec")
    def test_send_via_twilio_exception(self, mock_find_spec):
        """Test Twilio SMS exception handling."""
        # Mock that twilio package is available
        mock_find_spec.return_value = MagicMock()

        with patch.dict(
            "sys.modules", {"twilio": MagicMock(), "twilio.rest": MagicMock()}
        ):
            # Import after mocking sys.modules
            import sys

            # Make the Client constructor raise an exception
            sys.modules["twilio.rest"].Client = MagicMock(
                side_effect=Exception("Twilio API error")
            )

            with patch(
                "nginx_security_monitor.sms_alert.logging.getLogger"
            ) as mock_logger:
                mock_log = MagicMock()
                mock_logger.return_value = mock_log

                result = send_via_twilio("sid", "token", "+1111", "+2222", "test")

                self.assertFalse(result)
                mock_log.error.assert_called_with(
                    "Failed to send SMS via Twilio: Twilio API error"
                )

    def test_send_via_aws_sns_missing_package(self):
        """Test AWS SNS SMS when boto3 package is not installed."""
        with patch("importlib.util.find_spec", return_value=None):
            with patch(
                "nginx_security_monitor.sms_alert.logging.getLogger"
            ) as mock_logger:
                mock_log = MagicMock()
                mock_logger.return_value = mock_log

                result = send_via_aws_sns("key", "secret", "+1234567890", "test")

                self.assertFalse(result)
                mock_log.error.assert_called_with(
                    "boto3 package not installed. Install with: pip install boto3"
                )

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    @patch("importlib.util.find_spec")
    def test_send_via_aws_sns_success(self, mock_find_spec, mock_config_manager):
        """Test successful AWS SNS SMS sending."""
        # Mock that boto3 package is available
        mock_find_spec.return_value = MagicMock()

        # Mock config manager
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.aws_sns.region": "us-west-2"
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config

        with patch.dict("sys.modules", {"boto3": MagicMock()}):
            import sys

            # Mock boto3 client
            mock_client = MagicMock()
            mock_response = {"MessageId": "msg-123456"}
            mock_client.publish.return_value = mock_response
            sys.modules["boto3"].client.return_value = mock_client

            with patch(
                "nginx_security_monitor.sms_alert.logging.getLogger"
            ) as mock_logger:
                mock_log = MagicMock()
                mock_logger.return_value = mock_log

                result = send_via_aws_sns(
                    "test_key", "test_secret", "+1234567890", "Test AWS message"
                )

                self.assertTrue(result)
                sys.modules["boto3"].client.assert_called_once_with(
                    "sns",
                    aws_access_key_id="test_key",
                    aws_secret_access_key="test_secret",
                    region_name="us-west-2",
                )
                mock_client.publish.assert_called_once_with(
                    PhoneNumber="+1234567890",
                    Message="Test AWS message",
                    MessageAttributes={
                        "AWS.SNS.SMS.SenderID": {
                            "DataType": "String",
                            "StringValue": "NGXSECMON",
                        }
                    },
                )
                mock_log.info.assert_called_with(
                    "SMS sent via AWS SNS. Message ID: msg-123456"
                )

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    @patch("importlib.util.find_spec")
    def test_send_via_aws_sns_default_region(self, mock_find_spec, mock_config_manager):
        """Test AWS SNS with default region."""
        # Mock that boto3 package is available
        mock_find_spec.return_value = MagicMock()

        # Mock config manager to return default
        mock_config = MagicMock()
        mock_config.get.return_value = "us-east-1"  # Default region
        mock_config_manager.get_instance.return_value = mock_config

        with patch.dict("sys.modules", {"boto3": MagicMock()}):
            import sys

            mock_client = MagicMock()
            mock_response = {"MessageId": "msg-default"}
            mock_client.publish.return_value = mock_response
            sys.modules["boto3"].client.return_value = mock_client

            with patch("nginx_security_monitor.sms_alert.logging.getLogger"):
                result = send_via_aws_sns("key", "secret", "+1234567890", "test")

                self.assertTrue(result)
                sys.modules["boto3"].client.assert_called_once_with(
                    "sns",
                    aws_access_key_id="key",
                    aws_secret_access_key="secret",
                    region_name="us-east-1",
                )

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    @patch("importlib.util.find_spec")
    def test_send_via_aws_sns_exception(self, mock_find_spec, mock_config_manager):
        """Test AWS SNS exception handling."""
        # Mock that boto3 package is available
        mock_find_spec.return_value = MagicMock()

        mock_config = MagicMock()
        mock_config.get.return_value = "us-east-1"
        mock_config_manager.get_instance.return_value = mock_config

        with patch.dict("sys.modules", {"boto3": MagicMock()}):
            import sys

            # Mock boto3 client that raises an exception during creation
            sys.modules["boto3"].client.side_effect = Exception("AWS API error")

            with patch(
                "nginx_security_monitor.sms_alert.logging.getLogger"
            ) as mock_logger:
                mock_log = MagicMock()
                mock_logger.return_value = mock_log

                result = send_via_aws_sns("key", "secret", "+1234567890", "test")

                self.assertFalse(result)
                mock_log.error.assert_called_with(
                    "Failed to send SMS via AWS SNS: AWS API error"
                )

    @patch("nginx_security_monitor.sms_alert.ConfigManager")
    @patch("nginx_security_monitor.sms_alert.send_via_twilio")
    def test_send_sms_alert_provider_exception_with_retry(
        self, mock_send_twilio, mock_config_manager
    ):
        """Test provider exception handling with retry mechanism."""
        mock_config = MagicMock()
        mock_config.get.side_effect = lambda key, default=None: {
            "alert_system.sms.enabled": True,
            "alert_system.sms.provider": "twilio",
            "alert_system.sms.api_key": "test_sid",
            "alert_system.sms.api_secret": "test_token",
            "alert_system.sms.from_number": "+1111",
            "alert_system.sms.retry_count": 2,
            "alert_system.sms.retry_delay": 1,
            "alert_system.sms.default_recipient": "+2222",
        }.get(key, default)
        mock_config_manager.get_instance.return_value = mock_config

        # First call fails, second succeeds
        mock_send_twilio.side_effect = [Exception("Network error"), True]

        with patch("time.sleep") as mock_sleep:
            with patch(
                "nginx_security_monitor.sms_alert.logging.getLogger"
            ) as mock_logger:
                mock_log = MagicMock()
                mock_logger.return_value = mock_log

                result = send_sms_alert(self.config_alert)

                self.assertTrue(result)
                # Check that retry was attempted
                self.assertEqual(mock_send_twilio.call_count, 2)
                mock_sleep.assert_called_once_with(1)  # 1 * (2^0)
                mock_log.error.assert_called_with(
                    "Attempt 1/2 failed to send SMS: Network error"
                )


if __name__ == "__main__":
    unittest.main()
