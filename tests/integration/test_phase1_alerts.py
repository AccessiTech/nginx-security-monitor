#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phase 1.3 Integration Tests: Alert System Integration
Focus: Integration between alert_manager → email_alert → sms_alert
"""

import unittest
import json
import os
from unittest.mock import patch, MagicMock, call
from tests.integration.test_framework import (
    BaseIntegrationTest,
    IntegrationTestDataFactory,
)


class TestAlertSystemIntegration(BaseIntegrationTest):
    """Test integration between alert_manager → email_alert → sms_alert"""

    def setUp(self):
        """Set up test environment for alert system tests."""
        super().setUp()

        # Create test alert data
        self.test_alert = {
            "type": "security_threat",
            "severity": "high",
            "timestamp": "2023-12-25T12:00:00Z",
            "message": "Possible SQL injection attack detected",
            "details": {
                "source_ip": "192.168.1.100",
                "target_url": "/login?id=1' OR '1'='1",
                "pattern": "sql_injection",
            },
        }

    def test_multi_channel_alert_delivery(self):
        """Test sending alerts through multiple channels"""
        print("\n📱 Testing multi-channel alert delivery...")

        alert_manager = self.components["alert_manager"]
        email_alert = self.components["email_alert"]
        sms_alert = self.components["sms_alert"]

        # Mock the delivery methods to check they're called
        with patch.object(email_alert, "send") as mock_email_send, patch.object(
            sms_alert, "send"
        ) as mock_sms_send:

            # Act: Send alert through alert manager
            alert_manager.send_alert(self.test_alert, channels=["email", "sms"])

            # Assert: Both channels should have been used
            mock_email_send.assert_called_once()
            mock_sms_send.assert_called_once()

            # Verify alert content was properly passed to each channel
            email_args = mock_email_send.call_args[0][0]
            sms_args = mock_sms_send.call_args[0][0]

            self.assertEqual(email_args["severity"], "high")
            self.assertEqual(sms_args["severity"], "high")

    def test_alert_fallback_mechanisms(self):
        """Test fallback when primary alert channel fails"""
        print("\n🔄 Testing alert fallback mechanisms...")

        alert_manager = self.components["alert_manager"]
        email_alert = self.components["email_alert"]
        sms_alert = self.components["sms_alert"]

        # Configure primary and fallback channels
        alert_manager.configure(
            {"primary_channel": "email", "fallback_channels": ["sms"]}
        )

        # Mock email to fail, SMS to succeed
        with patch.object(
            email_alert, "send", side_effect=Exception("SMTP failure")
        ) as mock_email_send, patch.object(sms_alert, "send") as mock_sms_send:

            # Act: Send alert - should fall back to SMS
            alert_manager.send_alert(self.test_alert)

            # Assert: Email was attempted, SMS was used as fallback
            mock_email_send.assert_called_once()
            mock_sms_send.assert_called_once()

    def test_alert_rate_limiting_integration(self):
        """Test rate limiting across all alert channels"""
        print("\n⏱️ Testing alert rate limiting...")

        alert_manager = self.components["alert_manager"]
        email_alert = self.components["email_alert"]

        # Configure rate limiting
        alert_manager.configure(
            {"rate_limits": {"max_alerts_per_minute": 5, "max_alerts_per_hour": 20}}
        )

        # Mock the send method to verify rate limiting
        with patch.object(email_alert, "send") as mock_email_send:
            # Act: Send alerts in rapid succession
            for i in range(10):
                alert = self.test_alert.copy()
                alert["details"]["attempt"] = i
                alert_manager.send_alert(alert, channels=["email"])

            # Assert: Only the configured number of alerts should be sent
            self.assertLessEqual(mock_email_send.call_count, 5)

            # The rate limiter should have recorded the attempts
            self.assertEqual(alert_manager.get_rate_limited_count(), 5)


class TestAlertDataFlow(BaseIntegrationTest):
    """Test alert data flow and transformation across the alert system"""

    def test_threat_to_alert_transformation(self):
        """Test transformation of threat data to alerts"""
        print("\n🔄 Testing threat to alert transformation...")

        # Create a threat detection from the threat processor
        threat_processor = self.components["threat_processor"]
        alert_manager = self.components["alert_manager"]

        # Generate a threat
        test_pattern = {
            "type": "sql_injection",
            "confidence": 0.85,
            "source_ip": "192.168.1.100",
            "timestamp": "2023-12-25T12:00:00Z",
            "evidence": "OR '1'='1",
        }

        # Act: Process the threat and have it generate an alert
        threat = threat_processor.process_threat(test_pattern)

        # Capture alerts with a mock
        with patch.object(alert_manager, "_send_to_channel") as mock_send:
            # Connect threat processor to alert manager
            threat_processor.set_alert_manager(alert_manager)

            # Trigger the alert
            threat_processor.trigger_alerts_for_threat(threat)

            # Assert: Alert should contain the right information
            mock_send.assert_called()
            alert_data = mock_send.call_args[0][1]  # The alert data

            self.assertEqual(alert_data["type"], "security_threat")
            self.assertEqual(alert_data["details"]["source_ip"], "192.168.1.100")
            self.assertEqual(alert_data["details"]["pattern"], "sql_injection")


if __name__ == "__main__":
    unittest.main()
