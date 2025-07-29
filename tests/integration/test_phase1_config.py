#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phase 1.2 Integration Tests: Configuration System Integration
Focus: Integration between config_schema → config_manager → crypto_utils
"""

import unittest
import os
import tempfile
import yaml
from unittest.mock import patch, MagicMock
from tests.integration.test_framework import (
    BaseIntegrationTest,
    IntegrationTestDataFactory,
)


class TestConfigurationSystemIntegration(BaseIntegrationTest):
    """Test integration between config_schema → config_manager → crypto_utils"""

    def setUp(self):
        """Set up the test environment for configuration tests."""
        super().setUp()

        # Create test configuration files for testing
        self.encrypted_config_path = os.path.join(
            self.test_data_dir, "encrypted_settings.yaml"
        )
        self.plain_config_path = os.path.join(self.test_data_dir, "plain_settings.yaml")

        # Create a plain config file
        with open(self.plain_config_path, "w") as f:
            yaml.dump(self.test_config, f)

    def test_encrypted_config_loading(self):
        """Test loading and decrypting configuration files"""
        print("\n🔒 Testing encrypted configuration loading...")

        # Arrange: Use crypto_utils to encrypt a configuration file
        self.components["crypto_utils"].encrypt_file(
            input_file=self.plain_config_path,
            output_file=self.encrypted_config_path,
            key="test_encryption_key",
        )

        # Act: Use config_manager to load the encrypted configuration
        with patch.dict(os.environ, {"NGINX_MONITOR_KEY": "test_encryption_key"}):
            loaded_config = self.components["config_manager"].load_config(
                self.encrypted_config_path
            )

        # Assert: The loaded configuration should match the original
        self.assertIsNotNone(loaded_config)
        self.assertEqual(
            loaded_config["service"]["check_interval"],
            self.test_config["service"]["check_interval"],
        )

    def test_config_validation_with_schema(self):
        """Test configuration validation against schema"""
        print("\n🔍 Testing configuration validation against schema...")

        # Arrange: Create an invalid configuration
        invalid_config = self.test_config.copy()
        invalid_config["pattern_detection"]["thresholds"][
            "requests_per_ip_per_minute"
        ] = "not_a_number"

        invalid_config_path = os.path.join(self.test_data_dir, "invalid_config.yaml")
        with open(invalid_config_path, "w") as f:
            yaml.dump(invalid_config, f)

        # Act & Assert: Validate the configuration against the schema
        with self.assertRaises(Exception):
            self.components["config_schema"].validate_config(invalid_config)

    def test_config_hot_reload_integration(self):
        """Test live configuration updates across components"""
        print("\n🔄 Testing configuration hot reload...")

        # Arrange: Set up a config file and load it
        self.components["config_manager"].load_config(self.plain_config_path)

        # Act: Modify the configuration file
        updated_config = self.test_config.copy()
        updated_config["pattern_detection"]["thresholds"][
            "requests_per_ip_per_minute"
        ] = 75

        with open(self.plain_config_path, "w") as f:
            yaml.dump(updated_config, f)

        # Trigger a reload
        self.components["config_manager"].reload_config()

        # Assert: Components using the configuration should see the updated values
        pattern_detector = self.components["pattern_detector"]
        self.assertEqual(
            pattern_detector.get_threshold("requests_per_ip_per_minute"), 75
        )

    def test_environment_override_integration(self):
        """Test environment variable overrides with encryption"""
        print("\n🌐 Testing environment variable overrides...")

        # Arrange: Set environment variables that override config
        with patch.dict(
            os.environ,
            {
                "NGINX_MONITOR_THRESHOLDS_REQUESTS_PER_IP": "120",
                "NGINX_MONITOR_ALERT_EMAIL_ENABLED": "false",
            },
        ):
            # Act: Load configuration with environment overrides
            loaded_config = self.components["config_manager"].load_config(
                self.plain_config_path, apply_env_overrides=True
            )

        # Assert: The configuration should reflect environment overrides
        self.assertEqual(
            loaded_config["pattern_detection"]["thresholds"][
                "requests_per_ip_per_minute"
            ],
            120,
        )
        self.assertFalse(loaded_config["alert_system"]["email"]["enabled"])


class TestConfigurationDataFlow(BaseIntegrationTest):
    """Test data flow across configuration components"""

    def test_config_propagation_to_components(self):
        """Test configuration changes propagate to all components"""
        print("\n📊 Testing configuration propagation...")

        # Arrange: Create test configuration
        test_config_path = os.path.join(self.test_data_dir, "propagation_test.yaml")
        propagation_config = self.test_config.copy()
        propagation_config["pattern_detection"]["thresholds"][
            "requests_per_ip_per_minute"
        ] = 200

        with open(test_config_path, "w") as f:
            yaml.dump(propagation_config, f)

        # Act: Load the config and propagate to components
        config_manager = self.components["config_manager"]
        config_manager.load_config(test_config_path)
        config_manager.update_all_components()

        # Assert: Check that all components received the configuration
        pattern_detector = self.components["pattern_detector"]
        alert_manager = self.components["alert_manager"]
        threat_processor = self.components["threat_processor"]

        self.assertEqual(
            pattern_detector.get_threshold("requests_per_ip_per_minute"), 200
        )
        # Check more components based on your actual implementation


if __name__ == "__main__":
    unittest.main()
