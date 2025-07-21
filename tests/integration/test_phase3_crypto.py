#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phase 3.3 Integration Tests: Crypto Integration
Focus: Integration between crypto_utils → config_manager → All components
"""

import unittest
import os
import yaml
import json
import tempfile
from unittest.mock import patch, MagicMock
from tests.integration.test_framework import BaseIntegrationTest


class TestCryptoIntegration(BaseIntegrationTest):
    """Test integration between crypto_utils → config_manager → All components"""
    
    def setUp(self):
        """Set up test environment for crypto integration tests."""
        super().setUp()
        
        # Create test directories for encrypted files
        self.crypto_test_dir = os.path.join(self.test_data_dir, "crypto")
        self.keys_dir = os.path.join(self.crypto_test_dir, "keys")
        
        os.makedirs(self.crypto_test_dir, exist_ok=True)
        os.makedirs(self.keys_dir, exist_ok=True)
        
        # Create test data files
        self.config_file = os.path.join(self.crypto_test_dir, "test_config.yaml")
        self.encrypted_config_file = os.path.join(self.crypto_test_dir, "test_config.enc")
        self.secrets_file = os.path.join(self.crypto_test_dir, "secrets.json")
        self.encrypted_secrets_file = os.path.join(self.crypto_test_dir, "secrets.enc")
        
        # Create a test configuration
        self.test_config = {
            "service": {
                "name": "nginx-security-monitor",
                "version": "1.0.0",
                "log_level": "info"
            },
            "security": {
                "enable_ip_blocking": True,
                "block_duration_seconds": 3600,
                "alert_threshold": 5
            },
            "network": {
                "listen_port": 8080,
                "max_connections": 1000
            }
        }
        
        # Create a test secrets file
        self.test_secrets = {
            "api_keys": {
                "threat_intel": "abcdef123456",
                "notification_service": "xyz789"
            },
            "credentials": {
                "db_user": "monitor_service",
                "db_password": "super_secret_password"
            }
        }
        
        # Write test files
        with open(self.config_file, 'w') as f:
            yaml.dump(self.test_config, f)
        
        with open(self.secrets_file, 'w') as f:
            json.dump(self.test_secrets, f)
        
        # Test encryption keys
        self.test_key = "integration_test_encryption_key"
        self.key_file = os.path.join(self.keys_dir, "test_key.key")
        
        with open(self.key_file, 'w') as f:
            f.write(self.test_key)
    
    def test_end_to_end_encryption_integration(self):
        """Test encryption/decryption across all components"""
        print("\n🔒 Testing end-to-end encryption integration...")
        
        # Get components
        crypto_utils = self.components['crypto_utils']
        config_manager = self.components['config_manager']
        
        # Configure crypto utils
        crypto_utils.configure({
            "keys_directory": self.keys_dir,
            "default_key_file": self.key_file
        })
        
        # Act: Encrypt configuration file
        crypto_utils.encrypt_file(
            input_file=self.config_file,
            output_file=self.encrypted_config_file,
            key=self.test_key
        )
        
        # Verify encrypted file exists and is different from original
        self.assertTrue(os.path.exists(self.encrypted_config_file))
        
        with open(self.config_file, 'r') as f1, open(self.encrypted_config_file, 'r') as f2:
            self.assertNotEqual(f1.read(), f2.read())
        
        # Connect config manager to crypto utils
        config_manager.set_crypto_utils(crypto_utils)
        
        # Act: Load encrypted configuration
        loaded_config = config_manager.load_encrypted_config(
            self.encrypted_config_file,
            key=self.test_key
        )
        
        # Assert: Loaded config should match original
        self.assertEqual(loaded_config['service']['name'], self.test_config['service']['name'])
        self.assertEqual(loaded_config['security']['enable_ip_blocking'], 
                        self.test_config['security']['enable_ip_blocking'])
        
        # Test with other components that need to access encrypted data
        alert_manager = self.components['alert_manager']
        
        # Connect alert manager to config manager
        alert_manager.set_config_manager(config_manager)
        
        # Encrypt secrets file
        crypto_utils.encrypt_file(
            input_file=self.secrets_file,
            output_file=self.encrypted_secrets_file,
            key=self.test_key
        )
        
        # Configure alert manager to use encrypted secrets
        alert_manager.configure({
            "credentials_file": self.encrypted_secrets_file,
            "encrypted": True
        })
        
        # Assert: Alert manager should be able to access decrypted credentials
        api_key = alert_manager.get_credential('api_keys.notification_service')
        self.assertEqual(api_key, 'xyz789')
    
    def test_key_rotation_integration(self):
        """Test key rotation impact on all components"""
        print("\n🔄 Testing key rotation integration...")
        
        # Get components
        crypto_utils = self.components['crypto_utils']
        config_manager = self.components['config_manager']
        
        # Configure crypto utils
        crypto_utils.configure({
            "keys_directory": self.keys_dir,
            "default_key_file": self.key_file
        })
        
        # First encrypt with the original key
        crypto_utils.encrypt_file(
            input_file=self.config_file,
            output_file=self.encrypted_config_file,
            key=self.test_key
        )
        
        # Connect config manager
        config_manager.set_crypto_utils(crypto_utils)
        
        # Generate a new key
        new_key = "new_rotation_test_key_12345"
        new_key_file = os.path.join(self.keys_dir, "rotated_key.key")
        
        with open(new_key_file, 'w') as f:
            f.write(new_key)
        
        # Act: Perform key rotation
        rotated_file = os.path.join(self.crypto_test_dir, "rotated_config.enc")
        
        crypto_utils.rotate_key(
            input_file=self.encrypted_config_file,
            output_file=rotated_file,
            old_key=self.test_key,
            new_key=new_key
        )
        
        # Assert: File should be readable with new key
        rotated_config = config_manager.load_encrypted_config(
            rotated_file,
            key=new_key
        )
        
        self.assertEqual(rotated_config['service']['name'], self.test_config['service']['name'])
        
        # Update all components to use the new key
        components_using_crypto = [
            'config_manager', 'alert_manager', 'security_coordinator'
        ]
        
        for component_name in components_using_crypto:
            component = self.components[component_name]
            if hasattr(component, 'set_encryption_key'):
                component.set_encryption_key(new_key)
        
        # Assert: Components should still work with the new key
        # For example, config manager should load config with new key
        reloaded_config = config_manager.load_encrypted_config(
            rotated_file,
            key=new_key
        )
        
        self.assertEqual(reloaded_config['security']['enable_ip_blocking'], 
                        self.test_config['security']['enable_ip_blocking'])
    
    def test_crypto_failure_recovery(self):
        """Test system behavior when cryptographic operations fail"""
        print("\n⚠️ Testing crypto failure recovery...")
        
        # Get components
        crypto_utils = self.components['crypto_utils']
        config_manager = self.components['config_manager']
        alert_manager = self.components['alert_manager']
        
        # Connect components
        config_manager.set_crypto_utils(crypto_utils)
        config_manager.set_alert_manager(alert_manager)
        
        # Configure crypto utils
        crypto_utils.configure({
            "keys_directory": self.keys_dir,
            "default_key_file": self.key_file,
            "fallback_to_plaintext": True  # Allow fallback for critical components
        })
        
        # Mock alert manager to capture alerts
        with patch.object(alert_manager, 'send_alert') as mock_alert:
            # Act: Try to decrypt with wrong key
            wrong_key = "wrong_key_that_wont_work"
            
            # Encrypt file with correct key first
            crypto_utils.encrypt_file(
                input_file=self.config_file,
                output_file=self.encrypted_config_file,
                key=self.test_key
            )
            
            # Try to load with wrong key
            result = config_manager.load_encrypted_config(
                self.encrypted_config_file,
                key=wrong_key,
                allow_fallback=True
            )
            
            # Assert: Should fall back to plaintext and send alert
            mock_alert.assert_called_once()
            
            alert_data = mock_alert.call_args[0][0]
            self.assertEqual(alert_data['type'], 'crypto_failure')
            self.assertEqual(alert_data['severity'], 'critical')
            
            # Should still have loaded config from plaintext fallback
            self.assertIsNotNone(result)
            self.assertEqual(result['service']['name'], self.test_config['service']['name'])


class TestCryptoDataFlow(BaseIntegrationTest):
    """Test crypto data flow across components"""
    
    def test_encrypted_config_propagation(self):
        """Test propagation of encrypted configuration to components"""
        print("\n🔄 Testing encrypted config propagation...")
        
        # Set up test key for this test
        test_key = "integration_test_encryption_key"
        
        # Get components
        crypto_utils = self.components['crypto_utils']
        config_manager = self.components['config_manager']
        
        # Create temp files for this test
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as plain_file, \
             tempfile.NamedTemporaryFile(mode='w', suffix='.enc', delete=False) as enc_file:
            
            # Create test config with specific values for propagation test
            test_config = {
                "service": {"name": "propagation-test"},
                "pattern_detection": {
                    "thresholds": {
                        "requests_per_ip_per_minute": 123,  # Unique value for testing
                        "failed_requests_per_minute": 45    # Unique value for testing
                    }
                }
            }
            
            # Write config
            yaml.dump(test_config, plain_file)
            plain_path = plain_file.name
        
        enc_path = enc_file.name
        
        # Encrypt the config
        crypto_utils.encrypt_file(
            input_file=plain_path,
            output_file=enc_path,
            key=test_key
        )
        
        # Connect components
        config_manager.set_crypto_utils(crypto_utils)
        
        # Load the encrypted config
        loaded_config = config_manager.load_encrypted_config(
            enc_path,
            key=test_key
        )
        
        # Get components that should receive config
        pattern_detector = self.components['pattern_detector']
        threat_processor = self.components['threat_processor']
        
        # Act: Propagate config to all components
        config_manager.propagate_config(loaded_config)
        
        # Assert: Components should receive the configuration values
        self.assertEqual(
            pattern_detector.get_threshold('requests_per_ip_per_minute'),
            123
        )
        
        self.assertEqual(
            pattern_detector.get_threshold('failed_requests_per_minute'),
            45
        )
        
        # Clean up
        os.unlink(plain_path)
        os.unlink(enc_path)


if __name__ == "__main__":
    unittest.main()
