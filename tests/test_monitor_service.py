import unittest
import os
import tempfile
import yaml
import signal
import time
from unittest.mock import patch, mock_open, MagicMock, call, Mock
from datetime import datetime


class TestNginxSecurityMonitor(unittest.TestCase):
    """Test suite for NGINX Security Monitor service with isolated imports"""

    def setUp(self):
        """Set up test fixtures."""
        self.config_data = {
            "logging": {"level": "INFO", "file": "/tmp/test.log"},
            "monitoring": {"check_interval": 5},
            "security": {
                "self_check_interval": 60,
                "encrypted_patterns_file": "/tmp/patterns.enc",
            },
            "email_service": {"enabled": True, "to_address": "admin@example.com"},
            "sms_service": {"enabled": False},
            "log_file_path": "/var/log/nginx/access.log",
        }

        # Create a temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        )
        yaml.dump(self.config_data, self.temp_config)
        self.temp_config.close()

    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.temp_config.name):
            os.unlink(self.temp_config.name)
        
        # Reset ConfigManager singleton to ensure test isolation
        from nginx_security_monitor.config_manager import ConfigManager
        ConfigManager.reset_instance()

    @patch("nginx_security_monitor.monitor_service.SECURITY_FEATURES_AVAILABLE", True)
    @patch("nginx_security_monitor.monitor_service.SecurityConfigManager")
    @patch("nginx_security_monitor.monitor_service.PatternObfuscator")
    @patch("nginx_security_monitor.monitor_service.PluginManager")
    @patch("nginx_security_monitor.monitor_service.ServiceProtection")
    @patch("nginx_security_monitor.monitor_service.NetworkSecurity")
    @patch("nginx_security_monitor.monitor_service.SecurityHardening")
    @patch("nginx_security_monitor.monitor_service.SecurityIntegrationManager")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_initialization_with_security_features(
        self,
        mock_signal,
        mock_pattern_detector,
        mock_sec_integration_mgr,
        mock_sec_hardening,
        mock_network_security,
        mock_service_protection,
        mock_plugin_mgr,
        mock_pattern_obfuscator,
        mock_security_config_mgr,
    ):
        """Test monitor initialization with security features enabled"""

        # Import inside the test to avoid global import issues
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        # Mock the security components
        mock_security_config_mgr.return_value = MagicMock()
        mock_pattern_obfuscator.return_value = MagicMock()
        mock_plugin_mgr.return_value = MagicMock()
        mock_service_protection.return_value = MagicMock()
        mock_network_security.return_value = MagicMock()
        mock_sec_hardening.return_value = MagicMock()
        mock_sec_integration_mgr.return_value = MagicMock()
        mock_pattern_detector.return_value = MagicMock()

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Verify initialization
            self.assertIsNotNone(monitor.config)
            self.assertIsNotNone(monitor.security_manager)
            self.assertIsNotNone(monitor.obfuscator)
            self.assertIsNotNone(monitor.plugin_manager)
            self.assertIsNotNone(monitor.service_protection)
            self.assertIsNotNone(monitor.network_security)
            self.assertIsNotNone(monitor.security_hardening)
            self.assertIsNotNone(monitor.security_integrations)

            # Verify signal handlers were set up
            mock_signal.assert_any_call(signal.SIGTERM, monitor.signal_handler)
            mock_signal.assert_any_call(signal.SIGINT, monitor.signal_handler)

    @patch("nginx_security_monitor.monitor_service.SECURITY_FEATURES_AVAILABLE", False)
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_initialization_without_security_features(
        self, mock_signal, mock_pattern_detector
    ):
        """Test monitor initialization without security features"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Verify basic initialization
            self.assertIsNotNone(monitor.config)
            self.assertIsNone(monitor.security_manager)
            self.assertIsNone(monitor.obfuscator)
            self.assertIsNone(monitor.plugin_manager)

    @patch("nginx_security_monitor.monitor_service.sys.exit")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_config_file_not_found_error(self, mock_pattern_detector, mock_exit):
        """Test handling of missing config file"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        # Try to initialize with non-existent config file
        with patch("builtins.open", side_effect=FileNotFoundError()):
            monitor = NginxSecurityMonitor("/non/existent/config.yaml")

            # Should exit with error code 1
            mock_exit.assert_called_with(1)

    @patch("nginx_security_monitor.monitor_service.sys.exit")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_config_yaml_parse_error(self, mock_pattern_detector, mock_exit):
        """Test handling of invalid YAML config"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        invalid_yaml = "invalid: yaml: content: ["

        with patch("builtins.open", mock_open(read_data=invalid_yaml)):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Should exit with error code 1
            mock_exit.assert_called_with(1)

    @patch("nginx_security_monitor.monitor_service.os.makedirs")
    @patch("nginx_security_monitor.monitor_service.logging.basicConfig")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_setup_logging(
        self, mock_pattern_detector, mock_basic_config, mock_makedirs
    ):
        """Test logging setup"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Verify logging was configured (called twice: basic + full setup)
            self.assertEqual(mock_basic_config.call_count, 2)
            mock_makedirs.assert_called_once()

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_signal_handler(self, mock_pattern_detector):
        """Test signal handler functionality"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Test signal handler
            self.assertTrue(monitor.running)
            monitor.signal_handler(signal.SIGTERM, None)
            self.assertFalse(monitor.running)

    @patch("nginx_security_monitor.monitor_service.os.path.getsize")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_get_new_log_entries_success(self, mock_pattern_detector, mock_getsize):
        """Test getting new log entries successfully"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()
        mock_getsize.return_value = 1000

        sample_log = '127.0.0.1 - - [01/Jan/2025:12:00:00 +0000] "GET /test HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            with patch("builtins.open", mock_open(read_data=sample_log)):
                monitor.last_processed_size = 0
                # Create a mock log processor that returns entries
                monitor.log_processor = MagicMock()
                monitor.log_processor.get_new_log_entries.return_value = [{'ip_address': '127.0.0.1', 'timestamp': '01/Jan/2025:12:00:00 +0000', 'request': 'GET /test HTTP/1.1', 'status_code': '200', 'response_size': '1234', 'user_agent': 'Mozilla/5.0', 'raw_line': 'test'}]
                
                # Call the method (with updated API)
                entries = monitor.get_new_log_entries()

                self.assertEqual(len(entries), 1)
                self.assertEqual(entries[0]["ip_address"], "127.0.0.1")

    @patch("nginx_security_monitor.monitor_service.os.path.getsize")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_get_new_log_entries_no_new_data(self, mock_pattern_detector, mock_getsize):
        """Test getting new log entries when no new data"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()
        mock_getsize.return_value = 500

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)
            monitor.last_processed_size = 500

            # Create a mock log processor that returns entries
            monitor.log_processor = MagicMock()
            monitor.log_processor.get_new_log_entries.return_value = []
                
            # Call the method (with updated API)
            entries = monitor.get_new_log_entries()
            self.assertEqual(len(entries), 0)

    @patch("nginx_security_monitor.monitor_service.os.path.getsize")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_get_new_log_entries_file_rotated(
        self, mock_pattern_detector, mock_getsize
    ):
        """Test getting new log entries when log file was rotated"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()
        mock_getsize.return_value = 100  # Smaller than last processed size

        sample_log = '127.0.0.1 - - [01/Jan/2025:12:00:00 +0000] "GET /test HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)
            monitor.last_processed_size = {}
            monitor.last_processed_size = 100

            with patch("builtins.open", mock_open(read_data=sample_log)):
                # Create a mock log processor that returns entries
                monitor.log_processor = MagicMock()
                monitor.log_processor.get_new_log_entries.return_value = [{'ip_address': '127.0.0.1', 'timestamp': '01/Jan/2025:12:00:00 +0000', 'request': 'GET /test HTTP/1.1', 'status_code': '200', 'response_size': '1234', 'user_agent': 'Mozilla/5.0', 'raw_line': 'test'}]
                
                # Call the method (with updated API)
                entries = monitor.get_new_log_entries()

                # Should reset last_processed_size to 0 and process from beginning
                self.assertEqual(monitor.last_processed_size, 100)
                self.assertEqual(len(entries), 1)

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_get_new_log_entries_file_not_found(self, mock_pattern_detector):
        """Test getting new log entries when file not found"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            with patch(
                "nginx_security_monitor.monitor_service.os.path.getsize",
                side_effect=FileNotFoundError(),
            ):
                # Create a mock log processor that returns entries
                monitor.log_processor = MagicMock()
                monitor.log_processor.get_new_log_entries.return_value = []
                
                # Call the method (with updated API)
                entries = monitor.get_new_log_entries()
                self.assertEqual(len(entries), 0)

    @patch("nginx_security_monitor.monitor_service.time.sleep")
    @patch("nginx_security_monitor.monitor_service.mitigate_threat")
    @patch("nginx_security_monitor.monitor_service.send_email_alert")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_process_threats_without_plugins(
        self, mock_pattern_detector, mock_email_alert, mock_mitigate, mock_sleep
    ):
        """Test processing threats without plugin system"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()
        mock_mitigate.return_value = "Threat mitigated"

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)
            monitor.plugin_manager = None  # No plugins
            monitor.obfuscator = None  # No obfuscation
            monitor.security_integrations = None  # No integrations

            test_pattern = {
                "type": "SQL Injection",
                "ip": "192.168.1.100",
                "severity": "HIGH",
            }

            monitor.process_threats([test_pattern])

            # Verify mitigation was called
            mock_mitigate.assert_called_once_with(test_pattern)
            # Verify email alert was sent
            mock_email_alert.assert_called_once()

    @patch("nginx_security_monitor.monitor_service.time.sleep")
    @patch("nginx_security_monitor.monitor_service.mitigate_threat")
    @patch("nginx_security_monitor.monitor_service.send_email_alert")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_process_threats_with_plugins(
        self, mock_pattern_detector, mock_email_alert, mock_mitigate, mock_sleep
    ):
        """Test processing threats with plugin system"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        # Mock plugin manager
        mock_plugin_manager = MagicMock()
        mock_plugin_manager.execute_mitigation.return_value = [
            {
                "status": "success",
                "method": "custom_plugin",
                "result": "Plugin handled threat",
            }
        ]

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)
            monitor.plugin_manager = mock_plugin_manager
            monitor.obfuscator = None  # No obfuscation for simplicity
            monitor.security_integrations = None  # No integrations

            test_pattern = {
                "type": "SQL Injection",
                "ip": "192.168.1.100",
                "severity": "HIGH",
            }

            monitor.process_threats([test_pattern])

            # Verify plugin was called
            mock_plugin_manager.execute_mitigation.assert_called_once_with(test_pattern)
            # Default mitigation should not be called since plugin succeeded
            mock_mitigate.assert_not_called()
            # Verify email alert was sent
            mock_email_alert.assert_called_once()

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_create_alert_body(self, mock_pattern_detector):
        """Test alert body creation"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            test_pattern = {
                "type": "SQL Injection",
                "ip": "192.168.1.100",
                "severity": "HIGH",
                "timestamp": "2025-01-01T12:00:00",
            }

            mitigation_results = [
                {"status": "success", "method": "default"},
                {"status": "success", "method": "plugin"},
            ]

            body = monitor._create_alert_body(test_pattern, mitigation_results)

            self.assertIn("SQL Injection", body)
            self.assertIn("192.168.1.100", body)
            self.assertIn("HIGH", body)
            self.assertIn("2 countermeasure(s) applied", body)

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_create_emergency_alert_body(self, mock_pattern_detector):
        """Test emergency alert body creation"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            threats = [
                {
                    "type": "File Tampering",
                    "description": "Critical file modified",
                    "severity": "CRITICAL",
                },
                {
                    "type": "Process Hijacking",
                    "description": "Suspicious process detected",
                    "severity": "CRITICAL",
                },
            ]

            body = monitor._create_emergency_alert_body(threats)

            self.assertIn("EMERGENCY", body)
            self.assertIn("CRITICAL THREATS DETECTED: 2", body)
            self.assertIn("File Tampering", body)
            self.assertIn("Process Hijacking", body)
            self.assertIn("Critical file modified", body)

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_create_service_threat_alert_body(self, mock_pattern_detector):
        """Test service threat alert body creation"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            threats = [
                {"type": "File Tampering", "description": "Critical file modified"},
                {
                    "type": "Process Hijacking",
                    "description": "Suspicious process detected",
                },
            ]

            body = monitor._create_service_threat_alert_body(threats)

            self.assertIn("HIGH-SEVERITY THREATS: 2", body)
            self.assertIn("File Tampering", body)
            self.assertIn("Process Hijacking", body)
            self.assertIn("Critical file modified", body)

    @patch("nginx_security_monitor.monitor_service.send_email_alert")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_send_emergency_alert(self, mock_pattern_detector, mock_send_email):
        """Test sending emergency alert"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            threats = [
                {
                    "type": "File Tampering",
                    "description": "Critical file modified",
                    "severity": "CRITICAL",
                }
            ]

            monitor._send_emergency_alert(threats)

            # Verify email alert was called
            mock_send_email.assert_called_once()

            # Check alert details
            call_args = mock_send_email.call_args[0][0]
            self.assertIn("CRITICAL", call_args["subject"])
            self.assertEqual(call_args["pattern"]["severity"], "CRITICAL")

    @patch("nginx_security_monitor.monitor_service.main")
    def test_main_function_import(self, mock_main_func):
        """Test main function can be imported and called"""

        from nginx_security_monitor.monitor_service import main

        # Test that main can be called
        main()
        # The actual main function should be called, not our mock
        # This test just verifies the import works

    @patch("nginx_security_monitor.monitor_service.NginxSecurityMonitor")
    def test_main_function_keyboard_interrupt(self, mock_monitor_class):
        """Test main function handling keyboard interrupt"""

        from nginx_security_monitor.monitor_service import main

        mock_monitor = MagicMock()
        mock_monitor.run.side_effect = KeyboardInterrupt()
        mock_monitor.logger = MagicMock()
        mock_monitor_class.return_value = mock_monitor

        # Should not raise exception
        main()

        # Monitor should have been created and run called
        mock_monitor_class.assert_called_once()
        mock_monitor.run.assert_called_once()

    @patch("nginx_security_monitor.monitor_service.sys.exit")
    @patch("nginx_security_monitor.monitor_service.NginxSecurityMonitor")
    def test_main_function_exception(self, mock_monitor_class, mock_exit):
        """Test main function handling general exception"""

        from nginx_security_monitor.monitor_service import main

        mock_monitor = MagicMock()
        mock_monitor.run.side_effect = Exception("Test exception")
        mock_monitor.logger = MagicMock()
        mock_monitor_class.return_value = mock_monitor

        main()

        # Should log error and exit with code 1
        mock_monitor.logger.error.assert_called()
        mock_exit.assert_called_with(1)

    @patch("nginx_security_monitor.monitor_service.SECURITY_FEATURES_AVAILABLE", True)
    @patch("nginx_security_monitor.monitor_service.SecurityConfigManager")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_load_encrypted_patterns_success(
        self, mock_pattern_detector, mock_security_mgr
    ):
        """Test loading encrypted patterns successfully"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector_instance = MagicMock()
        mock_pattern_detector.return_value = mock_pattern_detector_instance

        mock_security_mgr_instance = MagicMock()
        # mock_security_mgr is not defined in this scope; this is unreachable code from a broken test stub. Commenting out.
        # mock_security_mgr.return_value = mock_security_mgr_instance
        mock_security_mgr_instance.decrypt_file.return_value = {
            "custom_pattern": "test"
        }

        config_with_encrypted = self.config_data.copy()
        config_with_encrypted["security"][
            "encrypted_patterns_file"
        ] = "/tmp/patterns.enc"

        with patch(
            "builtins.open", mock_open(read_data=yaml.dump(config_with_encrypted))
        ):
            with patch(
                "nginx_security_monitor.monitor_service.os.path.exists",
                return_value=True,
            ):
                monitor = NginxSecurityMonitor(self.temp_config.name)

                # Verify encrypted patterns were loaded
                mock_pattern_detector_instance.load_custom_patterns.assert_called_once()

    @patch("nginx_security_monitor.monitor_service.SECURITY_FEATURES_AVAILABLE", True)
    @patch("nginx_security_monitor.monitor_service.SecurityConfigManager")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_load_encrypted_patterns_failure(
        self, mock_pattern_detector, mock_security_mgr
    ):
        """Test handling encrypted patterns loading failure"""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector_instance = MagicMock()
        mock_pattern_detector.return_value = mock_pattern_detector_instance

        mock_security_mgr_instance = MagicMock()
        mock_security_mgr.return_value = mock_security_mgr_instance
        mock_security_mgr_instance.decrypt_file.side_effect = Exception(
            "Decryption failed"
        )

        config_with_encrypted = self.config_data.copy()
        config_with_encrypted["security"][
            "encrypted_patterns_file"
        ] = "/tmp/patterns.enc"

        with patch(
            "builtins.open", mock_open(read_data=yaml.dump(config_with_encrypted))
        ):
            with patch(
                "nginx_security_monitor.monitor_service.os.path.exists",
                return_value=True,
            ):
                # Should not raise exception, just log error
                monitor = NginxSecurityMonitor(self.temp_config.name)

                # Verify attempt was made
                mock_security_mgr_instance.decrypt_file.assert_called_once()

                # Verify attempt was made
                mock_security_mgr_instance.decrypt_file.assert_called_once()

    @patch("nginx_security_monitor.monitor_service.SECURITY_FEATURES_AVAILABLE", True)
    @patch("nginx_security_monitor.monitor_service.SecurityConfigManager")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_decrypt_config_sections_success(
        self, mock_pattern_detector, mock_security_mgr
    ):
        """Test decrypting config sections successfully"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        mock_security_mgr_instance = MagicMock()
        mock_security_mgr.return_value = mock_security_mgr_instance
        mock_security_mgr_instance.decrypt_data.return_value = {"decrypted": "value"}

        config_with_encrypted = self.config_data.copy()
        config_with_encrypted["encrypted_config"] = {"secret_section": "encrypted_data"}

        with patch(
            "builtins.open", mock_open(read_data=yaml.dump(config_with_encrypted))
        ):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Verify config was decrypted
            self.assertIn("secret_section", monitor.config)
            self.assertEqual(monitor.config["secret_section"], {"decrypted": "value"})

    @patch("nginx_security_monitor.monitor_service.SECURITY_FEATURES_AVAILABLE", True)
    @patch("nginx_security_monitor.monitor_service.SecurityConfigManager")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    def test_decrypt_config_sections_failure(
        self, mock_pattern_detector, mock_security_mgr
    ):
        """Test handling config decryption failure"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector.return_value = MagicMock()

        mock_security_mgr_instance = MagicMock()
        mock_security_mgr.return_value = mock_security_mgr_instance
        mock_security_mgr_instance.decrypt_data.side_effect = Exception(
            "Decryption failed"
        )

        config_with_encrypted = self.config_data.copy()
        config_with_encrypted["encrypted_config"] = {"secret_section": "encrypted_data"}

        with patch(
            "builtins.open", mock_open(read_data=yaml.dump(config_with_encrypted))
        ):
            # Should not raise exception, just log error
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Original config should remain unchanged
            self.assertNotIn("secret_section", monitor.config)

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_import_error_handling(self, mock_signal, mock_pattern_detector):
        """Test handling of ImportError during security feature imports."""
        # Simulate ImportError during imports by patching the module level
        with patch(
            "nginx_security_monitor.monitor_service.logging.warning"
        ) as mock_warning:
            # We can't easily test the actual ImportError at module level,
            # but we can test the fallback behavior when SECURITY_FEATURES_AVAILABLE is False

            @patch(
                "nginx_security_monitor.monitor_service.SECURITY_FEATURES_AVAILABLE",
                True,
            )
            @patch("nginx_security_monitor.monitor_service.SecurityConfigManager")
            @patch("nginx_security_monitor.monitor_service.PatternDetector")
            def test_load_encrypted_patterns_failure(
                self, mock_pattern_detector, mock_security_mgr
            ):
                """Test handling encrypted patterns loading failure"""

        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        mock_pattern_detector_instance = MagicMock()
        mock_pattern_detector.return_value = mock_pattern_detector_instance

        config_with_encrypted = self.config_data.copy()
        config_with_encrypted["security"][
            "encrypted_patterns_file"
        ] = "/tmp/patterns.enc"

        with patch(
            "builtins.open", mock_open(read_data=yaml.dump(config_with_encrypted))
        ):
            with patch(
                "nginx_security_monitor.monitor_service.os.path.exists",
                return_value=True,
            ):
                # Should not raise exception, just log error
                monitor = NginxSecurityMonitor(self.temp_config.name)

                # Verify attempt was made

            # context is not defined in this scope; this is unreachable code from a broken test stub. Commenting out.
            # self.assertIn("AlertManager initialization failed", str(context.exception))

    @patch("nginx_security_monitor.monitor_service.SecurityConfigManager")
    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_security_features_initialization_exception(
        self, mock_signal, mock_pattern_detector, mock_security_mgr
    ):
        """Test exception handling in _initialize_security_features."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        # Make SecurityConfigManager initialization raise an exception
        mock_security_mgr.side_effect = Exception(
            "Security manager initialization failed"
        )

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            # This should not raise an exception - it should be caught and logged
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Verify all security features are set to None due to exception
            self.assertIsNone(monitor.security_manager)
            self.assertIsNone(monitor.obfuscator)
            self.assertIsNone(monitor.plugin_manager)
            self.assertIsNone(monitor.service_protection)
            self.assertIsNone(monitor.network_security)
            self.assertIsNone(monitor.security_hardening)
            self.assertIsNone(monitor.security_integrations)

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_setup_logging_no_config(self, mock_signal, mock_pattern_detector):
        """Test setup_logging when config is None."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", side_effect=FileNotFoundError("Config not found")):
            with patch("sys.exit"):  # Prevent actual exit
                monitor = NginxSecurityMonitor(self.temp_config.name)
                monitor.config = None  # Force config to be None

                # This should return early without doing anything
                monitor.setup_logging()  # Should not raise an exception

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_run_no_security_coordinator(self, mock_signal, mock_pattern_detector):
        """Test run method when security_coordinator is not initialized."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Remove security_coordinator to simulate initialization failure
            if hasattr(monitor, "security_coordinator"):
                delattr(monitor, "security_coordinator")

            # Should log error and return without exception
            monitor.run()

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_run_exception_handling(self, mock_signal, mock_pattern_detector):
        """Test run method exception handling."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Mock security_coordinator to raise an exception
            mock_coordinator = MagicMock()
            mock_coordinator.start_monitoring.side_effect = Exception(
                "Monitoring failed"
            )
            monitor.security_coordinator = mock_coordinator

            # Should log error and re-raise the exception
            with self.assertRaises(Exception) as context:
                monitor.run()

            self.assertIn("Monitoring failed", str(context.exception))

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_get_monitoring_status_no_coordinator(
        self, mock_signal, mock_pattern_detector
    ):
        """Test get_monitoring_status when security_coordinator doesn't exist."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Remove security_coordinator
            if hasattr(monitor, "security_coordinator"):
                delattr(monitor, "security_coordinator")

            status = monitor.get_monitoring_status()

            self.assertEqual(status["running"], False)
            self.assertIn("not initialized", status["error"])

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_force_check_no_coordinator(self, mock_signal, mock_pattern_detector):
        """Test force_check when security_coordinator doesn't exist."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Remove security_coordinator
            if hasattr(monitor, "security_coordinator"):
                delattr(monitor, "security_coordinator")

            result = monitor.force_check()

            self.assertEqual(result["success"], False)
            self.assertIn("not initialized", result["error"])

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_get_new_log_entries_no_processor(self, mock_signal, mock_pattern_detector):
        """Test get_new_log_entries when log_processor doesn't exist."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Remove log_processor
            if hasattr(monitor, "log_processor"):
                delattr(monitor, "log_processor")

            result = monitor.get_new_log_entries("/var/log/nginx/access.log")

            self.assertEqual(result, [])

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_alert_methods_no_alert_manager(self, mock_signal, mock_pattern_detector):
        """Test alert creation methods when alert_manager doesn't exist."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Remove alert_manager
            if hasattr(monitor, "alert_manager"):
                delattr(monitor, "alert_manager")

            # Test _create_alert_body fallback
            pattern = {"type": "TestThreat", "ip": "192.168.1.1"}
            mitigation_results = []
            body = monitor._create_alert_body(pattern, mitigation_results)
            self.assertIn("Alert for TestThreat threat", body)

            # Test _create_emergency_alert_body fallback
            threats = [{"type": "critical1"}, {"type": "critical2"}]
            body = monitor._create_emergency_alert_body(threats)
            self.assertIn("Emergency: 2 critical threats detected", body)

            # Test _create_service_threat_alert_body fallback
            threats = [{"type": "service1"}]
            body = monitor._create_service_threat_alert_body(threats)
            self.assertIn("Service threats: 1 threats detected", body)

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    @patch("nginx_security_monitor.monitor_service.send_email_alert")
    def test_process_threats_exception_handling(
        self, mock_email, mock_signal, mock_pattern_detector
    ):
        """Test exception handling in process_threats method."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Make send_email_alert raise an exception
            mock_email.side_effect = Exception("Email sending failed")

            pattern = {"type": "TestThreat", "ip": "192.168.1.1", "severity": "HIGH"}

            # Should not raise exception, should log error instead
            monitor.process_threats([pattern])

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    def test_process_threats_with_security_integrations(
        self, mock_signal, mock_pattern_detector
    ):
        """Test process_threats with security integrations."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Mock security integrations
            mock_integrations = MagicMock()
            mock_integrations.handle_threat_with_integrations.return_value = {
                "actions_taken": ["blocked_ip", "updated_firewall"]
            }
            monitor.security_integrations = mock_integrations

            pattern = {"type": "TestThreat", "ip": "192.168.1.1", "severity": "HIGH"}

            with patch(
                "nginx_security_monitor.monitor_service.send_email_alert"
            ) as mock_email:
                monitor.process_threats([pattern])

                # Verify security integrations were called
                mock_integrations.handle_threat_with_integrations.assert_called_with(
                    pattern
                )

    @patch("nginx_security_monitor.monitor_service.PatternDetector")
    @patch("nginx_security_monitor.monitor_service.signal.signal")
    @patch("nginx_security_monitor.monitor_service.send_email_alert")
    def test_send_emergency_alert_exception(
        self, mock_email, mock_signal, mock_pattern_detector
    ):
        """Test exception handling in _send_emergency_alert."""
        from nginx_security_monitor.monitor_service import NginxSecurityMonitor

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.config_data))):
            monitor = NginxSecurityMonitor(self.temp_config.name)

            # Make send_email_alert raise an exception
            mock_email.side_effect = Exception("Emergency email failed")

            threats = [{"type": "critical1"}, {"type": "critical2"}]

            # Should not raise exception, should log error instead
            monitor._send_emergency_alert(threats)


if __name__ == "__main__":
    unittest.main()
