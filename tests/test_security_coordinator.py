#!/usr/bin/env python3
"""
Tests for SecurityCoordinator module
"""

import unittest
from unittest.mock import patch, MagicMock, call
import time

from nginx_security_monitor.security_coordinator import SecurityCoordinator


class TestSecurityCoordinator(unittest.TestCase):
    """Test cases for SecurityCoordinator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "check_interval": 30,
            "log_files": ["/var/log/nginx/access.log", "/var/log/nginx/error.log"],
        }
        self.mock_logger = MagicMock()
        self.mock_alert_manager = MagicMock()
        self.mock_log_processor = MagicMock()
        self.mock_threat_processor = MagicMock()
        self.mock_security_integrations = MagicMock()
        self.mock_service_protection = MagicMock()
        self.mock_network_security = MagicMock()

        # Mock the ConfigManager in security_coordinator
        self.mock_config_manager = MagicMock()
        self.mock_config_manager.get.return_value = 30  # Set default interval to 30

        # Create coordinator with mocked ConfigManager
        with patch(
            "nginx_security_monitor.config_manager.ConfigManager"
        ) as mock_cm_class:
            mock_cm_class.get_instance.return_value = self.mock_config_manager
            self.coordinator = SecurityCoordinator(
                config=self.config,
                logger=self.mock_logger,
                alert_manager=self.mock_alert_manager,
                log_processor=self.mock_log_processor,
                threat_processor=self.mock_threat_processor,
                security_integrations=self.mock_security_integrations,
                service_protection=self.mock_service_protection,
                network_security=self.mock_network_security,
            )

    def test_init(self):
        """Test SecurityCoordinator initialization."""
        self.assertEqual(self.coordinator.config, self.config)
        self.assertEqual(self.coordinator.logger, self.mock_logger)
        self.assertEqual(self.coordinator.alert_manager, self.mock_alert_manager)
        self.assertEqual(self.coordinator.log_processor, self.mock_log_processor)
        self.assertEqual(self.coordinator.threat_processor, self.mock_threat_processor)
        self.assertEqual(
            self.coordinator.security_integrations, self.mock_security_integrations
        )
        self.assertEqual(
            self.coordinator.service_protection, self.mock_service_protection
        )
        self.assertEqual(self.coordinator.network_security, self.mock_network_security)

        self.assertFalse(self.coordinator.running)
        self.assertEqual(self.coordinator.check_interval, 30)
        self.assertEqual(self.coordinator.stats["monitoring_cycles"], 0)
        self.assertEqual(self.coordinator.stats["total_log_entries"], 0)
        self.assertEqual(self.coordinator.stats["total_threats"], 0)
        self.assertEqual(self.coordinator.stats["alerts_sent"], 0)

    def test_init_with_no_config(self):
        """Test initialization with no config."""
        # Mock ConfigManager to return 60 for check_interval
        mock_cm = MagicMock()
        mock_cm.get.return_value = 60

        with patch(
            "nginx_security_monitor.config_manager.ConfigManager"
        ) as mock_cm_class:
            mock_cm_class.get_instance.return_value = mock_cm
            coordinator = SecurityCoordinator(
                config=None,
                logger=self.mock_logger,
                alert_manager=self.mock_alert_manager,
                log_processor=self.mock_log_processor,
                threat_processor=self.mock_threat_processor,
                security_integrations=self.mock_security_integrations,
                service_protection=self.mock_service_protection,
                network_security=self.mock_network_security,
            )

        self.assertIsNone(coordinator.config)
        self.assertEqual(coordinator.check_interval, 60)  # Default value

    def test_init_with_default_check_interval(self):
        """Test initialization with default check interval."""
        config_no_interval = {"log_files": []}

        # Mock ConfigManager to return 60 for check_interval
        mock_cm = MagicMock()
        mock_cm.get.return_value = 60

        with patch(
            "nginx_security_monitor.config_manager.ConfigManager"
        ) as mock_cm_class:
            mock_cm_class.get_instance.return_value = mock_cm
            coordinator = SecurityCoordinator(
                config=config_no_interval,
                logger=self.mock_logger,
                alert_manager=self.mock_alert_manager,
                log_processor=self.mock_log_processor,
                threat_processor=self.mock_threat_processor,
                security_integrations=self.mock_security_integrations,
                service_protection=self.mock_service_protection,
                network_security=self.mock_network_security,
            )

        self.assertEqual(coordinator.check_interval, 60)  # Default value

    def test_start_monitoring(self):
        """Test start monitoring functionality."""
        with patch("time.time") as mock_time:
            mock_time.return_value = 1000.0

            # Set up the coordinator to run one cycle then stop
            self.coordinator.running = True

            def stop_after_first_cycle():
                """Stop monitoring after first cycle to avoid infinite loop."""
                self.coordinator.running = False

            with patch.object(
                self.coordinator,
                "_run_monitoring_cycle",
                side_effect=stop_after_first_cycle,
            ) as mock_cycle, patch.object(
                self.coordinator, "_wait_for_next_cycle"
            ) as mock_wait:

                self.coordinator.start_monitoring()

                # Should have started monitoring
                self.assertEqual(self.coordinator.stats["start_time"], 1000.0)
                mock_cycle.assert_called_once()
                mock_wait.assert_called_once()

    def test_start_monitoring_with_keyboard_interrupt(self):
        """Test start monitoring with keyboard interrupt."""
        with patch("time.time") as mock_time:
            mock_time.return_value = 1000.0

            # Set up the coordinator to run and then get interrupted
            self.coordinator.running = True

            with patch.object(
                self.coordinator, "_run_monitoring_cycle"
            ) as mock_cycle, patch.object(
                self.coordinator, "stop_monitoring"
            ) as mock_stop:

                # Make the cycle raise KeyboardInterrupt immediately
                mock_cycle.side_effect = KeyboardInterrupt()

                self.coordinator.start_monitoring()

                mock_stop.assert_called_once()
                self.mock_logger.info.assert_any_call("Monitoring stopped by user")

    def test_start_monitoring_with_exception(self):
        """Test start monitoring with unexpected exception."""
        with patch("time.time") as mock_time:
            mock_time.return_value = 1000.0

            # Set up the coordinator to run and then get an error
            self.coordinator.running = True

            with patch.object(
                self.coordinator, "_run_monitoring_cycle"
            ) as mock_cycle, patch.object(
                self.coordinator, "stop_monitoring"
            ) as mock_stop:

                # Make the cycle raise an exception immediately
                mock_cycle.side_effect = Exception("Test error")

                with self.assertRaises(Exception):
                    self.coordinator.start_monitoring()

                mock_stop.assert_called_once()
                self.mock_logger.error.assert_any_call("Monitoring error: Test error")

    def test_start_monitoring_loop_control(self):
        """Test that monitoring loop can be controlled and stopped."""
        with patch("time.time") as mock_time:
            mock_time.return_value = 1000.0

            # Track how many times the cycle runs
            cycle_count = 0

            def run_cycle_and_stop():
                nonlocal cycle_count
                cycle_count += 1
                if cycle_count >= 3:  # Stop after 3 cycles
                    self.coordinator.running = False

            with patch.object(
                self.coordinator,
                "_run_monitoring_cycle",
                side_effect=run_cycle_and_stop,
            ) as mock_cycle, patch.object(
                self.coordinator, "_wait_for_next_cycle"
            ) as mock_wait:

                self.coordinator.running = True
                self.coordinator.start_monitoring()

                # Should have run exactly 3 cycles
                self.assertEqual(mock_cycle.call_count, 3)
                self.assertEqual(mock_wait.call_count, 3)
                self.assertFalse(self.coordinator.running)

    def test_stop_monitoring(self):
        """Test stop monitoring functionality."""
        with patch("time.time") as mock_time:
            # Mock time calls in stop_monitoring method
            mock_time.side_effect = [1100.0]  # Called once for runtime calculation

            self.coordinator.stats["start_time"] = 1000.0
            self.coordinator.stats["monitoring_cycles"] = 5
            self.coordinator.stats["total_log_entries"] = 100
            self.coordinator.stats["total_threats"] = 3
            self.coordinator.stats["alerts_sent"] = 2
            self.coordinator.running = True

            self.coordinator.stop_monitoring()

            self.assertFalse(self.coordinator.running)
            self.mock_logger.info.assert_any_call("Stopping NGINX Security Monitor")
            self.mock_logger.info.assert_any_call("Monitor ran for 100.00 seconds")
            self.mock_logger.info.assert_any_call("Processed 5 cycles")
            self.mock_logger.info.assert_any_call("Analyzed 100 log entries")
            self.mock_logger.info.assert_any_call("Detected 3 threats")
            self.mock_logger.info.assert_any_call("Sent 2 alerts")

    def test_run_monitoring_cycle(self):
        """Test running a monitoring cycle."""
        with patch("time.time") as mock_time:
            mock_time.side_effect = [2000.0, 2001.0]  # cycle start, cycle end

            # Mock all the cycle methods
            with patch.object(
                self.coordinator, "_check_service_protection"
            ) as mock_service, patch.object(
                self.coordinator, "_process_log_files"
            ) as mock_process, patch.object(
                self.coordinator, "_handle_threats"
            ) as mock_handle, patch.object(
                self.coordinator, "_check_security_integrations"
            ) as mock_integrations, patch.object(
                self.coordinator, "_update_network_security"
            ) as mock_network:

                # Set up return values
                mock_process.return_value = [{"type": "test_threat"}]

                self.coordinator._run_monitoring_cycle()

                # Verify all methods were called
                mock_service.assert_called_once()
                mock_process.assert_called_once()
                mock_handle.assert_called_once_with([{"type": "test_threat"}])
                mock_integrations.assert_called_once()
                mock_network.assert_called_once()

                # Check stats were updated
                self.assertEqual(self.coordinator.stats["monitoring_cycles"], 1)

    def test_run_monitoring_cycle_no_threats(self):
        """Test monitoring cycle with no threats detected."""
        with patch("time.time") as mock_time:
            mock_time.side_effect = [2000.0, 2001.0]

            with patch.object(
                self.coordinator, "_check_service_protection"
            ), patch.object(
                self.coordinator, "_process_log_files"
            ) as mock_process, patch.object(
                self.coordinator, "_handle_threats"
            ) as mock_handle, patch.object(
                self.coordinator, "_check_security_integrations"
            ), patch.object(
                self.coordinator, "_update_network_security"
            ):

                # No threats detected
                mock_process.return_value = []

                self.coordinator._run_monitoring_cycle()

                # Handle threats should not be called
                mock_handle.assert_not_called()

    def test_run_monitoring_cycle_with_exception(self):
        """Test monitoring cycle with exception handling."""
        with patch.object(
            self.coordinator, "_check_service_protection"
        ) as mock_service:
            mock_service.side_effect = Exception("Service check error")

            self.coordinator._run_monitoring_cycle()

            self.mock_logger.error.assert_any_call(
                "Error in monitoring cycle: Service check error"
            )

    def test_process_log_files(self):
        """Test processing log files."""
        # Set up config with log files
        self.coordinator.config = {
            "log_files": ["/var/log/nginx/access.log", "/var/log/nginx/error.log"]
        }

        # Mock log processor responses
        self.mock_log_processor.get_new_log_entries.side_effect = [
            ["entry1", "entry2"],  # First file
            ["entry3"],  # Second file
        ]

        # Mock threat processor responses
        self.mock_threat_processor.process_log_entries.side_effect = [
            [{"type": "threat1"}],  # First file threats
            [{"type": "threat2"}],  # Second file threats
        ]

        threats = self.coordinator._process_log_files()

        # Verify log processor was called for each file
        expected_calls = [
            call("/var/log/nginx/access.log"),
            call("/var/log/nginx/error.log"),
        ]
        self.mock_log_processor.get_new_log_entries.assert_has_calls(expected_calls)

        # Verify threat processor was called
        self.mock_threat_processor.process_log_entries.assert_any_call(
            ["entry1", "entry2"]
        )
        self.mock_threat_processor.process_log_entries.assert_any_call(["entry3"])

        # Check results
        self.assertEqual(len(threats), 2)
        self.assertEqual(threats[0]["type"], "threat1")
        self.assertEqual(threats[1]["type"], "threat2")

        # Check stats update (3 total entries)
        self.assertEqual(self.coordinator.stats["total_log_entries"], 3)

    def test_process_log_files_with_error(self):
        """Test processing log files with error handling."""
        self.coordinator.config = {"log_files": ["/var/log/nginx/access.log"]}

        # Mock log processor to raise an exception
        self.mock_log_processor.get_new_log_entries.side_effect = Exception(
            "File read error"
        )

        threats = self.coordinator._process_log_files()

        # Should return empty list and log error
        self.assertEqual(threats, [])
        self.mock_logger.error.assert_any_call(
            "Error processing log file /var/log/nginx/access.log: File read error"
        )

    def test_handle_threats(self):
        """Test handling detected threats."""
        threats = [
            {"type": "brute_force", "source_ip": "192.168.1.100", "severity": "high"},
            {"type": "sql_injection", "source_ip": "10.0.0.50", "severity": "critical"},
        ]

        # Mock alert manager
        self.mock_alert_manager.send_threat_alert.return_value = True

        # Mock security integrations method
        with patch.object(self.coordinator, "_send_to_integrations") as mock_send:
            self.coordinator._handle_threats(threats)

            # Verify alerts were sent
            self.assertEqual(self.mock_alert_manager.send_threat_alert.call_count, 2)

            # Verify threats were logged
            self.mock_logger.warning.assert_any_call(
                "Threat detected: brute_force from 192.168.1.100 [Severity: high]"
            )
            self.mock_logger.warning.assert_any_call(
                "Threat detected: sql_injection from 10.0.0.50 [Severity: critical]"
            )

            # Verify critical threats were sent to integrations
            self.assertEqual(mock_send.call_count, 2)  # Both high and critical

            # Check stats
            self.assertEqual(self.coordinator.stats["total_threats"], 2)
            self.assertEqual(self.coordinator.stats["alerts_sent"], 2)

    def test_handle_threats_alert_failure(self):
        """Test handling threats when alert sending fails."""
        threats = [{"type": "test", "source_ip": "1.1.1.1", "severity": "low"}]

        # Mock alert failure
        self.mock_alert_manager.send_threat_alert.return_value = False

        self.coordinator._handle_threats(threats)

        # Alert count should not increment
        self.assertEqual(self.coordinator.stats["alerts_sent"], 0)
        # But threat count should still increment
        self.assertEqual(self.coordinator.stats["total_threats"], 1)

    def test_handle_threats_with_exception(self):
        """Test handling threats with exception."""
        threats = [{"type": "test"}]

        # Mock alert manager to raise exception
        self.mock_alert_manager.send_threat_alert.side_effect = Exception("Alert error")

        self.coordinator._handle_threats(threats)

        self.mock_logger.error.assert_any_call(
            "Error handling threat {'type': 'test'}: Alert error"
        )

    def test_check_service_protection(self):
        """Test checking service protection."""
        # Mock service threats
        service_threats = [
            {"type": "service_down", "service": "nginx"},
            {"type": "high_load", "service": "nginx"},
        ]

        self.mock_service_protection.check_for_threats.return_value = service_threats
        self.mock_alert_manager.send_service_threat_alert.return_value = True

        self.coordinator._check_service_protection()

        # Verify service protection was checked
        self.mock_service_protection.check_for_threats.assert_called_once()

        # Verify alerts were sent
        self.assertEqual(
            self.mock_alert_manager.send_service_threat_alert.call_count, 2
        )

        # Verify threats were logged
        self.mock_logger.warning.assert_any_call(
            "Service threat detected: {'type': 'service_down', 'service': 'nginx'}"
        )
        self.mock_logger.warning.assert_any_call(
            "Service threat detected: {'type': 'high_load', 'service': 'nginx'}"
        )

        # Check stats
        self.assertEqual(self.coordinator.stats["alerts_sent"], 2)

    def test_check_service_protection_no_threats(self):
        """Test service protection check with no threats."""
        self.mock_service_protection.check_for_threats.return_value = []

        self.coordinator._check_service_protection()

        # No alerts should be sent
        self.mock_alert_manager.send_service_threat_alert.assert_not_called()

    def test_check_service_protection_with_exception(self):
        """Test service protection check with exception."""
        self.mock_service_protection.check_for_threats.side_effect = Exception(
            "Service error"
        )

        self.coordinator._check_service_protection()

        self.mock_logger.error.assert_any_call(
            "Error checking service protection: Service error"
        )

    def test_check_security_integrations(self):
        """Test checking security integrations."""
        integration_alerts = [
            {"type": "rule_update", "source": "fail2ban"},
            {"type": "threat_intel", "source": "ossec"},
        ]

        self.mock_security_integrations.check_for_updates.return_value = (
            integration_alerts
        )
        self.mock_alert_manager.send_integration_alert.return_value = True

        self.coordinator._check_security_integrations()

        # Verify integrations were checked
        self.mock_security_integrations.check_for_updates.assert_called_once()

        # Verify alerts were sent
        self.assertEqual(self.mock_alert_manager.send_integration_alert.call_count, 2)

        # Verify alerts were logged
        self.mock_logger.info.assert_any_call(
            "Integration alert: {'type': 'rule_update', 'source': 'fail2ban'}"
        )
        self.mock_logger.info.assert_any_call(
            "Integration alert: {'type': 'threat_intel', 'source': 'ossec'}"
        )

        # Check stats
        self.assertEqual(self.coordinator.stats["alerts_sent"], 2)

    def test_check_security_integrations_with_exception(self):
        """Test security integrations check with exception."""
        self.mock_security_integrations.check_for_updates.side_effect = Exception(
            "Integration error"
        )

        self.coordinator._check_security_integrations()

        self.mock_logger.error.assert_any_call(
            "Error checking security integrations: Integration error"
        )

    def test_update_network_security(self):
        """Test updating network security."""
        self.coordinator._update_network_security()

        # Verify network security was updated
        self.mock_network_security.update_security_rules.assert_called_once()

    def test_update_network_security_with_exception(self):
        """Test network security update with exception."""
        self.mock_network_security.update_security_rules.side_effect = Exception(
            "Network error"
        )

        self.coordinator._update_network_security()

        self.mock_logger.error.assert_any_call(
            "Error updating network security: Network error"
        )

    def test_send_to_integrations(self):
        """Test sending threats to integrations."""
        threat = {"type": "critical_threat", "severity": "critical"}

        self.coordinator._send_to_integrations(threat)

        # Verify threat was sent to integrations
        self.mock_security_integrations.send_threat_data.assert_called_once_with(threat)

    def test_send_to_integrations_with_exception(self):
        """Test sending to integrations with exception."""
        threat = {"type": "test"}
        self.mock_security_integrations.send_threat_data.side_effect = Exception(
            "Send error"
        )

        self.coordinator._send_to_integrations(threat)

        self.mock_logger.error.assert_any_call(
            "Error sending threat to integrations: Send error"
        )

    def test_wait_for_next_cycle(self):
        """Test waiting for next cycle."""
        with patch("time.sleep") as mock_sleep, patch("time.time") as mock_time:

            # Set up timing: last check was 20 seconds ago, interval is 30
            # elapsed = 30 - 20 = 10, need to sleep 30 - 10 = 20 seconds
            mock_time.side_effect = [30.0, 50.0, 50.0]  # current time, updated times
            self.coordinator.last_check_time = 10.0
            self.coordinator.check_interval = 30

            self.coordinator._wait_for_next_cycle()

            # Should sleep for 10 seconds (30 - (30-10))
            mock_sleep.assert_called_once_with(10.0)
            # Should update last check time
            self.assertEqual(self.coordinator.last_check_time, 50.0)

    def test_wait_for_next_cycle_no_sleep_needed(self):
        """Test waiting when no sleep is needed."""
        with patch("time.sleep") as mock_sleep, patch("time.time") as mock_time:

            # Set up timing: enough time has passed
            # Need 3 calls: current_time, final update (twice due to redundant call)
            mock_time.side_effect = [50.0, 60.0, 60.0]
            self.coordinator.last_check_time = 10.0
            self.coordinator.check_interval = 30

            self.coordinator._wait_for_next_cycle()

            # Should not sleep
            mock_sleep.assert_not_called()
            # Should still update last check time
            self.assertEqual(self.coordinator.last_check_time, 60.0)

    def test_get_monitoring_status(self):
        """Test getting monitoring status."""
        with patch("time.time") as mock_time:
            mock_time.return_value = 2000.0

            # Set up stats
            self.coordinator.stats["start_time"] = 1000.0
            self.coordinator.stats["monitoring_cycles"] = 10
            self.coordinator.stats["total_log_entries"] = 500
            self.coordinator.stats["total_threats"] = 5
            self.coordinator.stats["alerts_sent"] = 3
            self.coordinator.running = True
            self.coordinator.last_check_time = 1900.0

            status = self.coordinator.get_monitoring_status()

            expected = {
                "running": True,
                "runtime_seconds": 1000.0,  # 2000 - 1000
                "monitoring_cycles": 10,
                "total_log_entries": 500,
                "total_threats": 5,
                "alerts_sent": 3,
                "threats_per_hour": 18.0,  # (5 / (1000/3600))
                "last_check_time": 1900.0,
            }

            self.assertEqual(status, expected)

    def test_get_monitoring_status_zero_runtime(self):
        """Test monitoring status with zero runtime."""
        with patch("time.time") as mock_time:
            mock_time.return_value = 1000.0

            self.coordinator.stats["start_time"] = 1000.0
            self.coordinator.stats["total_threats"] = 5

            status = self.coordinator.get_monitoring_status()

            # Should handle division by zero
            self.assertEqual(status["threats_per_hour"], 0)

    def test_force_check(self):
        """Test forcing an immediate check."""
        with patch("time.time") as mock_time, patch.object(
            self.coordinator, "_process_log_files"
        ) as mock_process, patch.object(
            self.coordinator, "_handle_threats"
        ) as mock_handle:

            mock_time.return_value = 3000.0
            mock_process.return_value = [{"type": "forced_threat"}]

            result = self.coordinator.force_check()

            # Verify methods were called
            mock_process.assert_called_once()
            mock_handle.assert_called_once_with([{"type": "forced_threat"}])

            # Check result
            expected = {"success": True, "threats_detected": 1, "timestamp": 3000.0}
            self.assertEqual(result, expected)

            self.mock_logger.info.assert_any_call("Forcing immediate security check")

    def test_force_check_no_threats(self):
        """Test forced check with no threats."""
        with patch("time.time") as mock_time, patch.object(
            self.coordinator, "_process_log_files"
        ) as mock_process, patch.object(
            self.coordinator, "_handle_threats"
        ) as mock_handle:

            mock_time.return_value = 3000.0
            mock_process.return_value = []

            result = self.coordinator.force_check()

            # Handle threats should not be called
            mock_handle.assert_not_called()

            # Check result
            expected = {"success": True, "threats_detected": 0, "timestamp": 3000.0}
            self.assertEqual(result, expected)

    def test_force_check_with_exception(self):
        """Test forced check with exception."""
        with patch("time.time") as mock_time, patch.object(
            self.coordinator, "_process_log_files"
        ) as mock_process:

            mock_time.return_value = 3000.0
            mock_process.side_effect = Exception("Forced check error")

            result = self.coordinator.force_check()

            # Check error result
            expected = {
                "success": False,
                "error": "Forced check error",
                "timestamp": 3000.0,
            }
            self.assertEqual(result, expected)

            self.mock_logger.error.assert_any_call(
                "Error during forced check: Forced check error"
            )


if __name__ == "__main__":
    unittest.main()
