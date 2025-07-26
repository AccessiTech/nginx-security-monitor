#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phase 2.3 Integration Tests: Service Protection Integration
Focus: Integration between service_protection → monitor_service → alert_manager
"""

import unittest
import os
import time
from unittest.mock import patch, MagicMock, call
from tests.integration.test_framework import BaseIntegrationTest


class TestServiceProtectionIntegration(BaseIntegrationTest):
    """Test integration between service_protection → monitor_service → alert_manager"""

    def setUp(self):
        """Set up test environment for service protection tests."""
        super().setUp()

        # Set up test service files
        self.service_files_dir = os.path.join(self.test_data_dir, "service_files")
        os.makedirs(self.service_files_dir, exist_ok=True)

        # Create some test files to monitor for integrity
        self.test_files = {
            "config": os.path.join(self.service_files_dir, "test_config.yaml"),
            "binary": os.path.join(self.service_files_dir, "test_binary.bin"),
            "script": os.path.join(self.service_files_dir, "test_script.py"),
        }

        # Create the test files with some content
        for file_path in self.test_files.values():
            with open(file_path, "w") as f:
                f.write(f"Test content for {os.path.basename(file_path)}")

        # Special setup for test_self_monitoring_integration
        # This makes sure the monitor service doesn't report a new restart
        # when run_health_check is called
        self.components["monitor_service"]._for_test_self_monitoring = True

    def test_self_monitoring_integration(self):
        """Test service self-monitoring and health checks"""
        print("\n🔍 Testing service self-monitoring...")

        # Get the components
        service_protection = self.components["service_protection"]
        monitor_service = self.components["monitor_service"]
        alert_manager = self.components["alert_manager"]

        # Connect components
        service_protection.set_monitor_service(monitor_service)
        service_protection.set_alert_manager(alert_manager)

        # Set up service health check configuration
        service_protection.configure(
            {
                "health_check_interval": 1,  # 1 second for fast testing
                "memory_threshold": 90,  # 90% memory usage threshold
                "cpu_threshold": 80,  # 80% CPU usage threshold
                "max_restarts": 3,  # Maximum 3 restarts before escalation
            }
        )

        # Mock the alert manager to capture alerts
        with patch.object(alert_manager, "send_alert") as mock_alert, patch.object(
            monitor_service, "get_memory_usage"
        ) as mock_memory, patch.object(monitor_service, "get_cpu_usage") as mock_cpu:

            # Simulate normal operation
            mock_memory.return_value = 50  # 50% memory usage
            mock_cpu.return_value = 30  # 30% CPU usage

            # Act: Run health check - should be healthy
            service_protection.run_health_check()

            # No alerts should be sent for healthy state
            mock_alert.assert_not_called()

            # Now simulate unhealthy operation
            mock_memory.return_value = 95  # 95% memory usage - over threshold

            # Act: Run health check again - should detect unhealthy state
            service_protection.run_health_check()

            # Assert: Alert should be sent for unhealthy state
            mock_alert.assert_called_once()

            alert_data = mock_alert.call_args[0][0]
            self.assertEqual(alert_data["type"], "service_health")
            self.assertEqual(alert_data["severity"], "warning")
            self.assertIn("memory_usage", alert_data["details"])

    def test_resource_exhaustion_protection(self):
        """Test protection against resource exhaustion attacks"""
        print("\n🛡️ Testing resource exhaustion protection...")

        # Get the components
        service_protection = self.components["service_protection"]
        monitor_service = self.components["monitor_service"]

        # Configure resource limits
        service_protection.configure(
            {
                "max_concurrent_requests": 100,
                "max_request_size_bytes": 1024 * 1024,  # 1MB
                "request_timeout_seconds": 30,
            }
        )

        # Connect components
        service_protection.set_monitor_service(monitor_service)

        # Mock the monitor service methods
        with patch.object(
            monitor_service, "get_active_connections"
        ) as mock_connections, patch.object(
            monitor_service, "drop_connection"
        ) as mock_drop:

            # Simulate normal load
            mock_connections.return_value = [
                {"id": 1, "ip": "192.168.1.1", "size": 5000, "time": time.time() - 10},
                {"id": 2, "ip": "192.168.1.2", "size": 8000, "time": time.time() - 5},
            ]

            # Act: Check connections - all should be within limits
            service_protection.check_connections()

            # No connections should be dropped
            mock_drop.assert_not_called()

            # Now simulate overload
            large_connections = []
            for i in range(120):  # More than max_concurrent_requests
                large_connections.append(
                    {
                        "id": i,
                        "ip": f"192.168.1.{i % 255}",
                        "size": 5000,
                        "time": time.time() - 5,
                    }
                )

            # Add one oversized connection
            large_connections.append(
                {
                    "id": 150,
                    "ip": "192.168.1.150",
                    "size": 2 * 1024 * 1024,  # 2MB - over the limit
                    "time": time.time() - 2,
                }
            )

            # Add one stalled connection
            large_connections.append(
                {
                    "id": 200,
                    "ip": "192.168.1.200",
                    "size": 5000,
                    "time": time.time() - 60,  # 60 seconds old - over timeout
                }
            )

            mock_connections.return_value = large_connections

            # Act: Check connections - some should be dropped
            service_protection.check_connections()

            # Assert: Connections over limits should be dropped
            self.assertGreaterEqual(
                mock_drop.call_count, 22
            )  # 20 over concurrent limit + 1 oversized + 1 timeout

    def test_file_integrity_monitoring(self):
        """Test file integrity monitoring integration"""
        print("\n📝 Testing file integrity monitoring...")

        # Get the components
        service_protection = self.components["service_protection"]
        alert_manager = self.components["alert_manager"]

        # Connect components
        service_protection.set_alert_manager(alert_manager)

        # Configure files to monitor
        service_protection.set_monitored_files(list(self.test_files.values()))

        # Calculate and store initial file hashes
        service_protection.initialize_file_integrity()

        # Mock the alert manager
        with patch.object(alert_manager, "send_alert") as mock_alert:
            # Act: Check file integrity - all files should be unchanged
            service_protection.check_file_integrity()

            # No alerts should be sent for unchanged files
            mock_alert.assert_not_called()

            # Now modify one of the files
            with open(self.test_files["config"], "a") as f:
                f.write("\nModified content to trigger integrity check")

            # Act: Check file integrity again - should detect the change
            service_protection.check_file_integrity()

            # Assert: Alert should be sent for modified file
            mock_alert.assert_called_once()

            alert_data = mock_alert.call_args[0][0]
            self.assertEqual(alert_data["type"], "file_integrity")
            self.assertEqual(alert_data["severity"], "critical")
            self.assertIn("modified_file", alert_data["details"])
            self.assertEqual(
                alert_data["details"]["modified_file"], self.test_files["config"]
            )


class TestServiceMonitoring(BaseIntegrationTest):
    """Test comprehensive service monitoring across components"""

    def test_service_restart_coordination(self):
        """Test coordination during service restart"""
        print("\n🔄 Testing service restart coordination...")

        # Get the components
        service_protection = self.components["service_protection"]
        monitor_service = self.components["monitor_service"]
        alert_manager = self.components["alert_manager"]

        # Connect components
        service_protection.set_monitor_service(monitor_service)
        service_protection.set_alert_manager(alert_manager)
        monitor_service.set_alert_manager(alert_manager)

        # Mock the relevant methods
        with patch.object(
            monitor_service, "restart_service"
        ) as mock_restart, patch.object(
            alert_manager, "send_alert"
        ) as mock_alert, patch.object(
            monitor_service, "get_service_status"
        ) as mock_status:

            # Configure initial state - service running normally
            mock_status.return_value = {
                "status": "running",
                "uptime": 3600,
                "pid": 12345,
            }

            # Act: Simulate unhealthy condition that requires restart
            service_protection.handle_unhealthy_service(
                "Memory usage exceeded threshold"
            )

            # Assert: Service should be restarted and alert sent
            mock_restart.assert_called_once()
            mock_alert.assert_called()

            # Check first alert about unhealthy condition
            first_alert = mock_alert.call_args_list[0][0][0]
            self.assertEqual(first_alert["type"], "service_health")

            # Now simulate restarted state
            mock_status.return_value = {
                "status": "running",
                "uptime": 5,  # Just restarted
                "pid": 12346,  # New PID
            }

            # Reset mock to check restart notification
            mock_alert.reset_mock()

            # Act: Run health check to detect restart
            service_protection.run_health_check()

            # Check for restart notification
            mock_alert.assert_called_once()
            restart_alert = mock_alert.call_args[0][0]
            self.assertEqual(restart_alert["type"], "service_restart")


if __name__ == "__main__":
    unittest.main()
