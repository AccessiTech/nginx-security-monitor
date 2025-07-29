"""
Test suite for service protection functionality
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
import os
import tempfile
import hashlib
from datetime import datetime, timedelta
from collections import deque


from nginx_security_monitor.service_protection import ServiceProtection


class TestServiceProtection(unittest.TestCase):

    def setUp(self):
        self.config = {
            "security": {
                "self_check_interval": 300,
                "emergency_shutdown": {
                    "file_tampering": True,
                    "process_hijacking": True,
                },
            },
            "logging": {"file": "/var/log/nginx-security-monitor.log"},
            "log_file_path": "/var/log/nginx/access.log",
            "protection": {"allowed_ips": ["203.0.113.1", "198.51.100.1"]},
        }

    @patch("psutil.Process")
    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    def test_initialization(self, mock_disk, mock_memory, mock_cpu, mock_process):
        """Test ServiceProtection initialization."""
        # Mock process
        mock_process.return_value.pid = 1234
        mock_process.return_value.ppid.return_value = 1
        mock_process.return_value.name.return_value = "python3"
        mock_process.return_value.cmdline.return_value = [
            "python3",
            "monitor_service.py",
        ]
        mock_process.return_value.create_time.return_value = 1234567890

        # Mock resource monitoring
        mock_cpu.return_value = 25.0
        mock_memory.return_value.percent = 30.0
        mock_disk.return_value.percent = 20.0

        with patch.object(ServiceProtection, "_baseline_file_integrity"):
            protection = ServiceProtection(self.config)

            self.assertIsNotNone(protection.file_hashes)
            self.assertIsNotNone(protection.process_baseline)
            self.assertEqual(protection.process_baseline["pid"], 1234)
            self.assertEqual(protection.process_baseline["name"], "python3")

    def test_initialization_without_config(self):
        """Test initialization without config."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection()
            self.assertEqual(protection.config, {})

    @patch("psutil.Process")
    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    def test_initialization_exception_handling(
        self, mock_disk, mock_memory, mock_cpu, mock_process
    ):
        """Test initialization exception handling."""
        mock_process.side_effect = Exception("Process error")

        with patch.object(ServiceProtection, "_baseline_file_integrity"):
            protection = ServiceProtection(self.config)
            self.assertIsNotNone(protection)

    def test_calculate_file_hash(self):
        """Test file hash calculation."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Create temporary file with known content
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test content for hashing")
            temp_file = f.name

        try:
            file_hash = protection._calculate_file_hash(temp_file)

            # Verify hash is calculated correctly
            expected_hash = hashlib.sha256(b"test content for hashing").hexdigest()
            self.assertEqual(file_hash, expected_hash)

        finally:
            os.unlink(temp_file)

    def test_calculate_file_hash_exception(self):
        """Test file hash calculation with exception."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Test with non-existent file
        result = protection._calculate_file_hash("/non/existent/file")
        self.assertIsNone(result)

    @patch("os.path.isfile")
    @patch("os.path.isdir")
    @patch("os.walk")
    def test_baseline_file_integrity(self, mock_walk, mock_isdir, mock_isfile):
        """Test file integrity baseline creation."""
        # Mock file system structure
        mock_isfile.side_effect = lambda path: path == "/test/file.py"
        mock_isdir.side_effect = lambda path: path == "/test/dir"

        mock_walk.return_value = [
            ("/test/dir", [], ["monitor.py", "config.yml", "readme.txt"]),
        ]

        with patch.object(ServiceProtection, "_baseline_process_state"), patch.object(
            ServiceProtection, "_setup_resource_monitoring"
        ):
            protection = ServiceProtection(self.config)

            with patch.object(protection, "_calculate_file_hash") as mock_hash:
                mock_hash.return_value = "test_hash_value"
                protection.protected_files = ["/test/file.py", "/test/dir"]

                protection._baseline_file_integrity()

                # Should have hashed relevant files (py, yml but not txt)
                self.assertGreater(len(protection.file_hashes), 0)
                expected_calls = [
                    unittest.mock.call("/test/file.py"),
                    unittest.mock.call("/test/dir/monitor.py"),
                    unittest.mock.call("/test/dir/config.yml"),
                ]
                mock_hash.assert_has_calls(expected_calls, any_order=True)

    def test_check_rate_limiting(self):
        """Test rate limiting functionality."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # First few operations should pass
        self.assertTrue(protection.check_rate_limiting("test_op", limit_per_minute=5))
        self.assertTrue(protection.check_rate_limiting("test_op", limit_per_minute=5))

        # Simulate reaching the limit
        protection.operation_counts["test_op"] = deque(
            [datetime.now() for _ in range(5)]
        )

        # Should now be rate limited
        result = protection.check_rate_limiting("test_op", limit_per_minute=5)
        self.assertFalse(result)

    def test_check_rate_limiting_edge_cases(self):
        """Test rate limiting edge cases."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Test with zero limit
        result = protection.check_rate_limiting("zero_limit", limit_per_minute=0)
        self.assertFalse(result)

        # Test with old entries that should be cleaned up
        old_time = datetime.now() - timedelta(minutes=2)
        protection.operation_counts["cleanup_test"] = deque([old_time, old_time])

        result = protection.check_rate_limiting("cleanup_test", limit_per_minute=1)
        self.assertTrue(result)  # Should pass because old entries are cleaned

    @patch("os.path.exists")
    def test_check_file_integrity_tampering(self, mock_exists):
        """Test file integrity check with tampering."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Set up baseline hash
        test_file = "/test/file.py"
        protection.file_hashes[test_file] = "original_hash"

        mock_exists.return_value = True

        with patch.object(protection, "_calculate_file_hash") as mock_hash:
            mock_hash.return_value = (
                "modified_hash"  # Different hash indicates tampering
            )

            threats = protection.check_file_integrity()

            self.assertEqual(len(threats), 1)
            self.assertEqual(threats[0]["type"], "File Tampering")
            self.assertEqual(threats[0]["severity"], "CRITICAL")
            self.assertEqual(threats[0]["file"], test_file)

    @patch("os.path.exists")
    def test_check_file_integrity_deletion(self, mock_exists):
        """Test file integrity check with file deletion."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Set up baseline for file that no longer exists
        test_file = "/test/deleted.py"
        protection.file_hashes[test_file] = "original_hash"

        mock_exists.return_value = False  # File was deleted

        threats = protection.check_file_integrity()

        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "File Deletion")
        self.assertEqual(threats[0]["severity"], "CRITICAL")
        self.assertEqual(threats[0]["file"], test_file)

    @patch("os.path.exists")
    def test_check_file_integrity_no_tampering(self, mock_exists):
        """Test file integrity check with no tampering."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        test_file = "/test/file.py"
        protection.file_hashes[test_file] = "original_hash"

        mock_exists.return_value = True

        with patch.object(protection, "_calculate_file_hash") as mock_hash:
            mock_hash.return_value = "original_hash"  # Same hash, no tampering

            threats = protection.check_file_integrity()

            self.assertEqual(len(threats), 0)

    @patch("psutil.Process")
    def test_check_process_integrity_normal(self, mock_process):
        """Test process integrity check with normal process."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Set up baseline
        protection.process_baseline = {
            "pid": 1234,
            "ppid": 1,
            "name": "python3",
            "cmdline": ["python3", "monitor_service.py"],
        }

        # Mock current process state (unchanged)
        mock_process.return_value.pid = 1234
        mock_process.return_value.ppid.return_value = 1
        mock_process.return_value.name.return_value = "python3"
        mock_process.return_value.cmdline.return_value = [
            "python3",
            "monitor_service.py",
        ]
        mock_process.return_value.children.return_value = []

        threats = protection.check_process_integrity()

        self.assertEqual(len(threats), 0)  # No threats for normal process

    @patch("psutil.Process")
    def test_check_process_integrity_hijacking(self, mock_process):
        """Test process integrity check with hijacking."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Set up baseline
        protection.process_baseline = {
            "pid": 1234,
            "ppid": 1,
            "name": "python3",
            "cmdline": ["python3", "monitor_service.py"],
        }

        # Mock hijacked process state
        mock_process.return_value.pid = 1234
        mock_process.return_value.ppid.return_value = 1
        mock_process.return_value.name.return_value = (
            "malicious_process"  # Changed name
        )
        mock_process.return_value.cmdline.return_value = [
            "malicious_command"
        ]  # Changed command
        mock_process.return_value.children.return_value = []

        threats = protection.check_process_integrity()

        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "Process Hijacking")
        self.assertEqual(threats[0]["severity"], "CRITICAL")

    @patch("psutil.Process")
    def test_check_process_integrity_suspicious_children(self, mock_process):
        """Test process integrity check with suspicious child processes."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        protection.process_baseline = {
            "pid": 1234,
            "ppid": 1,
            "name": "python3",
            "cmdline": ["python3", "monitor_service.py"],
        }

        # Mock suspicious child
        mock_child = Mock()
        mock_child.name.return_value = "suspicious_process"
        mock_child.pid = 5678

        mock_process.return_value.pid = 1234
        mock_process.return_value.ppid.return_value = 1
        mock_process.return_value.name.return_value = "python3"
        mock_process.return_value.cmdline.return_value = [
            "python3",
            "monitor_service.py",
        ]
        mock_process.return_value.children.return_value = [mock_child]

        threats = protection.check_process_integrity()

        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "Suspicious Child Process")
        self.assertEqual(threats[0]["severity"], "HIGH")

    @patch("psutil.Process")
    def test_check_process_integrity_exception(self, mock_process):
        """Test process integrity check with exception."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_process.side_effect = Exception("Process error")

        threats = protection.check_process_integrity()

        self.assertEqual(len(threats), 0)  # Should handle exception gracefully

    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    @patch("psutil.net_connections")
    def test_check_resource_abuse_normal(
        self, mock_connections, mock_disk, mock_memory, mock_cpu
    ):
        """Test resource abuse check with normal usage."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_cpu.return_value = 25.0  # Normal CPU usage
        mock_memory.return_value.percent = 30.0  # Normal memory usage
        mock_disk.return_value.used = 100 * 1024**3  # 100GB used
        mock_disk.return_value.total = 500 * 1024**3  # 500GB total (20% usage)
        mock_connections.return_value = []

        threats = protection.check_resource_abuse()

        self.assertEqual(len(threats), 0)  # No threats for normal usage

    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    @patch("psutil.net_connections")
    def test_check_resource_abuse_high_usage(
        self, mock_connections, mock_disk, mock_memory, mock_cpu
    ):
        """Test resource abuse check with high usage."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_cpu.return_value = 95.0  # High CPU usage
        mock_memory.return_value.percent = 95.0  # High memory usage
        mock_disk.return_value.used = 460 * 1024**3  # 460GB used
        mock_disk.return_value.total = (
            500 * 1024**3
        )  # 500GB total (92% usage, above 90% threshold)
        mock_connections.return_value = []

        threats = protection.check_resource_abuse()

        # Should detect high resource usage
        self.assertGreater(len(threats), 0)
        threat_types = [threat["type"] for threat in threats]
        self.assertIn("High CPU Usage", threat_types)
        self.assertIn("High Memory Usage", threat_types)
        self.assertIn("High Disk Usage", threat_types)

    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    @patch("psutil.net_connections")
    def test_check_resource_abuse_suspicious_connections(
        self, mock_connections, mock_disk, mock_memory, mock_cpu
    ):
        """Test resource abuse check with suspicious network connections."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        from collections import namedtuple

        Connection = namedtuple("Connection", ["status", "laddr", "raddr"])
        Address = namedtuple("Address", ["ip", "port"])

        suspicious_conn = Connection(
            status="ESTABLISHED",
            laddr=Address("127.0.0.1", 8000),
            raddr=Address("8.8.8.8", 80),  # Public IP
        )

        mock_cpu.return_value = 50
        mock_memory.return_value.percent = 50
        mock_disk.return_value.used = 50000
        mock_disk.return_value.total = 100000
        mock_connections.return_value = [suspicious_conn]

        threats = protection.check_resource_abuse()

        # Should detect suspicious network activity
        network_threats = [
            t for t in threats if t["type"] == "Suspicious Network Activity"
        ]
        self.assertEqual(len(network_threats), 1)

    @patch("psutil.cpu_percent")
    def test_check_resource_abuse_exception(self, mock_cpu):
        """Test resource abuse check with exception."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_cpu.side_effect = Exception("CPU monitoring error")

        threats = protection.check_resource_abuse()

        self.assertEqual(len(threats), 0)  # Should handle exception gracefully

    def test_is_expected_connection_localhost(self):
        """Test expected connection detection for localhost."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Test localhost connections (should be expected)
        self.assertTrue(protection._is_expected_connection("127.0.0.1"))
        self.assertTrue(protection._is_expected_connection("127.0.0.5"))
        self.assertTrue(protection._is_expected_connection("::1"))

    def test_is_expected_connection_private_networks(self):
        """Test expected connection detection for private networks."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Test private network ranges
        self.assertTrue(protection._is_expected_connection("10.0.0.1"))
        self.assertTrue(protection._is_expected_connection("172.16.1.1"))
        self.assertTrue(protection._is_expected_connection("192.168.1.1"))

        # Test public IP
        self.assertFalse(protection._is_expected_connection("8.8.8.8"))

    def test_is_expected_connection_allowed_ips(self):
        """Test expected connection detection for configured allowed IPs."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Test allowed public IPs
        self.assertTrue(protection._is_expected_connection("203.0.113.1"))
        self.assertTrue(protection._is_expected_connection("198.51.100.1"))

        # Test non-allowed public IP
        self.assertFalse(protection._is_expected_connection("8.8.8.8"))

    @patch("os.path.exists")
    @patch("os.stat")
    def test_check_log_tampering_permissions(self, mock_stat, mock_exists):
        """Test log tampering check for file permissions."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_exists.return_value = True

        # Mock file with unsafe permissions (world-writable)
        mock_stat_result = Mock()
        mock_stat_result.st_mode = 0o100666  # Regular file with 666 permissions
        mock_stat_result.st_size = 1024
        mock_stat.return_value = mock_stat_result

        threats = protection.check_log_tampering("/var/log/test.log")

        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "Log File Permissions")
        self.assertEqual(threats[0]["severity"], "HIGH")

    @patch("os.path.exists")
    @patch("os.stat")
    def test_check_log_tampering_rapid_growth(self, mock_stat, mock_exists):
        """Test log tampering check for rapid log growth."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        protection.last_log_size = 1000  # Set previous size

        mock_exists.return_value = True
        mock_stat_result = Mock()
        mock_stat_result.st_mode = 0o100644  # Normal permissions
        mock_stat_result.st_size = 12000000  # 11MB larger (>10MB threshold)
        mock_stat.return_value = mock_stat_result

        threats = protection.check_log_tampering("/var/log/test.log")

        growth_threats = [t for t in threats if t["type"] == "Rapid Log Growth"]
        self.assertEqual(len(growth_threats), 1)
        self.assertEqual(growth_threats[0]["severity"], "MEDIUM")

    @patch("os.path.exists")
    @patch("os.stat")
    def test_check_log_tampering_normal(self, mock_stat, mock_exists):
        """Test log tampering check with normal log file."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_exists.return_value = True
        mock_stat_result = Mock()
        mock_stat_result.st_mode = 0o100644  # Normal permissions
        mock_stat_result.st_size = 1024
        mock_stat.return_value = mock_stat_result

        threats = protection.check_log_tampering("/var/log/test.log")

        self.assertEqual(len(threats), 0)  # No threats for normal log

    @patch("os.path.exists")
    def test_check_log_tampering_file_not_exists(self, mock_exists):
        """Test log tampering check when file doesn't exist."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_exists.return_value = False

        threats = protection.check_log_tampering("/var/log/nonexistent.log")

        self.assertEqual(len(threats), 0)  # Should handle missing file gracefully

    @patch("os.path.exists")
    @patch("os.stat")
    def test_check_log_tampering_exception(self, mock_stat, mock_exists):
        """Test log tampering check with exception."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_exists.return_value = True
        mock_stat.side_effect = Exception("Stat error")

        threats = protection.check_log_tampering("/var/log/test.log")

        self.assertEqual(len(threats), 0)  # Should handle exception gracefully

    @patch("subprocess.run")
    @patch("os.path.exists")
    @patch("os.stat")
    def test_check_service_availability_active(self, mock_stat, mock_exists, mock_run):
        """Test service availability check when service is active."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Mock systemctl success
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "active"

        # Mock recent log file
        mock_exists.return_value = True
        mock_stat_result = Mock()
        mock_stat_result.st_mtime = (datetime.now() - timedelta(seconds=60)).timestamp()
        mock_stat.return_value = mock_stat_result

        threats = protection.check_service_availability()

        self.assertEqual(len(threats), 0)

    @patch("subprocess.run")
    @patch("os.path.exists")
    def test_check_service_availability_inactive(self, mock_exists, mock_run):
        """Test service availability check when service is inactive."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Mock systemctl failure
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = "inactive"

        mock_exists.return_value = False

        threats = protection.check_service_availability()

        self.assertGreater(len(threats), 0)
        self.assertEqual(threats[0]["type"], "Service Status")
        self.assertEqual(threats[0]["severity"], "CRITICAL")

    @patch("subprocess.run")
    @patch("os.path.exists")
    @patch("os.stat")
    def test_check_service_availability_stale_log(
        self, mock_stat, mock_exists, mock_run
    ):
        """Test service availability with stale log file."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        # Mock systemctl success
        mock_run.return_value.returncode = 0

        # Mock stale log file (older than 5 minutes)
        mock_exists.return_value = True
        mock_stat_result = Mock()
        mock_stat_result.st_mtime = (datetime.now() - timedelta(minutes=10)).timestamp()
        mock_stat.return_value = mock_stat_result

        threats = protection.check_service_availability()

        service_threats = [t for t in threats if t["type"] == "Service Inactivity"]
        self.assertEqual(len(service_threats), 1)
        self.assertEqual(service_threats[0]["severity"], "HIGH")

    @patch("subprocess.run")
    def test_check_service_availability_exception(self, mock_run):
        """Test service availability check with exception."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_run.side_effect = Exception("Subprocess error")

        threats = protection.check_service_availability()

        # Should handle exception gracefully
        self.assertEqual(len(threats), 0)

    def test_perform_self_check_integration(self):
        """Test the integrated self-check functionality."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        with patch.object(
            protection, "check_rate_limiting"
        ) as mock_rate_limit, patch.object(
            protection, "check_file_integrity"
        ) as mock_file_check, patch.object(
            protection, "check_process_integrity"
        ) as mock_process_check, patch.object(
            protection, "check_resource_abuse"
        ) as mock_resource_check, patch.object(
            protection, "check_log_tampering"
        ) as mock_log_check, patch.object(
            protection, "check_service_availability"
        ) as mock_service_check:

            mock_rate_limit.return_value = True
            mock_file_check.return_value = []
            mock_process_check.return_value = []
            mock_resource_check.return_value = []
            mock_log_check.return_value = []
            mock_service_check.return_value = []

            threats = protection.perform_self_check()

            self.assertEqual(len(threats), 0)

            # Verify all checks were called
            mock_file_check.assert_called_once()
            mock_process_check.assert_called_once()
            mock_resource_check.assert_called_once()
            mock_log_check.assert_called_once()
            mock_service_check.assert_called_once()

    def test_perform_self_check_rate_limited(self):
        """Test self-check when rate limited."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        with patch.object(protection, "check_rate_limiting") as mock_rate_limit:
            mock_rate_limit.return_value = False  # Rate limited

            threats = protection.perform_self_check()

            self.assertEqual(len(threats), 0)

    def test_perform_self_check_with_threats(self):
        """Test self-check with threats detected."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        with patch.object(
            protection, "check_rate_limiting"
        ) as mock_rate_limit, patch.object(
            protection, "check_file_integrity"
        ) as mock_file_check, patch.object(
            protection, "check_process_integrity"
        ) as mock_process_check, patch.object(
            protection, "check_resource_abuse"
        ) as mock_resource_check, patch.object(
            protection, "check_log_tampering"
        ) as mock_log_check, patch.object(
            protection, "check_service_availability"
        ) as mock_service_check:

            mock_rate_limit.return_value = True
            mock_file_check.return_value = [
                {"type": "File Tampering", "severity": "CRITICAL"}
            ]
            mock_process_check.return_value = [
                {"type": "Process Hijacking", "severity": "CRITICAL"}
            ]
            mock_resource_check.return_value = []
            mock_log_check.return_value = []
            mock_service_check.return_value = []

            threats = protection.perform_self_check()

            self.assertEqual(len(threats), 2)

    def test_perform_self_check_exception(self):
        """Test self-check with exception."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        with patch.object(
            protection, "check_rate_limiting"
        ) as mock_rate_limit, patch.object(
            protection, "check_file_integrity"
        ) as mock_file_check:

            mock_rate_limit.return_value = True
            mock_file_check.side_effect = Exception("Check error")

            threats = protection.perform_self_check()

            self.assertEqual(len(threats), 0)  # Should handle exception gracefully

    @patch("builtins.open", new_callable=mock_open)
    @patch("sys.exit")
    @patch("time.time")
    def test_emergency_shutdown(self, mock_time, mock_exit, mock_file):
        """Test emergency shutdown functionality."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        mock_time.return_value = 1234567890

        protection.emergency_shutdown("Test emergency")

        # Should write emergency log
        mock_file.assert_called()
        mock_exit.assert_called_once_with(1)

    @patch("builtins.open", side_effect=IOError("Permission denied"))
    @patch("sys.exit")
    def test_emergency_shutdown_logging_failure(self, mock_exit, mock_file):
        """Test emergency shutdown with logging failure."""
        with patch.object(ServiceProtection, "_initialize_protection"):
            protection = ServiceProtection(self.config)

        protection.emergency_shutdown("Test emergency")

        # Should still exit even if logging fails
        mock_exit.assert_called_once_with(1)

    def test_initialization_exception_in_setup(self):
        """Test initialization with exception in protection setup."""
        # Mock successful process and file setup, but exception in resource monitoring
        with patch.object(
            ServiceProtection, "_baseline_file_integrity"
        ) as mock_file, patch.object(
            ServiceProtection, "_baseline_process_state"
        ) as mock_process, patch.object(
            ServiceProtection, "_setup_resource_monitoring"
        ) as mock_resource:

            mock_file.return_value = None
            mock_process.return_value = None
            mock_resource.side_effect = Exception("Resource monitoring error")

            # Should handle the exception and continue
            protection = ServiceProtection(self.config)
            self.assertIsNotNone(protection)

    @patch("psutil.cpu_percent")
    @patch("psutil.virtual_memory")
    @patch("psutil.disk_usage")
    def test_setup_resource_monitoring_exception(
        self, mock_disk, mock_memory, mock_cpu
    ):
        """Test resource monitoring setup with psutil exception."""
        with patch.object(ServiceProtection, "_baseline_file_integrity"), patch.object(
            ServiceProtection, "_baseline_process_state"
        ):

            # Mock psutil functions to raise exceptions
            mock_cpu.side_effect = Exception("CPU monitoring failed")
            mock_memory.side_effect = Exception("Memory monitoring failed")
            mock_disk.side_effect = Exception("Disk monitoring failed")

            # Should handle the exception gracefully
            protection = ServiceProtection(self.config)
            self.assertIsNotNone(protection)


if __name__ == "__main__":
    unittest.main()
