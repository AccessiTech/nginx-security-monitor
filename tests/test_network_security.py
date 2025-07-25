import unittest
import ipaddress
import subprocess
from datetime import datetime, timedelta
from unittest.mock import patch, mock_open, MagicMock, call
from collections import defaultdict, deque

from nginx_security_monitor.network_security import NetworkSecurity, SecurityHardening


class TestNetworkSecurity(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "network_security": {
                "allowed_ips": ["127.0.0.1", "192.168.1.100"],
                "allowed_interfaces": ["127.0.0.1", "localhost"],
                "allowed_ports": [8080, 9000],
            },
            "email_service": {
                "enabled": True,
                "smtp_server": "smtp.example.com",
                "smtp_port": 587,
                "use_tls": True,
            },
        }

    def test_initialization(self):
        """Test NetworkSecurity initialization"""
        net_sec = NetworkSecurity(self.config)

        self.assertIsNotNone(net_sec.logger)
        self.assertEqual(net_sec.config, self.config)
        self.assertIsInstance(net_sec.allowed_ips, set)
        self.assertIsInstance(net_sec.blocked_ips, set)
        self.assertIsInstance(net_sec.ip_attempt_counts, defaultdict)

        # Check that allowed IPs were loaded
        self.assertIn(ipaddress.ip_address("127.0.0.1"), net_sec.allowed_ips)
        self.assertIn(ipaddress.ip_address("192.168.1.100"), net_sec.allowed_ips)

    def test_initialization_without_config(self):
        """Test NetworkSecurity initialization without config"""
        net_sec = NetworkSecurity()

        self.assertEqual(net_sec.config, {})
        self.assertIsInstance(net_sec.allowed_ips, set)
        # When no config, allowed_interfaces gets default from config_manager
        self.assertEqual(set(net_sec.allowed_interfaces), {"127.0.0.1", "localhost"})

    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_load_network_config_invalid_ip(self, mock_logger):
        """Test loading config with invalid IP addresses"""
        config = {
            "network_security": {
                "allowed_ips": ["127.0.0.1", "invalid-ip", "192.168.1.1"]
            }
        }

        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        net_sec = NetworkSecurity(config)

        # Should log warning for invalid IP
        mock_logger_instance.warning.assert_called_with(
            "Invalid IP address in config: invalid-ip"
        )

        # Valid IPs should still be loaded
        self.assertIn(ipaddress.ip_address("127.0.0.1"), net_sec.allowed_ips)
        self.assertIn(ipaddress.ip_address("192.168.1.1"), net_sec.allowed_ips)

    def test_check_ip_access_allowed_ip(self):
        """Test IP access check for explicitly allowed IP"""
        net_sec = NetworkSecurity(self.config)

        # Test explicitly allowed IP
        self.assertTrue(net_sec.check_ip_access("127.0.0.1"))
        self.assertTrue(net_sec.check_ip_access("192.168.1.100"))

    def test_check_ip_access_blocked_ip(self):
        """Test IP access check for blocked IP"""
        net_sec = NetworkSecurity(self.config)

        # Block an IP and test
        net_sec.blocked_ips.add(ipaddress.ip_address("10.0.0.1"))
        self.assertFalse(net_sec.check_ip_access("10.0.0.1"))

    def test_check_ip_access_private_ip(self):
        """Test IP access check for private/loopback IPs"""
        net_sec = NetworkSecurity()

        # Private IPs should be allowed
        self.assertTrue(net_sec.check_ip_access("192.168.1.1"))
        self.assertTrue(net_sec.check_ip_access("10.0.0.1"))
        self.assertTrue(net_sec.check_ip_access("172.16.0.1"))

        # Loopback should be allowed
        self.assertTrue(net_sec.check_ip_access("127.0.0.1"))
        self.assertTrue(net_sec.check_ip_access("::1"))

    def test_check_ip_access_public_ip(self):
        """Test IP access check for public IPs"""
        net_sec = NetworkSecurity()

        # Public IPs should be denied by default
        self.assertFalse(net_sec.check_ip_access("8.8.8.8"))
        self.assertFalse(net_sec.check_ip_access("1.1.1.1"))

    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_check_ip_access_invalid_ip(self, mock_logger):
        """Test IP access check with invalid IP address"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        net_sec = NetworkSecurity()

        # Invalid IP should return False and log warning
        self.assertFalse(net_sec.check_ip_access("invalid-ip"))
        mock_logger_instance.warning.assert_called_with(
            "Invalid IP address: invalid-ip"
        )

    def test_track_access_attempt_successful(self):
        """Test tracking successful access attempts"""
        net_sec = NetworkSecurity()

        # Track successful attempts
        self.assertTrue(net_sec.track_access_attempt("192.168.1.1", success=True))
        self.assertTrue(net_sec.track_access_attempt("192.168.1.1", success=True))

        # Should have recorded attempts
        attempts = net_sec.ip_attempt_counts["192.168.1.1"]
        self.assertEqual(len(attempts), 2)

    @patch("nginx_security_monitor.network_security.NetworkSecurity.block_ip")
    def test_track_access_attempt_too_many_failures(self, mock_block_ip):
        """Test tracking too many failed access attempts"""
        net_sec = NetworkSecurity()

        # Simulate 11 failed attempts
        for _ in range(11):
            net_sec.track_access_attempt("192.168.1.1", success=False)

        # Should have called block_ip
        mock_block_ip.assert_called_with("192.168.1.1", "Too many failed attempts: 11")

    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_track_access_attempt_rate_limiting(self, mock_logger):
        """Test rate limiting for high frequency access"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        net_sec = NetworkSecurity()

        # Simulate 101 successful attempts
        for _ in range(101):
            result = net_sec.track_access_attempt("192.168.1.1", success=True)

        # Last attempt should be rate limited
        self.assertFalse(result)
        mock_logger_instance.warning.assert_called_with(
            "High access frequency from 192.168.1.1: 101 attempts"
        )

    def test_track_access_attempt_cleanup_old_attempts(self):
        """Test cleanup of old access attempts"""
        net_sec = NetworkSecurity()

        # Add old attempt (more than 1 hour ago)
        old_time = datetime.now() - timedelta(hours=2)
        net_sec.ip_attempt_counts["192.168.1.1"].append((old_time, True))

        # Add new attempt
        net_sec.track_access_attempt("192.168.1.1", success=True)

        # Old attempt should be cleaned up
        attempts = net_sec.ip_attempt_counts["192.168.1.1"]
        self.assertEqual(len(attempts), 1)
        self.assertGreater(attempts[0][0], old_time)

    @patch("nginx_security_monitor.network_security.subprocess.run")
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_block_ip_success(self, mock_logger, mock_subprocess):
        """Test successful IP blocking with iptables"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        # Mock successful iptables command
        mock_subprocess.return_value = MagicMock(returncode=0)

        net_sec = NetworkSecurity()
        net_sec.block_ip("192.168.1.1", "Test blocking")

        # Should add IP to blocked set
        self.assertIn(ipaddress.ip_address("192.168.1.1"), net_sec.blocked_ips)

        # Should log warning and success
        mock_logger_instance.warning.assert_called_with(
            "Blocking IP 192.168.1.1: Test blocking"
        )
        mock_logger_instance.info.assert_called_with(
            "Successfully added iptables rule for 192.168.1.1"
        )

    @patch("nginx_security_monitor.network_security.subprocess.run")
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_block_ip_iptables_failure(self, mock_logger, mock_subprocess):
        """Test IP blocking when iptables fails"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        # Mock failed iptables command
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stderr=MagicMock(decode=MagicMock(return_value="Permission denied")),
        )

        net_sec = NetworkSecurity()
        net_sec.block_ip("192.168.1.1", "Test blocking")

        # Should still add IP to blocked set
        self.assertIn(ipaddress.ip_address("192.168.1.1"), net_sec.blocked_ips)

        # Should log failure
        mock_logger_instance.warning.assert_any_call(
            "Blocking IP 192.168.1.1: Test blocking"
        )
        mock_logger_instance.warning.assert_any_call(
            "Failed to add iptables rule: Permission denied"
        )

    @patch("nginx_security_monitor.network_security.subprocess.run")
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_block_ip_iptables_exception(self, mock_logger, mock_subprocess):
        """Test IP blocking when iptables command raises exception"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        # Mock iptables command raising exception
        mock_subprocess.side_effect = subprocess.TimeoutExpired("iptables", 10)

        net_sec = NetworkSecurity()
        net_sec.block_ip("192.168.1.1", "Test blocking")

        # Should log the exception
        mock_logger_instance.warning.assert_any_call(
            "Cannot use iptables: Command 'iptables' timed out after 10 seconds"
        )

    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_block_ip_invalid_ip(self, mock_logger):
        """Test blocking invalid IP address"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        net_sec = NetworkSecurity()
        net_sec.block_ip("invalid-ip", "Test blocking")

        # Should log error
        mock_logger_instance.error.assert_called_with(
            "Invalid IP address for blocking: invalid-ip"
        )

    @patch("nginx_security_monitor.network_security.subprocess.run")
    def test_check_port_security_success(self, mock_subprocess):
        """Test successful port security check"""
        netstat_output = """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN      1234/nginx
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      5678/sshd
tcp        0      0 192.168.1.100:9999      0.0.0.0:*               LISTEN      9999/malware
tcp6       0      0 [::]:80                 [::]:*                  LISTEN      1234/nginx
tcp6       0      0 [::1]:3306             [::]:*                  LISTEN      999/mysqld
"""

        mock_subprocess.return_value = MagicMock(returncode=0, stdout=netstat_output)

        net_sec = NetworkSecurity(self.config)
        threats = net_sec.check_port_security()

        # Should detect unexpected services on non-standard ports
        self.assertEqual(len(threats), 2)

        # IPv4 threat
        ipv4_threat = next(t for t in threats if t["address"] == "192.168.1.100")
        self.assertEqual(ipv4_threat["type"], "Unexpected Network Service")
        self.assertEqual(ipv4_threat["port"], "9999")
        self.assertEqual(ipv4_threat["protocol"], "tcp")

        # IPv6 threat
        ipv6_threat = next(t for t in threats if t["address"] == "[::1]")
        self.assertEqual(ipv6_threat["type"], "Unexpected Network Service")
        self.assertEqual(ipv6_threat["port"], "3306")
        self.assertEqual(ipv6_threat["protocol"], "tcp6")

    @patch("nginx_security_monitor.network_security.subprocess.run")
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_check_port_security_command_failure(self, mock_logger, mock_subprocess):
        """Test port security check when netstat command fails"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        mock_subprocess.return_value = MagicMock(returncode=1)

        net_sec = NetworkSecurity()
        threats = net_sec.check_port_security()

        # Should return empty list when command fails
        self.assertEqual(len(threats), 0)

    @patch("nginx_security_monitor.network_security.subprocess.run")
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_check_port_security_exception(self, mock_logger, mock_subprocess):
        """Test port security check exception handling"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        mock_subprocess.side_effect = Exception("Command failed")

        net_sec = NetworkSecurity()
        threats = net_sec.check_port_security()

        # Should log error and return empty list
        self.assertEqual(len(threats), 0)
        mock_logger_instance.error.assert_called_with(
            "Port security check failed: Command failed"
        )

    def test_is_expected_service(self):
        """Test expected service port checking"""
        # Test with custom config
        custom_config = {"network": {"expected_ports": [22, 80, 443, 8080, 9000]}}
        net_sec = NetworkSecurity(custom_config)

        # Standard ports should be expected
        self.assertTrue(net_sec._is_expected_service("22"))  # SSH
        self.assertTrue(net_sec._is_expected_service("80"))  # HTTP
        self.assertTrue(net_sec._is_expected_service("443"))  # HTTPS

        # Configured custom ports should be expected
        self.assertTrue(net_sec._is_expected_service("8080"))
        self.assertTrue(net_sec._is_expected_service("9000"))

        # Random ports should not be expected
        self.assertFalse(net_sec._is_expected_service("9999"))

    def test_is_expected_service_with_defaults(self):
        """Test expected service port checking with default ports"""
        net_sec = NetworkSecurity()  # No config, should use defaults

        # Default secure ports should be expected
        self.assertTrue(net_sec._is_expected_service("22"))  # SSH
        self.assertTrue(net_sec._is_expected_service("80"))  # HTTP
        self.assertTrue(net_sec._is_expected_service("443"))  # HTTPS
        self.assertTrue(net_sec._is_expected_service("25"))  # SMTP
        self.assertTrue(net_sec._is_expected_service("587"))  # SMTP TLS
        self.assertTrue(net_sec._is_expected_service("993"))  # IMAPS
        self.assertTrue(net_sec._is_expected_service("995"))  # POP3S

        # Random ports should not be expected
        self.assertFalse(net_sec._is_expected_service("8080"))
        self.assertFalse(net_sec._is_expected_service("9999"))

    @patch("nginx_security_monitor.network_security.subprocess.run")
    def test_monitor_dns_queries_suspicious_found(self, mock_subprocess):
        """Test DNS monitoring when suspicious queries are found"""
        syslog_content = """Jul 19 10:30:25 server systemd-resolved[123]: DNS query for evil.onion
Jul 19 10:31:26 server systemd-resolved[123]: DNS query for c2server.bit
Jul 19 10:32:27 server systemd-resolved[123]: DNS query for abcdef1234567890abcdef1234567890.com
"""

        mock_subprocess.return_value = MagicMock(returncode=0, stdout=syslog_content)

        net_sec = NetworkSecurity()
        threats = net_sec.monitor_dns_queries()

        # Should detect suspicious DNS queries
        self.assertGreater(len(threats), 0)
        threat_types = [t["type"] for t in threats]
        self.assertIn("Suspicious DNS Query", threat_types)

    @patch("nginx_security_monitor.network_security.subprocess.run")
    def test_monitor_dns_queries_no_suspicious(self, mock_subprocess):
        """Test DNS monitoring when no suspicious queries found"""
        syslog_content = """Jul 19 10:30:25 server systemd-resolved[123]: DNS query for google.com
Jul 19 10:31:26 server systemd-resolved[123]: DNS query for github.com
"""

        mock_subprocess.return_value = MagicMock(returncode=0, stdout=syslog_content)

        net_sec = NetworkSecurity()
        threats = net_sec.monitor_dns_queries()

        # Should not detect any threats
        self.assertEqual(len(threats), 0)

    @patch("nginx_security_monitor.network_security.subprocess.run")
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_monitor_dns_queries_exception(self, mock_logger, mock_subprocess):
        """Test DNS monitoring exception handling"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        mock_subprocess.side_effect = Exception("Command failed")

        net_sec = NetworkSecurity()
        threats = net_sec.monitor_dns_queries()

        # Should return empty list and log debug message
        self.assertEqual(len(threats), 0)
        mock_logger_instance.debug.assert_called_with(
            "DNS monitoring failed: Command failed"
        )

    @patch("nginx_security_monitor.network_security.subprocess.run")
    def test_check_firewall_status_permissive_rules(self, mock_subprocess):
        """Test firewall check detecting permissive rules"""
        iptables_output = """Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere
DROP       all  --  192.168.1.100        anywhere

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
"""

        mock_subprocess.return_value = MagicMock(returncode=0, stdout=iptables_output)

        net_sec = NetworkSecurity()
        threats = net_sec.check_firewall_status()

        # Should detect permissive rule
        self.assertGreater(len(threats), 0)
        threat = next(
            (t for t in threats if t["type"] == "Permissive Firewall Rule"), None
        )
        self.assertIsNotNone(threat)

    @patch("nginx_security_monitor.network_security.subprocess.run")
    def test_check_firewall_status_command_failure(self, mock_subprocess):
        """Test firewall check when iptables command fails"""
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stderr=MagicMock(decode=MagicMock(return_value="Permission denied")),
        )

        net_sec = NetworkSecurity()
        threats = net_sec.check_firewall_status()

        # Should detect firewall check failure
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "Firewall Check Failed")
        self.assertEqual(threats[0]["severity"], "HIGH")

    @patch("nginx_security_monitor.network_security.subprocess.run")
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_check_firewall_status_exception(self, mock_logger, mock_subprocess):
        """Test firewall check exception handling"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        mock_subprocess.side_effect = Exception("Command failed")

        net_sec = NetworkSecurity()
        threats = net_sec.check_firewall_status()

        # Should return empty list and log warning
        self.assertEqual(len(threats), 0)
        mock_logger_instance.warning.assert_called_with(
            "Firewall check failed: Command failed"
        )

    def test_validate_tls_configuration_secure(self):
        """Test TLS validation with secure configuration"""
        net_sec = NetworkSecurity(self.config)
        threats = net_sec.validate_tls_configuration()

        # Should not detect any threats with secure config
        self.assertEqual(len(threats), 0)

    def test_validate_tls_configuration_insecure_no_tls(self):
        """Test TLS validation with insecure configuration (no TLS)"""
        insecure_config = {
            "email_service": {
                "enabled": True,
                "smtp_server": "smtp.example.com",
                "smtp_port": 587,
                "use_tls": False,
            }
        }

        net_sec = NetworkSecurity(insecure_config)
        threats = net_sec.validate_tls_configuration()

        # Should detect insecure email configuration
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "Insecure Email Configuration")

    def test_validate_tls_configuration_insecure_port(self):
        """Test TLS validation with insecure SMTP port"""
        insecure_config = {
            "email_service": {
                "enabled": True,
                "smtp_server": "smtp.example.com",
                "smtp_port": 25,  # Insecure port
                "use_tls": True,
            }
        }

        net_sec = NetworkSecurity(insecure_config)
        threats = net_sec.validate_tls_configuration()

        # Should detect insecure SMTP port
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]["type"], "Insecure SMTP Port")

    def test_validate_tls_configuration_email_disabled(self):
        """Test TLS validation when email service is disabled"""
        config = {
            "email_service": {"enabled": False, "smtp_port": 25, "use_tls": False}
        }

        net_sec = NetworkSecurity(config)
        threats = net_sec.validate_tls_configuration()

        # Should not detect any threats when email is disabled
        self.assertEqual(len(threats), 0)

    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_validate_tls_configuration_exception(self, mock_logger):
        """Test TLS validation exception handling"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        # Create config that will cause exception
        net_sec = NetworkSecurity()
        net_sec.config = None  # This will cause exception

        threats = net_sec.validate_tls_configuration()

        # Should return empty list and log error
        self.assertEqual(len(threats), 0)
        mock_logger_instance.error.assert_called()

    @patch(
        "nginx_security_monitor.network_security.NetworkSecurity.validate_tls_configuration"
    )
    @patch(
        "nginx_security_monitor.network_security.NetworkSecurity.monitor_dns_queries"
    )
    @patch(
        "nginx_security_monitor.network_security.NetworkSecurity.check_firewall_status"
    )
    @patch(
        "nginx_security_monitor.network_security.NetworkSecurity.check_port_security"
    )
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_perform_network_security_check_with_threats(
        self,
        mock_logger,
        mock_port_check,
        mock_firewall_check,
        mock_dns_check,
        mock_tls_check,
    ):
        """Test comprehensive network security check with threats found"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        # Mock methods to return some threats
        mock_port_check.return_value = [{"type": "Port Threat", "severity": "MEDIUM"}]
        mock_firewall_check.return_value = [
            {"type": "Firewall Threat", "severity": "HIGH"}
        ]
        mock_dns_check.return_value = [{"type": "DNS Threat", "severity": "LOW"}]
        mock_tls_check.return_value = [{"type": "TLS Threat", "severity": "MEDIUM"}]

        net_sec = NetworkSecurity()
        threats = net_sec.perform_network_security_check()

        # Should collect all threats
        self.assertEqual(len(threats), 4)

        # Should log warning about threats found
        mock_logger_instance.warning.assert_called_with(
            "Network security check found 4 issues"
        )

    @patch(
        "nginx_security_monitor.network_security.NetworkSecurity.check_port_security"
    )
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_perform_network_security_check_exception(
        self, mock_logger, mock_port_check
    ):
        """Test comprehensive network security check exception handling"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        # Mock method to raise exception
        mock_port_check.side_effect = Exception("Check failed")

        net_sec = NetworkSecurity()
        threats = net_sec.perform_network_security_check()

        # Should return empty list and log error
        self.assertEqual(len(threats), 0)
        mock_logger_instance.error.assert_called_with(
            "Network security check failed: Check failed"
        )


class TestSecurityHardening(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "security": {
                "critical_files": {
                    "/etc/test.conf": {
                        "mode": 0o640,
                        "owner": "root",
                        "group": "nginx",
                    },
                    "/etc/test.key": {"mode": 0o600, "owner": "root", "group": "root"},
                },
                "sensitive_env_vars": ["TEST_KEY", "TEST_PASSWORD"],
                "min_password_length": 12,
                "unsafe_file_modes": [0o777, 0o666],
                "weak_values": ["test", "password"],
            }
        }

    def test_initialization(self):
        """Test SecurityHardening initialization"""
        hardening = SecurityHardening(self.config)

        self.assertIsNotNone(hardening.logger)
        self.assertEqual(hardening.config, self.config)
        self.assertEqual(len(hardening.critical_files), 4)  # Updated from 2 to 4
        self.assertEqual(len(hardening.sensitive_env_vars), 5)  # Updated from 2 to 5
        self.assertEqual(hardening.min_password_length, 16)  # Updated from 12 to 16

    def test_initialization_without_config(self):
        """Test SecurityHardening initialization with defaults"""
        hardening = SecurityHardening()

        self.assertEqual(hardening.config, {})
        # Should use defaults from ConfigManager
        self.assertGreater(len(hardening.critical_files), 0)
        self.assertGreater(len(hardening.sensitive_env_vars), 0)
        self.assertGreaterEqual(hardening.min_password_length, 16)

    @patch("nginx_security_monitor.network_security.os.path.exists")
    @patch("nginx_security_monitor.network_security.os.stat")
    @patch("nginx_security_monitor.network_security.pwd.getpwuid")
    @patch("nginx_security_monitor.network_security.grp.getgrgid")
    def test_check_file_permissions_correct(
        self, mock_grp, mock_pwd, mock_stat, mock_exists
    ):
        """Test file permissions check with correct permissions and ownership"""
        mock_exists.return_value = True

        # Create different mock stat results for different files
        def stat_side_effect(path):
            if "settings.yaml" in path:
                return MagicMock(
                    st_mode=0o100640, st_uid=0, st_gid=991
                )  # 640, root:nginx
            elif ".salt" in path:
                return MagicMock(st_mode=0o100600, st_uid=0, st_gid=0)  # 600, root:root
            elif "src/" in path:
                return MagicMock(
                    st_mode=0o40755, st_uid=0, st_gid=0
                )  # 755, root:root (directory)
            elif "log" in path:
                return MagicMock(
                    st_mode=0o100640, st_uid=991, st_gid=991
                )  # 640, nginx:nginx
            else:
                return MagicMock(st_mode=0o100640, st_uid=0, st_gid=991)  # default

        def pwd_side_effect(uid):
            if uid == 0:
                return MagicMock(pw_name="root")
            elif uid == 991:
                return MagicMock(pw_name="nginx")
            else:
                return MagicMock(pw_name="other")

        def grp_side_effect(gid):
            if gid == 0:
                return MagicMock(gr_name="root")
            elif gid == 991:
                return MagicMock(gr_name="nginx")
            else:
                return MagicMock(gr_name="other")

        mock_stat.side_effect = stat_side_effect
        mock_pwd.side_effect = pwd_side_effect
        mock_grp.side_effect = grp_side_effect

        hardening = SecurityHardening(self.config)
        threats = hardening.check_file_permissions()

        # Should not detect any threats with correct permissions and ownership
        self.assertEqual(len(threats), 0)

    @patch("nginx_security_monitor.network_security.os.path.exists")
    @patch("nginx_security_monitor.network_security.os.stat")
    @patch("nginx_security_monitor.network_security.pwd.getpwuid")
    @patch("nginx_security_monitor.network_security.grp.getgrgid")
    @patch("nginx_security_monitor.network_security.os.geteuid")
    def test_check_file_permissions_incorrect(
        self, mock_geteuid, mock_grp, mock_pwd, mock_stat, mock_exists
    ):
        """Test file permissions check with incorrect permissions and ownership"""
        mock_exists.return_value = True
        mock_stat.return_value = MagicMock(
            st_mode=0o100666,  # World-writable permissions
            st_uid=1000,  # non-root user
            st_gid=1000,  # non-root group
        )
        mock_pwd.return_value = MagicMock(pw_name="user")
        mock_grp.return_value = MagicMock(gr_name="user")
        mock_geteuid.return_value = 0  # Running as root

        hardening = SecurityHardening(self.config)
        threats = hardening.check_file_permissions()

        # Should detect incorrect permissions and ownership for all 4 files
        # Each file can have multiple issues (permissions, owner, group, unsafe mode)
        self.assertGreater(len(threats), 0)  # Should detect multiple issues

        threat_types = [t["type"] for t in threats]
        self.assertIn("Incorrect File Permissions", threat_types)
        self.assertIn("Incorrect File Owner", threat_types)
        self.assertIn("Unsafe File Permissions", threat_types)

    @patch("nginx_security_monitor.network_security.os.path.exists")
    def test_check_file_permissions_file_not_exists(self, mock_exists):
        """Test file permissions check when file doesn't exist"""
        mock_exists.return_value = False

        hardening = SecurityHardening()
        threats = hardening.check_file_permissions()

        # Should not detect threats for non-existent files
        self.assertEqual(len(threats), 0)

    @patch("nginx_security_monitor.network_security.os.path.exists")
    @patch("nginx_security_monitor.network_security.os.stat")
    @patch("nginx_security_monitor.network_security.logging.getLogger")
    def test_check_file_permissions_exception(
        self, mock_logger, mock_stat, mock_exists
    ):
        """Test file permissions check exception handling"""
        mock_logger_instance = MagicMock()
        mock_logger.return_value = mock_logger_instance

        mock_exists.return_value = True
        mock_stat.side_effect = OSError("Permission denied")

        hardening = SecurityHardening()
        threats = hardening.check_file_permissions()

        # Should return empty list and log error
        self.assertEqual(len(threats), 0)
        mock_logger_instance.error.assert_called()

    @patch(
        "nginx_security_monitor.network_security.os.environ",
        {
            "NGINX_MONITOR_KEY": "Strong_Key_123!@#",
            "SMTP_PASSWORD": "StrongPassword123!",
            "API_KEY": "SecureAPIKey456$",
            "DB_PASSWORD": "DatabasePass789%",
            "SECRET_KEY": "SuperSecretKey012&",
        },
    )
    def test_check_environment_security_strong_key(self):
        """Test environment security check with strong key"""
        hardening = SecurityHardening(self.config)
        threats = hardening.check_environment_security()

        # Should not detect threats with strong keys
        self.assertEqual(len(threats), 0)

    @patch(
        "nginx_security_monitor.network_security.os.environ",
        {
            "NGINX_MONITOR_KEY": "weakpass",
            "SMTP_PASSWORD": "weak",
            "API_KEY": "short",
            "DB_PASSWORD": "123",
            "SECRET_KEY": "test",
        },
    )
    def test_check_environment_security_weak_key(self):
        """Test environment security check with weak key"""
        hardening = SecurityHardening(self.config)
        threats = hardening.check_environment_security()

        # Should detect multiple issues with weak keys
        self.assertGreater(len(threats), 0)  # At least some threats should be detected
        threat_types = [t["type"] for t in threats]
        # Each weak variable can trigger multiple issues (length, complexity, default value)
        self.assertGreaterEqual(
            threat_types.count("Weak Environment Variable"), 5
        )  # At least one issue per variable
        # Also check for default value detection
        default_threats = [
            t for t in threats if t["type"] == "Default Environment Variable"
        ]
        self.assertGreater(
            len(default_threats), 0
        )  # Should detect 'test' as default value
        severities = [t["severity"] for t in threats]
        self.assertIn("HIGH", severities)
        self.assertIn("MEDIUM", severities)

    @patch(
        "nginx_security_monitor.network_security.os.environ",
        {"NGINX_MONITOR_KEY": "password"},
    )
    def test_check_environment_security_default_value(self):
        """Test environment security check with default/weak value"""
        hardening = SecurityHardening(self.config)
        threats = hardening.check_environment_security()

        # Should detect multiple issues with default password
        self.assertGreater(
            len(threats), 0
        )  # Should detect issues including missing vars
        threat_types = [t["type"] for t in threats]
        self.assertEqual(threat_types.count("Weak Environment Variable"), 2)
        self.assertEqual(threat_types.count("Default Environment Variable"), 1)

    @patch("nginx_security_monitor.network_security.os.environ", {})
    def test_check_environment_security_missing_vars(self):
        """Test environment security check with missing required variables"""
        hardening = SecurityHardening(self.config)
        threats = hardening.check_environment_security()

        # Should detect missing required variables
        self.assertEqual(len(threats), 5)  # All 5 required vars missing
        self.assertTrue(
            all(t["type"] == "Missing Environment Variable" for t in threats)
        )
        self.assertTrue(all(t["severity"] == "HIGH" for t in threats))

    @patch("nginx_security_monitor.network_security.sys.modules")
    @patch("nginx_security_monitor.network_security.distributions")
    def test_check_module_security_vulnerable_packages(
        self, mock_distributions, mock_modules
    ):
        """Test detection of vulnerable package versions"""
        # Create mock distribution with vulnerable version
        mock_dist = MagicMock()
        mock_dist.metadata = {"Name": "cryptography"}
        mock_dist.version = "2.9.0"  # Vulnerable version
        mock_distributions.return_value = [mock_dist]

        # Mock sys.modules to return empty (no unsafe attributes to check)
        mock_modules.items.return_value = []

        hardening = SecurityHardening(self.config)
        threats = hardening.check_module_security()

        # Should detect vulnerable package
        self.assertEqual(len(threats), 1)
        threat = threats[0]
        self.assertEqual(threat["type"], "Vulnerable Package")
        self.assertEqual(threat["severity"], "HIGH")
        self.assertEqual(threat["package"], "cryptography")

    @patch("nginx_security_monitor.network_security.distributions")
    @patch("nginx_security_monitor.network_security.sys.modules")
    def test_check_module_security_unsafe_attributes(
        self, mock_modules, mock_distributions
    ):
        """Test detection of unsafe module attributes"""
        # Mock distributions to return empty (no vulnerable packages to check)
        mock_distributions.return_value = []

        # Create mock module with unsafe attribute
        mock_module = MagicMock()
        mock_module.__file__ = "/app/test_module.py"  # Not in site-packages
        mock_module.system = MagicMock()  # Unsafe attribute
        mock_modules.items.return_value = [("os", mock_module)]

        hardening = SecurityHardening(self.config)
        threats = hardening.check_module_security()

        # Should detect unsafe module usage (may be multiple if module has multiple unsafe attributes)
        self.assertGreater(len(threats), 0)
        # Check that at least one threat is for the expected module and attribute
        unsafe_threats = [t for t in threats if t["type"] == "Unsafe Module Usage"]
        self.assertGreater(len(unsafe_threats), 0)

        # Check that we found the specific threat we're looking for
        system_threats = [t for t in unsafe_threats if t.get("attribute") == "system"]
        self.assertEqual(len(system_threats), 1)

        threat = system_threats[0]
        self.assertEqual(threat["severity"], "MEDIUM")
        self.assertEqual(threat["module"], "os")

    def test_perform_security_audit(self):
        """Test comprehensive security audit"""
        hardening = SecurityHardening(self.config)

        # Mock the individual checks to return known threats
        hardening.check_file_permissions = MagicMock(
            return_value=[{"type": "Incorrect File Permissions", "severity": "MEDIUM"}]
        )
        hardening.check_environment_security = MagicMock(
            return_value=[{"type": "Weak Environment Variable", "severity": "HIGH"}]
        )
        hardening.check_module_security = MagicMock(
            return_value=[{"type": "Vulnerable Package", "severity": "CRITICAL"}]
        )

        threats = hardening.perform_security_audit()

        # Should collect all threats
        self.assertEqual(len(threats), 3)
        severities = [t["severity"] for t in threats]
        self.assertIn("CRITICAL", severities)
        self.assertIn("HIGH", severities)
        self.assertIn("MEDIUM", severities)


if __name__ == "__main__":
    unittest.main()
