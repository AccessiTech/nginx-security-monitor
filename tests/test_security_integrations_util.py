import unittest
import os
import tempfile
import yaml
from unittest.mock import patch, MagicMock, mock_open, call
from io import StringIO


# Import the utility functions
import nginx_security_monitor.security_integrations_util as security_integrations_util


class TestSecurityIntegrationsUtility(unittest.TestCase):
    """Comprehensive tests for security_integrations_util.py utility"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_config = {
            "security_integrations": {
                "fail2ban": {"enabled": True},
                "ossec": {"enabled": True},
                "suricata": {"enabled": False},
            }
        }

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_config_existing_file(self):
        """Test loading configuration from existing file"""
        # Arrange
        config_path = os.path.join(self.temp_dir, "test_config.yaml")
        with open(config_path, "w") as f:
            yaml.dump(self.test_config, f)

        # Act
        result = security_integrations_util.load_config(config_path)

        # Assert
        self.assertEqual(result, self.test_config)

    @patch("os.path.exists")
    def test_load_config_local_fallback(self, mock_exists):
        """Test loading configuration with local fallback"""
        # Arrange
        mock_exists.side_effect = lambda path: "config/service-settings.yaml" in path

        with patch("builtins.open", mock_open(read_data=yaml.dump(self.test_config))):
            # Act
            result = security_integrations_util.load_config("/nonexistent/path")

            # Assert
            self.assertEqual(result, self.test_config)

    @patch("os.path.exists", return_value=False)
    @patch("builtins.print")
    def test_load_config_file_not_found(self, mock_print, mock_exists):
        """Test loading configuration when file doesn't exist"""
        # Act
        result = security_integrations_util.load_config("/nonexistent/path")

        # Assert
        self.assertEqual(result, {})
        mock_print.assert_called_with("Configuration file not found: /nonexistent/path")

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", side_effect=Exception("File read error"))
    @patch("builtins.print")
    def test_load_config_exception_handling(self, mock_print, mock_open, mock_exists):
        """Test exception handling in load_config"""
        # Act
        result = security_integrations_util.load_config()

        # Assert
        self.assertEqual(result, {})
        mock_print.assert_called_with("Error loading configuration: File read error")

    @patch("nginx_security_monitor.security_integrations_util.load_config")
    @patch(
        "nginx_security_monitor.security_integrations_util.SecurityIntegrationManager"
    )
    @patch("builtins.print")
    def test_check_integrations_all_available(
        self, mock_print, mock_manager_class, mock_load_config
    ):
        """Test checking integrations when all are available"""
        # Arrange
        mock_load_config.return_value = self.test_config

        mock_manager = MagicMock()
        mock_manager.get_integration_status.return_value = {
            "available_integrations": {
                "fail2ban": True,
                "ossec": True,
                "suricata": True,
                "modsecurity": False,
            },
            "integration_details": {
                "fail2ban": {
                    "jails": {
                        "ssh": {"currently_banned": 5, "total_failed": 50},
                        "apache": {"currently_banned": 2, "total_failed": 20},
                    },
                    "banned_ips_count": 7,
                },
                "ossec": {"recent_alerts_count": 15, "high_severity_alerts": 3},
                "suricata": {"recent_alerts_count": 8, "critical_alerts": 1},
                "modsecurity": {"recent_blocks_count": 25},
            },
        }
        mock_manager_class.return_value = mock_manager

        # Act
        security_integrations_util.check_integrations()

        # Assert
        mock_manager.get_integration_status.assert_called_once()
        mock_print.assert_any_call("🔍 Checking available security integrations...\n")
        mock_print.assert_any_call("Security Framework Status:")

    @patch("nginx_security_monitor.security_integrations_util.load_config")
    @patch(
        "nginx_security_monitor.security_integrations_util.SecurityIntegrationManager"
    )
    @patch("builtins.print")
    def test_check_integrations_some_unavailable(
        self, mock_print, mock_manager_class, mock_load_config
    ):
        """Test checking integrations when some are unavailable"""
        # Arrange
        mock_load_config.return_value = {}

        mock_manager = MagicMock()
        mock_manager.get_integration_status.return_value = {
            "available_integrations": {
                "fail2ban": False,
                "ossec": False,
                "suricata": False,
                "modsecurity": False,
            },
            "integration_details": {},
        }
        mock_manager_class.return_value = mock_manager

        # Act
        security_integrations_util.check_integrations()

        # Assert
        # Should print "Not available" for each integration
        calls = mock_print.call_args_list
        unavailable_calls = [
            call for call in calls if "❌" in str(call) and "Not available" in str(call)
        ]
        self.assertGreater(len(unavailable_calls), 0)

    @patch("nginx_security_monitor.security_integrations_util.load_config")
    @patch(
        "nginx_security_monitor.security_integrations_util.SecurityIntegrationManager"
    )
    @patch("builtins.print")
    def test_test_integrations_with_threats(
        self, mock_print, mock_manager_class, mock_load_config
    ):
        """Test the test_integrations function with threats found"""
        # Arrange
        mock_load_config.return_value = self.test_config

        mock_manager = MagicMock()
        mock_manager.handle_threat_with_integrations.return_value = {
            "actions_taken": ["Banned IP 192.168.1.100", "Added OSSEC rule"],
            "integrations_used": ["fail2ban", "ossec"],
        }
        mock_manager.get_aggregated_threats.return_value = [
            {
                "source": "fail2ban",
                "severity": "HIGH",
                "description": "SSH brute force",
            },
            {
                "source": "ossec",
                "severity": "MEDIUM",
                "description": "Suspicious file access",
            },
        ]
        mock_manager_class.return_value = mock_manager

        # Act
        security_integrations_util.test_integrations()

        # Assert
        mock_manager.handle_threat_with_integrations.assert_called_once()
        mock_manager.get_aggregated_threats.assert_called_once_with(hours=1)

    @patch("nginx_security_monitor.security_integrations_util.load_config")
    @patch(
        "nginx_security_monitor.security_integrations_util.SecurityIntegrationManager"
    )
    @patch("builtins.print")
    def test_test_integrations_no_threats(
        self, mock_print, mock_manager_class, mock_load_config
    ):
        """Test the test_integrations function with no threats found"""
        # Arrange
        mock_load_config.return_value = self.test_config

        mock_manager = MagicMock()
        mock_manager.handle_threat_with_integrations.return_value = {
            "actions_taken": [],
            "integrations_used": ["fail2ban", "ossec"],
        }
        mock_manager.get_aggregated_threats.return_value = []
        mock_manager_class.return_value = mock_manager

        # Act
        security_integrations_util.test_integrations()

        # Assert
        mock_print.assert_any_call("ℹ️  No actions taken (this is expected for a test)")
        mock_print.assert_any_call("ℹ️  No recent threats found (this is good!)")

    @patch("subprocess.run")
    @patch("builtins.print")
    @patch(
        "nginx_security_monitor.security_integrations_util.SecurityIntegrationManager"
    )
    def test_setup_fail2ban_installed_and_working(
        self, mock_manager_class, mock_print, mock_subprocess
    ):
        """Test setup_fail2ban when fail2ban is installed and working"""
        # Arrange
        mock_subprocess.side_effect = [
            MagicMock(returncode=0, stdout="fail2ban v0.11.2"),  # Version check
            MagicMock(
                returncode=0,
                stdout="Status\n|- Number of jail: 2\n`- Jail list: ssh, apache-auth",
            ),  # Status check
        ]
        mock_manager = MagicMock()
        mock_manager.fail2ban.is_available.return_value = True
        mock_manager.fail2ban.get_jail_status.return_value = {"ssh": {}, "apache": {}}
        mock_manager_class.return_value = mock_manager

        with patch("os.path.exists", return_value=True):
            # Act
            security_integrations_util.setup_fail2ban()

            # Assert
            mock_print.assert_any_call("✅ fail2ban is installed")

    @patch("subprocess.run")
    @patch("builtins.print")
    def test_setup_fail2ban_not_installed(self, mock_print, mock_subprocess):
        """Test setup_fail2ban when fail2ban is not installed"""
        # Arrange
        mock_subprocess.side_effect = FileNotFoundError("fail2ban-client not found")

        # Act
        security_integrations_util.setup_fail2ban()

        # Assert
        mock_print.assert_any_call("❌ fail2ban is not installed")
        mock_print.assert_any_call("\nTo install fail2ban:")

    @patch("subprocess.run")
    @patch("builtins.print")
    @patch(
        "nginx_security_monitor.security_integrations_util.SecurityIntegrationManager"
    )
    def test_setup_fail2ban_not_working(
        self, mock_manager_class, mock_print, mock_subprocess
    ):
        """Test setup_fail2ban when fail2ban is installed but not working"""
        # Arrange
        mock_subprocess.return_value = MagicMock(returncode=1, stdout="")
        mock_manager = MagicMock()
        mock_manager.fail2ban.is_available.return_value = True
        mock_manager.fail2ban.get_jail_status.return_value = None
        mock_manager_class.return_value = mock_manager

        # Act
        security_integrations_util.setup_fail2ban()

        # Assert
        mock_print.assert_any_call("❌ fail2ban is not working properly")

    @patch("os.path.exists")
    @patch("builtins.print")
    def test_setup_ossec_found_and_running(self, mock_print, mock_exists):
        """Test setup_ossec when OSSEC/Wazuh is found and running"""

        # Arrange
        def exists_side_effect(path):
            return (
                any(ossec_dir in path for ossec_dir in ["/var/ossec", "/opt/ossec"])
                or "alerts.log" in path
            )

        mock_exists.side_effect = exists_side_effect

        with patch("subprocess.run") as mock_subprocess:
            mock_subprocess.return_value = MagicMock(
                returncode=0, stdout="ossec-analysisd running"
            )

            # Act
            security_integrations_util.setup_ossec()

            # Assert
            mock_print.assert_any_call("✅ OSSEC/Wazuh found at: /var/ossec")

    @patch("os.path.exists", return_value=False)
    @patch("builtins.print")
    def test_setup_ossec_not_found(self, mock_print, mock_exists):
        """Test setup_ossec when OSSEC/Wazuh is not found"""
        # Act
        security_integrations_util.setup_ossec()

        # Assert
        mock_print.assert_any_call("❌ OSSEC/Wazuh not found")
        mock_print.assert_any_call("\nTo install Wazuh agent:")

    @patch("sys.argv", ["security_integrations_util.py", "test"])
    def test_main_test_action(self):
        """Test main function with test action"""
        with patch(
            "nginx_security_monitor.security_integrations_util.test_integrations"
        ) as mock_test:
            # Act
            security_integrations_util.main()

            # Assert
            mock_test.assert_called_once()

    @patch("sys.argv", ["security_integrations_util.py", "setup-fail2ban"])
    def test_main_setup_fail2ban_action(self):
        """Test main function with setup-fail2ban action"""
        with patch(
            "nginx_security_monitor.security_integrations_util.setup_fail2ban"
        ) as mock_setup:
            # Act
            security_integrations_util.main()

            # Assert
            mock_setup.assert_called_once()

    @patch("sys.argv", ["security_integrations_util.py", "setup-ossec"])
    def test_main_setup_ossec_action(self):
        """Test main function with setup-ossec action"""
        with patch(
            "nginx_security_monitor.security_integrations_util.setup_ossec"
        ) as mock_setup:
            # Act
            security_integrations_util.main()

            # Assert
            mock_setup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
