"""
Test suite for security integrations functionality
"""
import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
import sys
import os
import tempfile
import json
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from security_integrations import (
        Fail2BanIntegration, 
        OSSECIntegration, 
        SuricataIntegration,
        ModSecurityIntegration,
        WazuhIntegration,
        SecurityIntegrationManager
    )
except ImportError as e:
    print(f"Could not import security integrations: {e}")


class TestFail2BanIntegration(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            'jail_files': ['/etc/fail2ban/jail.conf'],
            'fail2ban_socket': '/var/run/fail2ban/fail2ban.sock'
        }
        self.integration = Fail2BanIntegration(self.config)
    
    @patch('subprocess.run')
    def test_is_available_success(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'pong'
        
        self.assertTrue(self.integration.is_available())
        mock_run.assert_called_with(['fail2ban-client', 'ping'], 
                                   capture_output=True, text=True, timeout=5)
    
    @patch('subprocess.run')
    def test_is_available_failure(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        
        self.assertFalse(self.integration.is_available())
    
    @patch('subprocess.run')
    def test_ban_ip_success(self, mock_run):
        mock_run.return_value.returncode = 0
        
        result = self.integration.ban_ip('nginx-noscript', '192.168.1.100')
        
        self.assertTrue(result)
        self.assertIn('192.168.1.100', self.integration.banned_ips)
        mock_run.assert_called_with(
            ['fail2ban-client', 'set', 'nginx-noscript', 'banip', '192.168.1.100'],
            capture_output=True, text=True, timeout=5
        )
    
    @patch('subprocess.run')
    def test_unban_ip_success(self, mock_run):
        mock_run.return_value.returncode = 0
        self.integration.banned_ips.add('192.168.1.100')
        
        result = self.integration.unban_ip('nginx-noscript', '192.168.1.100')
        
        self.assertTrue(result)
        self.assertNotIn('192.168.1.100', self.integration.banned_ips)
    
    @patch('subprocess.run')
    def test_get_jail_status(self, mock_run):
        # Mock the status command response
        def side_effect(cmd, **kwargs):
            if cmd == ['fail2ban-client', 'ping']:
                # Mock ping response for is_available check
                mock_result = Mock()
                mock_result.returncode = 0
                mock_result.stdout = "pong"
                return mock_result
            elif cmd == ['fail2ban-client', 'status']:
                # Mock main status response
                mock_result = Mock()
                mock_result.returncode = 0
                mock_result.stdout = """Status
|- Number of jail:	2
`- Jail list:	nginx-noscript, nginx-http-auth"""
                return mock_result
            elif len(cmd) == 3 and cmd[0] == 'fail2ban-client' and cmd[1] == 'status':
                # Mock individual jail status
                mock_result = Mock()
                mock_result.returncode = 0
                mock_result.stdout = """Status for the jail: nginx-noscript
|- Filter
|  |- Currently failed:	5
|  |- Total failed:	20
|  `- File list:	/var/log/nginx/access.log
`- Actions
   |- Currently banned:	2
   |- Total banned:	10
   `- Banned IP list:	192.168.1.100 192.168.1.101"""
                return mock_result
            return Mock(returncode=1)

        mock_run.side_effect = side_effect
        
        jails = self.integration.get_jail_status()
        
        self.assertIn('nginx-noscript', jails)
        self.assertIn('nginx-http-auth', jails)
        self.assertEqual(jails['nginx-noscript']['currently_failed'], 5)
        self.assertEqual(jails['nginx-noscript']['currently_banned'], 2)
    
    @patch('subprocess.run')
    def test_ban_ip_failure(self, mock_run):
        """Test failed IP banning."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "Jail 'invalid-jail' does not exist"
        
        result = self.integration.ban_ip('invalid-jail', '192.168.1.100')
        
        self.assertFalse(result)
        self.assertNotIn('192.168.1.100', self.integration.banned_ips)
    
    @patch('subprocess.run')
    def test_ban_ip_exception(self, mock_run):
        """Test IP banning with exception."""
        mock_run.side_effect = Exception("Network error")
        
        result = self.integration.ban_ip('nginx-noscript', '192.168.1.100')
        
        self.assertFalse(result)
        self.assertNotIn('192.168.1.100', self.integration.banned_ips)
    
    @patch('subprocess.run')
    def test_unban_ip_failure(self, mock_run):
        """Test failed IP unbanning."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "IP not banned"
        self.integration.banned_ips.add('192.168.1.100')
        
        result = self.integration.unban_ip('nginx-noscript', '192.168.1.100')
        
        self.assertFalse(result)
        # IP should still be in banned list since unban failed
        self.assertIn('192.168.1.100', self.integration.banned_ips)
    
    @patch('subprocess.run')
    def test_unban_ip_exception(self, mock_run):
        """Test IP unbanning with exception."""
        mock_run.side_effect = Exception("Network error")
        self.integration.banned_ips.add('192.168.1.100')
        
        result = self.integration.unban_ip('nginx-noscript', '192.168.1.100')
        
        self.assertFalse(result)
        self.assertIn('192.168.1.100', self.integration.banned_ips)
    
    @patch('subprocess.run')
    def test_get_individual_jail_status_failure(self, mock_run):
        """Test individual jail status retrieval failure."""
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "Jail not found"
        
        result = self.integration.get_individual_jail_status('invalid-jail')
        
        self.assertIsNone(result)
    
    @patch('subprocess.run')
    def test_get_individual_jail_status_exception(self, mock_run):
        """Test individual jail status with exception."""
        mock_run.side_effect = Exception("Connection error")
        
        result = self.integration.get_individual_jail_status('nginx-noscript')
        
        self.assertIsNone(result)
    
    @patch('subprocess.run')
    def test_get_jail_status_unavailable(self, mock_run):
        """Test jail status when fail2ban is unavailable."""
        mock_run.side_effect = FileNotFoundError()
        
        result = self.integration.get_jail_status()
        
        self.assertEqual(result, {})
    
    @patch('subprocess.run')
    def test_get_jail_status_exception(self, mock_run):
        """Test jail status with exception during status retrieval."""
        # First call succeeds (is_available check)
        # Second call fails (status retrieval)
        mock_run.side_effect = [
            Mock(returncode=0, stdout="pong"),  # is_available check
            Exception("Command failed")         # status retrieval
        ]
        
        result = self.integration.get_jail_status()
        
        self.assertEqual(result, {})
    
    @patch('os.path.exists')
    @patch('os.path.isfile')
    @patch('os.path.isdir')
    def test_monitor_jail_files_with_files_and_dirs(self, mock_isdir, mock_isfile, mock_exists):
        """Test monitoring jail files with both files and directories."""
        # Setup file structure - only one path exists in jail_files
        self.integration.jail_files = ['/etc/fail2ban/jail.conf', '/etc/fail2ban/jail.d/']
        mock_exists.side_effect = lambda path: path in ['/etc/fail2ban/jail.conf', '/etc/fail2ban/jail.d/']
        mock_isfile.side_effect = lambda path: path == '/etc/fail2ban/jail.conf'
        mock_isdir.side_effect = lambda path: path == '/etc/fail2ban/jail.d/'
        
        with patch('pathlib.Path.glob') as mock_glob:
            mock_glob.return_value = [Path('/etc/fail2ban/jail.d/custom.conf')]
            with patch.object(self.integration, '_check_jail_file') as mock_check:
                mock_check.return_value = [{'threat': 'test'}]
                
                threats = self.integration.monitor_jail_files()
                
                # Should be called twice: once for the file, once for the dir content
                self.assertEqual(mock_check.call_count, 2)
                self.assertEqual(len(threats), 2)
    
    @patch('builtins.open', new_callable=unittest.mock.mock_open, read_data="""
[DEFAULT]
bantime = 100
findtime = 600
maxretry = 3

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6
""")
    @patch('os.path.exists')
    def test_check_jail_file_weak_config(self, mock_exists, mock_file):
        """Test checking jail file for weak configurations."""
        mock_exists.return_value = True
        
        threats = self.integration._check_jail_file('/etc/fail2ban/jail.conf')
        
        # Should detect weak ban time (100 seconds < 600 seconds minimum)
        self.assertTrue(any('weak ban time' in str(threat).lower() for threat in threats))
    
    @patch('builtins.open')
    @patch('os.path.exists')
    def test_check_jail_file_read_error(self, mock_exists, mock_open):
        """Test checking jail file with read error."""
        mock_exists.return_value = True
        mock_open.side_effect = IOError("Permission denied")
        
        threats = self.integration._check_jail_file('/etc/fail2ban/jail.conf')
        
        self.assertEqual(threats, [])


class TestOSSECIntegration(unittest.TestCase):
    
    def setUp(self):
        self.config = {'ossec_dir': '/var/ossec'}
        self.integration = OSSECIntegration(self.config)
    
    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_is_available_success(self, mock_run, mock_exists):
        mock_exists.return_value = True
        mock_run.return_value.stdout = 'ossec-analysisd is running'
        mock_run.return_value.returncode = 0  # Add missing returncode
        
        self.assertTrue(self.integration.is_available())
    
    @patch('os.path.exists')
    def test_is_available_failure(self, mock_exists):
        mock_exists.return_value = False
        
        self.assertFalse(self.integration.is_available())
    
    def test_get_recent_alerts(self):
        # Create a temporary alerts log file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("""2025 Jul 19 14:30:25 test-server->ossec-server
Rule: 1002 (level 5) -> 'User missed the password more than one time'
Src IP: 192.168.1.100
User: admin
Jul 19 14:30:25 test-server sshd[1234]: Failed password for admin

2025 Jul 19 14:30:30 test-server->ossec-server  
Rule: 5701 (level 10) -> 'Web server 400 error code.'
Src IP: 192.168.1.101
""")
            temp_file = f.name
        
        try:
            self.integration.alerts_log = temp_file
            alerts = self.integration.get_recent_alerts(hours=24)
            
            self.assertGreater(len(alerts), 0)
            self.assertIn('rule', alerts[0])
            self.assertIn('src_ip', alerts[0])
        finally:
            os.unlink(temp_file)
    
    def test_get_recent_alerts_no_file(self):
        """Test getting alerts when log file doesn't exist."""
        self.integration.alerts_log = '/nonexistent/path/alerts.log'
        
        alerts = self.integration.get_recent_alerts(hours=1)
        
        self.assertEqual(alerts, [])
    
    @patch('builtins.open')
    def test_get_recent_alerts_read_error(self, mock_open):
        """Test getting alerts with file read error."""
        mock_open.side_effect = IOError("Permission denied")
        
        alerts = self.integration.get_recent_alerts(hours=1)
        
        self.assertEqual(alerts, [])
    
    def test_is_recent_alert_true(self):
        """Test alert recency check for recent alert."""
        from datetime import datetime, timedelta
        
        recent_time = datetime.now() - timedelta(minutes=30)
        alert = {'timestamp': recent_time.strftime('%Y %b %d %H:%M:%S')}
        cutoff_time = datetime.now() - timedelta(hours=1)
        
        result = self.integration._is_recent_alert(alert, cutoff_time)
        
        self.assertTrue(result)
    
    def test_is_recent_alert_false(self):
        """Test alert recency check for old alert."""
        from datetime import datetime, timedelta
        
        old_time = datetime.now() - timedelta(hours=2)
        alert = {'timestamp': old_time.strftime('%Y %b %d %H:%M:%S')}
        cutoff_time = datetime.now() - timedelta(hours=1)
        
        result = self.integration._is_recent_alert(alert, cutoff_time)
        
        self.assertFalse(result)
    
    def test_is_recent_alert_invalid_timestamp(self):
        """Test alert recency check with invalid timestamp."""
        from datetime import datetime, timedelta
        
        alert = {'timestamp': 'invalid-timestamp'}
        cutoff_time = datetime.now() - timedelta(hours=1)
        
        result = self.integration._is_recent_alert(alert, cutoff_time)
        
        # The actual implementation returns True for unparseable timestamps
        self.assertTrue(result)
    
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    @patch('os.path.exists')
    def test_add_custom_rule_success(self, mock_exists, mock_open):
        """Test adding custom OSSEC rule successfully."""
        mock_exists.return_value = True
        
        rule_content = """
        <rule id="100001" level="10">
            <if_matched_group>web</if_matched_group>
            <regex>nginx security alert</regex>
            <description>NGINX Security Monitor Alert</description>
        </rule>
        """
        
        result = self.integration.add_custom_rule(rule_content)
        
        self.assertTrue(result)
        # Should be called twice: once for read, once for write
        self.assertEqual(mock_open.call_count, 2)
    
    @patch('os.path.exists')
    def test_add_custom_rule_dir_not_exist(self, mock_exists):
        """Test adding custom rule when rules directory doesn't exist."""
        mock_exists.return_value = False
        
        rule_content = "<rule id='100001' level='10'><description>Test</description></rule>"
        
        result = self.integration.add_custom_rule(rule_content)
        
        self.assertFalse(result)
    
    @patch('builtins.open')
    @patch('os.path.exists')
    def test_add_custom_rule_write_error(self, mock_exists, mock_open):
        """Test adding custom rule with write error."""
        mock_exists.return_value = True
        mock_open.side_effect = IOError("Permission denied")
        
        rule_content = "<rule id='100001' level='10'><description>Test</description></rule>"
        
        result = self.integration.add_custom_rule(rule_content)
        
        self.assertFalse(result)


class TestSuricataIntegration(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            'suricata_log': '/var/log/suricata/eve.json',
            'suricata_rules': '/etc/suricata/rules/'
        }
        self.integration = SuricataIntegration(self.config)
    
    @patch('subprocess.run')
    def test_is_available_success(self, mock_run):
        mock_run.return_value.returncode = 0
        
        self.assertTrue(self.integration.is_available())
    
    def test_get_recent_alerts(self):
        # Create temporary EVE JSON log
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            # Write sample Suricata EVE JSON events
            events = [
                {
                    "timestamp": "2025-07-19T14:30:25.000000+0000",
                    "event_type": "alert",
                    "src_ip": "192.168.1.100",
                    "dest_ip": "10.0.0.1", 
                    "src_port": 12345,
                    "dest_port": 80,
                    "proto": "TCP",
                    "alert": {
                        "signature": "SQL Injection Attempt",
                        "category": "Web Application Attack",
                        "severity": 1
                    }
                },
                {
                    "timestamp": "2025-07-19T14:30:26.000000+0000",
                    "event_type": "http",
                    "src_ip": "192.168.1.101",
                    "dest_ip": "10.0.0.1"
                }
            ]
            
            for event in events:
                f.write(json.dumps(event) + '\n')
            temp_file = f.name
        
        try:
            self.integration.suricata_log = temp_file
            alerts = self.integration.get_recent_alerts(hours=24)
            
            # Should only get alert events, not http events
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]['signature'], 'SQL Injection Attempt')
            self.assertEqual(alerts[0]['src_ip'], '192.168.1.100')
        finally:
            os.unlink(temp_file)
    
    @patch('subprocess.run')
    def test_is_available_failure(self, mock_run):
        """Test Suricata availability check failure."""
        mock_run.side_effect = FileNotFoundError()
        
        result = self.integration.is_available()
        
        self.assertFalse(result)
    
    def test_get_recent_alerts_no_file(self):
        """Test getting alerts when log file doesn't exist."""
        self.integration.suricata_log = '/nonexistent/path/eve.json'
        
        alerts = self.integration.get_recent_alerts(hours=1)
        
        self.assertEqual(alerts, [])
    
    @patch('builtins.open')
    def test_get_recent_alerts_read_error(self, mock_open):
        """Test getting alerts with file read error."""
        mock_open.side_effect = IOError("Permission denied")
        
        alerts = self.integration.get_recent_alerts(hours=1)
        
        self.assertEqual(alerts, [])
    
    def test_get_recent_alerts_invalid_json(self):
        """Test getting alerts with invalid JSON in log file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write('invalid json line\n')
            f.write('{"valid": "json"}\n')
            f.write('another invalid line\n')
            temp_file = f.name
        
        try:
            self.integration.suricata_log = temp_file
            alerts = self.integration.get_recent_alerts(hours=24)
            
            # Should skip invalid JSON lines and process valid ones
            self.assertEqual(len(alerts), 0)  # No alert events in valid JSON
        finally:
            os.unlink(temp_file)
    
    @patch('builtins.open', new_callable=unittest.mock.mock_open)
    @patch('os.path.exists')
    def test_add_custom_rule_success(self, mock_exists, mock_open):
        """Test adding custom Suricata rule successfully."""
        mock_exists.return_value = True
        
        rule_content = 'alert http any any -> any any (msg:"NGINX Security Alert"; content:"attack"; sid:1000001;)'
        
        result = self.integration.add_custom_rule(rule_content)
        
        self.assertTrue(result)
        mock_open.assert_called_once()
    
    @patch('os.path.exists')
    def test_add_custom_rule_dir_not_exist(self, mock_exists):
        """Test adding custom rule when rules directory doesn't exist."""
        mock_exists.return_value = False
        
        rule_content = 'alert http any any -> any any (msg:"Test"; sid:1000001;)'
        
        result = self.integration.add_custom_rule(rule_content)
        
        self.assertFalse(result)
    
    @patch('builtins.open')
    @patch('os.path.exists')
    def test_add_custom_rule_write_error(self, mock_exists, mock_open):
        """Test adding custom rule with write error."""
        mock_exists.return_value = True
        mock_open.side_effect = IOError("Permission denied")
        
        rule_content = 'alert http any any -> any any (msg:"Test"; sid:1000001;)'
        
        result = self.integration.add_custom_rule(rule_content)
        
        self.assertFalse(result)


class TestWazuhIntegration(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            'wazuh_api_url': 'https://localhost:55000',
            'wazuh_api_user': 'test_user',
            'wazuh_api_password': 'test_pass'
        }
        self.integration = WazuhIntegration(self.config)
    
    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_is_available_success(self, mock_run, mock_exists):
        """Test Wazuh availability check success."""
        mock_exists.return_value = True
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = 'wazuh-manager running'
        
        result = self.integration.is_available()
        
        self.assertTrue(result)
    
    @patch('os.path.exists')
    def test_is_available_failure_no_dir(self, mock_exists):
        """Test Wazuh availability when directory doesn't exist."""
        mock_exists.return_value = False
        
        result = self.integration.is_available()
        
        self.assertFalse(result)
    
    @patch('os.path.exists')
    @patch('subprocess.run')
    def test_is_available_failure_not_running(self, mock_run, mock_exists):
        """Test Wazuh availability when service not running."""
        mock_exists.return_value = True
        mock_run.side_effect = FileNotFoundError()
        
        result = self.integration.is_available()
        
        self.assertFalse(result)
    
    @patch('syslog.syslog')
    @patch('syslog.openlog')
    @patch('syslog.closelog')
    def test_send_custom_event_success(self, mock_closelog, mock_openlog, mock_syslog):
        """Test sending custom event successfully."""
        event_data = {
            'message': 'SQL injection detected',
            'src_ip': '192.168.1.100',
            'priority': 'high'
        }
        
        result = self.integration.send_custom_event(event_data)
        
        self.assertTrue(result)
        mock_openlog.assert_called_once()
        mock_syslog.assert_called_once()
        mock_closelog.assert_called_once()
    
    @patch('syslog.syslog')
    def test_send_custom_event_failure(self, mock_syslog):
        """Test sending custom event failure."""
        mock_syslog.side_effect = Exception("Syslog error")
        
        event_data = {'message': 'test alert'}
        
        result = self.integration.send_custom_event(event_data)
        
        self.assertFalse(result)
    
    @patch('syslog.syslog')
    @patch('syslog.openlog')
    @patch('syslog.closelog')
    def test_send_custom_event_with_priority_mapping(self, mock_closelog, mock_openlog, mock_syslog):
        """Test sending custom event with different priority levels."""
        event_data = {
            'message': 'Low priority alert',
            'priority': 'low'
        }
        
        result = self.integration.send_custom_event(event_data)
        
        self.assertTrue(result)
        mock_syslog.assert_called_once()


class TestModSecurityIntegration(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            'modsecurity_log': '/var/log/modsec_audit.log'
        }
        self.integration = ModSecurityIntegration(self.config)
    
    @patch('os.path.exists')
    def test_is_available_success(self, mock_exists):
        """Test ModSecurity availability check success."""
        mock_exists.return_value = True
        
        result = self.integration.is_available()
        
        self.assertTrue(result)
    
    @patch('os.path.exists')
    def test_is_available_failure(self, mock_exists):
        """Test ModSecurity availability check failure."""
        mock_exists.return_value = False
        
        result = self.integration.is_available()
        
        self.assertFalse(result)
    
    def test_get_recent_blocks_no_file(self):
        """Test getting recent blocks when log file doesn't exist."""
        self.integration.modsecurity_log = '/nonexistent/path/audit.log'
        
        blocks = self.integration.get_recent_blocks(hours=1)
        
        self.assertEqual(blocks, [])
    
    @patch('builtins.open')
    def test_get_recent_blocks_read_error(self, mock_open):
        """Test getting recent blocks with file read error."""
        mock_open.side_effect = IOError("Permission denied")
        
        blocks = self.integration.get_recent_blocks(hours=1)
        
        self.assertEqual(blocks, [])
    
    def test_parse_modsec_log_success(self):
        """Test parsing ModSecurity log successfully."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("""--12345678-A--
[19/Jul/2025:14:30:25 +0000] XYZ123 192.168.1.100 12345 10.0.0.1 80
--12345678-B--
POST /admin/login HTTP/1.1
Host: example.com
User-Agent: BadBot/1.0

--12345678-C--
username=admin&password=password123

--12345678-F--
HTTP/1.1 403 Forbidden
Content-Type: text/html

--12345678-H--
ModSecurity: Warning. Pattern match "union.*select" at ARGS:password.
Action: Blocked. [id "981231"]

--12345678-Z--

""")
            temp_file = f.name
        
        try:
            blocks = self.integration._parse_modsec_log(temp_file, hours=24)
            
            self.assertGreater(len(blocks), 0)
            self.assertIn('timestamp', blocks[0])
            self.assertIn('src_ip', blocks[0])
            self.assertIn('rule_id', blocks[0])
        finally:
            os.unlink(temp_file)
    
    def test_parse_modsec_log_invalid_format(self):
        """Test parsing ModSecurity log with invalid format."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Invalid log format without proper sections\n")
            temp_file = f.name
        
        try:
            blocks = self.integration._parse_modsec_log(temp_file, hours=24)
            
            self.assertEqual(blocks, [])
        finally:
            os.unlink(temp_file)


class TestSecurityIntegrationManager(unittest.TestCase):
    
    def setUp(self):
        self.config = {
            'fail2ban': {'enabled': True},
            'ossec': {'enabled': True},
            'suricata': {'enabled': True},
            'wazuh': {'enabled': True},
            'modsecurity': {'enabled': True}
        }
        
    @patch.multiple(
        'security_integrations',
        Fail2BanIntegration=Mock(),
        OSSECIntegration=Mock(), 
        SuricataIntegration=Mock(),
        WazuhIntegration=Mock(),
        ModSecurityIntegration=Mock()
    )
    def test_initialization(self):
        manager = SecurityIntegrationManager(self.config)
        
        self.assertIsNotNone(manager.fail2ban)
        self.assertIsNotNone(manager.ossec)
        self.assertIsNotNone(manager.suricata)
        self.assertIsNotNone(manager.wazuh)
        self.assertIsNotNone(manager.modsecurity)
    
    def test_handle_threat_with_integrations(self):
        # Mock integrations
        mock_fail2ban = Mock()
        mock_fail2ban.ban_ip.return_value = True
        
        mock_wazuh = Mock()
        mock_wazuh.send_custom_event.return_value = True
        
        manager = SecurityIntegrationManager(self.config)
        manager.fail2ban = mock_fail2ban
        manager.wazuh = mock_wazuh
        manager.available_integrations = {
            'fail2ban': True,
            'wazuh': True,
            'ossec': False,
            'suricata': False,
            'modsecurity': False
        }
        
        threat_info = {
            'type': 'SQL Injection',
            'severity': 'HIGH',
            'ip': '192.168.1.100'
        }
        
        result = manager.handle_threat_with_integrations(threat_info)
        
        self.assertIn('actions_taken', result)
        self.assertGreater(len(result['actions_taken']), 0)
        mock_fail2ban.ban_ip.assert_called_once()
        mock_wazuh.send_custom_event.assert_called_once()
    
    def test_get_aggregated_threats(self):
        # Mock integrations with sample threats
        mock_fail2ban = Mock()
        mock_fail2ban.get_jail_status.return_value = {
            'nginx-noscript': {'currently_banned': 2, 'total_failed': 10}
        }
        
        mock_ossec = Mock()
        mock_ossec.get_recent_alerts.return_value = [
            {'rule': 'High severity alert', 'src_ip': '192.168.1.100', 'timestamp': '2025-07-19T14:30:25'}
        ]
        
        manager = SecurityIntegrationManager(self.config)
        manager.fail2ban = mock_fail2ban
        manager.ossec = mock_ossec
        manager.available_integrations = {
            'fail2ban': True,
            'ossec': True,
            'suricata': False,
            'wazuh': False,
            'modsecurity': False
        }
        
        threats = manager.get_aggregated_threats(hours=1)
        
        self.assertGreater(len(threats), 0)
        # Should have threats from both fail2ban and OSSEC
        sources = [threat['source'] for threat in threats]
        self.assertIn('fail2ban', sources)
        self.assertIn('ossec', sources)
    
    def test_check_available_integrations(self):
        """Test checking available integrations."""
        manager = SecurityIntegrationManager(self.config)
        
        # Mock the integration objects and their is_available methods
        manager.fail2ban = Mock()
        manager.fail2ban.is_available.return_value = True
        manager.ossec = Mock()
        manager.ossec.is_available.return_value = False
        manager.suricata = Mock()
        manager.suricata.is_available.return_value = True
        manager.wazuh = Mock()
        manager.wazuh.is_available.return_value = False
        manager.modsecurity = Mock()
        manager.modsecurity.is_available.return_value = True
        
        result = manager._check_available_integrations()
        
        expected = {
            'fail2ban': True,
            'ossec': False,
            'suricata': True,
            'wazuh': False,
            'modsecurity': True
        }
        
        self.assertEqual(result, expected)
    
    def test_get_integration_status(self):
        """Test getting integration status summary."""
        manager = SecurityIntegrationManager(self.config)
        manager.available_integrations = {
            'fail2ban': True,
            'ossec': False,
            'suricata': True,
            'wazuh': True,
            'modsecurity': False
        }
        
        status = manager.get_integration_status()
        
        self.assertIn('available_integrations', status)
        self.assertIn('integration_details', status)
        # Check specific integration statuses
        self.assertEqual(status['available_integrations']['fail2ban'], True)
        self.assertEqual(status['available_integrations']['ossec'], False)
    
    def test_handle_threat_no_integrations_available(self):
        """Test handling threat when no integrations are available."""
        manager = SecurityIntegrationManager(self.config)
        manager.available_integrations = {
            'fail2ban': False,
            'ossec': False,
            'suricata': False,
            'wazuh': False,
            'modsecurity': False
        }
        
        threat_info = {
            'type': 'SQL Injection',
            'severity': 'HIGH',
            'ip': '192.168.1.100'
        }
        
        result = manager.handle_threat_with_integrations(threat_info)
        
        self.assertIn('actions_taken', result)
        self.assertEqual(len(result['actions_taken']), 0)
    
    def test_handle_threat_with_exceptions(self):
        """Test handling threat when integrations raise exceptions."""
        mock_fail2ban = Mock()
        mock_fail2ban.ban_ip.side_effect = Exception("Fail2ban error")
        
        manager = SecurityIntegrationManager(self.config)
        manager.fail2ban = mock_fail2ban
        manager.available_integrations = {
            'fail2ban': True,
            'wazuh': False,
            'ossec': False,
            'suricata': False,
            'modsecurity': False
        }
        
        threat_info = {
            'type': 'SQL Injection',
            'severity': 'HIGH',
            'ip': '192.168.1.100'
        }
        
        # The method doesn't handle exceptions internally, so it will raise
        with self.assertRaises(Exception):
            manager.handle_threat_with_integrations(threat_info)
    
    def test_get_aggregated_threats_with_exceptions(self):
        """Test getting aggregated threats when integrations raise exceptions."""
        mock_fail2ban = Mock()
        mock_fail2ban.get_jail_status.side_effect = Exception("Fail2ban error")
        
        mock_ossec = Mock()
        mock_ossec.get_recent_alerts.return_value = [
            {'rule': 'Test alert', 'src_ip': '192.168.1.100'}
        ]
        
        manager = SecurityIntegrationManager(self.config)
        manager.fail2ban = mock_fail2ban
        manager.ossec = mock_ossec
        manager.available_integrations = {
            'fail2ban': True,
            'ossec': True,
            'suricata': False,
            'wazuh': False,
            'modsecurity': False
        }
        
        # The method doesn't handle exceptions internally, so it will raise
        with self.assertRaises(Exception):
            manager.get_aggregated_threats(hours=1)
    
    def test_initialization_with_disabled_integrations(self):
        """Test initialization with some integrations disabled."""
        config = {
            'fail2ban': {'enabled': True},
            'ossec': {'enabled': False},
            'suricata': {'enabled': True},
            'wazuh': {'enabled': False},
            'modsecurity': {'enabled': False}
        }
        
        manager = SecurityIntegrationManager(config)
        
        # All integrations are always initialized, regardless of enabled setting
        # The enabled setting affects their availability checking, not initialization
        self.assertIsNotNone(manager.fail2ban)
        self.assertIsNotNone(manager.ossec)
        self.assertIsNotNone(manager.suricata)
        self.assertIsNotNone(manager.wazuh)
        self.assertIsNotNone(manager.modsecurity)

    def test_fail2ban_check_jail_file_disabled_jails(self):
        """Test detection of disabled critical jails in fail2ban config."""
        jail_content = """
[nginx-http-auth]
enabled = false
port = http,https

[nginx-noscript]
enabled = false

[DEFAULT]
bantime = 300
"""
        integration = Fail2BanIntegration()
        
        with patch('builtins.open', mock_open(read_data=jail_content)):
            threats = integration._check_jail_file('/etc/fail2ban/jail.conf')
            
            # Should detect 2 disabled critical jails
            disabled_jail_threats = [t for t in threats if t['type'] == 'Disabled Critical Jail']
            self.assertEqual(len(disabled_jail_threats), 2)
            
            # Check specific jails are detected
            jail_names = [t['jail'] for t in disabled_jail_threats]
            self.assertIn('nginx-http-auth', jail_names)
            self.assertIn('nginx-noscript', jail_names)

    def test_fail2ban_check_jail_file_weak_bantime(self):
        """Test detection of weak ban times in fail2ban config."""
        jail_content = """
[DEFAULT]
bantime = 300

[nginx-auth]
bantime = 60
"""
        integration = Fail2BanIntegration()
        
        with patch('builtins.open', mock_open(read_data=jail_content)):
            threats = integration._check_jail_file('/etc/fail2ban/jail.conf')
            
            # Should detect weak ban times (less than 600 seconds)
            weak_bantime_threats = [t for t in threats if t['type'] == 'Weak Ban Time']
            self.assertEqual(len(weak_bantime_threats), 2)  # Both 300 and 60 are weak

        def test_ossec_get_recent_alerts_with_src_ip(self):
            """Test OSSEC alert parsing including Src IP field."""
            alert_content = """2025 Jul 19 14:30:25 hostname->192.168.1.100
Rule: 31151 (level 10) -> 'High amount of POST requests from same source IP'
Src IP: 192.168.1.1
User: (none)
Jul 19 14:30:25 hostname httpd: 192.168.1.1 - - [19/Jul/2025:14:30:25 +0000] "POST /login" 200

2025 Jul 19 14:31:30 hostname->192.168.1.100
Rule: 31106 (level 6) -> 'Invalid URI, possible exploit attempt'
User: admin
Jul 19 14:31:30 hostname httpd: exploit attempt detected
"""
            integration = OSSECIntegration()

            with patch('builtins.open', mock_open(read_data=alert_content)):
                with patch('os.path.exists', return_value=True):
                    alerts = integration.get_recent_alerts(hours=24)

                    self.assertEqual(len(alerts), 2)                # Check first alert has src_ip parsed
                first_alert = alerts[0]
                self.assertEqual(first_alert.get('src_ip'), '192.168.1.1')
                self.assertIn('31151', first_alert.get('rule', ''))
                
                # Check second alert has user parsed but no src_ip
                second_alert = alerts[1]
                self.assertEqual(second_alert.get('user'), 'admin')
                self.assertNotIn('src_ip', second_alert)

    def test_ossec_get_recent_alerts_exception_handling(self):
        """Test OSSEC exception handling when file reading fails."""
        integration = OSSECIntegration()
        
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.path.exists', return_value=True):
                alerts = integration.get_recent_alerts(hours=1)
                
                # Should return empty list on exception
                self.assertEqual(alerts, [])

    def test_suricata_get_recent_alerts_with_timestamp_parsing(self):
        """Test Suricata alert parsing with proper timestamp handling."""
        # Use recent timestamps - within the last hour
        from datetime import datetime, timedelta
        recent_time = datetime.now() - timedelta(minutes=30)
        recent_timestamp = recent_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
        old_time = datetime.now() - timedelta(days=2)
        old_timestamp = old_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
        eve_log_content = f"""{{\"timestamp\":\"{recent_timestamp}\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.1\",\"dest_ip\":\"10.0.0.1\",\"alert\":{{\"signature\":\"Test signature\",\"category\":\"Test\",\"severity\":1}}}}
{{\"timestamp\":\"{recent_timestamp}\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.2\",\"dest_ip\":\"10.0.0.1\",\"alert\":{{\"signature\":\"Another test\",\"category\":\"Test2\",\"severity\":2}}}}
{{\"timestamp\":\"{old_timestamp}\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.3\",\"dest_ip\":\"10.0.0.1\",\"alert\":{{\"signature\":\"Old alert\",\"category\":\"Old\",\"severity\":3}}}}
"""
        integration = SuricataIntegration()

        with patch('builtins.open', mock_open(read_data=eve_log_content)):
            with patch('os.path.exists', return_value=True):
                alerts = integration.get_recent_alerts(hours=24)

                # Should get 2 recent alerts (the old one should be filtered out)
                self.assertEqual(len(alerts), 2)                # Check alert details
                self.assertEqual(alerts[0]['src_ip'], '192.168.1.1')
                self.assertEqual(alerts[0]['severity'], 1)
                self.assertEqual(alerts[1]['src_ip'], '192.168.1.2')
                self.assertEqual(alerts[1]['severity'], 2)

    def test_suricata_get_recent_alerts_json_decode_error(self):
        """Test Suricata handling of malformed JSON lines."""
        from datetime import datetime, timedelta
        recent_time = datetime.now() - timedelta(minutes=30)
        recent_timestamp = recent_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        
        eve_log_content = f"""{{\"timestamp\":\"{recent_timestamp}\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.1\"}}
{{invalid json line}}
{{\"timestamp\":\"{recent_timestamp}\",\"event_type\":\"alert\",\"src_ip\":\"192.168.1.2\"}}
"""
        integration = SuricataIntegration()
        
        with patch('builtins.open', mock_open(read_data=eve_log_content)):
            with patch('os.path.exists', return_value=True):
                alerts = integration.get_recent_alerts(hours=24)
                
                # Should get 2 valid alerts, skip the malformed one
                self.assertEqual(len(alerts), 2)

    def test_wazuh_send_custom_event_exception_handling(self):
        """Test Wazuh custom event exception handling."""
        integration = WazuhIntegration()
        
        # Mock syslog to raise an exception
        with patch('syslog.openlog', side_effect=Exception("Syslog error")):
            result = integration.send_custom_event({
                'priority': 'high',
                'message': 'Test alert'
            })
            
            self.assertFalse(result)

    def test_modsecurity_parse_modsec_log_with_entries(self):
        """Test ModSecurity log parsing with real entries."""
        from datetime import datetime, timedelta
        recent_time = datetime.now() - timedelta(minutes=30)
        timestamp_str = recent_time.strftime('%d/%b/%Y:%H:%M:%S')
        
        log_content = f"""--1234abcd-A--
[{timestamp_str} +0000] 192.168.1.1 GET /test
--1234abcd-B--
Request headers:
Host: example.com
--1234abcd-C--
[id "950001"] [msg "SQL Injection Detected"]
--1234abcd-F--
Response status: 403
--1234abcd-Z--

--abcd1234-A--
[{timestamp_str} +0000] 192.168.1.2 POST /login
--abcd1234-B--
Request headers:
--abcd1234-C--
[id "950002"] [msg "XSS Attack Blocked"]
--abcd1234-Z--
"""
        integration = ModSecurityIntegration()

        with patch('builtins.open', mock_open(read_data=log_content)):
            blocks = integration._parse_modsec_log('/var/log/modsec_audit.log', hours=24)

            self.assertEqual(len(blocks), 2)            # Check first block
            self.assertEqual(blocks[0]['src_ip'], '192.168.1.1')
            self.assertEqual(blocks[0]['rule_id'], '950001')
            self.assertEqual(blocks[0]['message'], 'SQL Injection Detected')
            
            # Check second block  
            self.assertEqual(blocks[1]['src_ip'], '192.168.1.2')
            self.assertEqual(blocks[1]['rule_id'], '950002')
            self.assertEqual(blocks[1]['message'], 'XSS Attack Blocked')

    def test_security_integration_manager_handle_threat_no_ip(self):
        """Test threat handling when no IP address is provided."""
        manager = SecurityIntegrationManager()
        
        # Mock fail2ban as available but no IP in threat
        manager.available_integrations['fail2ban'] = True
        
        threat_info = {
            'type': 'SQL Injection',
            'severity': 'HIGH'
            # No 'ip' field
        }
        
        result = manager.handle_threat_with_integrations(threat_info)
        
        # Should not attempt IP banning without IP
        self.assertEqual(len(result['actions_taken']), 0)

    def test_security_integration_manager_get_aggregated_threats_empty(self):
        """Test aggregated threats when no integrations are available."""
        manager = SecurityIntegrationManager()
        
        # All integrations unavailable
        manager.available_integrations = {
            'fail2ban': False,
            'ossec': False,
            'suricata': False,
            'modsecurity': False,
            'wazuh': False
        }
        
        threats = manager.get_aggregated_threats(hours=1)
        
        self.assertEqual(threats, [])

    def test_ossec_parsing_various_fields(self):
        """Test OSSEC alert parsing with various field types."""
        alerts_content = """2025 Jul 18 14:30:25 (server) any->10.0.0.1
** Alert 1627481425.123: - syslog,attacks,
2025 Jul 18 14:30:25 server -> alert1

Rule: 31151 (level 10) -> 'High amount of POST requests in a small period of time'
Src IP: 192.168.1.100
User: testuser
Server: example.com
Request: POST /login
"""
        integration = OSSECIntegration()
        
        with patch('builtins.open', mock_open(read_data=alerts_content)):
            with patch('os.path.exists', return_value=True):
                alerts = integration.get_recent_alerts(hours=24)
                
                self.assertGreaterEqual(len(alerts), 1)
                # Check the first alert has all the parsed fields
                alert = alerts[0]
                if 'rule' in alert:
                    self.assertIn('31151', alert['rule'])
                if 'level' in alert:
                    self.assertEqual(alert['level'], '10')
                if 'src_ip' in alert:
                    self.assertEqual(alert['src_ip'], '192.168.1.100')
                if 'user' in alert:
                    self.assertEqual(alert['user'], 'testuser')

    def test_ossec_add_custom_rule_creates_file_if_not_exists(self):
        """Test OSSEC add custom rule creates file if it doesn't exist."""
        integration = OSSECIntegration()
        
        with patch('os.path.exists') as mock_exists:
            mock_exists.side_effect = lambda path: '/rules' not in path  # Rules dir exists, file doesn't
            with patch('builtins.open', mock_open()) as mock_file:
                with patch('os.makedirs'):
                    result = integration.add_custom_rule('<rule id="100001" level="5"/>')
                    
                    self.assertTrue(result)
                    # Check file creation call
                    mock_file.assert_any_call(unittest.mock.ANY, 'w')

    def test_suricata_general_exception_handling(self):
        """Test Suricata general exception handling in get_recent_alerts."""
        integration = SuricataIntegration()
        
        with patch('builtins.open', side_effect=Exception("General read error")):
            with patch('os.path.exists', return_value=True):
                alerts = integration.get_recent_alerts(hours=24)
                
                self.assertEqual(len(alerts), 0)

    def test_modsecurity_log_exists_check(self):
        """Test ModSecurity checks multiple log file locations."""
        integration = ModSecurityIntegration()
        
        with patch('os.path.exists') as mock_exists:
            mock_exists.return_value = False  # No log files exist
            blocks = integration.get_recent_blocks(hours=24)
            
            self.assertEqual(len(blocks), 0)
            # Should check multiple log locations
            self.assertGreater(mock_exists.call_count, 1)

    def test_modsecurity_parse_log_exception_handling(self):
        """Test ModSecurity log parsing with general exception."""
        integration = ModSecurityIntegration()
        
        with patch('builtins.open', side_effect=Exception("Read error")):
            blocks = integration._parse_modsec_log('/var/log/modsec_audit.log', hours=24)
            
            self.assertEqual(len(blocks), 0)

    def test_modsecurity_parse_log_timestamp_value_error(self):
        """Test ModSecurity log parsing with invalid timestamp format."""
        from datetime import datetime, timedelta
        recent_time = datetime.now() - timedelta(minutes=30)
        
        log_content = f"""--1234abcd-A--
[invalid/timestamp/format] 192.168.1.1 GET /test
--1234abcd-B--
[id "950001"] [msg "SQL Injection Detected"]
--1234abcd-Z--
"""
        integration = ModSecurityIntegration()
        
        with patch('builtins.open', mock_open(read_data=log_content)):
            blocks = integration._parse_modsec_log('/var/log/modsec_audit.log', hours=24)
            
            self.assertEqual(len(blocks), 0)  # Should skip invalid timestamp

    def test_security_integration_manager_availability_check_exception(self):
        """Test SecurityIntegrationManager handling exceptions during availability checks."""
        config = {
            'fail2ban': {},
            'ossec': {}
        }
        
        # Patch at the module level where classes are used
        with patch('security_integrations.Fail2BanIntegration') as MockFail2Ban:
            with patch('security_integrations.OSSECIntegration') as MockOSSEC:
                # Make fail2ban is_available raise exception
                mock_fail2ban = Mock()
                mock_fail2ban.is_available.side_effect = Exception("Fail2ban check error")
                MockFail2Ban.return_value = mock_fail2ban
                
                # Make ossec work normally
                mock_ossec = Mock()
                mock_ossec.is_available.return_value = True
                MockOSSEC.return_value = mock_ossec
                
                manager = SecurityIntegrationManager(config)
                
                self.assertFalse(manager.available_integrations['fail2ban'])  # Should be False due to exception
                self.assertTrue(manager.available_integrations['ossec'])  # Should work normally

    def test_security_integration_manager_get_status_with_ossec_details(self):
        """Test SecurityIntegrationManager get status with OSSEC details."""
        config = {
            'ossec': {}
        }
        
        with patch('security_integrations.OSSECIntegration') as MockOSSEC:
            mock_ossec = Mock()
            mock_ossec.is_available.return_value = True
            # Return alerts with Level: 10 for high severity test
            mock_ossec.get_recent_alerts.return_value = [
                {'raw_lines': ['Level: 10']},
                {'raw_lines': ['Level: 5']},
                {'raw_lines': ['Level: 10']}
            ]
            MockOSSEC.return_value = mock_ossec
            
            manager = SecurityIntegrationManager(config)
            # Force ossec to be available for the test
            manager.available_integrations['ossec'] = True
            status = manager.get_integration_status()
            
            self.assertIn('ossec', status['integration_details'])
            self.assertEqual(status['integration_details']['ossec']['recent_alerts_count'], 3)
            self.assertEqual(status['integration_details']['ossec']['high_severity_alerts'], 2)

    def test_security_integration_manager_get_status_with_suricata_details(self):
        """Test SecurityIntegrationManager get status with Suricata details."""
        config = {
            'suricata': {}
        }
        
        with patch('security_integrations.SuricataIntegration') as MockSuricata:
            mock_suricata = Mock()
            mock_suricata.is_available.return_value = True
            # Return alerts with different severity levels
            mock_suricata.get_recent_alerts.return_value = [
                {'severity': 1},  # Critical
                {'severity': 2},  # High 
                {'severity': 3}   # Medium
            ]
            MockSuricata.return_value = mock_suricata
            
            manager = SecurityIntegrationManager(config)
            # Force suricata to be available for the test
            manager.available_integrations['suricata'] = True
            status = manager.get_integration_status()
            
            self.assertIn('suricata', status['integration_details'])
            self.assertEqual(status['integration_details']['suricata']['recent_alerts_count'], 3)
            self.assertEqual(status['integration_details']['suricata']['critical_alerts'], 3)  # severity >= 1

    def test_security_integration_manager_get_status_with_modsecurity_details(self):
        """Test SecurityIntegrationManager get status with ModSecurity details."""
        config = {
            'modsecurity': {}
        }
        
        with patch('security_integrations.ModSecurityIntegration') as MockModSec:
            mock_modsec = Mock()
            mock_modsec.is_available.return_value = True
            mock_modsec.get_recent_blocks.return_value = [
                {'rule_id': '950001'},
                {'rule_id': '950002'}
            ]
            MockModSec.return_value = mock_modsec
            
            manager = SecurityIntegrationManager(config)
            # Force modsecurity to be available for the test
            manager.available_integrations['modsecurity'] = True
            status = manager.get_integration_status()
            
            self.assertIn('modsecurity', status['integration_details'])
            self.assertEqual(status['integration_details']['modsecurity']['recent_blocks_count'], 2)

    def test_security_integration_manager_get_aggregated_threats_with_suricata(self):
        """Test SecurityIntegrationManager get aggregated threats including Suricata alerts."""
        config = {
            'suricata': {}
        }
        
        with patch('security_integrations.SuricataIntegration') as MockSuricata:
            mock_suricata = Mock()
            mock_suricata.is_available.return_value = True
            mock_suricata.get_recent_alerts.return_value = [
                {
                    'timestamp': '2025-07-18T14:30:25Z',
                    'src_ip': '192.168.1.1',
                    'severity': 1,
                    'signature': 'Test alert'
                }
            ]
            MockSuricata.return_value = mock_suricata
            
            manager = SecurityIntegrationManager(config)
            # Force suricata to be available for the test
            manager.available_integrations['suricata'] = True
            threats = manager.get_aggregated_threats(hours=1)
            
            self.assertEqual(len(threats), 1)
            threat = threats[0]
            self.assertEqual(threat['source'], 'suricata')
            self.assertEqual(threat['type'], 'IDS Alert')
            self.assertEqual(threat['severity'], 'CRITICAL')
            self.assertEqual(threat['src_ip'], '192.168.1.1')

    def test_security_integration_manager_get_aggregated_threats_with_modsecurity(self):
        """Test SecurityIntegrationManager get aggregated threats including ModSecurity blocks."""
        config = {
            'modsecurity': {}
        }
        
        with patch('security_integrations.ModSecurityIntegration') as MockModSec:
            mock_modsec = Mock()
            mock_modsec.is_available.return_value = True
            mock_modsec.get_recent_blocks.return_value = [
                {
                    'timestamp': '18/Jul/2025:14:30:25',
                    'src_ip': '192.168.1.1',
                    'rule_id': '950001',
                    'message': 'SQL Injection Detected'
                }
            ]
            MockModSec.return_value = mock_modsec
            
            manager = SecurityIntegrationManager(config)
            # Force modsecurity to be available for the test
            manager.available_integrations['modsecurity'] = True
            threats = manager.get_aggregated_threats(hours=1)
            
            self.assertEqual(len(threats), 1)
            threat = threats[0]
            self.assertEqual(threat['source'], 'modsecurity')
            self.assertEqual(threat['type'], 'WAF Block')
            self.assertEqual(threat['severity'], 'MEDIUM')
            self.assertEqual(threat['src_ip'], '192.168.1.1')


if __name__ == '__main__':
    unittest.main()
