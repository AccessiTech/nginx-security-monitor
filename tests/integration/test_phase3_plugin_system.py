#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phase 3.1 Integration Tests: Plugin System Integration
Focus: Integration between plugin_system and all core components
"""

import unittest
import os
import importlib.util
import sys
from unittest.mock import patch, MagicMock
from tests.integration.test_framework import BaseIntegrationTest


class TestPluginSystemIntegration(BaseIntegrationTest):
    """Test integration between plugin_system and all core components"""
    
    def setUp(self):
        """Set up test environment for plugin system tests."""
        super().setUp()
        
        # Create a plugins directory for testing
        self.plugins_dir = os.path.join(self.test_data_dir, "plugins")
        os.makedirs(self.plugins_dir, exist_ok=True)
        
        # Create a test plugin file
        self.custom_threat_plugin_path = os.path.join(self.plugins_dir, "custom_threat_detector.py")
        with open(self.custom_threat_plugin_path, 'w') as f:
            f.write("""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class CustomThreatDetector:
    \"\"\"Custom threat detection plugin for NGINX Security Monitor.\"\"\"
    
    def __init__(self):
        self.name = "custom_threat_detector"
        self.version = "1.0.0"
        self.description = "Detects custom threat patterns"
        self.enabled = True
    
    def initialize(self, config=None):
        \"\"\"Initialize the plugin with configuration.\"\"\"
        self.config = config or {}
        return True
    
    def detect_threat(self, log_data):
        \"\"\"Detect threats in log data.\"\"\"
        if not log_data or not isinstance(log_data, dict):
            return None
        
        # Check for specific pattern that indicates a custom threat
        if 'path' in log_data and '/admin/backdoor' in log_data['path']:
            return {
                'type': 'custom_backdoor_access',
                'confidence': 0.95,
                'severity': 'critical',
                'source_ip': log_data.get('client_ip', 'unknown'),
                'details': {
                    'path': log_data.get('path', ''),
                    'method': log_data.get('method', ''),
                    'timestamp': log_data.get('timestamp', '')
                }
            }
        
        return None
    
    def shutdown(self):
        \"\"\"Clean up resources when shutting down.\"\"\"
        pass
""")
        
        # Create a test alert plugin
        self.custom_alert_plugin_path = os.path.join(self.plugins_dir, "slack_alert.py")
        with open(self.custom_alert_plugin_path, 'w') as f:
            f.write("""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class SlackAlertChannel:
    \"\"\"Slack alert channel plugin for NGINX Security Monitor.\"\"\"
    
    def __init__(self):
        self.name = "slack_alert"
        self.version = "1.0.0"
        self.description = "Sends alerts to Slack channels"
        self.enabled = True
    
    def initialize(self, config=None):
        \"\"\"Initialize the plugin with configuration.\"\"\"
        self.config = config or {}
        self.webhook_url = self.config.get('webhook_url', '')
        self.default_channel = self.config.get('default_channel', '#security-alerts')
        return bool(self.webhook_url)
    
    def send(self, alert_data):
        \"\"\"Send an alert to Slack.\"\"\"
        if not alert_data:
            return False
        
        # In a real implementation, this would use requests to post to Slack
        print(f"[SLACK ALERT] Sending to {self.default_channel}: {alert_data['message']}")
        
        return {
            'success': True,
            'channel': self.default_channel,
            'timestamp': alert_data.get('timestamp', '')
        }
    
    def shutdown(self):
        \"\"\"Clean up resources when shutting down.\"\"\"
        pass
""")
    
    def test_plugin_threat_detection_integration(self):
        """Test custom threat detection plugins"""
        print("\n🔌 Testing plugin threat detection integration...")
        
        # Get components
        plugin_system = self.components['plugin_system']
        threat_processor = self.components['threat_processor']
        
        # Set up plugin system
        plugin_system.set_plugins_directory(self.plugins_dir)
        
        # Load the custom threat detection plugin
        loaded_plugins = plugin_system.discover_and_load_plugins(plugin_type="threat_detector")
        
        # Verify plugin was loaded
        self.assertGreaterEqual(len(loaded_plugins), 1)
        self.assertIn("custom_threat_detector", loaded_plugins)
        
        # Connect plugin system to threat processor
        threat_processor.set_plugin_system(plugin_system)
        
        # Create test log data with the custom threat pattern
        test_log_data = {
            'client_ip': '192.168.1.50',
            'timestamp': '2023-12-25T15:00:00Z',
            'method': 'GET',
            'path': '/admin/backdoor',
            'status': 200,
            'user_agent': 'BadAgent/1.0'
        }
        
        # Act: Process the log data that should trigger our custom plugin
        threats = threat_processor.detect_threats_with_plugins([test_log_data])
        
        # Assert: The custom threat should be detected
        self.assertGreaterEqual(len(threats), 1)
        self.assertEqual(threats[0]['type'], 'custom_backdoor_access')
        self.assertEqual(threats[0]['severity'], 'critical')
        self.assertEqual(threats[0]['source_ip'], '192.168.1.50')
    
    def test_plugin_alert_channel_integration(self):
        """Test custom alert channel plugins"""
        print("\n📱 Testing plugin alert channel integration...")
        
        # Get components
        plugin_system = self.components['plugin_system']
        alert_manager = self.components['alert_manager']
        
        # Set up plugin system
        plugin_system.set_plugins_directory(self.plugins_dir)
        
        # Load the custom alert channel plugin
        loaded_plugins = plugin_system.discover_and_load_plugins(plugin_type="alert_channel")
        
        # Verify plugin was loaded
        self.assertGreaterEqual(len(loaded_plugins), 1)
        self.assertIn("slack_alert", loaded_plugins)
        
        # Configure the plugin
        plugin_system.configure_plugin(
            "slack_alert",
            {
                "webhook_url": "https://hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/XXXXXXXX",
                "default_channel": "#security-test"
            }
        )
        
        # Connect plugin system to alert manager
        alert_manager.set_plugin_system(plugin_system)
        
        # Create test alert data
        test_alert = {
            "type": "security_threat",
            "severity": "high",
            "timestamp": "2023-12-25T15:30:00Z",
            "message": "Custom threat detected",
            "details": {
                "source_ip": "192.168.1.50",
                "path": "/admin/backdoor"
            }
        }
        
        # Mock the actual sending to avoid real external calls
        with patch.object(plugin_system, 'execute_plugin_method') as mock_execute:
            mock_execute.return_value = {
                'success': True,
                'channel': '#security-test',
                'timestamp': test_alert['timestamp']
            }
            
            # Act: Send alert through the custom channel
            alert_manager.send_alert(test_alert, channels=["plugin:slack_alert"])
            
            # Assert: The plugin's send method should be called
            mock_execute.assert_called_once()
            self.assertEqual(mock_execute.call_args[0][0], "slack_alert")
            self.assertEqual(mock_execute.call_args[0][1], "send")
    
    def test_plugin_lifecycle_integration(self):
        """Test plugin loading, reloading, and unloading"""
        print("\n🔄 Testing plugin lifecycle integration...")
        
        # Get component
        plugin_system = self.components['plugin_system']
        
        # Set up plugin system
        plugin_system.set_plugins_directory(self.plugins_dir)
        
        # Act: Load all plugins
        loaded_plugins = plugin_system.discover_and_load_plugins()
        initial_count = len(loaded_plugins)
        
        # Assert: Plugins should be loaded
        self.assertGreaterEqual(initial_count, 1)  # At least one plugin should be loaded
        
        # Create a new plugin during runtime
        new_plugin_path = os.path.join(self.plugins_dir, "runtime_plugin.py")
        with open(new_plugin_path, 'w') as f:
            f.write("""
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

class RuntimePlugin:
    \"\"\"Runtime-created plugin for testing.\"\"\"
    
    def __init__(self):
        self.name = "runtime_plugin"
        self.version = "1.0.0"
        self.description = "Created during runtime for testing"
        self.enabled = True
    
    def initialize(self, config=None):
        return True
    
    def process(self, data):
        return {'processed': True, 'original': data}
    
    def shutdown(self):
        pass
""")
        
        # Act: Reload plugins to discover the new one
        plugin_system.discover_and_load_plugins()  # Rediscover to find new plugin
        reloaded_plugins = plugin_system.get_loaded_plugins()
        
        # Assert: New plugin should be loaded
        self.assertEqual(len(reloaded_plugins), initial_count + 1)
        self.assertIn("runtime_plugin", reloaded_plugins)
        
        # Act: Unload a specific plugin
        plugin_system.unload_plugin("runtime_plugin")
        remaining_plugins = plugin_system.get_loaded_plugins()
        
        # Assert: Plugin should be unloaded
        self.assertEqual(len(remaining_plugins), initial_count)
        self.assertNotIn("runtime_plugin", remaining_plugins)


class TestPluginDataFlow(BaseIntegrationTest):
    """Test data flow between plugins and core components"""
    
    def test_plugin_data_transformation(self):
        """Test data transformation across plugin boundaries"""
        print("\n🔄 Testing plugin data transformation...")
        
        # This test would implement checks for data consistency as it flows
        # between core components and plugins, ensuring proper transformation
        # and preservation of important attributes.
        pass


if __name__ == "__main__":
    unittest.main()
