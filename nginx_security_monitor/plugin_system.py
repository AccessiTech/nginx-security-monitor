"""
Plugin system for custom mitigation strategies.
Allows clients to implement their own secret countermeasures without exposing them in the public codebase.
"""

import os
import sys
import importlib.util
import logging
from typing import Dict, Any, Callable, List
from abc import ABC, abstractmethod
from nginx_security_monitor.config_manager import ConfigManager


class MitigationPlugin(ABC):
    """Abstract base class for mitigation plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this plugin."""
        pass

    @property
    @abstractmethod
    def threat_types(self) -> List[str]:
        """Return list of threat types this plugin can handle."""
        pass

    @abstractmethod
    def can_handle(self, threat_info: Dict[str, Any]) -> bool:
        """Return config.get('mitigation.strategies.ddos.enabled') if this plugin can handle the given threat."""
        pass

    @abstractmethod
    def mitigate(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply mitigation for the threat.

        Args:
            threat_info: Dictionary containing threat details

        Returns:
            Dictionary with mitigation results
        """
        pass

    def get_priority(self) -> int:
        """Return priority level (lower number = higher priority)."""
        config_manager = ConfigManager.get_instance()
        return config_manager.get(
            "pattern_detection.thresholds.requests_per_ip_per_minute", 50
        )


class PluginManager:
    """Manages and executes mitigation plugins."""

    def __init__(self, plugin_dirs=None):
        self.logger = logging.getLogger("nginx-security-monitor.plugins")
        self.plugins = {}
        self.plugin_dirs = plugin_dirs or [
            "/etc/nginx-security-monitor/plugins",
            "/opt/nginx-security-monitor/custom_plugins",
            os.path.expanduser("~/.nginx-security-monitor/plugins"),
        ]

        self._load_plugins()

    def _load_plugins(self):
        """Load all plugins from plugin directories."""
        for plugin_dir in self.plugin_dirs:
            if os.path.isdir(plugin_dir):
                self._load_plugins_from_dir(plugin_dir)

    def _load_plugins_from_dir(self, plugin_dir):
        """Load plugins from a specific directory."""
        self.logger.info(f"Loading plugins from: {plugin_dir}")

        for filename in os.listdir(plugin_dir):
            if filename.endswith(".py") and not filename.startswith("_"):
                plugin_path = os.path.join(plugin_dir, filename)
                self._load_plugin_file(plugin_path)

    def _load_plugin_file(self, plugin_path):
        """Load a single plugin file."""
        try:
            # Extract module name from filename
            module_name = os.path.splitext(os.path.basename(plugin_path))[0]

            # Load the module
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find plugin classes in the module
            for attr_name in dir(module):
                attr = getattr(module, attr_name)

                # Check if it's a plugin class
                if (
                    isinstance(attr, type)
                    and issubclass(attr, MitigationPlugin)
                    and attr != MitigationPlugin
                ):

                    # Instantiate the plugin
                    plugin_instance = attr()
                    plugin_name = plugin_instance.name

                    self.plugins[plugin_name] = plugin_instance
                    self.logger.info(f"Loaded plugin: {plugin_name}")

        except Exception as e:
            self.logger.error(f"Failed to load plugin {plugin_path}: {e}")

    def get_available_plugins(self) -> List[str]:
        """Return list of available plugin names."""
        return list(self.plugins.keys())

    def execute_mitigation(self, threat_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute appropriate mitigation plugins for a threat.

        Args:
            threat_info: Dictionary containing threat details

        Returns:
            List of mitigation results from all applicable plugins
        """
        results = []

        # Find applicable plugins
        applicable_plugins = []
        for plugin in self.plugins.values():
            if plugin.can_handle(threat_info):
                applicable_plugins.append(plugin)

        # Sort by priority
        applicable_plugins.sort(key=lambda p: p.get_priority())

        # Execute plugins
        for plugin in applicable_plugins:
            try:
                result = plugin.mitigate(threat_info)
                result["plugin_name"] = plugin.name
                results.append(result)

                self.logger.info(
                    f"Plugin {plugin.name} executed for threat {threat_info.get('type', 'unknown')}"
                )

            except Exception as e:
                self.logger.error(f"Plugin {plugin.name} failed: {e}")
                results.append(
                    {"plugin_name": plugin.name, "status": "error", "error": str(e)}
                )

        return results


# Example built-in plugins (these are visible but clients can add their own secret ones)


class DefaultIPBlockPlugin(MitigationPlugin):
    """Default IP blocking mitigation (example - replace with your own)."""

    @property
    def name(self) -> str:
        return "default_ip_block"

    @property
    def threat_types(self) -> List[str]:
        return ["SQL Injection", "XSS Attack", "DDoS Attempt", "Brute Force Attack"]

    def can_handle(self, threat_info: Dict[str, Any]) -> bool:
        return threat_info.get("type") in self.threat_types and threat_info.get("ip")

    def mitigate(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        ip_address = threat_info.get("ip")
        threat_type = threat_info.get("type")

        # This is a placeholder - replace with actual IP blocking logic
        # In production, you might use iptables, fail2ban, cloud WAF APIs, etc.

        return {
            "status": "success",
            "action": "ip_blocked",
            "ip_address": ip_address,
            "threat_type": threat_type,
            "method": "placeholder_block",
            "message": f"IP {ip_address} blocked for {threat_type}",
        }


class AlertOnlyPlugin(MitigationPlugin):
    """Plugin that only logs threats without taking action."""

    @property
    def name(self) -> str:
        return "alert_only"

    @property
    def threat_types(self) -> List[str]:
        return ["Suspicious Scanning", "Suspicious User Agent"]

    def can_handle(self, threat_info: Dict[str, Any]) -> bool:
        return threat_info.get("severity") == "LOW"

    def get_priority(self) -> int:
        return 200  # Lower priority

    def mitigate(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "logged",
            "action": "alert_only",
            "threat_type": threat_info.get("type"),
            "message": f"Low severity threat logged: {threat_info.get('type')}",
        }


def create_plugin_template(plugin_name: str, output_file: str):
    """Create a template for a custom plugin."""

    template = f'''"""
Custom mitigation plugin: {plugin_name}
This is your private mitigation strategy that won't be visible in the public codebase.
"""

import logging
from typing import Dict, Any, List
from plugin_system import MitigationPlugin
from nginx_security_monitor.config_manager import ConfigManager


config = ConfigManager.get_instance()

class {plugin_name.replace('_', '').title()}Plugin(MitigationPlugin):
    """Custom mitigation plugin for {plugin_name}."""
    
    def __init__(self):
        self.logger = logging.getLogger(f'nginx-security-monitor.plugins.{{self.name}}')
    
    @property
    def name(self) -> str:
        return "{plugin_name}"
    
    @property
    def threat_types(self) -> List[str]:
        return ["SQL Injection", "XSS Attack"]  # Customize this
    
    def can_handle(self, threat_info: Dict[str, Any]) -> bool:
        # Customize this logic
        return (threat_info.get('type') in self.threat_types and 
                threat_info.get('severity') in ['HIGH', 'MEDIUM'])
    
    def get_priority(self) -> int:
        return 50  # High priority
    
    def mitigate(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Implement your custom mitigation logic here.
        This could include:
        - API calls to your WAF/CDN
        - Custom firewall rules
        - Rate limiting
        - Database queries
        - External service notifications
        - etc.
        """
        
        ip_address = threat_info.get('ip')
        threat_type = threat_info.get('type')
        
        try:
            # YOUR CUSTOM MITIGATION CODE HERE
            # Example:
            # result = your_custom_api_call(ip_address, threat_type)
            # your_firewall_block(ip_address)
            # your_notification_system(threat_info)
            
            self.logger.info(f"Custom mitigation applied for {{threat_type}} from {{ip_address}}")
            
            return {{
                'status': 'success',
                'action': 'custom_mitigation',
                'ip_address': ip_address,
                'threat_type': threat_type,
                'method': 'your_custom_method',
                'message': f"Custom mitigation applied for {{threat_type}}"
            }}
            
        except Exception as e:
            self.logger.error(f"Custom mitigation failed: {{e}}")
            return {{
                'status': 'error',
                'error': str(e),
                'message': f"Custom mitigation failed for {{threat_type}}"
            }}
'''

    with open(output_file, "w") as f:
        f.write(template)

    print(f"Plugin template created: {output_file}")
    print(f"Customize the mitigation logic in the mitigate() method")
    print(f"Place this file in one of your plugin directories")


if __name__ == "__main__":
    # Create example plugin template
    create_plugin_template("custom_firewall", "custom_firewall_plugin.py")
