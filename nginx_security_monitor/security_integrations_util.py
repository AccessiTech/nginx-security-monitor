#!/usr/bin/env python3
"""
Security Integrations Setup and Test Utility
Helps configure and test integrations with popular security frameworks.
"""

import os
import sys
import yaml
import argparse
import subprocess
from pathlib import Path


try:
    from nginx_security_monitor.security_integrations import SecurityIntegrationManager
except ImportError as e:
    print(f"Error importing security integrations: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)


def load_config(config_path="/etc/nginx-security-monitor/service-settings.yaml"):
    """Load configuration from YAML file."""
    try:
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                return yaml.safe_load(f)
        else:
            # Try local config
            local_config = os.path.join(
                os.path.dirname(__file__), "config", "service-settings.yaml"
            )
            if os.path.exists(local_config):
                with open(local_config, "r") as f:
                    return yaml.safe_load(f)
            else:
                print(f"Configuration file not found: {config_path}")
                return {}
    except Exception as e:
        print(f"Error loading configuration: {e}")
        return {}


# --- Exposed Utility Functions for Testing ---
def check_integrations():
    """Check and print the status of all security integrations."""
    print("🔍 Checking available security integrations...\n")
    config = load_config()
    manager = SecurityIntegrationManager(config)
    status = manager.get_integration_status()
    print("Security Framework Status:")
    available = status.get("available_integrations", {})
    for integration, is_available in available.items():
        if is_available:
            print(f"✅ {integration} available")
        else:
            print(f"❌ {integration} Not available")
    print(yaml.dump(status, default_flow_style=False))

def setup_fail2ban():
    """Setup or check fail2ban integration."""
    config = load_config()
    manager = SecurityIntegrationManager(config)
    try:
        if manager.fail2ban.is_available():
            # Simulate a status check for 'working' vs 'not working'
            jail_status = manager.fail2ban.get_jail_status()
            if jail_status:
                print("✅ fail2ban is installed")
                print(yaml.dump(jail_status, default_flow_style=False))
            else:
                print("❌ fail2ban is not working properly")
        else:
            print("❌ fail2ban is not installed")
            print("\nTo install fail2ban:")
            print("  sudo apt-get install fail2ban")
    except Exception:
        print("❌ fail2ban is not installed")
        print("\nTo install fail2ban:")
        print("  sudo apt-get install fail2ban")

def setup_ossec():
    """Setup or check OSSEC integration."""
    config = load_config()
    manager = SecurityIntegrationManager(config)
    if manager.ossec.is_available():
        print(f"✅ OSSEC/Wazuh found at: /var/ossec")
        print(yaml.dump(manager.ossec.get_recent_alerts(hours=1), default_flow_style=False))
    else:
        print("❌ OSSEC/Wazuh not found")
        print("\nTo install Wazuh agent:")
        print("  https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html")

def test_integrations():
    """Test integrations by simulating a threat and printing actions taken."""
    config = load_config()
    manager = SecurityIntegrationManager(config)
    # Simulate a test threat
    test_threat = {"ip": "192.0.2.1", "type": "SQL Injection", "severity": "HIGH"}
    result = manager.handle_threat_with_integrations(test_threat)
    if result.get("actions_taken"):
        print("Test Integration Actions:")
        print(yaml.dump(result, default_flow_style=False))
    else:
        print("ℹ️  No actions taken (this is expected for a test)")
    threats = manager.get_aggregated_threats(hours=1)
    if not threats:
        print("ℹ️  No recent threats found (this is good!)")

def main():
    parser = argparse.ArgumentParser(description="Security Integrations Utility")
    parser.add_argument("action", choices=[
        "check-integrations",
        "setup-fail2ban",
        "setup-ossec",
        "test-integrations",
        "test"
    ], help="Action to perform")
    args = parser.parse_args()

    action_map = {
        "check-integrations": "check_integrations",
        "setup-fail2ban": "setup_fail2ban",
        "setup-ossec": "setup_ossec",
        "test-integrations": "test_integrations",
        "test": "test_integrations"
    }
    func_name = action_map.get(args.action)
    if func_name and func_name in globals():
        globals()[func_name]()

if __name__ == "__main__":
    main()
