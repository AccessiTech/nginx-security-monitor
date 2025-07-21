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

# Add the src directory to Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
src_dir = os.path.join(script_dir, "src")
sys.path.insert(0, src_dir)

try:
    from security_integrations import SecurityIntegrationManager
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


def check_integrations():
    """Check which security integrations are available."""
    print("🔍 Checking available security integrations...\n")

    config = load_config()
    integrations_config = config.get("security_integrations", {})

    manager = SecurityIntegrationManager(integrations_config)
    status = manager.get_integration_status()

    available = status["available_integrations"]
    details = status.get("integration_details", {})

    print("Security Framework Status:")
    print("=" * 50)

    for name, is_available in available.items():
        status_icon = "✅" if is_available else "❌"
        status_text = "Available" if is_available else "Not available"

        print(f"{status_icon} {name.upper():<15} {status_text}")

        if is_available and name in details:
            detail = details[name]
            if name == "fail2ban":
                jails = detail.get("jails", {})
                banned_count = detail.get("banned_ips_count", 0)
                print(f"   • Active jails: {len(jails)}")
                print(f"   • Banned IPs: {banned_count}")

                if jails:
                    print("   • Jail status:")
                    for jail_name, jail_info in list(jails.items())[
                        :3
                    ]:  # Show first 3 jails
                        currently_banned = jail_info.get("currently_banned", 0)
                        total_failed = jail_info.get("total_failed", 0)
                        print(
                            f"     - {jail_name}: {currently_banned} banned, {total_failed} failed"
                        )

            elif name == "ossec":
                alerts_count = detail.get("recent_alerts_count", 0)
                high_severity = detail.get("high_severity_alerts", 0)
                print(f"   • Recent alerts (1h): {alerts_count}")
                print(f"   • High severity: {high_severity}")

            elif name == "suricata":
                alerts_count = detail.get("recent_alerts_count", 0)
                critical_alerts = detail.get("critical_alerts", 0)
                print(f"   • Recent alerts (1h): {alerts_count}")
                print(f"   • Critical alerts: {critical_alerts}")

            elif name == "modsecurity":
                blocks_count = detail.get("recent_blocks_count", 0)
                print(f"   • Recent blocks (1h): {blocks_count}")

        print()

    # Show overall status
    available_count = sum(available.values())
    total_count = len(available)

    print(f"Summary: {available_count}/{total_count} security frameworks available")

    if available_count == 0:
        print("\n⚠️  No security frameworks detected!")
        print("Consider installing: fail2ban, OSSEC/Wazuh, Suricata, or ModSecurity")
    elif available_count < total_count:
        print(
            f"\n💡 Consider installing additional security tools for better protection"
        )


def test_integrations():
    """Test security integrations functionality."""
    print("🧪 Testing security integrations...\n")

    config = load_config()
    integrations_config = config.get("security_integrations", {})

    manager = SecurityIntegrationManager(integrations_config)

    # Test threat handling
    test_threat = {
        "type": "Test Threat",
        "severity": "MEDIUM",
        "ip": "192.168.1.100",
        "timestamp": "2024-01-19T15:30:00",
        "request": "GET /test HTTP/1.1",
    }

    print("Testing threat handling with integrations:")
    result = manager.handle_threat_with_integrations(test_threat)

    if result["actions_taken"]:
        print("✅ Actions taken:")
        for action in result["actions_taken"]:
            print(f"   • {action}")
    else:
        print("ℹ️  No actions taken (this is expected for a test)")

    print(f"📊 Available integrations: {', '.join(result['integrations_used'])}")

    # Test aggregated threats
    print("\nGetting recent threats from integrations...")
    threats = manager.get_aggregated_threats(hours=1)

    if threats:
        print(f"🔍 Found {len(threats)} recent threats:")

        # Group by source
        threats_by_source = {}
        for threat in threats:
            source = threat.get("source", "unknown")
            if source not in threats_by_source:
                threats_by_source[source] = []
            threats_by_source[source].append(threat)

        for source, source_threats in threats_by_source.items():
            print(f"\n   {source.upper()} ({len(source_threats)} threats):")
            for threat in source_threats[:3]:  # Show first 3
                severity = threat.get("severity", "UNKNOWN")
                description = threat.get("description", "No description")
                print(f"     • [{severity}] {description}")

            if len(source_threats) > 3:
                print(f"     ... and {len(source_threats) - 3} more")
    else:
        print("ℹ️  No recent threats found (this is good!)")


def setup_fail2ban():
    """Help set up fail2ban integration."""
    print("🔧 Setting up fail2ban integration...\n")

    # Check if fail2ban is installed
    try:
        result = subprocess.run(
            ["fail2ban-client", "--version"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            print("✅ fail2ban is installed")
            print(f"   Version: {result.stdout.strip()}")
        else:
            print("❌ fail2ban is not working properly")
            return
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("❌ fail2ban is not installed")
        print("\nTo install fail2ban:")
        print("  Ubuntu/Debian: sudo apt-get install fail2ban")
        print("  CentOS/RHEL:   sudo yum install fail2ban")
        print("  Fedora:        sudo dnf install fail2ban")
        return

    # Check jail configuration
    jail_files = ["/etc/fail2ban/jail.local", "/etc/fail2ban/jail.conf"]

    print("\nChecking jail configuration:")
    for jail_file in jail_files:
        if os.path.exists(jail_file):
            print(f"✅ Found: {jail_file}")
        else:
            print(f"❌ Missing: {jail_file}")

    # Suggest NGINX-specific jails
    nginx_jails = [
        "nginx-http-auth",
        "nginx-noscript",
        "nginx-badbots",
        "nginx-noproxy",
    ]

    print(f"\nRecommended NGINX jails to enable:")
    for jail in nginx_jails:
        print(f"  • {jail}")

    # Check if jails are enabled
    try:
        result = subprocess.run(
            ["fail2ban-client", "status"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            active_jails = []
            for line in result.stdout.split("\n"):
                if "Jail list:" in line:
                    jail_list = line.split("Jail list:")[1].strip()
                    if jail_list:
                        active_jails = [j.strip() for j in jail_list.split(",")]

            print(f"\nCurrently active jails: {len(active_jails)}")
            if active_jails:
                for jail in active_jails:
                    print(f"  • {jail}")
            else:
                print("  (none)")
    except Exception as e:
        print(f"\nCould not check jail status: {e}")


def setup_ossec():
    """Help set up OSSEC/Wazuh integration."""
    print("🔧 Setting up OSSEC/Wazuh integration...\n")

    ossec_dirs = ["/var/ossec", "/opt/ossec"]
    ossec_found = False

    for ossec_dir in ossec_dirs:
        if os.path.exists(ossec_dir):
            print(f"✅ OSSEC/Wazuh found at: {ossec_dir}")
            ossec_found = True

            # Check control script
            control_script = os.path.join(ossec_dir, "bin", "ossec-control")
            if os.path.exists(control_script):
                print(f"   Control script: {control_script}")

                # Check status
                try:
                    result = subprocess.run(
                        [control_script, "status"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if "running" in result.stdout.lower():
                        print("   Status: ✅ Running")
                    else:
                        print("   Status: ❌ Not running")
                        print("   Try: sudo systemctl start wazuh-agent")
                except Exception as e:
                    print(f"   Could not check status: {e}")

            # Check logs directory
            logs_dir = os.path.join(ossec_dir, "logs")
            if os.path.exists(logs_dir):
                alerts_log = os.path.join(logs_dir, "alerts", "alerts.log")
                if os.path.exists(alerts_log):
                    print(f"   Alerts log: ✅ {alerts_log}")
                else:
                    print(f"   Alerts log: ❌ Not found")

            break

    if not ossec_found:
        print("❌ OSSEC/Wazuh not found")
        print("\nTo install Wazuh agent:")
        print("  1. Visit: https://documentation.wazuh.com/current/installation-guide/")
        print("  2. Follow the installation guide for your OS")
        print("  3. Configure the agent to connect to your Wazuh manager")


def main():
    parser = argparse.ArgumentParser(
        description="Security Integrations Setup and Test Utility"
    )
    parser.add_argument(
        "action",
        choices=["check", "test", "setup-fail2ban", "setup-ossec"],
        help="Action to perform",
    )

    args = parser.parse_args()

    print("🔒 NGINX Security Monitor - Security Integrations Utility")
    print("=" * 60)
    print()

    if args.action == "check":
        check_integrations()
    elif args.action == "test":
        test_integrations()
    elif args.action == "setup-fail2ban":
        setup_fail2ban()
    elif args.action == "setup-ossec":
        setup_ossec()


if __name__ == "__main__":
    main()
