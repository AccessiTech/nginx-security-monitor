"""
Network Security and Access Control for NGINX Security Monitor
Implements network-level protection and access controls.
"""

import os
import re
import time
import socket
import ipaddress
import subprocess
import logging
import sys
import grp
import pwd

try:
    from importlib.metadata import distributions
except ImportError:
    # Fallback for Python < 3.8
    from importlib_metadata import distributions
from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Lock
from nginx_security_monitor.config_manager import ConfigManager


config = ConfigManager.get_instance()


class NetworkSecurity:
    """Implements network security controls for the service."""

    def __init__(self, config=None):
        self.logger = logging.getLogger("nginx-security-monitor.network")
        self.config = config or {}
        self.config_manager = ConfigManager.get_instance()

        # IP-based access control
        self.allowed_ips = set()
        self.blocked_ips = set()
        self.ip_attempt_counts = defaultdict(lambda: deque())
        self.ip_lock = Lock()

        # Load configuration
        self._load_network_config()

    def _load_network_config(self):
        """Load network security configuration."""
        # Load allowed IPs from config or config manager
        allowed_ips = self.config.get("network_security", {}).get(
            "allowed_ips"
        ) or self.config_manager.get(
            "network_security.allowed_ips", ["127.0.0.1", "::1"]
        )

        for ip in allowed_ips:
            try:
                self.allowed_ips.add(ipaddress.ip_address(ip))
            except ValueError:
                self.logger.warning(f"Invalid IP address in config: {ip}")

        # Load service binding configuration
        self.allowed_interfaces = self.config_manager.get(
            "network_security.allowed_interfaces", ["127.0.0.1", "localhost"]
        )

        # Load access control settings
        self.trust_private_ips = self.config_manager.get(
            "network_security.trust_private_ips", True
        )
        self.trust_loopback = self.config_manager.get(
            "network_security.trust_loopback", True
        )

        # Load rate limiting settings
        self.tracking_window_hours = self.config_manager.get(
            "network_security.tracking_window_hours", 1
        )
        self.max_failed_attempts = self.config_manager.get(
            "network_security.max_failed_attempts", 10
        )
        self.max_total_attempts = self.config_manager.get(
            "network_security.max_total_attempts", 100
        )

        self.logger.info(
            f"Network security initialized: {len(self.allowed_ips)} allowed IPs, "
            f"{len(self.allowed_interfaces)} allowed interfaces"
        )

    def check_ip_access(self, ip_address):
        """Check if an IP address is allowed to access the service."""
        try:
            ip = ipaddress.ip_address(ip_address)

            # Check if explicitly blocked
            if ip in self.blocked_ips:
                return False

            # Check if explicitly allowed
            if ip in self.allowed_ips:
                return True

            # Check private/local address access based on configuration
            if (ip.is_private and self.trust_private_ips) or (
                ip.is_loopback and self.trust_loopback
            ):
                return True

            # Public IPs require explicit permission
            return False

        except ValueError:
            self.logger.warning(f"Invalid IP address: {ip_address}")
            return False

    def track_access_attempt(self, ip_address, success=True):
        """Track access attempts for rate limiting and monitoring."""
        with self.ip_lock:
            now = datetime.now()
            attempts = self.ip_attempt_counts[ip_address]

            # Add current attempt
            attempts.append((now, success))

            # Clean old attempts based on configured window
            cutoff = now - timedelta(hours=self.tracking_window_hours)
            while attempts and attempts[0][0] < cutoff:
                attempts.popleft()

            # Check for suspicious patterns
            failed_attempts = sum(1 for _, success in attempts if not success)
            total_attempts = len(attempts)

            # Block IP if too many failures
            if failed_attempts > self.max_failed_attempts:
                self.block_ip(
                    ip_address, f"Too many failed attempts: {failed_attempts}"
                )
                return False

            # Rate limit if too many attempts
            if total_attempts > self.max_total_attempts:
                self.logger.warning(
                    f"High access frequency from {ip_address}: {total_attempts} attempts"
                )
                return False

            return True

    def block_ip(self, ip_address, reason="Security violation"):
        """Block an IP address using iptables (if available)."""
        try:
            ip = ipaddress.ip_address(ip_address)
            self.blocked_ips.add(ip)

            self.logger.warning(f"Blocking IP {ip_address}: {reason}")

            # Try to add iptables rule (requires root privileges)
            try:
                cmd = [
                    "iptables",
                    "-A",
                    "INPUT",
                    "-s",
                    str(ip_address),
                    "-j",
                    "DROP",
                    "-m",
                    "comment",
                    "--comment",
                    f"nginx-monitor-block-{int(time.time())}",
                ]

                result = subprocess.run(cmd, capture_output=True, timeout=10)
                if result.returncode == 0:
                    self.logger.info(
                        f"Successfully added iptables rule for {ip_address}"
                    )
                else:
                    self.logger.warning(
                        f"Failed to add iptables rule: {result.stderr.decode()}"
                    )

            except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
                self.logger.warning(f"Cannot use iptables: {e}")

        except ValueError:
            self.logger.error(f"Invalid IP address for blocking: {ip_address}")

    def check_port_security(self):
        """Check for unauthorized network services."""
        threats = []

        try:
            # Get list of listening ports (both IPv4 and IPv6)
            netstat_cmd = ["netstat", "-tlnp"]
            result = subprocess.run(
                netstat_cmd, capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines[2:]:  # Skip header lines
                    if not line.strip():
                        continue

                    parts = line.split()
                    if len(parts) >= 4:
                        protocol = parts[0]
                        local_address = parts[3]

                        # Parse address and port
                        if ":" in local_address:
                            # Handle IPv6 addresses which contain multiple colons
                            if "[" in local_address:  # IPv6
                                addr_end = local_address.rindex("]")
                                addr = local_address[
                                    : addr_end + 1
                                ]  # Include the brackets
                                port = local_address[
                                    addr_end + 2 :
                                ]  # Skip the ']:' part
                            else:  # IPv4
                                addr, port = local_address.rsplit(":", 1)

                            # Check for unexpected listening services on non-localhost addresses
                            safe_loopback = {
                                "127.0.0.1",
                                "[::1]",
                            }  # Localhost addresses
                            safe_any = {
                                "0.0.0.0",
                                "[::0]",
                                "[::]::",
                                "::",
                                "[::]",
                            }  # Any address

                            # Report services that aren't expected,
                            # except for well-known services like HTTP(S) and SSH on any/loopback
                            if not self._is_expected_service(port):
                                # Skip common services on loopback/any
                                if addr in safe_any or addr in safe_loopback:
                                    if port in {
                                        "80",
                                        "443",
                                        "22",
                                    }:  # Common web and SSH ports
                                        continue
                                threats.append(
                                    {
                                        "type": "Unexpected Network Service",
                                        "severity": "MEDIUM",
                                        "description": f"Unexpected service listening on {local_address}",
                                        "protocol": protocol,
                                        "address": addr,
                                        "port": port,
                                    }
                                )

        except Exception as e:
            self.logger.error(f"Port security check failed: {e}")

        return threats

    def _is_expected_service(self, port):
        """Check if a service on a port is expected."""
        # Get expected ports from config or use default secure ports
        default_ports = {
            "22",
            "80",
            "443",
            "25",
            "587",
            "993",
            "995",
        }  # SSH, HTTP(S), Mail
        expected_ports = set(
            str(p)
            for p in (
                self.config.get("network", {}).get("expected_ports", [])
                or self.config.get("network_security", {}).get("allowed_ports", [])
                or default_ports
            )
        )

        return port in expected_ports

    def monitor_dns_queries(self):
        """Monitor for suspicious DNS queries that might indicate compromise."""
        threats = []

        try:
            # Check recent DNS queries in system logs
            dns_log_cmd = ["grep", "-i", "dns", "/var/log/syslog"]
            result = subprocess.run(
                dns_log_cmd, capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                lines = result.stdout.split("\n")

                # Look for suspicious domains
                suspicious_patterns = [
                    r"\.bit\b",  # Namecoin domains
                    r"\.onion\b",  # Tor domains
                    r"\d+\.\d+\.\d+\.\d+\.in-addr\.arpa",  # Reverse DNS lookups
                    r"[a-f0-9]{32,}",  # Long hex strings (possible C2)
                ]

                for line in lines[-100:]:  # Check last 100 lines
                    for pattern in suspicious_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            threats.append(
                                {
                                    "type": "Suspicious DNS Query",
                                    "severity": "LOW",
                                    "description": f"Suspicious DNS pattern detected",
                                    "log_line": line.strip(),
                                    "pattern": pattern,
                                }
                            )

        except Exception as e:
            self.logger.debug(f"DNS monitoring failed: {e}")

        return threats

    def check_firewall_status(self):
        """Check if firewall is properly configured."""
        threats = []

        try:
            # Check iptables status
            iptables_cmd = ["iptables", "-L", "-n"]
            result = subprocess.run(
                iptables_cmd, capture_output=True, text=True, timeout=10
            )

            if result.returncode == 0:
                output = result.stdout

                # Check if default policies are secure
                if "policy ACCEPT" in output:
                    # Look for overly permissive rules
                    lines = output.split("\n")
                    for line in lines:
                        if "ACCEPT" in line and "anywhere" in line.lower():
                            threats.append(
                                {
                                    "type": "Permissive Firewall Rule",
                                    "severity": "MEDIUM",
                                    "description": "Overly permissive firewall rule detected",
                                    "rule": line.strip(),
                                }
                            )

                # Check if our blocking rules are in place
                our_rules = [
                    line for line in output.split("\n") if "nginx-monitor-block" in line
                ]

                self.logger.debug(
                    f"Found {len(our_rules)} nginx-monitor firewall rules"
                )

            else:
                threats.append(
                    {
                        "type": "Firewall Check Failed",
                        "severity": "HIGH",
                        "description": "Unable to check firewall status",
                        "error": result.stderr.decode(),
                    }
                )

        except Exception as e:
            self.logger.warning(f"Firewall check failed: {e}")

        return threats

    def validate_tls_configuration(self):
        """Validate TLS/SSL configuration for secure communications."""
        threats = []

        try:
            # Check if the service is using secure protocols
            email_config = self.config.get("email_service", {})

            if email_config.get("enabled"):
                smtp_server = email_config.get("smtp_server")
                smtp_port = email_config.get("smtp_port", 587)
                use_tls = email_config.get("use_tls", True)

                if not use_tls:
                    threats.append(
                        {
                            "type": "Insecure Email Configuration",
                            "severity": "MEDIUM",
                            "description": "Email service not configured to use TLS",
                            "smtp_server": smtp_server,
                            "smtp_port": smtp_port,
                        }
                    )

                # Check for weak ports
                if smtp_port == 25:  # Unencrypted SMTP
                    threats.append(
                        {
                            "type": "Insecure SMTP Port",
                            "severity": "MEDIUM",
                            "description": "Using unencrypted SMTP port 25",
                            "smtp_server": smtp_server,
                        }
                    )

        except Exception as e:
            self.logger.error(f"TLS validation failed: {e}")

        return threats

    def perform_network_security_check(self):
        """Perform comprehensive network security check."""
        all_threats = []

        try:
            # Port security
            all_threats.extend(self.check_port_security())

            # Firewall status
            all_threats.extend(self.check_firewall_status())

            # DNS monitoring
            all_threats.extend(self.monitor_dns_queries())

            # TLS configuration
            all_threats.extend(self.validate_tls_configuration())

            if all_threats:
                self.logger.warning(
                    f"Network security check found {len(all_threats)} issues"
                )

        except Exception as e:
            self.logger.error(f"Network security check failed: {e}")

        return all_threats


class SecurityHardening:
    """Implements additional security hardening measures including:
    - File permissions and ownership checks
    - Environment variable security validation
    - Module security auditing
    - Package version vulnerability checks
    - Runtime security monitoring
    """

    def __init__(self, config=None):
        self.logger = logging.getLogger("nginx-security-monitor.hardening")
        self.config = config or {}
        self.config_manager = ConfigManager.get_instance()

        # Load security configuration
        self._load_security_config()

    def _load_security_config(self):
        """Load security hardening configuration."""
        # Load critical file permissions
        self.critical_files = self.config_manager.get(
            "security.critical_files",
            {
                "/etc/nginx-security-monitor/settings.yaml": {
                    "mode": 0o640,
                    "owner": "root",
                    "group": "nginx",
                },
                "/etc/nginx-security-monitor/.salt": {
                    "mode": 0o600,
                    "owner": "root",
                    "group": "root",
                },
                "/opt/nginx-security-monitor/src/": {
                    "mode": 0o755,
                    "owner": "root",
                    "group": "root",
                },
                "/var/log/nginx-security-monitor.log": {
                    "mode": 0o640,
                    "owner": "nginx",
                    "group": "nginx",
                },
            },
        )

        # Load sensitive environment variables to check
        self.sensitive_env_vars = self.config_manager.get(
            "security.sensitive_env_vars",
            [
                "NGINX_MONITOR_KEY",
                "SMTP_PASSWORD",
                "API_KEY",
                "DB_PASSWORD",
                "SECRET_KEY",
            ],
        )

        # Load security thresholds
        self.min_password_length = self.config_manager.get(
            "security.min_password_length", 16
        )
        self.unsafe_file_modes = self.config_manager.get(
            "security.unsafe_file_modes", [0o777, 0o666, 0o777]
        )

        self.logger.info(
            f"Security hardening initialized: monitoring {len(self.critical_files)} files "
            f"and {len(self.sensitive_env_vars)} environment variables"
        )

    def check_file_permissions(self):
        """Check critical file permissions and ownership."""
        threats = []

        for file_path, requirements in self.critical_files.items():
            try:
                if os.path.exists(file_path):
                    stat_info = os.stat(file_path)
                    actual_mode = stat_info.st_mode & 0o777

                    # Check file permissions
                    expected_mode = requirements.get("mode", 0o644)
                    if actual_mode != expected_mode:
                        threats.append(
                            {
                                "type": "Incorrect File Permissions",
                                "severity": "MEDIUM",
                                "description": f"File has incorrect permissions: {file_path}",
                                "file": file_path,
                                "expected": oct(expected_mode),
                                "actual": oct(actual_mode),
                            }
                        )

                    # Check for unsafe permissions
                    if actual_mode in self.unsafe_file_modes:
                        threats.append(
                            {
                                "type": "Unsafe File Permissions",
                                "severity": "HIGH",
                                "description": f"File has unsafe permissions (world-writable): {file_path}",
                                "file": file_path,
                                "mode": oct(actual_mode),
                            }
                        )

                    # Check ownership if running as root
                    if os.geteuid() == 0:  # Only check if we have permission
                        import pwd
                        import grp

                        # Get actual owner/group
                        actual_owner = pwd.getpwuid(stat_info.st_uid).pw_name
                        actual_group = grp.getgrgid(stat_info.st_gid).gr_name

                        # Check owner
                        expected_owner = requirements.get("owner")
                        if expected_owner and actual_owner != expected_owner:
                            threats.append(
                                {
                                    "type": "Incorrect File Owner",
                                    "severity": "MEDIUM",
                                    "description": f"File has incorrect owner: {file_path}",
                                    "file": file_path,
                                    "expected": expected_owner,
                                    "actual": actual_owner,
                                }
                            )

                        # Check group
                        expected_group = requirements.get("group")
                        if expected_group and actual_group != expected_group:
                            threats.append(
                                {
                                    "type": "Incorrect File Group",
                                    "severity": "MEDIUM",
                                    "description": f"File has incorrect group: {file_path}",
                                    "file": file_path,
                                    "expected": expected_group,
                                    "actual": actual_group,
                                }
                            )
                else:
                    self.logger.warning(
                        f"Critical security file not found: {file_path}"
                    )

            except Exception as e:
                self.logger.error(f"Permission check failed for {file_path}: {e}")

        return threats

    def check_environment_security(self):
        """Check environment for security issues."""
        threats = []

        # Load weak/default values from config
        weak_values = self.config_manager.get(
            "security.weak_values",
            [
                "test",
                "default",
                "password",
                "123456",
                "admin",
                "secret",
                "changeme",
                "letmein",
                "please",
            ],
        )

        # Check for missing or insecure environment variables
        for var in self.sensitive_env_vars:
            if var not in os.environ:
                threats.append(
                    {
                        "type": "Missing Environment Variable",
                        "severity": "HIGH",
                        "description": f"Required environment variable {var} is not set",
                        "variable": var,
                    }
                )
                continue

            value = os.environ[var]

            # Check for weak values
            if len(value) < self.min_password_length:
                threats.append(
                    {
                        "type": "Weak Environment Variable",
                        "severity": "HIGH",
                        "description": f"Environment variable {var} appears to be weak (too short)",
                        "variable": var,
                        "min_length": self.min_password_length,
                    }
                )

            # Check for default/test values
            if value.lower() in weak_values:
                threats.append(
                    {
                        "type": "Default Environment Variable",
                        "severity": "CRITICAL",
                        "description": f"Environment variable {var} uses default/weak value",
                        "variable": var,
                    }
                )

            # Check for environment variable value strength
            if (
                not any(c.isupper() for c in value)
                or not any(c.islower() for c in value)
                or not any(c.isdigit() for c in value)
                or not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?~" for c in value)
            ):
                threats.append(
                    {
                        "type": "Weak Environment Variable",
                        "severity": "MEDIUM",
                        "description": f"Environment variable {var} does not meet complexity requirements",
                        "variable": var,
                        "requirements": "Must contain uppercase, lowercase, numbers, and special characters",
                    }
                )

        return threats

    def check_module_security(self):
        """Check for vulnerable packages and unsafe module usage."""
        threats = []

        # Check for vulnerable packages
        try:
            installed_packages = distributions()
            vulnerable_packages = self.config_manager.get(
                "security.vulnerable_packages",
                {
                    "cryptography": ["2.9.0", "2.8.0", "2.7.0"],
                    "requests": ["2.19.0", "2.18.0"],
                    "urllib3": ["1.24.0", "1.23.0"],
                },
            )

            for package in installed_packages:
                package_name = package.metadata["Name"].lower()
                package_version = package.version

                if package_name in vulnerable_packages:
                    if package_version in vulnerable_packages[package_name]:
                        threats.append(
                            {
                                "type": "Vulnerable Package",
                                "severity": "HIGH",
                                "description": f"Vulnerable package version detected: {package_name} {package_version}",
                                "package": package_name,
                                "version": package_version,
                                "recommended_action": "Update to latest version",
                            }
                        )

        except Exception as e:
            self.logger.error(f"Package vulnerability check failed: {e}")

        # Check for unsafe module usage
        try:
            unsafe_attributes = self.config_manager.get(
                "security.unsafe_attributes", ["system", "exec", "eval", "compile"]
            )

            for module_name, module in sys.modules.items():
                if module and hasattr(module, "__file__"):
                    module_file = getattr(module, "__file__", "")
                    # Only check modules not in site-packages (user modules)
                    if module_file and "site-packages" not in module_file:
                        for attr in unsafe_attributes:
                            if hasattr(module, attr):
                                threats.append(
                                    {
                                        "type": "Unsafe Module Usage",
                                        "severity": "MEDIUM",
                                        "description": f"Module {module_name} has unsafe attribute: {attr}",
                                        "module": module_name,
                                        "attribute": attr,
                                        "file": module_file,
                                    }
                                )

        except Exception as e:
            self.logger.error(f"Module security check failed: {e}")

        return threats

    def perform_security_audit(self):
        """Perform comprehensive security audit."""
        self.logger.info("Starting comprehensive security audit")
        all_threats = []

        # Collect threats from all security checks
        try:
            file_threats = self.check_file_permissions()
            all_threats.extend(file_threats)
            self.logger.info(
                f"File permission check: {len(file_threats)} threats found"
            )
        except Exception as e:
            self.logger.error(f"File permission check failed: {e}")

        try:
            env_threats = self.check_environment_security()
            all_threats.extend(env_threats)
            self.logger.info(
                f"Environment security check: {len(env_threats)} threats found"
            )
        except Exception as e:
            self.logger.error(f"Environment security check failed: {e}")

        try:
            module_threats = self.check_module_security()
            all_threats.extend(module_threats)
            self.logger.info(
                f"Module security check: {len(module_threats)} threats found"
            )
        except Exception as e:
            self.logger.error(f"Module security check failed: {e}")

        # Sort threats by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_threats.sort(key=lambda x: severity_order.get(x.get("severity", "LOW"), 3))

        self.logger.info(
            f"Security audit completed: {len(all_threats)} total threats found"
        )
        return all_threats

        return threats
