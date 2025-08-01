"""
Self-Protection Module for NGINX Security Monitor
Implements security measures to protect the monitoring service itself from attacks.
"""

import os
import sys
import time
import hashlib
import psutil
import logging
import subprocess
from pathlib import Path
from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Lock
from nginx_security_monitor.config_manager import ConfigManager


config = ConfigManager.get_instance()


class ServiceProtection:
    """Protects the security monitor service from attacks."""

    def __init__(self, config=None):
        self.logger = logging.getLogger("nginx-security-monitor.protection")
        self.config = config or {}
        self.config_manager = ConfigManager.get_instance()

        # Rate limiting for service operations
        self.operation_counts = defaultdict(lambda: deque())
        self.rate_limit_lock = Lock()

        # File integrity monitoring
        self.file_hashes = {}
        self.protected_files = self.config_manager.get(
            "service_protection.protected_files",
            [
                "/opt/nginx-security-monitor/src/",
                "/etc/nginx-security-monitor/",
                "/etc/systemd/system/nginx-security-monitor.service",
            ],
        )

        # Process monitoring
        self.expected_processes = self.config_manager.get(
            "service_protection.expected_processes", ["monitor_service.py"]
        )
        self.process_baseline = None

        # Resource monitoring
        self.resource_thresholds = self.config_manager.get(
            "service_protection.resource_thresholds",
            {"cpu_percent": 80.0, "memory_percent": 80.0, "disk_usage_percent": 90.0},
        )

        # Initialize protection
        self._initialize_protection()

    def _initialize_protection(self):
        """Initialize protection mechanisms."""
        try:
            self._baseline_file_integrity()
            self._baseline_process_state()
            self._setup_resource_monitoring()
            self.logger.info("Service protection initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize protection: {e}")

    def _baseline_file_integrity(self):
        """Create baseline hashes for critical files."""
        for file_path in self.protected_files:
            if os.path.isfile(file_path):
                self.file_hashes[file_path] = self._calculate_file_hash(file_path)
            elif os.path.isdir(file_path):
                for root, dirs, files in os.walk(file_path):
                    for file in files:
                        if file.endswith((".py", ".yaml", ".yml", ".conf", ".service")):
                            full_path = os.path.join(root, file)
                            self.file_hashes[full_path] = self._calculate_file_hash(
                                full_path
                            )

        self.logger.info(f"Monitoring integrity of {len(self.file_hashes)} files")

    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        try:
            hasher = hashlib.sha256()
            chunk_size = self.config_manager.get(
                "service_protection.hash_chunk_size", 4096
            )
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to hash {file_path}: {e}")
            return None

    def _baseline_process_state(self):
        """Baseline normal process state."""
        try:
            current_process = psutil.Process()
            self.process_baseline = {
                "pid": current_process.pid,
                "ppid": current_process.ppid(),
                "name": current_process.name(),
                "cmdline": current_process.cmdline(),
                "create_time": current_process.create_time(),
            }
        except Exception as e:
            self.logger.error(f"Failed to baseline process state: {e}")

    def _setup_resource_monitoring(self):
        """Setup resource usage monitoring."""
        # Get baseline resource usage
        try:
            monitor_interval = self.config_manager.get(
                "service_protection.monitor_interval_seconds", 1
            )
            disk_path = self.config_manager.get(
                "service_protection.monitor_disk_path", "/"
            )

            self.baseline_cpu = psutil.cpu_percent(interval=monitor_interval)
            self.baseline_memory = psutil.virtual_memory().percent
            self.baseline_disk = psutil.disk_usage(disk_path).percent
        except Exception as e:
            self.logger.error(f"Failed to setup resource monitoring: {e}")

    def check_rate_limiting(self, operation_type, limit_per_minute=None):
        """Check if operation is within rate limits."""
        with self.rate_limit_lock:
            now = datetime.now()
            window_minutes = self.config_manager.get(
                "service_protection.rate_limit_window_minutes", 1
            )
            cutoff = now - timedelta(minutes=window_minutes)

            # Get operation history and limits
            operations = self.operation_counts[operation_type]
            limit = (
                limit_per_minute
                if limit_per_minute is not None
                else self.config_manager.get(
                    f"service_protection.rate_limits.{operation_type}",
                    self.config_manager.get(
                        "service_protection.rate_limits.default", 60
                    ),
                )
            )

            # Handle zero or negative limits - always rate limit
            if limit <= 0:
                return False

            # Remove expired entries
            while operations and operations[0] < cutoff:
                operations.popleft()

            # Check limit
            if len(operations) >= limit:
                return False

            # Add new operation
            operations.append(now)
            return True

    def check_file_integrity(self):
        """Check if monitored files have been tampered with."""
        threats = []

        for file_path, expected_hash in self.file_hashes.items():
            if not os.path.exists(file_path):
                threats.append(
                    {
                        "type": "File Deletion",
                        "file": file_path,
                        "severity": "CRITICAL",
                        "description": f"Protected file deleted: {file_path}",
                    }
                )
                continue

            current_hash = self._calculate_file_hash(file_path)
            if current_hash and current_hash != expected_hash:
                threats.append(
                    {
                        "type": "File Tampering",
                        "file": file_path,
                        "severity": "CRITICAL",
                        "description": f"Protected file modified: {file_path}",
                        "expected_hash": expected_hash,
                        "current_hash": current_hash,
                    }
                )

        if threats:
            self.logger.critical(
                f"File integrity violations detected: {len(threats)} files affected"
            )

        return threats

    def check_process_integrity(self):
        """Check if the service process has been compromised."""
        threats = []

        try:
            current_process = psutil.Process()

            # Check if process details match baseline
            if self.process_baseline:
                current_state = {
                    "pid": current_process.pid,
                    "ppid": current_process.ppid(),
                    "name": current_process.name(),
                    "cmdline": current_process.cmdline(),
                }

                # PID and create time should remain the same
                if (
                    current_state["name"] != self.process_baseline["name"]
                    or current_state["cmdline"] != self.process_baseline["cmdline"]
                ):
                    threats.append(
                        {
                            "type": "Process Hijacking",
                            "severity": "CRITICAL",
                            "description": "Service process appears to have been hijacked",
                            "baseline": self.process_baseline,
                            "current": current_state,
                        }
                    )

            # Check for suspicious child processes
            children = current_process.children(recursive=True)
            for child in children:
                if child.name() not in ["python3", "python"]:
                    threats.append(
                        {
                            "type": "Suspicious Child Process",
                            "severity": "HIGH",
                            "description": f"Unexpected child process: {child.name()} (PID: {child.pid})",
                            "process_name": child.name(),
                            "process_pid": child.pid,
                        }
                    )

        except Exception as e:
            self.logger.error(f"Process integrity check failed: {e}")

        return threats

    def check_resource_abuse(self):
        """Check for resource exhaustion attacks."""
        threats = []

        try:
            # CPU usage check
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > self.resource_thresholds["cpu_percent"]:
                threats.append(
                    {
                        "type": "High CPU Usage",
                        "severity": "MEDIUM",
                        "description": f"CPU usage at {cpu_percent}%",
                        "current_value": cpu_percent,
                        "threshold": self.resource_thresholds["cpu_percent"],
                    }
                )

            # Memory usage check
            memory = psutil.virtual_memory()
            if memory.percent > self.resource_thresholds["memory_percent"]:
                threats.append(
                    {
                        "type": "High Memory Usage",
                        "severity": "MEDIUM",
                        "description": f"Memory usage at {memory.percent}%",
                        "current_value": memory.percent,
                        "threshold": self.resource_thresholds["memory_percent"],
                    }
                )

            # Disk usage check
            disk = psutil.disk_usage("/")
            disk_percent = (disk.used / disk.total) * 100
            if disk_percent > self.resource_thresholds["disk_usage_percent"]:
                threats.append(
                    {
                        "type": "High Disk Usage",
                        "severity": "HIGH",
                        "description": f"Disk usage at {disk_percent:.1f}%",
                        "current_value": disk_percent,
                        "threshold": self.resource_thresholds["disk_usage_percent"],
                    }
                )

            # Check for suspicious network connections
            connections = psutil.net_connections()
            suspicious_connections = []
            for conn in connections:
                # Look for unexpected outbound connections
                if (
                    conn.status == "ESTABLISHED"
                    and conn.laddr
                    and conn.raddr
                    and not self._is_expected_connection(conn.raddr.ip)
                ):
                    suspicious_connections.append(conn)

            if suspicious_connections:
                threats.append(
                    {
                        "type": "Suspicious Network Activity",
                        "severity": "MEDIUM",
                        "description": f"{len(suspicious_connections)} unexpected network connections",
                        "connections": [
                            (c.raddr.ip, c.raddr.port)
                            for c in suspicious_connections[:5]
                        ],
                    }
                )

        except Exception as e:
            self.logger.error(f"Resource monitoring failed: {e}")

        return threats

    def _is_expected_connection(self, ip):
        """Check if a network connection is expected."""
        # Allow localhost connections
        if ip.startswith("127.") or ip == "::1":
            return True

        # Allow private network ranges
        if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168."):
            return True

        # Allow configured SMTP servers, APIs, etc.
        allowed_ips = self.config.get("protection", {}).get("allowed_ips", [])
        if ip in allowed_ips:
            return True

        return False

    def check_log_tampering(self, log_file_path):
        """Check for log file tampering attempts."""
        threats = []

        try:
            if not os.path.exists(log_file_path):
                return threats

            # Check log file permissions
            stat_info = os.stat(log_file_path)
            mode = oct(stat_info.st_mode)[-3:]

            # Log file should not be world-writable
            if mode.endswith("2") or mode.endswith("6") or mode.endswith("7"):
                threats.append(
                    {
                        "type": "Log File Permissions",
                        "severity": "HIGH",
                        "description": f"Log file has unsafe permissions: {mode}",
                        "file": log_file_path,
                        "permissions": mode,
                    }
                )

            # Check for rapid size changes (potential log injection)
            if hasattr(self, "last_log_size"):
                current_size = stat_info.st_size
                size_diff = current_size - self.last_log_size

                # Alert on very large size increases
                if size_diff > 10 * 1024 * 1024:  # 10MB increase
                    threats.append(
                        {
                            "type": "Rapid Log Growth",
                            "severity": "MEDIUM",
                            "description": f"Log file grew by {size_diff} bytes rapidly",
                            "file": log_file_path,
                            "size_increase": size_diff,
                        }
                    )

            self.last_log_size = stat_info.st_size

        except Exception as e:
            self.logger.error(f"Log tampering check failed: {e}")

        return threats

    def check_service_availability(self):
        """Check if the service is functioning correctly."""
        threats = []


        try:
            # Only check systemctl in production environment
            if os.getenv("NSM_ENV", "development") == "production":
                result = subprocess.run(
                    ["systemctl", "is-active", "nginx-security-monitor"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )

                if result.returncode != 0:
                    threats.append(
                        {
                            "type": "Service Status",
                            "severity": "CRITICAL",
                            "description": "Service is not active according to systemd",
                            "status": result.stdout.strip(),
                        }
                    )
            else:
                self.logger.info("Skipping systemctl service check: not in production environment")

            # Check if log file is being written to (indicates active monitoring)
            log_file = self.config.get("logging", {}).get(
                "file", "/var/log/nginx-security-monitor.log"
            )
            if os.path.exists(log_file):
                stat_info = os.stat(log_file)
                last_modified = datetime.fromtimestamp(stat_info.st_mtime)
                time_since_modified = datetime.now() - last_modified

                # Alert if log hasn't been written to in 5 minutes
                if time_since_modified.total_seconds() > 300:
                    threats.append(
                        {
                            "type": "Service Inactivity",
                            "severity": "HIGH",
                            "description": f"Service log not updated in {time_since_modified}",
                            "last_update": last_modified.isoformat(),
                        }
                    )

        except Exception as e:
            self.logger.error(f"Service availability check failed: {e}")

        return threats

    def perform_self_check(self):
        """Perform comprehensive self-protection check."""
        all_threats = []

        # Rate limit self-checks
        if not self.check_rate_limiting("self_check", limit_per_minute=10):
            return []

        try:
            # File integrity
            all_threats.extend(self.check_file_integrity())

            # Process integrity
            all_threats.extend(self.check_process_integrity())

            # Resource abuse
            all_threats.extend(self.check_resource_abuse())

            # Log tampering
            log_file = self.config.get("log_file_path", "/var/log/nginx/access.log")
            all_threats.extend(self.check_log_tampering(log_file))

            # Service availability
            all_threats.extend(self.check_service_availability())

            if all_threats:
                self.logger.warning(
                    f"Self-protection detected {len(all_threats)} threats"
                )

        except Exception as e:
            self.logger.error(f"Self-check failed: {e}")

        return all_threats

    def emergency_shutdown(self, reason):
        """Emergency shutdown if service is compromised."""
        self.logger.critical(f"EMERGENCY SHUTDOWN: {reason}")

        try:
            # Log the emergency
            emergency_log = f"/tmp/nginx-monitor-emergency-{int(time.time())}.log"
            with open(emergency_log, "w") as f:
                f.write(f"Emergency shutdown at {datetime.now()}\n")
                f.write(f"Reason: {reason}\n")
                f.write(f"Process PID: {os.getpid()}\n")

            # Attempt to notify administrators
            # (implement your emergency notification here)

        except Exception as e:
            self.logger.error(f"Emergency logging failed: {e}")

        # Exit the process
        sys.exit(1)
