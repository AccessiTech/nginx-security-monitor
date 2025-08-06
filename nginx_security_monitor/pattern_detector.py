import re
import json
import urllib.parse
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from nginx_security_monitor.config_manager import ConfigManager


class PatternDetector:
    def __init__(self, config_path=None):
        self.detected_patterns = []
        self.ip_request_counts = defaultdict(list)
        self.failed_login_attempts = defaultdict(list)

        # Get the ConfigManager instance
        self.config_manager = ConfigManager.get_instance()

        # Load the patterns configuration
        self.config = self.load_patterns_config(config_path)

        # Load patterns from configuration
        self.sql_injection_patterns = self.config_manager.get(
            "pattern_detection.sql_injection_patterns",
            [
                r"(\bunion\b.*\bselect\b|\bselect\b.*\bunion\b)",
                r"(\bdrop\b.*\btable\b|\btable\b.*\bdrop\b)",
                r"(\binsert\b.*\binto\b|\binto\b.*\binsert\b)",
                r"('.*or.*'.*=.*'|'.*=.*'.*or.*')",
                r"(--|\#|\/\*|\*\/)",
            ],
        )

        self.xss_patterns = self.config_manager.get(
            "pattern_detection.xss_patterns",
            [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
            ],
        )

        self.suspicious_user_agents = self.config_manager.get(
            "pattern_detection.suspicious_user_agents",
            [
                r"sqlmap",
                r"nmap",
                r"nikto",
                r"dirb",
                r"gobuster",
                r"masscan",
            ],
        )

        # Custom patterns (will be loaded from encrypted files)
        self.custom_patterns = {}

    def _url_decode_request(self, request):
        """URL decode a request string for pattern matching.
        
        Args:
            request: The request string to decode
            
        Returns:
            str: URL decoded request string
        """
        try:
            return urllib.parse.unquote(request)
        except Exception:
            # If decoding fails, return original
            return request

    def load_patterns_config(self, config_path):
        """Load pattern configuration from file."""
        # Default config gets loaded from ConfigManager
        default_config = {
            "thresholds": {
                "requests_per_ip_per_minute": self.config_manager.get(
                    "pattern_detection.thresholds.requests_per_ip_per_minute", 100
                ),
                "failed_requests_per_minute": self.config_manager.get(
                    "pattern_detection.thresholds.failed_requests_per_minute", 20
                ),
                "error_rate_threshold": self.config_manager.get(
                    "pattern_detection.thresholds.error_rate_threshold", 10
                ),
            },
            "ddos_detection": {
                "time_window_minutes": self.config_manager.get(
                    "ddos_detection.time_window_minutes", 5
                ),
                "requests_per_ip_threshold": self.config_manager.get(
                    "ddos_detection.requests_per_ip_threshold", 100
                ),
            },
            "directory_traversal": {
                "patterns": self.config_manager.get(
                    "directory_traversal.patterns",
                    [
                        r"\.\./|\.\.\%2f|\.\.\%5c",
                        r"%2e%2e%2f|%2e%2e%5c",
                        r"\.\.\\|\.\./",
                    ],
                )
            },
            "suspicious_scan": {
                "patterns": self.config_manager.get(
                    "suspicious_scan.patterns",
                    [
                        r"\.php$|\.asp$|\.jsp$",
                        r"admin|administrator|wp-admin",
                        r"config|backup|\.env|\.git",
                    ],
                )
            },
        }

        # Load from file if provided
        if config_path:
            try:
                with open(config_path, "r") as f:
                    file_config = json.load(f)
                    # Merge configs, with file_config taking precedence
                    self._deep_merge(default_config, file_config)
            except Exception as e:
                import logging

                logger = logging.getLogger("nginx-security-monitor.patterns")
                logger.error(f"Failed to load patterns config from {config_path}: {e}")

        return default_config

    def _deep_merge(self, target, source):
        """Recursively merge source dict into target dict."""
        for key, value in source.items():
            if (
                key in target
                and isinstance(target[key], dict)
                and isinstance(value, dict)
            ):
                self._deep_merge(target[key], value)
            else:
                target[key] = value

    def load_custom_patterns(self, custom_patterns_dict):
        """Load custom patterns from decrypted configuration."""
        try:
            self.custom_patterns = custom_patterns_dict

            # Extend existing patterns with custom ones
            if "sql_injection" in custom_patterns_dict:
                self.sql_injection_patterns.extend(
                    custom_patterns_dict["sql_injection"]
                )

            if "xss_patterns" in custom_patterns_dict:
                self.xss_patterns.extend(custom_patterns_dict["xss_patterns"])

            if "suspicious_user_agents" in custom_patterns_dict:
                self.suspicious_user_agents.extend(
                    custom_patterns_dict["suspicious_user_agents"]
                )

            # Update thresholds if provided
            if "thresholds" in custom_patterns_dict:
                self.config["thresholds"].update(custom_patterns_dict["thresholds"])

        except Exception as e:
            import logging

            logger = logging.getLogger("nginx-security-monitor.patterns")
            logger.error(f"Failed to load custom patterns: {e}")

    def detect_patterns(self, parsed_logs):
        """Detect various attack patterns in logs."""
        current_time = datetime.now()

        for log in parsed_logs:
            if isinstance(log, dict):
                self._detect_sql_injection(log)
                self._detect_xss_attack(log)
                self._detect_suspicious_user_agent(log)
                self._detect_brute_force(log, current_time)
                self._detect_ddos_attempt(log, current_time)
                self._detect_directory_traversal(log)
                self._detect_error_patterns(log)

                # Check custom patterns if available
                if self.custom_patterns:
                    self._detect_custom_patterns(log)

    def detect_threats(self, log_entry):
        """Detect threats in a single log entry and return list of threats.
        
        Args:
            log_entry: Single parsed log entry dict
            
        Returns:
            list: List of detected threat dictionaries
        """
        threats = []
        current_time = datetime.now()
        
        if not isinstance(log_entry, dict):
            return threats
            
        # SQL Injection Detection
        if self._detect_sql_injection_single(log_entry):
            threats.append({
                'type': 'sql_injection',
                'description': 'SQL injection attempt detected',
                'confidence': 'high',
                'pattern_matched': True
            })
            
        # XSS Detection
        if self._detect_xss_attack_single(log_entry):
            threats.append({
                'type': 'xss_attack', 
                'description': 'Cross-site scripting attempt detected',
                'confidence': 'high',
                'pattern_matched': True
            })
            
        # Suspicious User Agent Detection
        if self._detect_suspicious_user_agent_single(log_entry):
            threats.append({
                'type': 'suspicious_user_agent',
                'description': 'Suspicious user agent detected',
                'confidence': 'medium',
                'pattern_matched': True
            })
            
        # Directory Traversal Detection  
        if self._detect_directory_traversal_single(log_entry):
            threats.append({
                'type': 'directory_traversal',
                'description': 'Directory traversal attempt detected',
                'confidence': 'high',
                'pattern_matched': True
            })
            
        return threats

    def _detect_custom_patterns(self, log):
        """Detect custom patterns loaded from encrypted configuration."""
        try:
            # This method processes your secret custom patterns
            # The patterns themselves are encrypted and not visible in the source code

            for pattern_name, pattern_config in self.custom_patterns.items():
                if pattern_name.startswith("custom_"):
                    if isinstance(pattern_config, dict):
                        patterns = pattern_config.get("patterns", [])
                        default_severity = self.config_manager.get(
                            "severity_levels.custom_patterns", "MEDIUM"
                        )
                        severity = pattern_config.get("severity", default_severity)

                        request = log.get("request", "").lower()
                        raw_line = log.get("raw_line", "").lower()

                        for pattern in patterns:
                            if re.search(pattern, request, re.IGNORECASE) or re.search(
                                pattern, raw_line, re.IGNORECASE
                            ):
                                self.detected_patterns.append(
                                    {
                                        "type": f"Custom Pattern: {pattern_name}",
                                        "ip": log.get("ip_address"),
                                        "request": log.get("request"),
                                        "timestamp": log.get("timestamp"),
                                        "severity": severity,
                                        "pattern_name": pattern_name,
                                    }
                                )
                                break

        except Exception as e:
            import logging

            logger = logging.getLogger("nginx-security-monitor.patterns")
            logger.error(f"Error in custom pattern detection: {e}")

    def _detect_sql_injection(self, log):
        """Detect SQL injection attempts."""
        request = log.get("request", "").lower()
        raw_line = log.get("raw_line", "").lower()

        for pattern in self.sql_injection_patterns:
            if re.search(pattern, request, re.IGNORECASE) or re.search(
                pattern, raw_line, re.IGNORECASE
            ):
                self.detected_patterns.append(
                    {
                        "type": "SQL Injection",
                        "ip": log.get("ip_address"),
                        "request": log.get("request"),
                        "timestamp": log.get("timestamp"),
                        "severity": self.config_manager.get(
                            "severity_levels.sql_injection", "HIGH"
                        ),
                    }
                )
                break

    def _detect_xss_attack(self, log):
        """Detect XSS attack attempts."""
        request = log.get("request", "")
        raw_line = log.get("raw_line", "")

        for pattern in self.xss_patterns:
            if re.search(pattern, request, re.IGNORECASE) or re.search(
                pattern, raw_line, re.IGNORECASE
            ):
                self.detected_patterns.append(
                    {
                        "type": "XSS Attack",
                        "ip": log.get("ip_address"),
                        "request": log.get("request"),
                        "timestamp": log.get("timestamp"),
                        "severity": self.config_manager.get(
                            "severity_levels.xss_attack", "HIGH"
                        ),
                    }
                )
                break

    def _detect_suspicious_user_agent(self, log):
        """Detect suspicious user agents."""
        user_agent = log.get("user_agent", "").lower()

        for pattern in self.suspicious_user_agents:
            if re.search(pattern, user_agent, re.IGNORECASE):
                self.detected_patterns.append(
                    {
                        "type": "Suspicious User Agent",
                        "ip": log.get("ip_address"),
                        "user_agent": log.get("user_agent"),
                        "timestamp": log.get("timestamp"),
                        "severity": self.config_manager.get(
                            "severity_levels.suspicious_user_agent", "MEDIUM"
                        ),
                    }
                )
                break

    def _detect_brute_force(self, log, current_time):
        """Detect brute force login attempts."""
        status_code = log.get("status_code", "")
        ip = log.get("ip_address", "")

        # Track failed login attempts (401, 403 status codes)
        if status_code in ["401", "403"]:
            self.failed_login_attempts[ip].append(current_time)

            # Get brute force detection configuration
            time_window_seconds = self.config_manager.get(
                "pattern_detection.thresholds.brute_force.time_window_seconds", 300
            )  # Default: 5 minutes
            max_attempts = self.config_manager.get(
                "pattern_detection.thresholds.brute_force.max_attempts", 10
            )

            # Clean old entries (older than configured time window)
            cutoff_time = current_time - timedelta(seconds=time_window_seconds)
            self.failed_login_attempts[ip] = [
                t for t in self.failed_login_attempts[ip] if t > cutoff_time
            ]

            # Check if threshold exceeded
            if len(self.failed_login_attempts[ip]) > max_attempts:
                self.detected_patterns.append(
                    {
                        "type": "Brute Force Attack",
                        "ip": ip,
                        "attempts": len(self.failed_login_attempts[ip]),
                        "timestamp": log.get("timestamp"),
                        "severity": self.config_manager.get(
                            "severity_levels.brute_force", "HIGH"
                        ),
                    }
                )

    def _detect_ddos_attempt(self, log, current_time):
        """Detect potential DDoS attempts."""
        ip = log.get("ip", "")  # Changed from 'ip_address' to 'ip' to match log format

        if not ip:  # Skip if IP is missing
            return

        # Track request frequency per IP
        self.ip_request_counts[ip].append(current_time)

        # Clean old entries (older than window time)
        window_minutes = self.config_manager.get(
            "ddos_detection.time_window_minutes", 1
        )
        cutoff_time = current_time - timedelta(minutes=window_minutes)
        self.ip_request_counts[ip] = [
            t for t in self.ip_request_counts[ip] if t > cutoff_time
        ]

        # Check if threshold exceeded
        threshold = self.config["thresholds"][
            "requests_per_ip_per_minute"
        ]  # Use the loaded threshold
        if len(self.ip_request_counts[ip]) > threshold:
            self.detected_patterns.append(
                {
                    "type": "DDoS Attempt",
                    "ip": ip,
                    "requests_per_minute": len(self.ip_request_counts[ip]),
                    "timestamp": log.get("timestamp"),
                    "severity": self.config_manager.get("severity_levels.ddos", "HIGH"),
                }
            )

    def _detect_directory_traversal(self, log):
        """Detect directory traversal attempts."""
        request = log.get("request", "")

        # Get directory traversal patterns from config
        traversal_patterns = self.config_manager.get(
            "directory_traversal.patterns",
            [
                r"\.\./|\.\.\%2f|\.\.\%5c",
                r"%2e%2e%2f|%2e%2e%5c",
                r"\.\.\\|\.\./",
            ],
        )

        for pattern in traversal_patterns:
            if re.search(pattern, request, re.IGNORECASE):
                self.detected_patterns.append(
                    {
                        "type": "Directory Traversal",
                        "ip": log.get("ip_address"),
                        "request": log.get("request"),
                        "timestamp": log.get("timestamp"),
                        "severity": self.config_manager.get(
                            "severity_levels.directory_traversal", "MEDIUM"
                        ),
                    }
                )
                break

    def _detect_error_patterns(self, log):
        """Detect suspicious error patterns."""
        status_code = log.get("status_code", "")
        request = log.get("request", "")

        # Track 404 errors that might indicate scanning
        if status_code == "404":
            suspicious_404_patterns = self.config_manager.get(
                "suspicious_scan.patterns",
                [
                    r"\.php$|\.asp$|\.jsp$",  # Looking for specific file types
                    r"admin|administrator|wp-admin",  # Admin panel searches
                    r"config|backup|\.env|\.git",  # Configuration file searches
                ],
            )

            for pattern in suspicious_404_patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    self.detected_patterns.append(
                        {
                            "type": "Suspicious Scanning",
                            "ip": log.get("ip_address"),
                            "request": log.get("request"),
                            "timestamp": log.get("timestamp"),
                            "severity": self.config_manager.get(
                                "severity_levels.suspicious_scanning", "LOW"
                            ),
                        }
                    )
                    break

    def get_detected_patterns(self):
        """Get all detected patterns."""
        return self.detected_patterns

    def get_pattern_summary(self):
        """Get a summary of detected patterns."""
        if not self.detected_patterns:
            return {}

        summary = {
            "total_threats": len(self.detected_patterns),
            "by_type": Counter(p["type"] for p in self.detected_patterns),
            "by_severity": Counter(p["severity"] for p in self.detected_patterns),
            "top_attacking_ips": Counter(
                p["ip"] for p in self.detected_patterns
            ).most_common(self.config_manager.get("reporting.top_ips_count", 5)),
        }

        return summary

    def _detect_sql_injection_single(self, log):
        """Detect SQL injection attempts in a single log entry.
        
        Args:
            log: Single log entry dict
            
        Returns:
            bool: True if SQL injection detected, False otherwise
        """
        request = log.get("request", "")
        # URL decode the request for pattern matching
        decoded_request = self._url_decode_request(request).lower()
        raw_line = log.get("raw_line", "").lower()

        for pattern in self.sql_injection_patterns:
            if re.search(pattern, decoded_request, re.IGNORECASE) or re.search(
                pattern, raw_line, re.IGNORECASE
            ):
                return True
        return False

    def _detect_xss_attack_single(self, log):
        """Detect XSS attack attempts in a single log entry.
        
        Args:
            log: Single log entry dict
            
        Returns:
            bool: True if XSS attack detected, False otherwise
        """
        request = log.get("request", "")
        # URL decode the request for pattern matching
        decoded_request = self._url_decode_request(request)
        raw_line = log.get("raw_line", "")

        for pattern in self.xss_patterns:
            if re.search(pattern, decoded_request, re.IGNORECASE) or re.search(
                pattern, raw_line, re.IGNORECASE
            ):
                return True
        return False

    def _detect_suspicious_user_agent_single(self, log):
        """Detect suspicious user agents in a single log entry.
        
        Args:
            log: Single log entry dict
            
        Returns:
            bool: True if suspicious user agent detected, False otherwise
        """
        user_agent = log.get("user_agent", "").lower()

        for pattern in self.suspicious_user_agents:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        return False

    def _detect_directory_traversal_single(self, log):
        """Detect directory traversal attempts in a single log entry.
        
        Args:
            log: Single log entry dict
            
        Returns:
            bool: True if directory traversal detected, False otherwise
        """
        request = log.get("request", "")
        # URL decode the request for pattern matching
        decoded_request = self._url_decode_request(request).lower()
        raw_line = log.get("raw_line", "").lower()

        directory_traversal_patterns = self.config_manager.get(
            "directory_traversal.patterns", 
            [r'\.\.\/|\.\.%2f|\.\.%5c', r'%2e%2e%2f|%2e%2e%5c', r'\.\.\\|\.\.\/']
        )

        for pattern in directory_traversal_patterns:
            if re.search(pattern, decoded_request, re.IGNORECASE) or re.search(
                pattern, raw_line, re.IGNORECASE
            ):
                return True
        return False
