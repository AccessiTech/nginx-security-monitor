#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration Schema for NGINX Security Monitor

This file defines the schema for all configurable options in the NGINX Security Monitor.
It is used by the ConfigManager for validation, type conversion, and documentation.
"""

import yaml
import logging
import os
from pathlib import Path

logger = logging.getLogger("nginx-security-monitor.schema")

# Schema definition for all configuration options
SCHEMA = {
    "service": {
        "config_path": {
            "__type": "string",
            "__default": "/opt/nginx-security-monitor/settings.yaml",
            "__description": "Path to the configuration file",
            "__env": "NGINX_MONITOR_CONFIG_PATH",
        },
        "check_interval": {
            "__type": "integer",
            "__default": 60,
            "__range": [1, 3600],
            "__description": "Interval between security checks in seconds",
            "__env": "NGINX_MONITOR_CHECK_INTERVAL",
        },
        "log_file_path": {
            "__type": "string",
            "__default": "/var/log/nginx/access.log",
            "__description": "Path to the NGINX access log file",
            "__env": "NGINX_MONITOR_LOG_FILE_PATH",
        },
        "error_log_file_path": {
            "__type": "string",
            "__default": "/var/log/nginx/error.log",
            "__description": "Path to the NGINX error log file",
            "__env": "NGINX_MONITOR_ERROR_LOG_FILE_PATH",
        },
    },
    "log_processing": {
        "log_format_pattern": {
            "__type": "string",
            "__default": r'^(\S+) \S+ \S+ \[([^:]+):(\d+:\d+:\d+) ([^\]]+)\] "(\S+) (.*?) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$',
            "__description": "Regular expression pattern for parsing log entries",
            "__env": "NGINX_MONITOR_LOG_FORMAT_PATTERN",
        },
        "field_mappings": {
            "__type": "object",
            "__description": "Mapping of field names to position in the log format pattern",
            "ip_address": {"__type": "integer", "__default": 1},
            "date": {"__type": "integer", "__default": 2},
            "time": {"__type": "integer", "__default": 3},
            "timezone": {"__type": "integer", "__default": 4},
            "method": {"__type": "integer", "__default": 5},
            "path": {"__type": "integer", "__default": 6},
            "protocol": {"__type": "integer", "__default": 7},
            "status_code": {"__type": "integer", "__default": 8},
            "response_size": {"__type": "integer", "__default": 9},
            "referrer": {"__type": "integer", "__default": 10},
            "user_agent": {"__type": "integer", "__default": 11},
        },
        "min_fields_required": {
            "__type": "integer",
            "__default": 10,
            "__range": [5, 20],
            "__description": "Minimum number of fields required for a valid log entry",
            "__env": "NGINX_MONITOR_MIN_LOG_FIELDS",
        },
    },
    "pattern_detection": {
        "thresholds": {
            "requests_per_ip_per_minute": {
                "__type": "integer",
                "__default": 100,
                "__range": [10, 10000],
                "__description": "Maximum number of requests per IP address per minute",
                "__security_critical": True,
                "__min_secure": 30,
                "__env": "NGINX_MONITOR_MAX_REQUESTS_PER_IP",
            },
            "failed_requests_per_minute": {
                "__type": "integer",
                "__default": 50,
                "__range": [5, 5000],
                "__description": "Maximum number of failed requests per minute",
                "__security_critical": True,
                "__min_secure": 20,
                "__env": "NGINX_MONITOR_MAX_FAILED_REQUESTS",
            },
            "error_rate_threshold": {
                "__type": "number",
                "__default": 0.1,
                "__range": [0.01, 1.0],
                "__description": "Threshold for suspicious error rate",
                "__security_critical": True,
                "__min_secure": 0.05,
                "__env": "NGINX_MONITOR_ERROR_RATE_THRESHOLD",
            },
            "brute_force": {
                "max_attempts": {
                    "__type": "integer",
                    "__default": 10,
                    "__range": [3, 100],
                    "__description": "Maximum number of failed login attempts before triggering brute force detection",
                    "__security_critical": True,
                    "__min_secure": 5,
                    "__env": "NGINX_MONITOR_BRUTE_FORCE_MAX_ATTEMPTS",
                },
                "time_window_seconds": {
                    "__type": "integer",
                    "__default": 300,
                    "__range": [60, 3600],
                    "__description": "Time window in seconds for brute force detection",
                    "__security_critical": True,
                    "__min_secure": 300,
                    "__env": "NGINX_MONITOR_BRUTE_FORCE_TIME_WINDOW",
                },
            },
        },
        "sql_injection_patterns": {
            "__type": "array",
            "__default": [
                "(\bunion\b.*\bselect\b|\bselect\b.*\bunion\b)",
                "(\bdrop\b.*\btable\b|\btable\b.*\bdrop\b)",
                "(\binsert\b.*\binto\b|\binto\b.*\binsert\b)",
                "('.*or.*'.*=.*'|'.*=.*'.*or.*')",
                r"(--|\#|\/\*|\*\/)",
            ],
            "__description": "Regular expression patterns for detecting SQL injection attempts",
            "__env": "NGINX_MONITOR_SQL_INJECTION_PATTERNS",
        },
        "xss_patterns": {
            "__type": "array",
            "__default": [
                "<script[^>]*>.*?</script>",
                "javascript:",
                r"on\w+\s*=",
                "<iframe[^>]*>",
            ],
            "__description": "Regular expression patterns for detecting XSS attacks",
            "__env": "NGINX_MONITOR_XSS_PATTERNS",
        },
        "suspicious_user_agents": {
            "__type": "array",
            "__default": ["sqlmap", "nmap", "nikto", "dirb", "gobuster", "masscan"],
            "__description": "Patterns for identifying suspicious user agents",
            "__env": "NGINX_MONITOR_SUSPICIOUS_USER_AGENTS",
        },
    },
    "mitigation": {
        "strategies": {
            "ddos": {
                "enabled": {"__type": "boolean", "__default": True},
                "action": {
                    "__type": "string",
                    "__default": "rate_limit",
                    "__description": "Action to take when a DDoS attack is detected",
                },
                "description": {
                    "__type": "string",
                    "__default": "DDoS mitigation tactics applied.",
                },
            },
            "sql_injection": {
                "enabled": {"__type": "boolean", "__default": True},
                "action": {
                    "__type": "string",
                    "__default": "block_ip",
                    "__description": "Action to take when SQL injection is detected",
                },
                "description": {
                    "__type": "string",
                    "__default": "SQL injection mitigation tactics applied.",
                },
            },
            "xss": {
                "enabled": {"__type": "boolean", "__default": True},
                "action": {
                    "__type": "string",
                    "__default": "sanitize",
                    "__description": "Action to take when XSS is detected",
                },
                "description": {
                    "__type": "string",
                    "__default": "XSS mitigation tactics applied.",
                },
            },
            "brute_force": {
                "enabled": {"__type": "boolean", "__default": True},
                "action": {
                    "__type": "string",
                    "__default": "temporary_ban",
                    "__description": "Action to take when brute force is detected",
                },
                "ban_duration": {
                    "__type": "integer",
                    "__default": 3600,
                    "__range": [300, 86400],
                    "__description": "Duration of temporary ban in seconds",
                    "__security_critical": True,
                    "__min_secure": 3600,
                    "__env": "NGINX_MONITOR_BRUTE_FORCE_BAN_DURATION",
                },
                "description": {
                    "__type": "string",
                    "__default": "Brute force mitigation tactics applied.",
                },
            },
        },
        "default_response": {
            "__type": "string",
            "__default": "No specific mitigation tactics available for this pattern.",
            "__description": "Default response when no specific mitigation is available",
        },
    },
    "service_protection": {
        "protected_files": {
            "__type": "array",
            "__default": [
                "/opt/nginx-security-monitor/src/",
                "/opt/nginx-security-monitor/",
                "/etc/systemd/system/nginx-security-monitor.service",
            ],
            "__description": "Files and directories to monitor for integrity",
            "__env": "NGINX_MONITOR_PROTECTED_FILES",
        },
        "expected_processes": {
            "__type": "array",
            "__default": ["monitor_service.py"],
            "__description": "Expected process names for the service",
            "__env": "NGINX_MONITOR_EXPECTED_PROCESSES",
        },
        "resource_thresholds": {
            "cpu_percent": {
                "__type": "number",
                "__default": 80.0,
                "__range": [50.0, 99.0],
                "__description": "CPU usage threshold percentage",
                "__security_critical": True,
                "__min_secure": 70.0,
                "__env": "NGINX_MONITOR_CPU_THRESHOLD",
            },
            "memory_percent": {
                "__type": "number",
                "__default": 80.0,
                "__range": [50.0, 99.0],
                "__description": "Memory usage threshold percentage",
                "__security_critical": True,
                "__min_secure": 70.0,
                "__env": "NGINX_MONITOR_MEMORY_THRESHOLD",
            },
            "disk_usage_percent": {
                "__type": "number",
                "__default": 90.0,
                "__range": [50.0, 99.0],
                "__description": "Disk usage threshold percentage",
                "__security_critical": True,
                "__min_secure": 80.0,
                "__env": "NGINX_MONITOR_DISK_THRESHOLD",
            },
        },
        "cpu_check_interval": {
            "__type": "number",
            "__default": 1.0,
            "__range": [0.1, 10.0],
            "__description": "Interval in seconds for CPU usage checks",
            "__env": "NGINX_MONITOR_CPU_CHECK_INTERVAL",
        },
        "max_file_growth": {
            "__type": "integer",
            "__default": 10485760,  # 10MB
            "__range": [1048576, 1073741824],  # 1MB to 1GB
            "__description": "Maximum allowed file growth in bytes (10MB default)",
            "__env": "NGINX_MONITOR_MAX_FILE_GROWTH",
        },
        "max_log_age_seconds": {
            "__type": "integer",
            "__default": 300,
            "__range": [60, 3600],
            "__description": "Maximum age of log file in seconds before warning",
            "__env": "NGINX_MONITOR_MAX_LOG_AGE",
        },
        "self_check_rate_limit": {
            "__type": "integer",
            "__default": 10,
            "__range": [1, 100],
            "__description": "Maximum number of self-check operations per minute",
            "__env": "NGINX_MONITOR_SELF_CHECK_LIMIT",
        },
    },
    "network_security": {
        "max_failed_attempts": {
            "__type": "integer",
            "__default": 10,
            "__range": [3, 100],
            "__description": "Maximum number of failed login attempts before alerting",
            "__security_critical": True,
            "__min_secure": 5,
            "__env": "NGINX_MONITOR_MAX_FAILED_ATTEMPTS",
        },
        "max_login_attempts": {
            "__type": "integer",
            "__default": 100,
            "__range": [10, 1000],
            "__description": "Maximum number of login attempts in the monitoring period",
            "__env": "NGINX_MONITOR_MAX_LOGIN_ATTEMPTS",
        },
        "internal_ip_prefixes": {
            "__type": "array",
            "__default": [
                "127.",
                "10.",
                "172.16.",
                "172.17.",
                "172.18.",
                "172.19.",
                "172.20.",
                "172.21.",
                "172.22.",
                "172.23.",
                "172.24.",
                "172.25.",
                "172.26.",
                "172.27.",
                "172.28.",
                "172.29.",
                "172.30.",
                "172.31.",
                "192.168.",
            ],
            "__description": "IP address prefixes considered internal",
            "__env": "NGINX_MONITOR_INTERNAL_IP_PREFIXES",
        },
        "file_permissions": {
            "__type": "object",
            "__description": "File permissions in octal format",
            "/opt/nginx-security-monitor/settings.yaml": {
                "__type": "string",
                "__default": "0640",
            },
            "/opt/nginx-security-monitor/.salt": {
                "__type": "string",
                "__default": "0600",
            },
        },
    },
    "crypto": {
        "master_key_env": {
            "__type": "string",
            "__default": "NGINX_MONITOR_KEY",
            "__description": "Environment variable name for the master key",
            "__env": "NGINX_MONITOR_MASTER_KEY_ENV",
        },
        "salt_file": {
            "__type": "string",
            "__default": "/opt/nginx-security-monitor/.salt",
            "__description": "Path to the salt file",
            "__env": "NGINX_MONITOR_SALT_FILE",
        },
        "check_interval_variance": {
            "__type": "integer",
            "__default": 20,
            "__range": [0, 50],
            "__description": "Randomization percentage for check intervals",
            "__env": "NGINX_MONITOR_CHECK_INTERVAL_VARIANCE",
        },
        "base_delay": {
            "__type": "number",
            "__default": 0.1,
            "__range": [0.01, 1.0],
            "__description": "Base delay for variable delays in seconds",
            "__env": "NGINX_MONITOR_BASE_DELAY",
        },
        "max_delay": {
            "__type": "number",
            "__default": 1.0,
            "__range": [0.1, 10.0],
            "__description": "Maximum delay for variable delays in seconds",
            "__env": "NGINX_MONITOR_MAX_DELAY",
        },
    },
    "plugin_system": {
        "plugin_dirs": {
            "__type": "array",
            "__default": [
                "/opt/nginx-security-monitor/plugins",
                "/opt/nginx-security-monitor/custom_plugins",
                "~/.nginx-security-monitor/plugins",
            ],
            "__description": "Directories to search for plugins",
            "__env": "NGINX_MONITOR_PLUGIN_DIRS",
        },
        "default_priority": {
            "__type": "integer",
            "__default": 100,
            "__range": [1, 1000],
            "__description": "Default priority for plugins",
            "__env": "NGINX_MONITOR_DEFAULT_PLUGIN_PRIORITY",
        },
        "enabled": {
            "__type": "boolean",
            "__default": True,
            "__description": "Whether the plugin system is enabled",
            "__env": "NGINX_MONITOR_PLUGINS_ENABLED",
        },
        "auto_reload": {
            "__type": "boolean",
            "__default": False,
            "__description": "Whether to automatically reload plugins when they change",
            "__env": "NGINX_MONITOR_PLUGINS_AUTO_RELOAD",
        },
        "reload_interval": {
            "__type": "integer",
            "__default": 300,
            "__range": [60, 3600],
            "__description": "Interval in seconds for checking for plugin changes",
            "__env": "NGINX_MONITOR_PLUGINS_RELOAD_INTERVAL",
        },
    },
    "security_integrations": {
        "command_timeout": {
            "__type": "integer",
            "__default": 5,
            "__range": [1, 60],
            "__description": "Timeout in seconds for integration commands",
            "__env": "NGINX_MONITOR_COMMAND_TIMEOUT",
        },
        "extended_command_timeout": {
            "__type": "integer",
            "__default": 10,
            "__range": [1, 300],
            "__description": "Extended timeout in seconds for longer-running commands",
            "__env": "NGINX_MONITOR_EXTENDED_COMMAND_TIMEOUT",
        },
        "fail2ban": {
            "enabled": {
                "__type": "boolean",
                "__default": True,
                "__description": "Whether fail2ban integration is enabled",
                "__env": "NGINX_MONITOR_FAIL2BAN_ENABLED",
            },
            "min_bantime": {
                "__type": "integer",
                "__default": 600,
                "__range": [60, 86400],
                "__description": "Minimum ban time in seconds",
                "__env": "NGINX_MONITOR_FAIL2BAN_MIN_BANTIME",
            },
            "jail_files": {
                "__type": "array",
                "__default": [
                    "/etc/fail2ban/jail.local",
                    "/etc/fail2ban/jail.conf",
                    "/etc/fail2ban/jail.d/",
                ],
                "__description": "Paths to fail2ban jail configuration files",
                "__env": "NGINX_MONITOR_FAIL2BAN_JAIL_FILES",
            },
        },
        "suricata": {
            "enabled": {
                "__type": "boolean",
                "__default": False,
                "__description": "Whether Suricata integration is enabled",
                "__env": "NGINX_MONITOR_SURICATA_ENABLED",
            },
            "rules_dir": {
                "__type": "string",
                "__default": "/etc/suricata/rules/",
                "__description": "Path to Suricata rules directory",
                "__env": "NGINX_MONITOR_SURICATA_RULES_DIR",
            },
        },
        "modsecurity": {
            "enabled": {
                "__type": "boolean",
                "__default": False,
                "__description": "Whether ModSecurity integration is enabled",
                "__env": "NGINX_MONITOR_MODSECURITY_ENABLED",
            },
            "rules_dir": {
                "__type": "string",
                "__default": "/etc/modsecurity/rules",
                "__description": "Path to ModSecurity rules directory",
                "__env": "NGINX_MONITOR_MODSECURITY_RULES_DIR",
            },
        },
    },
    "alert_system": {
        "email": {
            "enabled": {
                "__type": "boolean",
                "__default": True,
                "__description": "Whether email alerts are enabled",
                "__env": "NGINX_MONITOR_EMAIL_ENABLED",
            },
            "config_path": {
                "__type": "string",
                "__default": "/opt/nginx-security-monitor/settings.yaml",
                "__description": "Path to email configuration file",
                "__env": "NGINX_MONITOR_EMAIL_CONFIG_PATH",
            },
            "smtp_server": {
                "__type": "string",
                "__default": "smtp.example.com",
                "__description": "SMTP server hostname",
                "__env": "NGINX_MONITOR_SMTP_SERVER",
            },
            "smtp_port": {
                "__type": "integer",
                "__default": 587,
                "__range": [1, 65535],
                "__description": "SMTP server port",
                "__env": "NGINX_MONITOR_SMTP_PORT",
            },
            "smtp_server_default": {
                "__type": "string",
                "__default": "localhost",
                "__description": "Default SMTP server if not specified",
                "__env": "NGINX_MONITOR_SMTP_SERVER_DEFAULT",
            },
            "smtp_port_default": {
                "__type": "integer",
                "__default": 587,
                "__range": [1, 65535],
                "__description": "Default SMTP port if not specified",
                "__env": "NGINX_MONITOR_SMTP_PORT_DEFAULT",
            },
            "use_tls": {
                "__type": "boolean",
                "__default": True,
                "__description": "Whether to use TLS for SMTP connection",
                "__env": "NGINX_MONITOR_SMTP_USE_TLS",
            },
            "use_tls_default": {
                "__type": "boolean",
                "__default": True,
                "__description": "Default TLS setting if not specified",
                "__env": "NGINX_MONITOR_SMTP_USE_TLS_DEFAULT",
            },
            "username": {
                "__type": "string",
                "__default": "your_email@example.com",
                "__description": "SMTP username",
                "__sensitive": True,
                "__env": "NGINX_MONITOR_SMTP_USERNAME",
            },
            "password": {
                "__type": "string",
                "__default": "your_email_password",
                "__description": "SMTP password",
                "__sensitive": True,
                "__env": "NGINX_MONITOR_SMTP_PASSWORD",
            },
            "from_address": {
                "__type": "string",
                "__default": "your_email@example.com",
                "__description": "Email from address",
                "__env": "NGINX_MONITOR_EMAIL_FROM",
            },
            "to_address": {
                "__type": "string",
                "__default": "alert_recipient@example.com",
                "__description": "Email recipient address",
                "__env": "NGINX_MONITOR_EMAIL_TO",
            },
        },
        "sms": {
            "enabled": {
                "__type": "boolean",
                "__default": False,
                "__description": "Whether SMS alerts are enabled",
                "__env": "NGINX_MONITOR_SMS_ENABLED",
            },
            "provider": {
                "__type": "string",
                "__default": "your_sms_provider",
                "__description": "SMS provider name",
                "__env": "NGINX_MONITOR_SMS_PROVIDER",
            },
            "api_key": {
                "__type": "string",
                "__default": "your_sms_api_key",
                "__description": "SMS provider API key",
                "__sensitive": True,
                "__env": "NGINX_MONITOR_SMS_API_KEY",
            },
            "from_number": {
                "__type": "string",
                "__default": "+1234567890",
                "__description": "SMS sender phone number",
                "__env": "NGINX_MONITOR_SMS_FROM",
            },
            "to_number": {
                "__type": "string",
                "__default": "+0987654321",
                "__description": "SMS recipient phone number",
                "__env": "NGINX_MONITOR_SMS_TO",
            },
        },
        "thresholds": {
            "high": {
                "__type": "integer",
                "__default": 10,
                "__range": [1, 100],
                "__description": "High priority alert threshold",
                "__env": "NGINX_MONITOR_ALERT_HIGH",
            },
            "medium": {
                "__type": "integer",
                "__default": 5,
                "__range": [1, 100],
                "__description": "Medium priority alert threshold",
                "__env": "NGINX_MONITOR_ALERT_MEDIUM",
            },
            "low": {
                "__type": "integer",
                "__default": 1,
                "__range": [1, 100],
                "__description": "Low priority alert threshold",
                "__env": "NGINX_MONITOR_ALERT_LOW",
            },
        },
        "cooldown_periods": {
            "high": {
                "__type": "integer",
                "__default": 300,
                "__range": [60, 3600],
                "__description": "Cooldown period in seconds for high priority alerts",
                "__env": "NGINX_MONITOR_COOLDOWN_HIGH",
            },
            "medium": {
                "__type": "integer",
                "__default": 1800,
                "__range": [300, 7200],
                "__description": "Cooldown period in seconds for medium priority alerts",
                "__env": "NGINX_MONITOR_COOLDOWN_MEDIUM",
            },
            "low": {
                "__type": "integer",
                "__default": 3600,
                "__range": [600, 86400],
                "__description": "Cooldown period in seconds for low priority alerts",
                "__env": "NGINX_MONITOR_COOLDOWN_LOW",
            },
        },
    },
    "alert_system": {
        "email": {
            "enabled": {
                "__type": "boolean",
                "__default": True,
                "__description": "Enable or disable email alerts",
                "__env": "NGINX_MONITOR_EMAIL_ENABLED",
            },
            "config_path": {
                "__type": "string",
                "__default": "/opt/nginx-security-monitor/settings.yaml",
                "__description": "Path to the email configuration file",
                "__env": "NGINX_MONITOR_EMAIL_CONFIG_PATH",
            },
            "from_address": {
                "__type": "string",
                "__default": "nginx-security@example.com",
                "__description": "Email address to send alerts from",
                "__env": "NGINX_MONITOR_EMAIL_FROM",
            },
            "to_address": {
                "__type": "string",
                "__default": "admin@example.com",
                "__description": "Email address to send alerts to",
                "__env": "NGINX_MONITOR_EMAIL_TO",
            },
            "smtp_server": {
                "__type": "string",
                "__default": "localhost",
                "__description": "SMTP server hostname",
                "__env": "NGINX_MONITOR_EMAIL_SMTP_SERVER",
            },
            "smtp_port": {
                "__type": "integer",
                "__default": 587,
                "__range": [1, 65535],
                "__description": "SMTP server port",
                "__env": "NGINX_MONITOR_EMAIL_SMTP_PORT",
            },
            "username": {
                "__type": "string",
                "__default": "",
                "__description": "SMTP username",
                "__env": "NGINX_MONITOR_EMAIL_USERNAME",
            },
            "password": {
                "__type": "string",
                "__default": "",
                "__description": "SMTP password",
                "__sensitive": True,
                "__env": "NGINX_MONITOR_EMAIL_PASSWORD",
            },
            "use_tls": {
                "__type": "boolean",
                "__default": True,
                "__description": "Use TLS for SMTP connection",
                "__env": "NGINX_MONITOR_EMAIL_USE_TLS",
            },
            "retry_count": {
                "__type": "integer",
                "__default": 3,
                "__range": [1, 10],
                "__description": "Number of retry attempts for sending email",
                "__env": "NGINX_MONITOR_EMAIL_RETRY_COUNT",
            },
            "retry_delay": {
                "__type": "integer",
                "__default": 5,
                "__range": [1, 60],
                "__description": "Delay between retry attempts in seconds",
                "__env": "NGINX_MONITOR_EMAIL_RETRY_DELAY",
            },
            "debug_level": {
                "__type": "integer",
                "__default": 0,
                "__range": [0, 2],
                "__description": "Debug level for SMTP connection",
                "__env": "NGINX_MONITOR_EMAIL_DEBUG_LEVEL",
            },
            "footer_text": {
                "__type": "string",
                "__default": "This is an automated alert from NGINX Security Monitor. Please do not reply to this email.",
                "__description": "Footer text for email alerts",
                "__env": "NGINX_MONITOR_EMAIL_FOOTER_TEXT",
            },
            "copyright_text": {
                "__type": "string",
                "__default": "© NGINX Security Monitor",
                "__description": "Copyright text for email alerts",
                "__env": "NGINX_MONITOR_EMAIL_COPYRIGHT_TEXT",
            },
            "text_alert_header": {
                "__type": "string",
                "__default": "NGINX Security Alert",
                "__description": "Header text for plain text email alerts",
                "__env": "NGINX_MONITOR_EMAIL_TEXT_HEADER",
            },
            "alert_header": {
                "__type": "string",
                "__default": "🚨 Security Alert",
                "__description": "Header text for HTML email alerts",
                "__env": "NGINX_MONITOR_EMAIL_ALERT_HEADER",
            },
            "action_message": {
                "__type": "string",
                "__default": "Please investigate this security threat immediately and take appropriate action to secure your system.",
                "__description": "Action message for email alerts",
                "__env": "NGINX_MONITOR_EMAIL_ACTION_MESSAGE",
            },
            "fallback_enabled": {
                "__type": "boolean",
                "__default": False,
                "__description": "Enable fallback notification if email fails",
                "__env": "NGINX_MONITOR_EMAIL_FALLBACK_ENABLED",
            },
            "fallback_address": {
                "__type": "string",
                "__default": "",
                "__description": "Fallback email address if primary fails",
                "__env": "NGINX_MONITOR_EMAIL_FALLBACK_ADDRESS",
            },
            "severity_colors": {
                "__type": "object",
                "__description": "Colors for different severity levels in HTML emails",
                "HIGH": {"__type": "string", "__default": "#dc3545"},
                "MEDIUM": {"__type": "string", "__default": "#fd7e14"},
                "LOW": {"__type": "string", "__default": "#ffc107"},
            },
        },
        "sms": {
            "enabled": {
                "__type": "boolean",
                "__default": False,
                "__description": "Enable or disable SMS alerts",
                "__env": "NGINX_MONITOR_SMS_ENABLED",
            },
            "provider": {
                "__type": "string",
                "__default": "dummy",
                "__options": ["dummy", "twilio", "aws_sns"],
                "__description": "SMS service provider",
                "__env": "NGINX_MONITOR_SMS_PROVIDER",
            },
            "api_key": {
                "__type": "string",
                "__default": "",
                "__description": "API key for SMS service",
                "__sensitive": True,
                "__env": "NGINX_MONITOR_SMS_API_KEY",
            },
            "api_secret": {
                "__type": "string",
                "__default": "",
                "__description": "API secret for SMS service",
                "__sensitive": True,
                "__env": "NGINX_MONITOR_SMS_API_SECRET",
            },
            "from_number": {
                "__type": "string",
                "__default": "",
                "__description": "Phone number to send SMS from",
                "__env": "NGINX_MONITOR_SMS_FROM_NUMBER",
            },
            "default_recipient": {
                "__type": "string",
                "__default": "",
                "__description": "Default phone number to send SMS to",
                "__env": "NGINX_MONITOR_SMS_DEFAULT_RECIPIENT",
            },
            "max_length": {
                "__type": "integer",
                "__default": 160,
                "__range": [50, 1600],
                "__description": "Maximum length of SMS message",
                "__env": "NGINX_MONITOR_SMS_MAX_LENGTH",
            },
            "retry_count": {
                "__type": "integer",
                "__default": 3,
                "__range": [1, 10],
                "__description": "Number of retry attempts for sending SMS",
                "__env": "NGINX_MONITOR_SMS_RETRY_COUNT",
            },
            "retry_delay": {
                "__type": "integer",
                "__default": 5,
                "__range": [1, 60],
                "__description": "Delay between retry attempts in seconds",
                "__env": "NGINX_MONITOR_SMS_RETRY_DELAY",
            },
        },
    },
}


def save_schema_to_file(schema_path="/opt/nginx-security-monitor/schema.yml"):
    """
    Save the schema to a YAML file.

    Args:
        schema_path: Path to save the schema to
    """
    try:
        # Make sure directory exists
        os.makedirs(os.path.dirname(schema_path), exist_ok=True)

        # Write schema to file
        with open(schema_path, "w") as f:
            yaml.dump(SCHEMA, f, default_flow_style=False, sort_keys=False)

        # Set secure permissions
        os.chmod(schema_path, 0o640)

        logger.info(f"Schema saved to {schema_path}")
    except Exception as e:
        logger.error(f"Error saving schema to {schema_path}: {e}")
        raise


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Save schema to default location
    save_schema_to_file()
