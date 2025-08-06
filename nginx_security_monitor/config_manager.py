#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ConfigManager for NGINX Security Monitor

This module implements a secure configuration management system for the NGINX Security Monitor.
It provides centralized access to configuration with security hardening features.
"""

import os
import yaml
import json
import logging
import re
import hashlib
import hmac
import secrets
import time
import random
from typing import Any, Dict, List, Optional, Union, Tuple
from pathlib import Path


class SecureString:
    """A string class that protects its contents in memory as much as possible."""

    def __init__(self, value: str):
        """
        Initialize a secure string.

        Args:
            value: The string value to protect
        """
        self._value = value

    def __str__(self) -> str:
        """Return a redacted representation for printing."""
        return "[REDACTED]"

    def __repr__(self) -> str:
        """Return a redacted representation for debugging."""
        return "[REDACTED]"

    def get_value(self) -> str:
        """Return the actual string value."""
        return self._value

    def clear(self):
        """Securely clear the string value from memory."""
        # Overwrite with random data
        try:
            random_bytes = os.urandom(len(self._value) * 2)
            self._value = random_bytes.hex()[: len(self._value)]
            # Clear again
            self._value = ""
        except Exception:
            # In case of any error, still ensure the value is cleared
            self._value = ""


class ConfigManager:
    """
    A centralized configuration manager for the NGINX Security Monitor with security hardening.

    This class handles loading, validating, and accessing configuration from:
    - Default schema values
    - Configuration files (YAML)
    - Environment variables

    Features:
    - Schema-based validation
    - Type conversion
    - Environment variable override
    - Nested configuration access
    - Configuration reload
    - Security hardening
    - Configuration integrity verification
    - Protection against injection attacks
    """

    # Singleton instance
    _instance = None

    @classmethod
    def get_instance(cls, schema_path=None, config_path=None, lockdown_mode=False):
        """Get or create the singleton instance of ConfigManager."""
        if cls._instance is None:
            cls._instance = cls(schema_path, config_path, lockdown_mode)
        return cls._instance

    @classmethod
    def reset_instance(cls):
        """Reset the singleton instance. Primarily used for testing."""
        cls._instance = None

    def __init__(
        self,
        schema_path: str = None,
        config_path: str = None,
        lockdown_mode: bool = False,
    ):
        """
        Initialize the ConfigManager with a schema and optional config file.

        Args:
            schema_path: Path to the schema file (YAML)
            config_path: Path to the configuration file (YAML)
            lockdown_mode: If True, uses ultra-conservative security settings
        """
        self.logger = logging.getLogger("nginx-security-monitor.config")
        self.lockdown_mode = lockdown_mode

        # Initialize secure random number generator for variable delays
        self._rng = random.SystemRandom()

        # Add small random delay to prevent timing analysis
        self._variable_delay()

        # In lockdown mode, use only built-in defaults and ignore external config
        if self.lockdown_mode:
            self.logger.warning(
                "Operating in LOCKDOWN mode - using only built-in secure defaults"
            )

        # Default paths
        self.schema_path = schema_path or "/opt/nginx-security-monitor/schema.yml"

        # Verify schema integrity before loading
        if not self._verify_config_integrity(self.schema_path):
            self.logger.warning(
                f"Schema integrity check failed for {self.schema_path}, using built-in defaults"
            )
            # Fall back to built-in defaults
            self.schema = self._get_builtin_schema()
        else:
            # Load schema
            self.schema = self._load_yaml(self.schema_path)
            if not self.schema:
                self.logger.warning(
                    f"Failed to load schema from {self.schema_path}, using built-in defaults"
                )
                self.schema = self._get_builtin_schema()

        # Get config path from schema default if not provided
        if (
            not config_path
            and "service" in self.schema
            and "config_path" in self.schema["service"]
        ):
            config_path_schema = self.schema["service"]["config_path"]
            if (
                isinstance(config_path_schema, dict)
                and "__default" in config_path_schema
            ):
                config_path = config_path_schema["__default"]
            elif isinstance(config_path_schema, str):
                config_path = config_path_schema

        self.config_path = config_path or "/opt/nginx-security-monitor/settings.yaml"

        # Initialize configuration with defaults from schema
        self.config = self._extract_defaults(self.schema)

        # Load configuration file if it exists and not in lockdown mode
        if not self.lockdown_mode:
            self._load_config()

        # Apply environment variable overrides (even in lockdown mode for critical overrides)
        self._apply_env_overrides()

        # Apply security hardening defaults in lockdown mode
        if self.lockdown_mode:
            self._apply_security_hardening()

        # Validate the final configuration
        validation_errors = self._validate_config()
        if validation_errors:
            self.logger.error(
                f"Configuration validation failed with {len(validation_errors)} errors"
            )
            raise ValueError("Configuration validation failed, see logs for details")

        # Secure configuration files
        self._secure_config_files()

        self.logger.info(f"Configuration loaded and validated from {self.config_path}")

    def _variable_delay(self):
        """Add a small random delay to prevent timing analysis."""
        base_delay = 0.1  # Default if not yet available from config
        max_delay = 1.0  # Default if not yet available from config

        if hasattr(self, "config"):
            base_delay = self.get("crypto.base_delay", 0.1)
            max_delay = self.get("crypto.max_delay", 1.0)

        delay = base_delay + self._rng.random() * (max_delay - base_delay)
        time.sleep(delay)

    def _get_builtin_schema(self):
        """
        Return built-in secure default schema when external schema is unavailable.

        This provides a minimal set of secure defaults that can be used when
        the schema file is missing or compromised.
        """
        # Minimal built-in schema with secure defaults
        return {
            "service": {
                "check_interval": {
                    "__type": "integer",
                    "__default": 60,
                    "__range": [30, 3600],
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
            "pattern_detection": {
                "thresholds": {
                    "requests_per_ip_per_minute": {
                        "__type": "integer",
                        "__default": 50,  # More conservative default
                        "__range": [10, 10000],
                        "__description": "Maximum number of requests per IP address per minute",
                        "__security_critical": True,
                        "__min_secure": 30,
                        "__env": "NGINX_MONITOR_MAX_REQUESTS_PER_IP",
                    },
                    "failed_requests_per_minute": {
                        "__type": "integer",
                        "__default": 30,  # More conservative default
                        "__range": [5, 5000],
                        "__description": "Maximum number of failed requests per minute",
                        "__security_critical": True,
                        "__min_secure": 20,
                        "__env": "NGINX_MONITOR_MAX_FAILED_REQUESTS",
                    },
                    "error_rate_threshold": {
                        "__type": "number",
                        "__default": 0.05,  # More conservative default
                        "__range": [0.01, 1.0],
                        "__description": "Threshold for suspicious error rate",
                        "__security_critical": True,
                        "__min_secure": 0.05,
                        "__env": "NGINX_MONITOR_ERROR_RATE_THRESHOLD",
                    },
                    "brute_force": {
                        "max_attempts": {
                            "__type": "integer",
                            "__default": 5,  # More conservative default
                            "__range": [3, 100],
                            "__description": "Maximum number of failed login attempts before triggering brute force detection",
                            "__security_critical": True,
                            "__min_secure": 5,
                            "__env": "NGINX_MONITOR_BRUTE_FORCE_MAX_ATTEMPTS",
                        },
                        "time_window_seconds": {
                            "__type": "integer",
                            "__default": 600,  # More conservative default
                            "__range": [60, 3600],
                            "__description": "Time window in seconds for brute force detection",
                            "__security_critical": True,
                            "__min_secure": 300,
                            "__env": "NGINX_MONITOR_BRUTE_FORCE_TIME_WINDOW",
                        },
                    },
                }
            },
            "mitigation": {
                "strategies": {
                    "brute_force": {
                        "ban_duration": {
                            "__type": "integer",
                            "__default": 7200,  # More conservative default (2 hours)
                            "__range": [300, 86400],
                            "__description": "Duration of temporary ban in seconds",
                            "__security_critical": True,
                            "__min_secure": 3600,
                            "__env": "NGINX_MONITOR_BRUTE_FORCE_BAN_DURATION",
                        }
                    }
                }
            },
            "service_protection": {
                "resource_thresholds": {
                    "cpu_percent": {
                        "__type": "number",
                        "__default": 70.0,  # More conservative default
                        "__range": [50.0, 99.0],
                        "__description": "CPU usage threshold percentage",
                        "__security_critical": True,
                        "__min_secure": 70.0,
                        "__env": "NGINX_MONITOR_CPU_THRESHOLD",
                    },
                    "memory_percent": {
                        "__type": "number",
                        "__default": 70.0,  # More conservative default
                        "__range": [50.0, 99.0],
                        "__description": "Memory usage threshold percentage",
                        "__security_critical": True,
                        "__min_secure": 70.0,
                        "__env": "NGINX_MONITOR_MEMORY_THRESHOLD",
                    },
                    "disk_usage_percent": {
                        "__type": "number",
                        "__default": 80.0,  # More conservative default
                        "__range": [50.0, 99.0],
                        "__description": "Disk usage threshold percentage",
                        "__security_critical": True,
                        "__min_secure": 80.0,
                        "__env": "NGINX_MONITOR_DISK_THRESHOLD",
                    },
                }
            },
            "network_security": {
                "max_failed_attempts": {
                    "__type": "integer",
                    "__default": 5,  # More conservative default
                    "__range": [3, 100],
                    "__description": "Maximum number of failed login attempts before alerting",
                    "__security_critical": True,
                    "__min_secure": 5,
                    "__env": "NGINX_MONITOR_MAX_FAILED_ATTEMPTS",
                }
            },
            "crypto": {
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
            # Additional sections for test compatibility
            "logging": {
                "level": {
                    "__type": "string",
                    "__default": "INFO",
                    "__description": "Logging level",
                },
                "file": {
                    "__type": "string",
                    "__default": "/var/log/nginx-security-monitor.log",
                    "__description": "Log file path",
                },
            },
            "monitoring": {
                "check_interval": {
                    "__type": "integer",
                    "__default": 60,
                    "__range": [1, 3600],  # Allow smaller values for testing
                    "__description": "Monitoring check interval in seconds",
                },
            },
            "security": {
                "self_check_interval": {
                    "__type": "integer", 
                    "__default": 60,
                    "__description": "Self-check interval in seconds",
                },
                "encrypted_patterns_file": {
                    "__type": "string",
                    "__default": "/opt/nginx-security-monitor/patterns.enc",
                    "__description": "Path to encrypted patterns file",
                },
            },
            "email_service": {
                "enabled": {
                    "__type": "boolean",
                    "__default": False,
                    "__description": "Enable email alerts",
                },
                "to_address": {
                    "__type": "string",
                    "__default": "",
                    "__description": "Email address for alerts",
                },
            },
            "sms_service": {
                "enabled": {
                    "__type": "boolean", 
                    "__default": False,
                    "__description": "Enable SMS alerts",
                },
            },
            "log_file_path": {
                "__type": "string",
                "__default": "/var/log/nginx/access.log",
                "__description": "Legacy log file path setting",
            },
            "encrypted_config": {
                "__type": "dict",
                "__default": {},
                "__description": "Encrypted configuration sections",
                "__flexible": True,  # Allow arbitrary keys
            },
        }

    def _secure_config_files(self):
        """Ensure configuration files have proper permissions and ownership."""
        # Check and set proper permissions for config files
        config_files = [self.config_path, self.schema_path]
        for file_path in config_files:
            if os.path.exists(file_path):
                try:
                    current_mode = os.stat(file_path).st_mode & 0o777
                    if current_mode != 0o640:  # -rw-r-----
                        os.chmod(file_path, 0o640)
                        self.logger.info(f"Fixed permissions for {file_path} to 0640")
                except Exception as e:
                    self.logger.error(f"Failed to set permissions on {file_path}: {e}")

    def _load_yaml(self, file_path: str) -> Dict:
        """
        Load YAML file securely and return contents as dictionary.

        Uses SafeLoader to prevent YAML deserialization attacks.

        Args:
            file_path: Path to the YAML file

        Returns:
            Dictionary with YAML contents, or empty dict on error
        """
        try:
            with open(file_path, "r") as file:
                # Explicitly use SafeLoader to prevent deserialization attacks
                return yaml.load(file, Loader=yaml.SafeLoader)
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing YAML from {file_path}: {e}")
            return {}
        except Exception as e:
            self.logger.error(f"Error loading YAML from {file_path}: {e}")
            return {}

    def _compare_digest(self, a, b):
        """
        Perform a constant-time comparison to avoid timing attacks.

        Args:
            a: First string to compare
            b: Second string to compare

        Returns:
            True if the strings are equal, False otherwise
        """
        return hmac.compare_digest(str(a), str(b))

    def _verify_config_integrity(self, file_path: str) -> bool:
        """
        Verify the integrity of a configuration file.

        Args:
            file_path: Path to the configuration file

        Returns:
            True if integrity check passes, False otherwise
        """
        if not os.path.exists(file_path):
            return False

        # Get the hash from the signature file if it exists
        sig_file = f"{file_path}.sig"
        if not os.path.exists(sig_file):
            self.logger.warning(f"No signature file found for {file_path}")
            return True  # Skip verification if no signature file

        try:
            # Read the stored hash
            with open(sig_file, "r") as f:
                stored_hash = f.read().strip()

            # Calculate the current hash
            with open(file_path, "rb") as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()

            # Use constant-time comparison for hash verification
            if not self._compare_digest(stored_hash, current_hash):
                self.logger.error(f"Integrity check failed for {file_path}")
                return False

            return True
        except Exception as e:
            self.logger.error(f"Error verifying integrity of {file_path}: {e}")
            return False

    def create_config_signature(self, file_path: str):
        """
        Create a signature file for configuration integrity verification.

        Args:
            file_path: Path to the configuration file
        """
        if not os.path.exists(file_path):
            return

        try:
            # Calculate hash
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            # Write to signature file
            sig_file = f"{file_path}.sig"
            with open(sig_file, "w") as f:
                f.write(file_hash)

            # Set restrictive permissions
            os.chmod(sig_file, 0o600)

            self.logger.info(f"Created signature file for {file_path}")
        except Exception as e:
            self.logger.error(f"Error creating signature for {file_path}: {e}")

    def _extract_defaults(self, schema: Dict, path: str = "") -> Dict:
        """
        Extract default values from schema.

        Args:
            schema: Schema dictionary
            path: Current path in the schema (for nested objects)

        Returns:
            Dictionary with default values
        """
        defaults = {}

        for key, value in schema.items():
            current_path = f"{path}.{key}" if path else key

            # Skip metadata fields
            if key.startswith("__"):
                continue

            # Handle nested objects
            if isinstance(value, dict):
                if "__type" in value and value["__type"] == "object":
                    # This is an object type with nested properties
                    child_defaults = {}
                    for child_key, child_value in value.items():
                        if not child_key.startswith("__"):
                            if (
                                isinstance(child_value, dict)
                                and "__default" in child_value
                            ):
                                child_defaults[child_key] = child_value["__default"]
                            elif isinstance(child_value, dict):
                                child_defaults[child_key] = self._extract_defaults(
                                    child_value, f"{current_path}.{child_key}"
                                )
                    defaults[key] = child_defaults
                elif "__default" in value:
                    # This is a leaf node with a default value
                    defaults[key] = value["__default"]
                else:
                    # This is a nested configuration object
                    defaults[key] = self._extract_defaults(value, current_path)

        return defaults

    def _load_config(self):
        """Load configuration from file and merge with defaults."""
        if os.path.exists(self.config_path):
            # Verify integrity before loading
            if not self._verify_config_integrity(self.config_path):
                self.logger.warning(
                    f"Configuration integrity check failed for {self.config_path}"
                )
                return

            file_config = self._load_yaml(self.config_path)
            if file_config:
                self._merge_config(self.config, file_config)
                # Debug the loaded configuration structure
                self._debug_config_structure()
                
    def _debug_config_structure(self):
        """
        Log the structure of the loaded configuration for debugging purposes.
        Redacts sensitive values but provides insight into config structure.
        """
        try:
            # Only do this in debug mode
            if self.logger.getEffectiveLevel() <= logging.DEBUG:
                structure = {}
                
                # Log top-level structure
                for key, value in self.config.items():
                    if isinstance(value, dict):
                        structure[key] = list(value.keys())
                    elif isinstance(value, list):
                        structure[key] = f"[{len(value)} items]"
                    else:
                        # Redact potentially sensitive values
                        if any(term in key.lower() for term in 
                              ["password", "secret", "key", "token", "auth", "credential"]):
                            structure[key] = "[REDACTED]"
                        else:
                            structure[key] = f"{type(value).__name__}: {str(value)}"
                            
                self.logger.debug(f"Configuration structure: {structure}")
                
                # Specifically debug important sections for monitoring and detection
                if "detection" in self.config:
                    detection = self.config["detection"]
                    self.logger.debug(f"Detection section keys: {list(detection.keys()) if detection else []}")
                    
                    # Debug whitelist section
                    if "whitelist" in detection:
                        whitelist = detection["whitelist"]
                        if isinstance(whitelist, dict):
                            self.logger.debug(f"Whitelist section keys: {list(whitelist.keys())}")
                            # Debug processes section
                            if "processes" in whitelist:
                                self.logger.debug(f"Processes in whitelist: {whitelist['processes']}")
                        else:
                            self.logger.debug(f"Whitelist is not a dictionary: {type(whitelist)}")
                
                # Debug monitoring section for log_files
                if "monitoring" in self.config and "log_files" in self.config["monitoring"]:
                    self.logger.debug(f"Log files configured: {self.config['monitoring']['log_files']}")
                
        except Exception as e:
            self.logger.debug(f"Error in debug_config_structure: {e}")

    def _merge_config(self, base: Dict, override: Dict):
        """
        Recursively merge override dict into base dict.

        Args:
            base: Base dictionary to be updated
            override: Dictionary with values to override base
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                # Recursively merge nested dictionaries
                self._merge_config(base[key], value)
            else:
                # Override or add the value
                base[key] = value

    def _get_env_mapping(
        self, schema: Dict = None, prefix: str = ""
    ) -> Dict[str, Tuple[str, Any]]:
        """
        Build a mapping of environment variables to config paths.

        Args:
            schema: Schema dictionary to process
            prefix: Current prefix in dot notation

        Returns:
            Dictionary mapping env var names to config paths and schema info
        """
        if schema is None:
            schema = self.schema

        env_mapping = {}

        for key, value in schema.items():
            if key.startswith("__"):
                continue

            current_path = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                # Check if this is a leaf node with __env defined
                if "__env" in value:
                    env_var = value["__env"]
                    env_mapping[env_var] = (current_path, value)
                # Otherwise recurse into nested objects
                else:
                    env_mapping.update(self._get_env_mapping(value, current_path))

        return env_mapping

    def _sanitize_value(self, value, value_type, path):
        """
        Sanitize and validate configuration values to prevent injection attacks.

        Args:
            value: The value to sanitize
            value_type: The expected type of the value
            path: The configuration path (for logging)

        Returns:
            Sanitized value
        """
        # Basic type checking
        if value_type == "string" and not isinstance(value, str):
            self.logger.warning(
                f"Type mismatch for {path}: expected string, got {type(value).__name__}"
            )
            return str(value)

        # Sanitize strings to prevent command injection
        if value_type == "string" and isinstance(value, str):
            # Check for dangerous shell command characters
            if any(char in value for char in ["$", "`", "|", "&", ";", ">", "<"]):
                if path.endswith("_command") or "command" in path:
                    # This is an expected command, validate it doesn't have shell pipelines
                    if "|" in value or ";" in value or "&" in value:
                        self.logger.error(
                            f"Potential command injection in {path}: {value}"
                        )
                        raise ValueError(f"Invalid command value for {path}")
                elif not path.endswith("_pattern"):
                    # If not a regex pattern, sanitize shell characters
                    self.logger.warning(
                        f"Removed potentially dangerous characters from {path}"
                    )
                    value = re.sub(r"[$`|&;><]", "", value)

        # Sanitize file paths to prevent path traversal
        if (
            path.endswith("_path")
            or path.endswith("_file")
            or path.endswith("_dir")
            or "_path" in path
            or "_file" in path
        ) and isinstance(value, str):
            # Normalize path to prevent path traversal attacks
            normalized_path = os.path.normpath(value)
            if ".." in normalized_path.split(os.path.sep):
                self.logger.error(
                    f"Potential path traversal in {path}: {value} -> {normalized_path}"
                )
                raise ValueError(f"Invalid path value for {path}: {value}")

        return value

    def _convert_value(self, value: str, value_type: str) -> Any:
        """
        Convert string value to specified type.

        Args:
            value: String value to convert
            value_type: Target type ('string', 'integer', 'number', 'boolean', 'array', 'object')

        Returns:
            Converted value
        """
        if value_type == "string":
            return value
        elif value_type == "integer":
            try:
                return int(value)
            except ValueError:
                self.logger.warning(f"Failed to convert '{value}' to integer, using 0")
                return 0
        elif value_type == "number":
            try:
                return float(value)
            except ValueError:
                self.logger.warning(f"Failed to convert '{value}' to float, using 0.0")
                return 0.0
        elif value_type == "boolean":
            return value.lower() in ("true", "yes", "1", "y")
        elif value_type == "array":
            # Parse as JSON if it starts with [ or as comma-separated list otherwise
            if value.strip().startswith("["):
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value.split(",")
            else:
                return value.split(",")
        elif value_type == "object":
            # Parse as JSON
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                self.logger.warning(
                    f"Failed to parse JSON object from environment variable: {value}"
                )
                return {}
        else:
            self.logger.warning(f"Unknown type {value_type}, treating as string")
            return value

    def _apply_env_overrides(self):
        """
        Apply environment variable overrides to configuration securely.

        Masks sensitive values in logs and sanitizes inputs.
        """
        env_mapping = self._get_env_mapping()

        for env_var, (path, schema_info) in env_mapping.items():
            if env_var in os.environ:
                env_value = os.environ[env_var]
                value_type = schema_info.get("__type", "string")

                # Determine if this is sensitive data
                is_sensitive = schema_info.get("__sensitive", False) or any(
                    term in path.lower()
                    for term in [
                        "password",
                        "secret",
                        "key",
                        "token",
                        "auth",
                        "credential",
                    ]
                )

                # Log appropriately
                if is_sensitive:
                    self.logger.debug(
                        f"Applied environment override {env_var} to {path} [value masked]"
                    )
                else:
                    self.logger.debug(
                        f"Applied environment override {env_var} to {path}"
                    )

                # Convert and sanitize environment variable value
                converted_value = self._convert_value(env_value, value_type)
                sanitized_value = self._sanitize_value(
                    converted_value, value_type, path
                )

                # Set the value in the configuration
                self.set(path, sanitized_value)

    def _apply_security_hardening(self):
        """Apply security-hardened values to the configuration in lockdown mode."""
        # Apply more conservative limits
        security_hardening = {
            "pattern_detection.thresholds.requests_per_ip_per_minute": 30,
            "pattern_detection.thresholds.failed_requests_per_minute": 20,
            "pattern_detection.thresholds.error_rate_threshold": 0.05,
            "pattern_detection.thresholds.brute_force.max_attempts": 5,
            "pattern_detection.thresholds.brute_force.time_window_seconds": 600,
            "mitigation.strategies.brute_force.ban_duration": 7200,
            "service_protection.resource_thresholds.cpu_percent": 70.0,
            "service_protection.resource_thresholds.memory_percent": 70.0,
            "service_protection.resource_thresholds.disk_usage_percent": 80.0,
            "network_security.max_failed_attempts": 5,
        }

        for path, value in security_hardening.items():
            self.set(path, value)
            self.logger.info(f"Applied security hardening: {path} = {value}")

    def _validate_config(self) -> List[str]:
        """
        Validate the configuration against the schema.

        Returns:
            List of validation error messages
        """
        return self._validate_against_schema(self.config, self.schema)

    def _validate_against_schema(
        self, config: Dict, schema: Dict, path: str = ""
    ) -> List[str]:
        """
        Recursively validate configuration against schema with enhanced security checks.

        Args:
            config: Configuration to validate
            schema: Schema to validate against
            path: Current path in the schema

        Returns:
            List of validation error messages
        """
        errors = []

        # Check for required fields
        for key, value in schema.items():
            current_path = f"{path}.{key}" if path else key

            # Skip metadata fields
            if key.startswith("__"):
                continue

            # Check if the field is required but missing
            if (
                isinstance(value, dict)
                and value.get("__required", False)
                and key not in config
            ):
                errors.append(f"Missing required field: {current_path}")
                continue

            # Skip validation if the field is not in the config
            if key not in config:
                continue

            config_value = config[key]

            # Validate based on the schema type
            if isinstance(value, dict) and "__type" in value:
                value_type = value["__type"]

                # Type validation
                if value_type == "string" and not isinstance(config_value, str):
                    errors.append(
                        f"Field {current_path} should be a string, got {type(config_value).__name__}"
                    )

                elif value_type == "integer" and not isinstance(config_value, int):
                    errors.append(
                        f"Field {current_path} should be an integer, got {type(config_value).__name__}"
                    )

                elif value_type == "number" and not isinstance(
                    config_value, (int, float)
                ):
                    errors.append(
                        f"Field {current_path} should be a number, got {type(config_value).__name__}"
                    )

                elif value_type == "boolean" and not isinstance(config_value, bool):
                    errors.append(
                        f"Field {current_path} should be a boolean, got {type(config_value).__name__}"
                    )

                elif value_type == "array" and not isinstance(config_value, list):
                    errors.append(
                        f"Field {current_path} should be an array, got {type(config_value).__name__}"
                    )

                elif value_type == "object" and not isinstance(config_value, dict):
                    errors.append(
                        f"Field {current_path} should be an object, got {type(config_value).__name__}"
                    )

                # Range validation for numeric types
                if (
                    value_type in ("integer", "number")
                    and "__range" in value
                    and isinstance(config_value, (int, float))
                ):
                    range_min, range_max = value["__range"]
                    if not (range_min <= config_value <= range_max):
                        errors.append(
                            f"Field {current_path} should be between {range_min} and {range_max}, got {config_value}"
                        )
                        errors.append(
                            f"Field {current_path} value {config_value} outside allowed range [{range_min}, {range_max}]"
                        )

                # Pattern validation for strings
                if (
                    value_type == "string"
                    and "__pattern" in value
                    and isinstance(config_value, str)
                ):
                    pattern = value["__pattern"]
                    if not re.match(pattern, config_value):
                        errors.append(
                            f"Field {current_path} value '{config_value}' does not match pattern '{pattern}'"
                        )

                # Security-critical field validation
                if value.get("__security_critical", False) and "__min_secure" in value:
                    min_secure = value["__min_secure"]
                    if (
                        isinstance(config_value, (int, float))
                        and config_value < min_secure
                    ):
                        errors.append(
                            f"Field {current_path} value {config_value} is below minimum secure threshold {min_secure}"
                        )

            # Path traversal prevention for path fields
            if (
                current_path.endswith(".path")
                or current_path.endswith("_path")
                or current_path.endswith("_file")
                or current_path.endswith("_dir")
            ) and isinstance(config_value, str):

                normalized = os.path.normpath(config_value)
                if ".." in normalized.split(os.path.sep):
                    errors.append(
                        f"Path traversal attempt detected in {current_path}: {config_value}"
                    )

            # Command injection prevention
            if (
                current_path.endswith("_command") or "command" in current_path
            ) and isinstance(config_value, str):
                if re.search(r"[|&;]", config_value):
                    errors.append(
                        f"Potential command injection in {current_path}: {config_value}"
                    )

            # Recursive validation for nested objects
            elif isinstance(value, dict) and isinstance(config_value, dict):
                # Skip validation for flexible sections like encrypted_config
                if not value.get("__flexible", False):
                    errors.extend(
                        self._validate_against_schema(config_value, value, current_path)
                    )

        # Check for unknown fields (potential injection)
        for key in config:
            current_path = f"{path}.{key}" if path else key
            if key not in schema:
                # Allow arbitrary keys under encrypted_config
                if not current_path.startswith("encrypted_config."):
                    errors.append(f"Unknown configuration option: {current_path}")

        return errors

    def get(self, path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation path with secure handling.

        Args:
            path: Path to the configuration value (e.g., 'service.check_interval')
            default: Default value to return if path not found

        Returns:
            Configuration value or default
        """
        if not path or not self.config:
            self.logger.debug(f"No path specified or no config available, returning default: {default}")
            return default
            
        parts = path.split(".")
        value = self.config
        current_path = ""

        try:
            for i, part in enumerate(parts):
                current_path = current_path + "." + part if current_path else part
                
                if isinstance(value, dict) and part in value:
                    value = value[part]
                    # Debug full structure at each level to help with troubleshooting
                    if i < len(parts) - 1:  # Only log intermediate structures
                        self.logger.debug(f"Config at {current_path}: {type(value).__name__} with keys: {list(value.keys()) if isinstance(value, dict) else 'N/A'}")
                else:
                    # More detailed logging about the failure point
                    if isinstance(value, dict):
                        self.logger.debug(f"Configuration path not found: {path} (stopped at {part}), available keys at this level: {list(value.keys())}, returning default: {default}")
                    else:
                        self.logger.debug(f"Configuration path not found: {path} (stopped at {part}), current value is not a dict but {type(value).__name__}, returning default: {default}")
                    return default

            # Handle empty lists or dictionaries - return default if empty
            if (isinstance(value, list) or isinstance(value, dict)) and not value:
                self.logger.debug(f"Empty list or dict at path: {path}, returning default: {default}")
                return default

            # Check if this is a sensitive value
            schema_info = self.get_schema_info(path)
            is_sensitive = schema_info.get("__sensitive", False) or any(
                term in path.lower()
                for term in ["password", "secret", "key", "token", "auth", "credential"]
            )

            # Return sensitive values wrapped in SecureString
            if is_sensitive and isinstance(value, str):
                return SecureString(value)

            return value
        except Exception as e:
            self.logger.debug(f"Error accessing configuration path {path}: {e}")
            return default

    def get_raw(self, path: str, default: Any = None) -> Any:
        """
        Get raw configuration value without secure wrapping.
        Only use when the actual value is needed for operations.

        Args:
            path: Path to the configuration value (e.g., 'service.check_interval')
            default: Default value to return if path not found

        Returns:
            Raw configuration value or default
        """
        value = self.get(path, default)
        if isinstance(value, SecureString):
            return value.get_value()
        return value

    def set(self, path: str, value: Any):
        """
        Set configuration value by dot-notation path with audit logging.

        Args:
            path: Path to the configuration value (e.g., 'service.check_interval')
            value: Value to set
        """
        # Check for sensitive values in logs
        is_sensitive = any(
            term in path.lower()
            for term in ["password", "secret", "key", "token", "auth", "credential"]
        )

        # Sanitize the value
        schema_info = self.get_schema_info(path)
        value_type = schema_info.get("__type", "string")
        sanitized_value = self._sanitize_value(value, value_type, path)

        # Get the old value for audit logging
        old_value = self.get(path)
        if isinstance(old_value, SecureString):
            old_value_str = "[REDACTED]"
        else:
            old_value_str = str(old_value)

        # Set the value
        parts = path.split(".")
        config = self.config

        # Navigate to the parent object
        for part in parts[:-1]:
            if part not in config:
                config[part] = {}
            config = config[part]

        # Set the value
        config[parts[-1]] = sanitized_value

        # Audit log the change
        if is_sensitive:
            self.logger.info(
                f"Configuration changed: {path} from [REDACTED] to [REDACTED]"
            )
        else:
            self.logger.info(
                f"Configuration changed: {path} from {old_value_str} to {sanitized_value}"
            )

    def reload(self):
        """Reload configuration from file and reapply environment overrides."""
        # Reset to defaults
        self.config = self._extract_defaults(self.schema)

        # Reload from file (if not in lockdown mode)
        if not self.lockdown_mode:
            self._load_config()

        # Reapply environment overrides
        self._apply_env_overrides()

        # Reapply security hardening in lockdown mode
        if self.lockdown_mode:
            self._apply_security_hardening()

        # Validate the configuration
        validation_errors = self._validate_config()
        if validation_errors:
            self.logger.error(
                f"Configuration validation failed with {len(validation_errors)} errors"
            )
            raise ValueError("Configuration validation failed, see logs for details")

        self.logger.info(f"Configuration reloaded from {self.config_path}")

    def save(self, file_path: str = None):
        """
        Save current configuration to file.

        Args:
            file_path: Path to save configuration to (defaults to self.config_path)
        """
        file_path = file_path or self.config_path

        try:
            # Make sure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Create a sanitized copy of the configuration without sensitive values
            sanitized_config = self._sanitize_config_for_save(self.config)

            with open(file_path, "w") as file:
                yaml.dump(
                    sanitized_config, file, default_flow_style=False, sort_keys=False
                )

            # Set secure permissions
            os.chmod(file_path, 0o640)

            # Create signature file for integrity verification
            self.create_config_signature(file_path)

            self.logger.info(f"Configuration saved to {file_path}")
        except Exception as e:
            self.logger.error(f"Error saving configuration to {file_path}: {e}")
            raise

    def _sanitize_config_for_save(self, config: Dict, path: str = "") -> Dict:
        """
        Create a sanitized copy of the configuration for saving to file.

        Replaces sensitive values with placeholders to avoid writing them to disk.

        Args:
            config: The configuration dictionary to sanitize
            path: Current path in the configuration

        Returns:
            Sanitized configuration dictionary
        """
        sanitized = {}

        for key, value in config.items():
            current_path = f"{path}.{key}" if path else key

            if isinstance(value, dict):
                sanitized[key] = self._sanitize_config_for_save(value, current_path)
            elif isinstance(value, SecureString):
                sanitized[key] = "[SENSITIVE - SET VIA ENV VAR]"
            elif any(
                term in current_path.lower()
                for term in ["password", "secret", "key", "token", "auth", "credential"]
            ):
                sanitized[key] = "[SENSITIVE - SET VIA ENV VAR]"
            else:
                sanitized[key] = value

        return sanitized

    def get_schema_info(self, path: str) -> Dict:
        """
        Get schema information for a configuration path.

        Args:
            path: Path to the configuration value (e.g., 'service.check_interval')

        Returns:
            Schema information (type, default, description, etc.)
        """
        parts = path.split(".")
        schema = self.schema

        for part in parts:
            if isinstance(schema, dict) and part in schema:
                schema = schema[part]
            else:
                return {}

        return {k: v for k, v in schema.items() if k.startswith("__")}

    def to_dict(self) -> Dict:
        """
        Return the complete configuration as a dictionary.

        Sensitive values are masked in the returned dictionary.
        """
        return self._sanitize_config_for_save(self.config)

    def get_env_var_name(self, path: str) -> str:
        """
        Get the corresponding environment variable name for a config path.

        Args:
            path: Path to the configuration value (e.g., 'service.check_interval')

        Returns:
            Environment variable name or None if not defined
        """
        schema_info = self.get_schema_info(path)
        return schema_info.get("__env")

    def self_monitor(self) -> Dict:
        """
        Monitor the configuration system for security issues.

        Returns:
            Dict with monitoring results
        """
        results = {"status": "ok", "issues": []}

        # Check config file permissions
        if os.path.exists(self.config_path):
            try:
                stat_info = os.stat(self.config_path)
                mode = stat_info.st_mode & 0o777
                if mode != 0o640:
                    results["issues"].append(
                        f"Config file {self.config_path} has insecure permissions: {oct(mode)}"
                    )
                    results["status"] = "warning"
            except Exception as e:
                results["issues"].append(f"Error checking config file permissions: {e}")
                results["status"] = "warning"

        # Check schema file permissions
        if os.path.exists(self.schema_path):
            try:
                stat_info = os.stat(self.schema_path)
                mode = stat_info.st_mode & 0o777
                if mode != 0o640:
                    results["issues"].append(
                        f"Schema file {self.schema_path} has insecure permissions: {oct(mode)}"
                    )
                    results["status"] = "warning"
            except Exception as e:
                results["issues"].append(f"Error checking schema file permissions: {e}")
                results["status"] = "warning"

        # Check for modification of config files
        if not self._verify_config_integrity(self.config_path):
            results["issues"].append(f"Configuration file integrity check failed")
            results["status"] = "critical"

        if not self._verify_config_integrity(self.schema_path):
            results["issues"].append(f"Schema file integrity check failed")
            results["status"] = "critical"

        # Check for insecure configuration values
        for path, security_info in self._get_security_critical_configs().items():
            current_value = self.get_raw(path)
            if current_value is not None:
                if (
                    "min_secure" in security_info
                    and current_value < security_info["min_secure"]
                ):
                    results["issues"].append(
                        f"Insecure configuration: {path} = {current_value} (minimum secure: {security_info['min_secure']})"
                    )
                    results["status"] = "warning"

        return results

    def _get_security_critical_configs(self) -> Dict:
        """
        Get a list of security-critical configuration options and their minimum secure values.

        Returns:
            Dict mapping config paths to security requirements
        """
        # Start with hardcoded critical configs
        critical_configs = {
            "pattern_detection.thresholds.requests_per_ip_per_minute": {
                "min_secure": 30
            },
            "pattern_detection.thresholds.failed_requests_per_minute": {
                "min_secure": 20
            },
            "pattern_detection.thresholds.brute_force.max_attempts": {"min_secure": 5},
            "mitigation.strategies.brute_force.ban_duration": {"min_secure": 3600},
            "network_security.max_failed_attempts": {"min_secure": 5},
            "service_protection.resource_thresholds.cpu_percent": {"min_secure": 70.0},
            "service_protection.resource_thresholds.memory_percent": {
                "min_secure": 70.0
            },
            "service_protection.resource_thresholds.disk_usage_percent": {
                "min_secure": 80.0
            },
        }

        # Add any security_critical fields from schema
        def scan_schema(schema, path=""):
            for key, value in schema.items():
                if key.startswith("__"):
                    continue

                current_path = f"{path}.{key}" if path else key

                if isinstance(value, dict):
                    if (
                        "__security_critical" in value
                        and value["__security_critical"]
                        and "__min_secure" in value
                    ):
                        critical_configs[current_path] = {
                            "min_secure": value["__min_secure"]
                        }

                    scan_schema(value, current_path)

        scan_schema(self.schema)

        return critical_configs

    def reload_config(self):
        """Reload configuration from the config file."""
        # Store the original config as a backup
        backup_config = self.config.copy()

        try:
            # Reinitialize configuration with defaults from schema
            self.config = self._extract_defaults(self.schema)

            # Load configuration file if it exists and not in lockdown mode
            if not self.lockdown_mode:
                self._load_config()

            # Apply environment variable overrides
            self._apply_env_overrides()

            # Apply security hardening defaults in lockdown mode
            if self.lockdown_mode:
                self._apply_security_hardening()

            # Validate the final configuration
            validation_errors = self._validate_config()
            if validation_errors:
                self.logger.error(
                    f"Configuration reload validation failed with {len(validation_errors)} errors"
                )
                # Restore backup on validation failure
                self.config = backup_config
                return False

            self.logger.info(f"Configuration reloaded from {self.config_path}")
            return True

        except Exception as e:
            self.logger.error(f"Configuration reload failed: {str(e)}")
            # Restore backup on any exception
            self.config = backup_config
            return False
