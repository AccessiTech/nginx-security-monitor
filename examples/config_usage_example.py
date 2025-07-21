#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Example module demonstrating ConfigManager usage

This module shows how to use the ConfigManager in a typical module.
It demonstrates:
1. Importing and getting a ConfigManager instance
2. Accessing configuration values
3. Using fallbacks for missing values
4. Working with different data types
5. Handling sensitive data
"""

import logging
from typing import Dict, Any

# Import the ConfigManager
from src.config_manager import ConfigManager

# Get a ConfigManager instance (singleton)
config = ConfigManager.get_instance()

# Configure logging
logger = logging.getLogger("nginx-security-monitor.example")


def get_pattern_detection_settings() -> Dict[str, Any]:
    """
    Get settings for pattern detection.

    Returns:
        Dictionary of pattern detection settings
    """
    settings = {}

    # Get thresholds with fallbacks
    settings["requests_per_ip_per_minute"] = config.get(
        "pattern_detection.thresholds.requests_per_ip_per_minute", 100
    )
    settings["failed_requests_per_minute"] = config.get(
        "pattern_detection.thresholds.failed_requests_per_minute", 50
    )
    settings["error_rate_threshold"] = config.get(
        "pattern_detection.thresholds.error_rate_threshold", 0.1
    )

    # Get brute force settings
    brute_force = {}
    brute_force["max_attempts"] = config.get(
        "pattern_detection.thresholds.brute_force.max_attempts", 10
    )
    brute_force["time_window_seconds"] = config.get(
        "pattern_detection.thresholds.brute_force.time_window_seconds", 300
    )
    settings["brute_force"] = brute_force

    # Get detection patterns
    settings["sql_injection_patterns"] = config.get(
        "pattern_detection.sql_injection_patterns", []
    )
    settings["xss_patterns"] = config.get("pattern_detection.xss_patterns", [])
    settings["suspicious_user_agents"] = config.get(
        "pattern_detection.suspicious_user_agents", []
    )

    return settings


def get_email_alert_settings() -> Dict[str, Any]:
    """
    Get settings for email alerts.

    Returns:
        Dictionary of email alert settings
    """
    settings = {}

    # Check if email alerts are enabled
    settings["enabled"] = config.get("alert_system.email.enabled", False)

    if settings["enabled"]:
        # Get email settings
        settings["smtp_server"] = config.get("alert_system.email.smtp_server")
        settings["smtp_port"] = config.get("alert_system.email.smtp_port", 587)
        settings["use_tls"] = config.get("alert_system.email.use_tls", True)
        settings["from_address"] = config.get("alert_system.email.from_address")
        settings["to_address"] = config.get("alert_system.email.to_address")

        # Get sensitive values (username and password)
        # Note: These are handled securely by the ConfigManager
        settings["username"] = config.get("alert_system.email.username")
        settings["password"] = config.get("alert_system.email.password")

    return settings


def get_service_settings() -> Dict[str, Any]:
    """
    Get general service settings.

    Returns:
        Dictionary of service settings
    """
    settings = {}

    # Get check interval with fallback
    settings["check_interval"] = config.get("service.check_interval", 60)

    # Get log file paths
    settings["log_file_path"] = config.get(
        "service.log_file_path", "/var/log/nginx/access.log"
    )
    settings["error_log_file_path"] = config.get(
        "service.error_log_file_path", "/var/log/nginx/error.log"
    )

    return settings


def example_usage():
    """Example function demonstrating ConfigManager usage."""
    # Get settings
    pattern_settings = get_pattern_detection_settings()
    email_settings = get_email_alert_settings()
    service_settings = get_service_settings()

    # Log settings (except sensitive values)
    logger.info("Pattern Detection Settings:")
    logger.info(
        f"  Requests per IP per minute: {pattern_settings['requests_per_ip_per_minute']}"
    )
    logger.info(
        f"  Failed requests per minute: {pattern_settings['failed_requests_per_minute']}"
    )
    logger.info(f"  Error rate threshold: {pattern_settings['error_rate_threshold']}")
    logger.info(
        f"  Brute force max attempts: {pattern_settings['brute_force']['max_attempts']}"
    )
    logger.info(
        f"  Brute force time window: {pattern_settings['brute_force']['time_window_seconds']} seconds"
    )

    logger.info("Email Alert Settings:")
    logger.info(f"  Enabled: {email_settings['enabled']}")
    if email_settings["enabled"]:
        logger.info(f"  SMTP Server: {email_settings['smtp_server']}")
        logger.info(f"  SMTP Port: {email_settings['smtp_port']}")
        logger.info(f"  Use TLS: {email_settings['use_tls']}")
        logger.info(f"  From Address: {email_settings['from_address']}")
        logger.info(f"  To Address: {email_settings['to_address']}")
        # Note: Do not log sensitive values like username and password

    logger.info("Service Settings:")
    logger.info(f"  Check Interval: {service_settings['check_interval']} seconds")
    logger.info(f"  Log File Path: {service_settings['log_file_path']}")
    logger.info(f"  Error Log File Path: {service_settings['error_log_file_path']}")

    # Example of checking lockdown mode
    if config.is_in_lockdown_mode():
        logger.warning("System is in LOCKDOWN mode - using secure defaults only")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Run the example
    example_usage()
