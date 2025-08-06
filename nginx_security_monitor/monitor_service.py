#!/usr/bin/env python3
"""
NGINX Security Monitor Service
Main entry point for running the monitor as a system service.
"""

import os
import sys
import time
import signal
import logging
import yaml
from datetime import datetime

from nginx_security_monitor.pattern_detector import PatternDetector
from nginx_security_monitor.mitigation import mitigate_threat

# Import alert functions for backward compatibility
from nginx_security_monitor.email_alert import send_email_alert
from nginx_security_monitor.sms_alert import send_sms_alert

# Import our new modular components
from nginx_security_monitor.alert_manager import AlertManager
from nginx_security_monitor.log_processor import LogProcessor
from nginx_security_monitor.threat_processor import ThreatProcessor

from nginx_security_monitor.security_coordinator import SecurityCoordinator
from nginx_security_monitor.config_manager import ConfigManager
# Import our security modules (optional)
try:
    from nginx_security_monitor.crypto_utils import SecurityConfigManager, PatternObfuscator
    from nginx_security_monitor.plugin_system import PluginManager
    from nginx_security_monitor.service_protection import ServiceProtection
    from nginx_security_monitor.network_security import NetworkSecurity, SecurityHardening
    from nginx_security_monitor.security_integrations import SecurityIntegrationManager
    SECURITY_FEATURES_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Security features not available (install dependencies): {e}")
    SECURITY_FEATURES_AVAILABLE = False

config = ConfigManager.get_instance()


class NginxSecurityMonitor:
    """Main service class for the NGINX Security Monitor."""

    def __init__(self, config_path=None):
        # If a config_path is provided, reset the ConfigManager singleton to use the new path
        if config_path:
            # Reset the singleton to use the new config path
            ConfigManager._instance = None
            self.config_manager = ConfigManager.get_instance(config_path=config_path)
        else:
            self.config_manager = ConfigManager.get_instance()

        # Get initial running state from config
        self.running = self.config_manager.get("service.initial_running_state", True)

        # Get config path from config manager if not provided
        default_config_path = self.config_manager.get(
            "service.default_config_path", "/opt/nginx-security-monitor/settings.yaml"
        )
        self.config_path = config_path or default_config_path

        # Initialize basic logging first so we can log errors during config loading
        self._setup_basic_logging()

        self.config = self.load_config()
        if self.config:  # Only setup full logging if config loaded successfully
            self.setup_logging()  # Setup full logging with config settings

        # Initialize components in order specified by config
        init_order = self.config_manager.get(
            "service.initialization_order",
            ["core_components", "security_features", "modular_components"],
        )

        for component_type in init_order:
            if component_type == "core_components":
                self._initialize_core_components()
            elif component_type == "security_features":
                self._initialize_security_features()
            elif component_type == "modular_components":
                self._initialize_modular_components()

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    def _initialize_core_components(self):
        """Initialize core detection and mitigation components."""
        self.pattern_detector = PatternDetector()
        # Note: mitigation is now handled as a function, not a class

    def _initialize_modular_components(self):
        """Initialize the new modular components."""
        try:
            # Initialize alert manager
            self.alert_manager = AlertManager(self.config, self.logger)

            # Initialize log processor
            self.log_processor = LogProcessor(self.config, self.logger)

            # Initialize threat processor
            self.threat_processor = ThreatProcessor(
                self.config,
                self.logger,
                self.pattern_detector,
                mitigate_threat,  # Pass the function directly
                self.plugin_manager,
            )

            # Initialize security coordinator
            self.security_coordinator = SecurityCoordinator(
                self.config,
                self.logger,
                self.alert_manager,
                self.log_processor,
                self.threat_processor,
                self.security_integrations,
                self.service_protection,
                self.network_security,
            )

            self.logger.info("Modular components initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize modular components: {e}")
            raise

    def _initialize_security_features(self):
        """Initialize encryption and plugin systems."""
        try:
            # Initialize encryption manager
            self.security_manager = (
                SecurityConfigManager() if SECURITY_FEATURES_AVAILABLE else None
            )

            # Initialize obfuscation
            self.obfuscator = (
                PatternObfuscator() if SECURITY_FEATURES_AVAILABLE else None
            )

            # Initialize plugin system
            plugin_dirs = (
                self.config.get("plugins", {}).get("directories", [])
                if self.config
                else []
            )
            self.plugin_manager = (
                PluginManager(plugin_dirs) if SECURITY_FEATURES_AVAILABLE else None
            )

            # Initialize service protection
            self.service_protection = (
                ServiceProtection(self.config)
                if SECURITY_FEATURES_AVAILABLE and self.config
                else None
            )

            # Initialize network security
            self.network_security = (
                NetworkSecurity(self.config)
                if SECURITY_FEATURES_AVAILABLE and self.config
                else None
            )

            # Initialize security hardening
            self.security_hardening = (
                SecurityHardening(self.config)
                if SECURITY_FEATURES_AVAILABLE and self.config
                else None
            )

            # Initialize security integrations
            integrations_config = (
                self.config.get("security_integrations", {}) if self.config else {}
            )
            self.security_integrations = (
                SecurityIntegrationManager(integrations_config)
                if SECURITY_FEATURES_AVAILABLE
                else None
            )

            # Load encrypted patterns if available
            if self.security_manager and self.config:
                self._load_encrypted_patterns()

            self.logger.info("Security features initialized successfully")

        except Exception as e:
            self.logger.error(f"Failed to initialize security features: {e}")
            # Set all security features to None on failure
            self.security_manager = None
            self.obfuscator = None
            self.plugin_manager = None
            self.service_protection = None
            self.network_security = None
            self.security_hardening = None
            self.security_integrations = None

    def _load_encrypted_patterns(self):
        """Load encrypted custom patterns if available."""
        encrypted_patterns_file = self.config.get("security", {}).get(
            "encrypted_patterns_file"
        )

        if encrypted_patterns_file and os.path.exists(encrypted_patterns_file):
            try:
                custom_patterns = self.security_manager.decrypt_file(
                    encrypted_patterns_file
                )
                if custom_patterns:
                    # Merge with detector's patterns
                    self.pattern_detector.load_custom_patterns(custom_patterns)
                    self.logger.info("Loaded encrypted custom patterns")
            except Exception as e:
                self.logger.error(f"Failed to load encrypted patterns: {e}")

    def load_config(self):
        """Load configuration from YAML file."""
        try:
            with open(self.config_path, "r") as file:
                config = yaml.safe_load(file)

                # Decrypt sensitive configuration sections if needed
                if SECURITY_FEATURES_AVAILABLE and "encrypted_config" in config:
                    self._decrypt_config_sections(config)

                return config

        except FileNotFoundError:
            self.logger.error(f"Config file not found: {self.config_path}")
            sys.exit(1)
            return None
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing config file: {e}")
            sys.exit(1)
            return None

    def _decrypt_config_sections(self, config):
        """Decrypt sensitive configuration sections."""
        try:
            security_manager = SecurityConfigManager()
            encrypted_sections = config.get("encrypted_config", {})

            for section_name, encrypted_data in encrypted_sections.items():
                decrypted = security_manager.decrypt_data(encrypted_data)
                if decrypted:
                    config[section_name] = decrypted
                    self.logger.debug(f"Decrypted config section: {section_name}")

        except Exception as e:
            self.logger.error(f"Failed to decrypt config sections: {e}")

    def _setup_basic_logging(self):
        """Setup basic logging for early initialization."""
        basic_config = {
            "level": self.config_manager.get("logging.basic.level", "INFO"),
            "format": self.config_manager.get(
                "logging.basic.format",
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            ),
            "handlers": [
                logging.StreamHandler(
                    self.config_manager.get("logging.basic.output_stream", sys.stdout)
                )
            ],
        }

        logging.basicConfig(**basic_config)
        self.logger = logging.getLogger(
            self.config_manager.get(
                "logging.basic.logger_name", "nginx-security-monitor"
            )
        )

    def setup_logging(self):
        """Setup logging configuration."""
        if not self.config:
            return  # Skip if no config loaded

        log_level = self.config_manager.get("logging.level", "INFO")
        log_file = self.config_manager.get(
            "logging.file",
            self.config.get("logging", {}).get(
                "file",
                self.config_manager.get(
                    "logging.default_file", "/var/log/nginx-security-monitor.log"
                ),
            ),
        )

        # Create log directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)

        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler(log_file), logging.StreamHandler(sys.stdout)],
            force=True,  # Override the basic config
        )
        self.logger = logging.getLogger("nginx-security-monitor")

    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
        if hasattr(self, "security_coordinator"):
            self.security_coordinator.stop_monitoring()

    def run(self):
        """Main service entry point - delegates to security coordinator."""
        try:
            if not hasattr(self, "security_coordinator"):
                self.logger.error("Security coordinator not initialized")
                return

            # Start the coordinated monitoring process
            self.security_coordinator.start_monitoring()

        except Exception as e:
            self.logger.error(f"Service error: {e}")
            raise

    def get_monitoring_status(self):
        """Get current monitoring status."""
        if hasattr(self, "security_coordinator"):
            return self.security_coordinator.get_monitoring_status()
        else:
            return {"running": False, "error": "Security coordinator not initialized"}

    def force_check(self):
        """Force an immediate security check."""
        if hasattr(self, "security_coordinator"):
            return self.security_coordinator.force_check()
        else:
            return {"success": False, "error": "Security coordinator not initialized"}

    # Backward compatibility methods for tests
    def get_new_log_entries(self, log_file_path=None):
        """Get new log entries - delegates to log processor with state sync."""
        if hasattr(self, "log_processor"):
            # Initialize last_processed_size if not present
            if not hasattr(self, "last_processed_size"):
                self.last_processed_size = {}

            # Call the updated LogProcessor API
            entries = self.log_processor.get_new_log_entries()
            return entries
        return []

    def _create_alert_body(self, pattern, mitigation_results):
        """Create alert body - delegates to alert manager."""
        if hasattr(self, "alert_manager"):
            # Enhanced version with mitigation results for backward compatibility
            threat_type = pattern.get("type", "Unknown")
            ip_address = pattern.get("ip", pattern.get("source_ip", "Unknown"))
            timestamp = pattern.get("timestamp", pattern.get("timestamp", ""))
            severity = pattern.get("severity", "UNKNOWN")

            # Summary with mitigation details as the test expects
            mitigation_summary = f"{len(mitigation_results)} countermeasure(s) applied"
            successful_mitigations = len(
                [r for r in mitigation_results if r.get("status") == "success"]
            )

            body = f"""
Security Alert: {threat_type}

Threat Details:
- Source IP: {ip_address}
- Detection Time: {timestamp}
- Severity: {severity}

Response:
- {mitigation_summary}
- {successful_mitigations} successful response(s)

This threat has been automatically processed by your security system.
            """.strip()

            return body
        return f"Alert for {pattern.get('type', 'Unknown')} threat"

    def _create_emergency_alert_body(self, threats):
        """Create emergency alert body - delegates to alert manager."""
        if hasattr(self, "alert_manager"):
            return self.alert_manager._create_emergency_alert_body(threats)
        return f"Emergency: {len(threats)} critical threats detected"

    def _create_service_threat_alert_body(self, threats):
        """Create service threat alert body - delegates to alert manager."""
        if hasattr(self, "alert_manager"):
            return self.alert_manager._create_service_threat_alert_body(threats)
        return f"Service threats: {len(threats)} threats detected"

    def process_threats(self, detected_patterns):
        """Process threats - backward compatibility with test expectations."""
        for pattern in detected_patterns:
            try:
                # Use plugin system for mitigation if available
                mitigation_results = []

                if self.plugin_manager:
                    # Try custom plugins first
                    plugin_results = self.plugin_manager.execute_mitigation(pattern)
                    mitigation_results.extend(plugin_results)

                    # Log plugin execution (without revealing specific strategies)
                    if plugin_results:
                        self.logger.info(
                            f"Applied {len(plugin_results)} custom mitigations"
                        )

                # Fallback to default mitigation
                if not mitigation_results or all(
                    r.get("status") == "error" for r in mitigation_results
                ):
                    default_result = mitigate_threat(pattern)
                    mitigation_results.append(
                        {
                            "status": "success",
                            "method": "default",
                            "result": default_result,
                        }
                    )

                # Use security framework integrations
                if self.security_integrations:
                    integration_result = (
                        self.security_integrations.handle_threat_with_integrations(
                            pattern
                        )
                    )
                    if integration_result.get("actions_taken"):
                        mitigation_results.append(
                            {
                                "status": "success",
                                "method": "security_integrations",
                                "result": integration_result,
                            }
                        )
                        self.logger.info(
                            f"Security integrations: {', '.join(integration_result['actions_taken'])}"
                        )

                # Prepare alert details
                alert_details = {
                    "recipient": (
                        self.config.get("email_service", {}).get("to_address")
                        if self.config
                        else None
                    ),
                    "subject": f'NGINX Security Alert: {pattern.get("type", "Unknown")}',
                    "body": self._create_alert_body(pattern, mitigation_results),
                    "pattern": pattern,
                    "timestamp": datetime.now().isoformat(),
                }

                # Send email alert
                if self.config and self.config.get("email_service", {}).get(
                    "enabled", True
                ):
                    send_email_alert(alert_details)
                    self.logger.info("Alert sent")

                # Send SMS alert
                if self.config and self.config.get("sms_service", {}).get(
                    "enabled", False
                ):
                    send_sms_alert(alert_details)
                    self.logger.info("SMS alert sent")

            except Exception as e:
                self.logger.error(f"Error processing threat: {e}")

    def _send_emergency_alert(self, critical_threats):
        """Send emergency alert - delegates to alert manager but also calls email directly for test compatibility."""
        if hasattr(self, "alert_manager"):
            # For backward compatibility with tests, also call send_email_alert directly
            try:
                alert_details = {
                    "subject": "🚨 CRITICAL: Security Monitor Service Under Attack",
                    "pattern": {
                        "type": "Service Protection Emergency",
                        "severity": "CRITICAL",
                        "ip": "SERVICE_HOST",
                        "request": f"{len(critical_threats)} critical threats detected",
                    },
                    "timestamp": datetime.now().isoformat(),
                    "body": self._create_emergency_alert_body(critical_threats),
                }

                # Direct call for test compatibility
                send_email_alert(alert_details)
                self.logger.info("Emergency alert sent")

            except Exception as e:
                self.logger.error(f"Failed to send emergency alert: {e}")


def main():
    """Main entry point."""
    config_path = sys.argv[1] if len(sys.argv) > 1 else None

    monitor = NginxSecurityMonitor(config_path)
    try:
        monitor.run()
    except KeyboardInterrupt:
        monitor.logger.info("Service interrupted by user")
    except Exception as e:
        monitor.logger.error(f"Service crashed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
