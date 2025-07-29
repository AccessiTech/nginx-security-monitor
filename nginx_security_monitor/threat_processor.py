#!/usr/bin/env python3
"""
Threat Processor Module
Handles threat analysis and processing for the NGINX Security Monitor.
"""

from typing import List, Dict, Any
from nginx_security_monitor.config_manager import ConfigManager


config = ConfigManager.get_instance()


class ThreatProcessor:
    """Handles threat detection and processing functionality."""

    def __init__(
        self, config, logger, pattern_detector, mitigation_function, plugin_system
    ):
        """Initialize the threat processor.

        Args:
            config: Configuration dictionary
            logger: Logger instance
            pattern_detector: Pattern detector instance
            mitigation_function: Mitigation function to call
            plugin_system: Plugin system instance
        """
        self.config = config
        self.logger = logger
        self.pattern_detector = pattern_detector
        self.mitigation_function = mitigation_function
        self.plugin_system = plugin_system
        self.config_manager = ConfigManager.get_instance()

    def process_log_entries(
        self, log_entries: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Process log entries for threats and return detected threats.

        Args:
            log_entries: List of parsed log entries

        Returns:
            list: List of detected threats
        """
        threats = []

        for entry in log_entries:
            try:
                # Detect threats using pattern detector
                detected_threats = self.pattern_detector.detect_threats(entry)

                for threat in detected_threats:
                    # Enrich threat with additional context
                    enriched_threat = self._enrich_threat(threat, entry)

                    # Process through plugins
                    plugin_result = self.plugin_system.run_threat_detection_plugins(
                        enriched_threat
                    )
                    if plugin_result:
                        enriched_threat.update(plugin_result)

                    threats.append(enriched_threat)

                    # Apply mitigation if configured
                    if self.config.get("auto_mitigation", False):
                        self._apply_mitigation(enriched_threat)

            except Exception as e:
                self.logger.error(f"Error processing log entry {entry}: {e}")
                continue

        return threats

    def _enrich_threat(
        self, threat: Dict[str, Any], log_entry: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enrich a threat with additional context and metadata.

        Args:
            threat: Base threat detection
            log_entry: Original log entry

        Returns:
            dict: Enriched threat information
        """
        enriched = threat.copy()

        # Add log entry context
        enriched.update(
            {
                "source_ip": log_entry.get("ip_address", "unknown"),
                "timestamp": log_entry.get("timestamp", ""),
                "request_uri": log_entry.get("request", ""),
                "status_code": log_entry.get("status_code", ""),
                "user_agent": log_entry.get("user_agent", ""),
                "raw_log": log_entry.get("raw_line", ""),
            }
        )

        # Add severity assessment
        enriched["severity"] = self._assess_threat_severity(threat, log_entry)

        # Add geolocation if available
        geo_info = self._get_geolocation_info(log_entry.get("ip_address"))
        if geo_info:
            enriched["geolocation"] = geo_info

        return enriched

    def _assess_threat_severity(
        self, threat: Dict[str, Any], log_entry: Dict[str, Any]
    ) -> str:
        """Assess the severity level of a threat.

        Args:
            threat: Threat information
            log_entry: Log entry data

        Returns:
            str: Severity level (low, medium, high, critical)
        """
        # Get severity mappings from config
        severity_mappings = self.config_manager.get(
            "threat_severity.mappings",
            {
                "critical": ["sql_injection", "command_injection", "path_traversal"],
                "high": ["xss", "csrf", "file_inclusion"],
                "medium": ["brute_force", "dos", "scanning"],
                "low": ["suspicious_user_agent", "unusual_request"],
            },
        )

        # Get status codes that indicate successful attacks
        success_status_codes = self.config_manager.get(
            "threat_severity.success_status_codes", ["200", "301", "302"]
        )

        # Default severity from config
        severity = self.config_manager.get("threat_severity.default", "medium")

        threat_type = threat.get("type", "").lower()
        status_code = log_entry.get("status_code", "")

        # Determine severity based on threat type
        for sev, threats in severity_mappings.items():
            if threat_type in threats:
                severity = sev
                break

        # Adjust severity for successful attack patterns
        if threat_type in severity_mappings.get("medium", []):
            severity = "high" if status_code in success_status_codes else "medium"

        # Escalate based on successful attacks (2xx, 3xx status codes)
        escalation_rules = self.config_manager.get(
            "threat_severity.escalation",
            {
                "success_prefixes": ["2", "3"],
                "escalate_from": ["low", "medium"],
                "escalate_to": {"medium": "high", "low": "medium"},
            },
        )

        if (
            any(
                status_code.startswith(prefix)
                for prefix in escalation_rules["success_prefixes"]
            )
            and severity in escalation_rules["escalate_from"]
        ):
            severity = escalation_rules["escalate_to"].get(severity, severity)

        return severity

    def _get_geolocation_info(self, ip_address: str) -> Dict[str, str]:
        """Get geolocation information for an IP address.

        Args:
            ip_address: IP address to look up

        Returns:
            dict: Geolocation information or None
        """
        # Placeholder for geolocation lookup
        # In a real implementation, this would use a geolocation service
        try:
            # Mock geolocation for demonstration
            if ip_address and ip_address != "unknown":
                # Simulate a lookup operation that could fail
                parts = self._parse_ip_address(ip_address)
                if len(parts) == 4:
                    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
        except Exception as e:
            self.logger.debug(f"Failed to get geolocation for {ip_address}: {e}")

        return None

    def _parse_ip_address(self, ip_address: str) -> list:
        """Parse IP address into components.

        Args:
            ip_address: IP address to parse

        Returns:
            list: IP address components
        """
        return ip_address.split(".")

    def _apply_mitigation(self, threat: Dict[str, Any]) -> None:
        """Apply mitigation measures for a detected threat.

        Args:
            threat: Threat information
        """
        try:
            threat_type = threat.get("type")
            severity = threat.get("severity", "medium")

            # Apply mitigation using the mitigation function
            if self.mitigation_function and severity in ["high", "critical"]:
                result = self.mitigation_function(threat_type)
                self.logger.info(f"Applied mitigation for {threat_type}: {result}")

        except Exception as e:
            self.logger.error(f"Failed to apply mitigation for threat: {e}")

    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get statistics about processed threats.

        Returns:
            dict: Threat statistics
        """
        # This would maintain counters in a real implementation
        return {
            "total_threats": 0,  # Will be updated in real implementation
            "threats_by_type": {},
            "threats_by_severity": {},
            "blocked_ips": 0,
            "rate_limited_ips": 0,
        }
