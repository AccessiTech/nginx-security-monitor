#!/usr/bin/env python3
"""
Alert Manager Module
Handles all alert generation and sending logic for the NGINX Security Monitor.
"""

import socket
from datetime import datetime
from src.alerts.email_alert import send_email_alert
from src.alerts.sms_alert import send_sms_alert
from src.config_manager import ConfigManager


config = ConfigManager.get_instance()


class AlertManager:
    """Manages all alert generation and sending functionality."""

    def __init__(self, config, logger):
        """Initialize the alert manager.

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.config_manager = ConfigManager.get_instance()

    def send_threat_alert(self, pattern, mitigation_results):
        """Send alerts for detected threats.

        Args:
            pattern: The detected threat pattern
            mitigation_results: List of mitigation results
        """
        try:
            # Prepare alert details
            alert_details = {
                "recipient": self.config_manager.get(
                    "alert_system.email.to_address",
                    self.config.get("email_service", {}).get("to_address"),
                ),
                "subject": f'NGINX Security Alert: {pattern.get("type", "Unknown")}',
                "body": self._create_threat_alert_body(pattern, mitigation_results),
                "pattern": pattern,
                "timestamp": datetime.now().isoformat(),
            }

            # Send email alert
            if self.config_manager.get(
                "alert_system.email.enabled",
                self.config.get("email_service", {}).get("enabled", True),
            ):
                send_email_alert(alert_details)
                self.logger.info("Threat alert sent via email")

            # Send SMS alert
            if self.config_manager.get(
                "alert_system.sms.enabled",
                self.config.get("sms_service", {}).get("enabled", False),
            ):
                send_sms_alert(alert_details)
                self.logger.info("Threat alert sent via SMS")

        except Exception as e:
            self.logger.error(f"Failed to send threat alert: {e}")

    def send_emergency_alert(self, critical_threats):
        """Send emergency alert for critical service threats.

        Args:
            critical_threats: List of critical threat objects
        """
        try:
            alert_details = {
                "recipient": self.config_manager.get(
                    "alert_system.email.to_address",
                    self.config.get("email_service", {}).get("to_address"),
                ),
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

            # Send email alert if available
            if self.config_manager.get(
                "alert_system.email.enabled",
                self.config.get("email_service", {}).get("enabled", True),
            ):
                send_email_alert(alert_details)
                self.logger.info("Emergency alert sent")

        except Exception as e:
            self.logger.error(f"Failed to send emergency alert: {e}")

    def send_service_threat_alert(self, high_threats):
        """Send alert for high-severity service threats.

        Args:
            high_threats: List of high-severity threat objects
        """
        try:
            alert_details = {
                "recipient": self.config_manager.get(
                    "alert_system.email.to_address",
                    self.config.get("email_service", {}).get("to_address"),
                ),
                "subject": "⚠️ Security Monitor Service Threats Detected",
                "pattern": {
                    "type": "Service Protection Alert",
                    "severity": "HIGH",
                    "ip": "SERVICE_HOST",
                    "request": f"{len(high_threats)} high-severity threats",
                },
                "timestamp": datetime.now().isoformat(),
                "body": self._create_service_threat_alert_body(high_threats),
            }

            # Send email alert if available
            if self.config_manager.get(
                "alert_system.email.enabled",
                self.config.get("email_service", {}).get("enabled", True),
            ):
                send_email_alert(alert_details)
                self.logger.info("Service threat alert sent")

        except Exception as e:
            self.logger.error(f"Failed to send service threat alert: {e}")

    def send_integration_alert(self, threats):
        """Send alert for threats detected by security integrations.

        Args:
            threats: List of threat objects from security integrations
        """
        try:
            threat_sources = list(set(t.get("source", "unknown") for t in threats))

            alert_details = {
                "recipient": self.config_manager.get(
                    "alert_system.email.to_address",
                    self.config.get("email_service", {}).get("to_address"),
                ),
                "subject": f"🔒 Security Framework Alert: {len(threats)} threats detected",
                "pattern": {
                    "type": "Security Framework Alert",
                    "severity": "HIGH",
                    "ip": "MULTIPLE",
                    "request": f'Threats from: {", ".join(threat_sources)}',
                },
                "timestamp": datetime.now().isoformat(),
                "body": self._create_integration_alert_body(threats),
            }

            # Send email alert if available
            if self.config_manager.get(
                "alert_system.email.enabled",
                self.config.get("email_service", {}).get("enabled", True),
            ):
                send_email_alert(alert_details)
                self.logger.info("Security integration alert sent")

        except Exception as e:
            self.logger.error(f"Failed to send integration alert: {e}")

    def _create_threat_alert_body(self, pattern, mitigation_results):
        """Create alert body for detected threats.

        Args:
            pattern: The threat pattern
            mitigation_results: List of mitigation results

        Returns:
            str: Formatted alert body
        """
        threat_type = pattern.get("type", "Unknown")
        ip_address = pattern.get("ip", "Unknown")
        timestamp = pattern.get("timestamp", datetime.now().isoformat())

        # Summary without revealing details
        mitigation_summary = f"{len(mitigation_results)} countermeasure(s) applied"
        successful_mitigations = len(
            [r for r in mitigation_results if r.get("status") == "success"]
        )

        body = f"""
Security Alert: {threat_type}

Threat Details:
- Source IP: {ip_address}
- Detection Time: {timestamp}
- Severity: {pattern.get('severity', 'UNKNOWN')}

Response:
- {mitigation_summary}
- {successful_mitigations} successful response(s)

This threat has been automatically processed by your security system.
        """.strip()

        return body

    def _create_emergency_alert_body(self, threats):
        """Create emergency alert body.

        Args:
            threats: List of critical threat objects

        Returns:
            str: Formatted emergency alert body
        """
        body = f"""
🚨 EMERGENCY: NGINX Security Monitor Under Attack

CRITICAL THREATS DETECTED: {len(threats)}

The security monitoring service itself is under attack and may be compromised.

Threats Detected:
"""

        for threat in threats:
            body += f"""
- Type: {threat.get('type', 'Unknown')}
  Description: {threat.get('description', 'No description')}
  Severity: {threat.get('severity', 'UNKNOWN')}
"""

        body += f"""

IMMEDIATE ACTION REQUIRED:
{self._get_emergency_recommendations()}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Host: {socket.gethostname()}

This is an automated emergency alert from your NGINX Security Monitor.
        """.strip()

        return body

    def _get_emergency_recommendations(self):
        """Get emergency action recommendations from config."""
        recommendations = self.config_manager.get(
            "alert_system.emergency_recommendations",
            [
                "Investigate the service host immediately",
                "Check for unauthorized access",
                "Verify file integrity",
                "Review system logs",
                "Consider isolating the system",
            ],
        )

        # Format recommendations as numbered list
        return "\n".join([f"{i+1}. {rec}" for i, rec in enumerate(recommendations)])

    def _create_service_threat_alert_body(self, threats):
        """Create service threat alert body.

        Args:
            threats: List of threat objects

        Returns:
            str: Formatted service threat alert body
        """
        body = f"""
⚠️  Security Monitor Service Threats

HIGH-SEVERITY THREATS: {len(threats)}

The security monitoring service has detected threats against itself.

Threats Detected:
"""

        for threat in threats:
            body += f"""
- {threat.get('type', 'Unknown')}: {threat.get('description', 'No description')}
"""

        body += f"""

Recommended Actions:
{self._get_service_threat_recommendations()}

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is an automated alert from your NGINX Security Monitor.
        """.strip()

        return body

    def _get_service_threat_recommendations(self):
        """Get service threat action recommendations from config."""
        recommendations = self.config_manager.get(
            "alert_system.service_threat_recommendations",
            [
                "Review service logs",
                "Check system security",
                "Verify configurations",
                "Monitor for additional threats",
            ],
        )

        # Format recommendations as numbered list
        return "\n".join([f"{i+1}. {rec}" for i, rec in enumerate(recommendations)])

    def _create_integration_alert_body(self, threats):
        """Create alert body for security integration threats.

        Args:
            threats: List of threat objects from integrations

        Returns:
            str: Formatted integration alert body
        """
        body = f"""
🔒 Security Framework Alert

THREATS DETECTED BY SECURITY TOOLS: {len(threats)}

The following threats were detected by integrated security frameworks:

"""

        # Group threats by source
        threats_by_source = {}
        for threat in threats:
            source = threat.get("source", "unknown")
            if source not in threats_by_source:
                threats_by_source[source] = []
            threats_by_source[source].append(threat)

        for source, source_threats in threats_by_source.items():
            body += f"\n{source.upper()} ({len(source_threats)} threats):\n"

            # Get max threats to display per source from config
            max_threats_per_source = self.config_manager.get(
                "alert_system.max_threats_per_source", 5
            )

            for threat in source_threats[
                :max_threats_per_source
            ]:  # Limit threats displayed
                severity = threat.get("severity", "UNKNOWN")
                description = threat.get("description", "No description")
                src_ip = threat.get("src_ip", "N/A")
                timestamp = threat.get("timestamp", "N/A")

                body += f"  • [{severity}] {description}\n"
                if src_ip != "N/A":
                    body += f"    Source IP: {src_ip}\n"
                if timestamp != "N/A":
                    body += f"    Time: {timestamp}\n"
                body += "\n"

            if len(source_threats) > max_threats_per_source:
                body += f"  ... and {len(source_threats) - max_threats_per_source} more threats\n\n"

        body += f"""
RECOMMENDED ACTIONS:
{self._get_integration_recommendations()}

This alert was generated by NGINX Security Monitor's security integration system.
        """

        return body

    def _get_integration_recommendations(self):
        """Get integration alert recommendations from config."""
        recommendations = self.config_manager.get(
            "alert_system.integration_recommendations",
            [
                "Review security tool logs for detailed information",
                "Investigate source IPs showing malicious activity",
                "Consider additional blocking measures if attacks persist",
                "Ensure all security tools are properly configured",
            ],
        )

        # Format recommendations as numbered list
        return "\n".join([f"{i+1}. {rec}" for i, rec in enumerate(recommendations)])

    def _create_simple_threat_alert_body(self, threat):
        """Create alert body for a threat detection.

        Args:
            threat: Threat information dict

        Returns:
            str: Alert body text
        """
        threat_type = threat.get("type", "Unknown")
        ip_address = threat.get("source_ip", threat.get("ip", "Unknown"))
        timestamp = threat.get("timestamp", datetime.now().isoformat())
        severity = threat.get("severity", "UNKNOWN")

        body = f"""
Security Alert: {threat_type}

Threat Details:
- Source IP: {ip_address}
- Detection Time: {timestamp}
- Severity: {severity}

Response:
- Automated countermeasures applied
- Threat processed by security system

This threat has been automatically processed by your security system.
        """.strip()

        return body
