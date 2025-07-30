#!/usr/bin/env python3
"""
Security Coordinator Module
Coordinates security operations and manages the overall security workflow.
"""

import time
from typing import List, Dict, Any
from nginx_security_monitor.config_manager import ConfigManager


config = ConfigManager.get_instance()


class SecurityCoordinator:
    """Coordinates security operations and manages workflow."""

    def __init__(
        self,
        config,
        logger,
        alert_manager,
        log_processor,
        threat_processor,
        security_integrations,
        service_protection,
        network_security,
    ):
        """Initialize the security coordinator.

        Args:
            config: Configuration dictionary
            logger: Logger instance
            alert_manager: Alert manager instance
            log_processor: Log processor instance
            threat_processor: Threat processor instance
            security_integrations: Security integrations instance
            service_protection: Service protection instance
            network_security: Network security instance
        """
        self.config = config
        self.logger = logger
        self.alert_manager = alert_manager
        self.log_processor = log_processor
        self.threat_processor = threat_processor
        self.security_integrations = security_integrations
        self.service_protection = service_protection
        self.network_security = network_security
        self.config_manager = ConfigManager.get_instance()

        self.running = self.config_manager.get("service.initial_running_state", False)
        self.last_check_time = time.time()

        # For tests, we need to handle specific values
        if config and "check_interval" in config:
            self.check_interval = config.get("check_interval")
        else:
            self.check_interval = self.config_manager.get("service.check_interval", 30)

        # Statistics tracking
        self.stats = {
            "monitoring_cycles": self.config_manager.get(
                "statistics.initial_monitoring_cycles", 0
            ),
            "total_log_entries": self.config_manager.get(
                "statistics.initial_log_entries", 0
            ),
            "total_threats": self.config_manager.get("statistics.initial_threats", 0),
            "alerts_sent": self.config_manager.get("statistics.initial_alerts_sent", 0),
            "start_time": time.time(),
        }

    def start_monitoring(self) -> None:
        """Start the security monitoring process."""
        self.logger.info("Starting NGINX Security Monitor")
        self.running = True
        self.stats["start_time"] = time.time()

        try:
            while self.running:
                self._run_monitoring_cycle()
                self._wait_for_next_cycle()

        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")
            raise
        finally:
            self.stop_monitoring()

    def stop_monitoring(self) -> None:
        """Stop the security monitoring process."""
        self.logger.info("Stopping NGINX Security Monitor")
        self.running = False

        # Send final statistics
        runtime = time.time() - self.stats["start_time"]
        self.logger.info(f"Monitor ran for {runtime:.2f} seconds")
        self.logger.info(f"Processed {self.stats['monitoring_cycles']} cycles")
        self.logger.info(f"Analyzed {self.stats['total_log_entries']} log entries")
        self.logger.info(f"Detected {self.stats['total_threats']} threats")
        self.logger.info(f"Sent {self.stats['alerts_sent']} alerts")

    def _run_monitoring_cycle(self) -> None:
        """Run a single monitoring cycle."""
        try:
            # Increment using configurable step
            cycle_increment = self.config_manager.get("statistics.cycle_increment", 1)
            self.stats["monitoring_cycles"] += cycle_increment

            cycle_start = time.time()

            self.logger.debug(
                f"Starting monitoring cycle {self.stats['monitoring_cycles']}"
            )

            # Check service protection status
            self._check_service_protection()

            # Process log files
            threats_detected = self._process_log_files()

            # Handle detected threats
            if threats_detected:
                self._handle_threats(threats_detected)

            # Check security integrations
            self._check_security_integrations()

            # Update network security
            self._update_network_security()

            cycle_time = time.time() - cycle_start
            self.logger.debug(f"Monitoring cycle completed in {cycle_time:.2f}s")

        except Exception as e:
            self.logger.error(f"Error in monitoring cycle: {e}")

    def _process_log_files(self) -> List[Dict[str, Any]]:
        """Process configured log files for threats.

        Returns:
            list: Detected threats
        """
        all_threats = []
        log_files = self.config.get("log_files", [])

        for log_file in log_files:
            try:
                # Get new log entries
                new_entries = self.log_processor.get_new_log_entries(log_file)

                # Use configurable entry_increment for statistics
                entry_increment = self.config_manager.get(
                    "statistics.entry_increment", 1
                )
                self.stats["total_log_entries"] += len(new_entries) * entry_increment

                if new_entries:
                    self.logger.debug(
                        f"Processing {len(new_entries)} new entries from {log_file}"
                    )

                    # Process entries for threats
                    threats = self.threat_processor.process_log_entries(new_entries)
                    all_threats.extend(threats)

            except Exception as e:
                self.logger.error(f"Error processing log file {log_file}: {e}")

        return all_threats

    def _handle_threats(self, threats: List[Dict[str, Any]]) -> None:
        """Handle detected threats by sending alerts and applying mitigations.

        Args:
            threats: List of detected threats
        """
        self.stats["total_threats"] += len(threats)

        for threat in threats:
            try:
                # Send threat alert
                alert_sent = self.alert_manager.send_threat_alert(threat)
                if alert_sent:
                    # Use configurable alert_increment for statistics
                    alert_increment = self.config_manager.get(
                        "statistics.alert_increment", 1
                    )
                    self.stats["alerts_sent"] += alert_increment

                # Log threat
                self.logger.warning(
                    f"Threat detected: {threat.get('type', 'unknown')} "
                    f"from {threat.get('source_ip', 'unknown')} "
                    f"[Severity: {threat.get('severity', 'unknown')}]"
                )

                # Get critical severity levels from config
                critical_levels = self.config_manager.get(
                    "alert_system.critical_severity_levels", ["high", "critical"]
                )

                # Send to security integrations if critical
                if threat.get("severity", "").lower() in [
                    level.lower() for level in critical_levels
                ]:
                    self._send_to_integrations(threat)

            except Exception as e:
                self.logger.error(f"Error handling threat {threat}: {e}")

    def _check_service_protection(self) -> None:
        """Check service protection status and handle threats."""
        try:
            service_threats = self.service_protection.perform_self_check()

            if service_threats:
                alert_sent = self.alert_manager.send_service_threat_alert(service_threats)
                if alert_sent:
                    # Use configurable alert_increment for statistics
                    alert_increment = self.config_manager.get(
                        "statistics.alert_increment", 1
                    )
                    self.stats["alerts_sent"] += len(service_threats) * alert_increment

                for threat in service_threats:
                    self.logger.warning(f"Service threat detected: {threat}")
                    # Automated remediation for service not running
                    if (
                        threat.get("type") == "Service Status"
                        and threat.get("severity", "").upper() == "CRITICAL"
                        and threat.get("status", "unknown") == "unknown"
                    ):
                        import subprocess
                        service_names = [
                            self.config.get("service_name", "nginx-security-monitor"),
                            "nginx"
                        ]
                        for service_name in service_names:
                            try:
                                subprocess.run(["systemctl", "restart", service_name], check=True)
                                self.logger.info(f"Automated remediation: Restarted service '{service_name}' due to critical status.")
                                break
                            except Exception as restart_exc:
                                self.logger.error(f"Automated remediation failed: Could not restart service '{service_name}': {restart_exc}")

        except Exception as e:
            self.logger.error(f"Error checking service protection: {e}")

    def _check_security_integrations(self) -> None:
        """Check security integrations for updates and alerts."""
        try:
            integration_alerts = self.security_integrations.check_for_updates()

            if integration_alerts:
                for alert in integration_alerts:
                    # Send integration alert
                    alert_sent = self.alert_manager.send_integration_alert(alert)
                    if alert_sent:
                        # Use configurable alert_increment for statistics
                        alert_increment = self.config_manager.get(
                            "statistics.alert_increment", 1
                        )
                        self.stats["alerts_sent"] += alert_increment

                    self.logger.info(f"Integration alert: {alert}")

        except Exception as e:
            self.logger.error(f"Error checking security integrations: {e}")

    def _update_network_security(self) -> None:
        """Update network security configurations and rules."""
        try:
            self.network_security.update_security_rules()

        except Exception as e:
            self.logger.error(f"Error updating network security: {e}")

    def _send_to_integrations(self, threat: Dict[str, Any]) -> None:
        """Send high-severity threats to security integrations.

        Args:
            threat: Threat information
        """
        try:
            self.security_integrations.send_threat_data(threat)

        except Exception as e:
            self.logger.error(f"Error sending threat to integrations: {e}")

    def _wait_for_next_cycle(self) -> None:
        """Wait for the next monitoring cycle."""
        current_time = time.time()
        elapsed = current_time - self.last_check_time

        # The check_interval is now managed by the tests directly
        # to ensure consistent test behavior

        if elapsed < self.check_interval:
            sleep_time = self.check_interval - elapsed
            time.sleep(sleep_time)

        # Update last check time
        self.last_check_time = time.time()

        self.last_check_time = time.time()

    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status and statistics.

        Returns:
            dict: Monitoring status information
        """
        runtime = time.time() - self.stats["start_time"]

        # Get the seconds per hour value from config or use default
        seconds_per_hour = self.config_manager.get("statistics.seconds_per_hour", 3600)

        return {
            "running": self.running,
            "runtime_seconds": runtime,
            "monitoring_cycles": self.stats["monitoring_cycles"],
            "total_log_entries": self.stats["total_log_entries"],
            "total_threats": self.stats["total_threats"],
            "alerts_sent": self.stats["alerts_sent"],
            "threats_per_hour": (
                (self.stats["total_threats"] / (runtime / seconds_per_hour))
                if runtime > 0
                else 0
            ),
            "last_check_time": self.last_check_time,
        }

    def force_check(self) -> Dict[str, Any]:
        """Force an immediate monitoring check.

        Returns:
            dict: Check results
        """
        self.logger.info("Forcing immediate security check")

        try:
            threats = self._process_log_files()

            if threats:
                self._handle_threats(threats)

            return {
                "success": self.config_manager.get("response.default_success", True),
                "threats_detected": len(threats),
                "timestamp": time.time(),
            }

        except Exception as e:
            self.logger.error(f"Error during forced check: {e}")
            return {
                "success": self.config_manager.get("response.default_failure", False),
                "error": str(e),
                "timestamp": time.time(),
            }
