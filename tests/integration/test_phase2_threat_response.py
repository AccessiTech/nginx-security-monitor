#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phase 2.1 Integration Tests: Threat Response Integration
Focus: Integration between threat_processor → mitigation → security_coordinator
"""

import unittest
import time
import threading
from unittest.mock import patch, MagicMock, call
from tests.integration.test_framework import (
    BaseIntegrationTest,
    IntegrationTestDataFactory,
)


class TestThreatResponseIntegration(BaseIntegrationTest):
    """Test integration between threat_processor → mitigation → security_coordinator"""

    def setUp(self):
        """Set up test environment for threat response tests."""
        super().setUp()

        # Create test threat data
        self.test_threat = {
            "type": "sql_injection",
            "confidence": 0.95,
            "severity": "high",
            "source_ip": "192.168.1.100",
            "timestamp": "2023-12-25T12:00:00Z",
            "details": {
                "request_url": "/login?id=1' OR '1'='1",
                "user_agent": "sqlmap/1.6.3",
                "http_method": "GET",
            },
        }

        # Connect components for all tests - needs to happen in each test
        # self.components['threat_processor'].set_mitigation_engine(self.components['mitigation'])
        # self.components['threat_processor'].set_security_coordinator(self.components['security_coordinator'])

    def test_threat_to_mitigation_flow(self):
        """Test automatic mitigation based on threat classification"""
        print("\n🛡️ Testing threat to mitigation flow...")

        # Get the components
        threat_processor = self.components["threat_processor"]
        mitigation = self.components["mitigation"]

        # Connect components explicitly
        threat_processor.set_mitigation_engine(mitigation)

        # Clear any previous applied mitigations
        mitigation.applied_mitigations.clear()

        # Act: Process a threat that should trigger mitigation
        threat = threat_processor.process_threat(self.test_threat)

        # Now handle the threat which should call apply_mitigation
        threat_processor.handle_threat(threat)

        # Assert: mitigation should have been applied
        self.assertGreaterEqual(
            len(mitigation.applied_mitigations),
            1,
            "Expected at least one mitigation to be applied",
        )

        # Check the mitigation details
        applied_mitigation = mitigation.applied_mitigations[0]
        self.assertEqual(applied_mitigation["type"], "block_ip")
        self.assertEqual(applied_mitigation["target_ip"], "192.168.1.100")

    def test_escalation_procedure(self):
        """Test threat escalation procedure"""
        print("\n📈 Testing threat escalation procedure...")

        # Get components
        security_coordinator = self.components["security_coordinator"]
        threat_processor = self.components["threat_processor"]

        # Clear previous tracking data
        security_coordinator.escalation_calls.clear()

        # Create critical threat that should trigger escalation
        critical_threat = {
            "threat_type": "exploit_attempt",
            "severity": "critical",
            "source_ip": "10.0.0.100",
            "confidence": 0.95,
            "attack_vector": "buffer_overflow",
            "timestamp": "2024-01-01T12:00:00Z",
        }

        # Connect components
        threat_processor.set_security_coordinator(security_coordinator)

        # Process threat that should trigger escalation
        processed_threat = threat_processor.process_threat(critical_threat)
        security_coordinator.handle_critical_threat(processed_threat)

        # Verify escalation was triggered
        self.assertGreater(
            len(security_coordinator.escalation_calls),
            0,
            "Expected escalation to be triggered for critical threat",
        )

        # Check escalation details
        escalation_data = security_coordinator.escalation_calls[0]
        self.assertEqual(escalation_data["threat_type"], "exploit_attempt")
        self.assertEqual(
            escalation_data["severity"], "HIGH"
        )  # HIGH due to confidence 0.95

    def test_concurrent_threat_handling(self):
        """Test handling multiple simultaneous threats"""
        print("\n🔄 Testing concurrent threat handling...")

        # Get components
        threat_processor = self.components["threat_processor"]
        mitigation = self.components["mitigation"]

        # Connect components
        threat_processor.set_mitigation_engine(mitigation)

        # Clear previous data
        mitigation.applied_mitigations.clear()

        # Create multiple test threats
        concurrent_threats = []
        for i in range(5):
            threat = self.test_threat.copy()
            threat["source_ip"] = f"192.168.1.{100 + i}"
            concurrent_threats.append(threat)

        # Act: Process multiple threats concurrently
        import threading

        threads = []
        for threat in concurrent_threats:
            processed_threat = threat_processor.process_threat(threat)
            thread = threading.Thread(
                target=threat_processor.handle_threat, args=(processed_threat,)
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Assert: All threats should have been handled
        self.assertEqual(
            len(mitigation.applied_mitigations),
            5,
            f"Expected 5 mitigations, got {len(mitigation.applied_mitigations)}",
        )

        # Check that all different IPs were handled
        ips_blocked = set()
        for mitigation_data in mitigation.applied_mitigations:
            ips_blocked.add(mitigation_data["target_ip"])

        # Verify we have 5 different IPs
        self.assertEqual(
            len(ips_blocked), 5, f"Expected 5 unique IPs, got {len(ips_blocked)}"
        )


class TestSecurityCoordinationFlow(BaseIntegrationTest):
    """Test the security coordination flow between components"""

    def test_threat_lifecycle_coordination(self):
        """Test coordination of the complete threat lifecycle"""
        print("\n🔄 Testing threat lifecycle coordination...")

        # Get all relevant components
        threat_processor = self.components["threat_processor"]
        security_coordinator = self.components["security_coordinator"]
        mitigation = self.components["mitigation"]
        alert_manager = self.components["alert_manager"]

        # Connect all components
        security_coordinator.set_mitigation_engine(mitigation)
        security_coordinator.set_alert_manager(alert_manager)
        threat_processor.set_security_coordinator(security_coordinator)

        # Test threat data
        test_threat = {
            "type": "brute_force",
            "confidence": 0.9,
            "severity": "high",
            "source_ip": "203.0.113.42",
            "timestamp": "2023-12-25T14:30:00Z",
            "details": {
                "target": "/admin/login",
                "attempts": 25,
                "timeframe_minutes": 5,
            },
        }

        # Mock the components to verify the coordination flow
        with patch.object(
            mitigation, "apply_mitigation", wraps=mitigation.apply_mitigation
        ) as mock_mitigate, patch.object(
            alert_manager, "send_alert", wraps=alert_manager.send_alert
        ) as mock_alert:

            # Act: Process a threat through the security coordinator
            processed_threat = threat_processor.process_threat(test_threat)
            security_coordinator.coordinate_response(processed_threat)

            # Assert: Both mitigation and alerting should have happened
            mock_mitigate.assert_called_once()
            mock_alert.assert_called_once()

            # Verify the coordination sequence (mitigation should happen before alert)
            # We use the times stored in the objects themselves rather than the mocks
            self.assertLess(mitigation.call_time, alert_manager.call_time)

    def test_multi_tool_coordination(self):
        """Test coordination between multiple security tools"""
        print("\n🔗 Testing multi-tool coordination...")

        # Get components
        security_coordinator = self.components["security_coordinator"]

        # Clear previous tracking data
        security_coordinator.tool_coordination_calls.clear()

        # Create scenario requiring multi-tool response
        complex_threat = {
            "threat_type": "advanced_persistent_threat",
            "severity": "high",
            "source_ip": "203.0.113.10",
            "confidence": 0.85,
            "requires_coordination": True,
            "tools_needed": ["fail2ban", "ossec", "suricata"],
            "timestamp": "2024-01-01T12:00:00Z",
        }

        # Trigger multi-tool coordination
        security_coordinator.coordinate_multi_tool_response(complex_threat)

        # Verify coordination was executed
        self.assertGreater(
            len(security_coordinator.tool_coordination_calls),
            0,
            "Expected multi-tool coordination to be executed",
        )

        # Check coordination details
        coordination_data = security_coordinator.tool_coordination_calls[0]
        self.assertEqual(coordination_data["threat_type"], "advanced_persistent_threat")
        self.assertIn("tools_needed", coordination_data)
        self.assertEqual(len(coordination_data["tools_needed"]), 3)


if __name__ == "__main__":
    unittest.main()
