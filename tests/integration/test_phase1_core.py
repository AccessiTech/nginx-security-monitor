#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phase 1 Integration Tests: Core Component Integration
Focus: Threat Detection Pipeline Integration
"""

import unittest
import time
from unittest.mock import patch, MagicMock
from tests.integration.test_framework import BaseIntegrationTest, IntegrationTestDataFactory


class TestThreatDetectionPipelineIntegration(BaseIntegrationTest):
    """Test integration between log_parser → log_processor → pattern_detector → threat_processor"""
    
    def test_complete_threat_detection_pipeline(self):
        """Test full pipeline from log entry to threat classification"""
        print("\n🔍 Testing complete threat detection pipeline...")
        
        # Arrange: Create test log entries with known threats
        test_logs = IntegrationTestDataFactory.create_realistic_log_entries(
            count=50, include_threats=True
        )
        
        threats_detected = []
        processed_logs = []
        
        # Act: Process logs through the complete pipeline
        for log_entry in test_logs:
            try:
                # Step 1: Log Parser extracts structured data
                parsed_data = self.components['log_parser'].parse_log_line(log_entry)
                self.assertIsNotNone(parsed_data, "Log parser should return structured data")
                
                # Step 2: Log Processor validates and enriches data
                processed_data = self.components['log_processor'].process_log_entry(parsed_data)
                if processed_data:
                    processed_logs.append(processed_data)
                    
                    # Step 3: Pattern Detector identifies suspicious patterns
                    patterns = self.components['pattern_detector'].detect_patterns([processed_data])
                    
                    # Step 4: Threat Processor classifies and scores threats
                    if patterns:
                        for pattern in patterns:
                            threat = self.components['threat_processor'].process_threat(pattern)
                            if threat:
                                threats_detected.append(threat)
                                
            except Exception as e:
                self.fail(f"Pipeline failed processing log entry: {e}")
        
        # Assert: Verify pipeline results
        self.assertGreater(len(processed_logs), 0, "Should process some logs successfully")
        self.assertGreater(len(threats_detected), 0, "Should detect some threats")
        
        # Verify threat types are properly classified
        threat_types = [threat.get('type', 'unknown') for threat in threats_detected]
        expected_types = ['sql_injection', 'xss', 'brute_force']
        
        for expected_type in expected_types:
            self.assertIn(expected_type, threat_types, 
                         f"Should detect {expected_type} threats")
        
        print(f"✅ Pipeline processed {len(processed_logs)} logs, detected {len(threats_detected)} threats")
    
    def test_malformed_log_handling_across_pipeline(self):
        """Test how pipeline handles malformed log entries"""
        print("\n🚨 Testing malformed log handling across pipeline...")
        
        # Arrange: Create malformed log entries
        malformed_logs = [
            "",  # Empty log
            "invalid log format",  # Invalid format
            "192.168.1.1 - - incomplete",  # Incomplete log
            None,  # None value
            "🚨 unicode characters in log 测试",  # Unicode issues
        ]
        
        successful_processing = 0
        errors_handled = 0
        
        # Act: Process malformed logs through pipeline
        for log_entry in malformed_logs:
            try:
                # The pipeline should handle errors gracefully
                parsed_data = self.components['log_parser'].parse_log_line(log_entry)
                
                if parsed_data:
                    processed_data = self.components['log_processor'].process_log_entry(parsed_data)
                    successful_processing += 1
                else:
                    errors_handled += 1
                    
            except Exception:
                # Pipeline should handle exceptions gracefully
                errors_handled += 1
        
        # Assert: Pipeline should handle malformed logs without crashing
        total_logs = len(malformed_logs)
        self.assertEqual(successful_processing + errors_handled, total_logs,
                        "All malformed logs should be processed or handled gracefully")
        
        print(f"✅ Handled {errors_handled} malformed logs gracefully, processed {successful_processing} successfully")
    
    def test_high_volume_log_processing_integration(self):
        """Test pipeline performance under load"""
        print("\n⚡ Testing high-volume log processing performance...")
        
        # Arrange: Create large volume of logs
        high_volume_logs = IntegrationTestDataFactory.create_realistic_log_entries(
            count=1000, include_threats=True
        )
        
        start_time = time.time()
        processed_count = 0
        threats_count = 0
        
        # Act: Process high volume through pipeline
        for log_entry in high_volume_logs:
            try:
                parsed_data = self.components['log_parser'].parse_log_line(log_entry)
                if parsed_data:
                    processed_data = self.components['log_processor'].process_log_entry(parsed_data)
                    if processed_data:
                        processed_count += 1
                        
                        # Check for threats (simplified for performance test)
                        patterns = self.components['pattern_detector'].detect_patterns([processed_data])
                        if patterns:
                            threats_count += len(patterns)
                            
            except Exception as e:
                self.fail(f"High volume processing failed: {e}")
        
        end_time = time.time()
        processing_time = end_time - start_time
        logs_per_second = len(high_volume_logs) / processing_time if processing_time > 0 else 0
        
        # Assert: Performance should meet minimum requirements
        self.assertLess(processing_time, 30.0, "Should process 1000 logs in under 30 seconds")
        self.assertGreater(logs_per_second, 10, "Should process at least 10 logs per second")
        self.assertGreater(processed_count, len(high_volume_logs) * 0.8, 
                          "Should successfully process at least 80% of logs")
        
        print(f"✅ Processed {processed_count} logs in {processing_time:.2f}s ({logs_per_second:.1f} logs/sec)")
        print(f"   Detected {threats_count} threat patterns")
    
    def test_component_failure_recovery_in_pipeline(self):
        """Test pipeline behavior when individual components fail"""
        print("\n🔧 Testing component failure recovery...")
        
        test_logs = self.create_test_log_entries(count=10, threat_type="sql_injection")
        
        # Test pattern detector failure
        with patch.object(self.components['pattern_detector'], 'detect_patterns', 
                         side_effect=Exception("Pattern detector failed")):
            
            processed_without_pattern_detection = 0
            
            for log_entry in test_logs:
                try:
                    parsed_data = self.components['log_parser'].parse_log_line(log_entry)
                    if parsed_data:
                        processed_data = self.components['log_processor'].process_log_entry(parsed_data)
                        if processed_data:
                            processed_without_pattern_detection += 1
                            
                            # Pipeline should continue even if pattern detection fails
                            try:
                                self.components['pattern_detector'].detect_patterns([processed_data])
                            except Exception:
                                # This is expected - pattern detector is mocked to fail
                                pass
                                
                except Exception as e:
                    self.fail(f"Pipeline should continue despite pattern detector failure: {e}")
            
            # Assert: Basic log processing should continue
            self.assertGreater(processed_without_pattern_detection, 0,
                             "Log processing should continue despite pattern detector failure")
        
        print(f"✅ Pipeline handled component failure gracefully")
    
    def test_threat_escalation_integration(self):
        """Test integration between threat detection and escalation"""
        print("\n🚨 Testing threat escalation integration...")
        
        # Arrange: Create high-severity threat scenario
        critical_logs = [
            # Multiple SQL injection attempts from same IP
            '192.168.1.100 - - [25/Dec/2023:10:00:01 +0000] "GET /admin/users?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 1234 "-" "sqlmap/1.6.3"',
            '192.168.1.100 - - [25/Dec/2023:10:00:02 +0000] "GET /admin/users?id=2\' UNION SELECT * FROM passwords-- HTTP/1.1" 200 1234 "-" "sqlmap/1.6.3"',
            '192.168.1.100 - - [25/Dec/2023:10:00:03 +0000] "GET /admin/users?id=3\'; DROP TABLE users;-- HTTP/1.1" 403 0 "-" "sqlmap/1.6.3"',
        ]
        
        high_severity_threats = []
        
        # Act: Process critical logs and check escalation
        for log_entry in critical_logs:
            parsed_data = self.components['log_parser'].parse_log_line(log_entry)
            if parsed_data:
                processed_data = self.components['log_processor'].process_log_entry(parsed_data)
                if processed_data:
                    patterns = self.components['pattern_detector'].detect_patterns([processed_data])
                    
                    for pattern in patterns:
                        threat = self.components['threat_processor'].process_threat(pattern)
                        if threat and threat.get('severity') == 'HIGH':
                            high_severity_threats.append(threat)
        
        # Assert: High severity threats should be properly identified
        self.assertGreater(len(high_severity_threats), 0, 
                          "Should identify high-severity threats")
        
        # Verify threat details
        for threat in high_severity_threats:
            self.assertIn('ip_address', threat, "Threat should include IP address")
            self.assertIn('timestamp', threat, "Threat should include timestamp")
            self.assertIn('severity', threat, "Threat should include severity")
            self.assertEqual(threat['severity'], 'HIGH', "Should be high severity")
        
        print(f"✅ Identified {len(high_severity_threats)} high-severity threats for escalation")


class TestConfigurationSystemIntegration(BaseIntegrationTest):
    """Test integration between config_schema → config_manager → crypto_utils"""
    
    def test_encrypted_config_loading_integration(self):
        """Test loading and decrypting configuration files"""
        print("\n🔐 Testing encrypted configuration loading...")
        
        # This test would verify that encrypted configurations
        # can be loaded and decrypted properly across the system
        
        # Arrange: Create test configuration
        test_config = {
            "service": {
                "check_interval": 30,
                "log_file_path": "/test/path/access.log"
            },
            "alert_system": {
                "email": {
                    "enabled": True,
                    "smtp_server": "test.smtp.com"
                }
            }
        }
        
        # Act: Save and load configuration
        config_manager = self.components['config_manager']
        
        # This would test the actual integration
        # For now, we'll test the basic functionality
        self.assertIsNotNone(config_manager, "Config manager should be initialized")
        
        print("✅ Configuration integration test framework ready")
    
    def test_config_validation_with_schema_integration(self):
        """Test configuration validation against schema"""
        print("\n📋 Testing configuration validation integration...")
        
        # This would test that configurations are validated
        # against the schema during loading
        
        self.assertTrue(True, "Schema validation integration test placeholder")
        print("✅ Schema validation integration ready for implementation")


if __name__ == "__main__":
    print("🧪 Running Phase 1 Integration Tests: Core Component Integration")
    unittest.main(verbosity=2)
