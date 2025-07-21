#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Phase 3.2 Integration Tests: Network Security Integration
Focus: Integration between network_security → pattern_detector → threat_processor
"""

import unittest
import ipaddress
from unittest.mock import patch, MagicMock
from tests.integration.test_framework import BaseIntegrationTest


class TestNetworkSecurityIntegration(BaseIntegrationTest):
    """Test integration between network_security → pattern_detector → threat_processor"""
    
    def setUp(self):
        """Set up test environment for network security tests."""
        super().setUp()
        
        # Create test network data
        self.test_ip_data = {
            "malicious": [
                "203.0.113.42",   # Known attacker IP
                "198.51.100.17",  # Tor exit node
                "192.0.2.5"       # Part of botnet
            ],
            "suspicious": [
                "203.0.113.100",  # Multiple failed logins
                "198.51.100.200"  # Unusual traffic patterns
            ],
            "country_block": [
                "203.0.113.50",   # Country X
                "198.51.100.50"   # Country Y
            ]
        }
    
    def test_network_threat_detection_flow(self):
        """Test network-based threat detection integration"""
        print("\n🌐 Testing network threat detection flow...")
        
        # Get components
        network_security = self.components['network_security']
        pattern_detector = self.components['pattern_detector']
        threat_processor = self.components['threat_processor']
        
        # Connect components
        network_security.set_pattern_detector(pattern_detector)
        pattern_detector.set_threat_processor(threat_processor)
        
        # Configure network security with test data
        network_security.configure({
            "malicious_ip_list": self.test_ip_data["malicious"],
            "suspicious_ip_list": self.test_ip_data["suspicious"],
            "blocked_countries": ["XY", "ZZ"],  # Example country codes
            "enable_ip_reputation": True,
            "enable_traffic_analysis": True
        })
        
        # Create test log entries with suspicious network patterns
        test_logs = [
            {
                'client_ip': '203.0.113.42',  # Known malicious
                'timestamp': '2023-12-25T16:00:00Z',
                'method': 'POST',
                'path': '/login',
                'status': 401,
                'bytes_sent': 532
            },
            {
                'client_ip': '198.51.100.200',  # Suspicious
                'timestamp': '2023-12-25T16:05:00Z',
                'method': 'GET',
                'path': '/admin',
                'status': 403,
                'bytes_sent': 1024
            }
        ]
        
        # Mock IP reputation service
        with patch.object(network_security, 'check_ip_reputation') as mock_reputation:
            mock_reputation.return_value = {'score': 85, 'categories': ['malware', 'scanning']}
            
            # Act: Process network traffic
            detected_threats = network_security.analyze_network_traffic(test_logs)
            
            # Process detected patterns through the threat processor
            processed_threats = []
            for threat in detected_threats:
                processed_threat = threat_processor.process_threat(threat)
                if processed_threat:
                    processed_threats.append(processed_threat)
            
            # Assert: Threats should be detected and processed
            self.assertGreaterEqual(len(detected_threats), 1)
            self.assertGreaterEqual(len(processed_threats), 1)
            
            # Check that malicious IP was detected
            malicious_threats = [t for t in processed_threats if t['source_ip'] == '203.0.113.42']
            self.assertEqual(len(malicious_threats), 1)
            self.assertIn('blacklisted_ip', malicious_threats[0]['type'])
    
    def test_ip_reputation_integration(self):
        """Test IP reputation checking across components"""
        print("\n🔍 Testing IP reputation integration...")
        
        # Get components
        network_security = self.components['network_security']
        pattern_detector = self.components['pattern_detector']
        
        # Configure IP reputation thresholds and database
        network_security.configure({
            "reputation_thresholds": {
                "suspicious": 50,
                "malicious": 80
            },
            "enable_ip_reputation": True,
            "reputation_db_path": "/mock/path"  # This triggers loading test data
        })
        
        # Connect components
        network_security.set_pattern_detector(pattern_detector)
        
        # Test reputation checking with the configured database
        malicious_result = network_security.check_ip_reputation("203.0.113.42")
        suspicious_result = network_security.check_ip_reputation("198.51.100.50")  # Use test IP from db
        benign_result = network_security.check_ip_reputation("192.168.1.1")
        
        # Assert: Results should match expected reputation categories  
        self.assertEqual(malicious_result['score'], 90)
        self.assertEqual(suspicious_result['score'], 60)
        self.assertEqual(benign_result['score'], 50)  # Default neutral score
    
    def test_geographic_blocking_integration(self):
        """Test geographic IP blocking workflows"""
        print("\n🌍 Testing geographic IP blocking...")
        
        # Get components
        network_security = self.components['network_security']
        mitigation = self.components['mitigation']
        
        # Configure geographic blocking and set up test geo data
        network_security.configure({
            "blocked_countries": ["XA", "XB"],  # Match the test geo data country codes
            "country_block_action": "drop",
            "enable_geo_blocking": True,
            "geo_db_path": "/mock/path"  # This triggers loading test geo data
        })
        
        # Connect components
        network_security.set_mitigation_engine(mitigation)
        
        # Act: Process traffic from different countries
        blocked_ip = "203.0.113.50"  # Should be from blocked country XA (from test geo db)
        allowed_ip = "192.168.1.1"   # Should be from allowed country US (default)
        
        with patch.object(mitigation, 'block_ip') as mock_block_ip:
            network_security.check_geographic_restrictions(blocked_ip)
            network_security.check_geographic_restrictions(allowed_ip)
            
            # Assert: IP from blocked country should be blocked
            mock_block_ip.assert_called_once_with(blocked_ip, reason="Country blocked: XA")
            
            # Create a log entry from a blocked country
            test_log = {
                'client_ip': '198.51.100.50',  # From blocked country XB
                'timestamp': '2023-12-25T17:00:00Z',
                'method': 'GET',
                'path': '/api/data',
                'status': 200
            }
            
            # Reset mock to check new calls
            mock_block_ip.reset_mock()
            
            # Process the log entry
            network_security.process_log_entry(test_log)
            
            # Assert: IP should be blocked based on country
            mock_block_ip.assert_called_once_with('198.51.100.50', reason="Country blocked: XB")


class TestNetworkAnalytics(BaseIntegrationTest):
    """Test network traffic analytics integration"""
    
    def test_network_traffic_pattern_analysis(self):
        """Test analysis of network traffic patterns"""
        print("\n📊 Testing network traffic pattern analysis...")
        
        # Get components
        network_security = self.components['network_security']
        pattern_detector = self.components['pattern_detector']
        
        # Configure pattern detection
        network_security.configure({
            "traffic_pattern_thresholds": {
                "requests_per_minute": 60,
                "error_rate": 0.2,
                "bandwidth_per_ip_mbps": 10
            }
        })
        
        # Connect components
        network_security.set_pattern_detector(pattern_detector)
        
        # Generate test traffic data - normal pattern
        normal_traffic = []
        for i in range(30):  # 30 requests over 10 minutes = 3 RPM
            normal_traffic.append({
                'client_ip': '192.168.1.10',
                'timestamp': f'2023-12-25T16:{i//3:02d}:{i%3*20:02d}Z',
                'method': 'GET',
                'path': f'/api/resource/{i}',
                'status': 200,
                'bytes_sent': 5000  # 5KB per request
            })
        
        # Generate suspicious traffic - high request rate
        suspicious_traffic = []
        for i in range(300):  # 300 requests in 5 minutes = 60 RPM
            suspicious_traffic.append({
                'client_ip': '203.0.113.100',
                'timestamp': f'2023-12-25T17:{i//60:02d}:{i%60:02d}Z',
                'method': 'GET',
                'path': f'/api/resource/{i}',
                'status': 200,
                'bytes_sent': 5000
            })
        
        # Act: Analyze traffic patterns
        with patch.object(pattern_detector, 'detect_pattern') as mock_detect:
            # Analyze normal traffic - should not trigger detection
            network_security.analyze_traffic_patterns(normal_traffic)
            
            # No pattern should be detected for normal traffic
            mock_detect.assert_not_called()
            
            # Reset mock
            mock_detect.reset_mock()
            
            # Analyze suspicious traffic - should trigger detection
            network_security.analyze_traffic_patterns(suspicious_traffic)
            
            # Pattern should be detected for suspicious traffic
            mock_detect.assert_called()
            pattern_data = mock_detect.call_args[0][0]
            self.assertEqual(pattern_data['client_ip'], '203.0.113.100')
            self.assertIn('high_request_rate', pattern_data['type'])


if __name__ == "__main__":
    unittest.main()
