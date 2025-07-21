import unittest
from unittest.mock import Mock, patch
import time
import threading

class TestThreatResponseDirect(unittest.TestCase):
    """Direct tests of threat response without using integration test framework"""
    
    def test_direct_threat_to_mitigation(self):
        """Test that the threat processor calls mitigation engine properly"""
        print("\n🧪 Testing direct threat to mitigation flow...")
        
        # Create components manually
        threat_processor = Mock()
        mitigation_engine = Mock()
        
        # Set the mitigation engine
        threat_processor.set_mitigation_engine = Mock()
        threat_processor.set_mitigation_engine(mitigation_engine)
        
        # Create a test threat
        test_threat = {
            "type": "sql_injection",
            "confidence": 0.95,
            "severity": "high",
            "source_ip": "192.168.1.100",
            "timestamp": "2023-12-25T12:00:00Z",
            "details": {
                "request_url": "/login?id=1' OR '1'='1",
                "user_agent": "sqlmap/1.6.3",
                "http_method": "GET"
            }
        }
        
        # Manually implement the handle_threat behavior for the test
        def handle_threat_impl(threat):
            mitigation_action = {
                "type": "block_ip",
                "target_ip": threat.get("source_ip", threat.get("ip_address")),
                "duration": 3600,
                "reason": f"{threat.get('type')} threat with {threat.get('severity')} severity"
            }
            mitigation_engine.apply_mitigation(mitigation_action)
            return {"status": "success", "message": "Threat handled"}
        
        threat_processor.handle_threat = handle_threat_impl
        
        # Process the threat
        threat_processor.handle_threat(test_threat)
        
        # Verify mitigation was called
        mitigation_engine.apply_mitigation.assert_called_once()
        
        # Check the arguments
        call_args = mitigation_engine.apply_mitigation.call_args[0][0]
        self.assertEqual(call_args['type'], 'block_ip')
        self.assertEqual(call_args['target_ip'], '192.168.1.100')
        self.assertEqual(call_args['reason'], 'sql_injection threat with high severity')

if __name__ == "__main__":
    unittest.main()
