#!/usr/bin/env python3
"""
Test script for custom plugins
"""

import sys
import os

# Add the project root to the path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

def test_plugin_loading():
    """Test that plugins can be loaded correctly."""
    print("🧪 Testing plugin loading...")
    
    try:
        # Import the plugin directly
        plugin_path = os.path.join(os.path.dirname(__file__), 'test_plugin.py')
        spec = __import__('importlib.util').util.spec_from_file_location("test_plugin", plugin_path)
        module = __import__('importlib.util').util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        plugin = module.TestpluginPlugin()
        
        print(f"✅ Plugin '{plugin.name}' loaded successfully")
        print(f"   Handles threat types: {plugin.threat_types}")
        print(f"   Priority: {plugin.get_priority()}")
        
        return True
    except Exception as e:
        print(f"❌ Plugin loading failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_plugin_mitigation():
    """Test plugin mitigation functionality."""
    print("\n🧪 Testing plugin mitigation...")
    
    try:
        # Import the plugin directly
        plugin_path = os.path.join(os.path.dirname(__file__), 'test_plugin.py')
        spec = __import__('importlib.util').util.spec_from_file_location("test_plugin", plugin_path)
        module = __import__('importlib.util').util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        plugin = module.TestpluginPlugin()
        
        # Test threat info
        threat_info = {
            'type': 'SQL Injection',
            'severity': 'HIGH',
            'ip': '192.168.1.100',
            'timestamp': '2025-07-21T10:30:00Z'
        }
        
        # Test can_handle
        can_handle = plugin.can_handle(threat_info)
        print(f"   Can handle test threat: {can_handle}")
        
        if can_handle:
            # Test mitigation
            result = plugin.mitigate(threat_info)
            print(f"   Mitigation result: {result.get('status', 'unknown')}")
            print(f"   Action taken: {result.get('action', 'none')}")
            return True
        else:
            print("   Plugin cannot handle this threat type")
            return False
            
    except Exception as e:
        print(f"❌ Plugin mitigation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🔌 Custom Plugin Test Suite")
    print("=" * 40)
    
    success = True
    success &= test_plugin_loading()
    success &= test_plugin_mitigation()
    
    print("\n" + "=" * 40)
    if success:
        print("🎉 All plugin tests passed!")
    else:
        print("💥 Some plugin tests failed!")
    
    sys.exit(0 if success else 1)
