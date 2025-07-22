# 🔌 Plugin Development Guide - NGINX Security Monitor

## 🎯 **Overview**

The NGINX Security Monitor features a flexible plugin architecture that allows you to extend
its capabilities with custom detection algorithms, mitigation strategies, and integration modules.
This guide covers everything you need to know about developing, testing, and deploying custom plugins.

## 🏗️ **Plugin Architecture**

### **Plugin Types**

The system supports several types of plugins:

| Plugin Type     | Purpose                       | Interface           |
| --------------- | ----------------------------- | ------------------- |
| **Detection**   | Custom threat detection logic | `DetectionPlugin`   |
| **Mitigation**  | Custom mitigation strategies  | `MitigationPlugin`  |
| **Alert**       | Custom notification channels  | `AlertPlugin`       |
| **Parser**      | Custom log format parsers     | `ParserPlugin`      |
| **Integration** | External system integrations  | `IntegrationPlugin` |
| **Filter**      | Request/response filtering    | `FilterPlugin`      |

### **Plugin Lifecycle**

1. **Discovery** → Plugins are discovered in configured directories
1. **Loading** → Plugin modules are imported and validated
1. **Registration** → Plugins register their capabilities
1. **Initialization** → Plugins are initialized with configuration
1. **Execution** → Plugins are called during processing
1. **Cleanup** → Plugins are properly shut down

______________________________________________________________________

## 🔍 **Detection Plugins**

### **Basic Detection Plugin**

Create a simple detection plugin:

```python
# plugins/custom_detector.py
from src.plugin_system import DetectionPlugin
from typing import Dict, List, Any
import re

class CustomThreatDetector(DetectionPlugin):
    """Custom threat detection plugin example."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.name = "custom_threat_detector"
        self.version = "1.0.0"
        self.description = "Detects custom threat patterns"
        
        # Load configuration
        self.patterns = config.get('patterns', [])
        self.severity = config.get('severity', 'medium')
        self.confidence_threshold = config.get('confidence_threshold', 0.7)
        
        # Compile regex patterns for performance
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.patterns
        ]
    
    def detect(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect threats in log entry.
        
        Args:
            log_entry: Parsed log entry containing fields like:
                - ip: source IP address
                - url: requested URL
                - method: HTTP method
                - user_agent: user agent string
                - headers: HTTP headers
                
        Returns:
            List of threat detections with metadata
        """
        threats = []
        
        # Extract relevant fields
        url = log_entry.get('url', '')
        user_agent = log_entry.get('user_agent', '')
        method = log_entry.get('method', '')
        
        # Check patterns against URL
        for i, pattern in enumerate(self.compiled_patterns):
            if pattern.search(url):
                confidence = self._calculate_confidence(log_entry, pattern)
                
                if confidence >= self.confidence_threshold:
                    threats.append({
                        'threat_type': 'custom_threat',
                        'severity': self.severity,
                        'confidence': confidence,
                        'description': f'Custom pattern {i+1} detected in URL',
                        'matched_pattern': self.patterns[i],
                        'matched_field': 'url',
                        'matched_value': url,
                        'metadata': {
                            'pattern_index': i,
                            'detection_method': 'regex',
                            'plugin_name': self.name
                        }
                    })
        
        # Additional detection logic for user agent
        threats.extend(self._check_user_agent(log_entry))
        
        return threats
    
    def _calculate_confidence(self, log_entry: Dict[str, Any], pattern: re.Pattern) -> float:
        """Calculate confidence score for detection."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence based on additional factors
        if log_entry.get('status', 0) in [400, 401, 403, 404]:
            confidence += 0.2
            
        if 'bot' in log_entry.get('user_agent', '').lower():
            confidence += 0.1
            
        if log_entry.get('method') in ['POST', 'PUT', 'DELETE']:
            confidence += 0.1
            
        return min(confidence, 1.0)
    
    def _check_user_agent(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check user agent for suspicious patterns."""
        threats = []
        user_agent = log_entry.get('user_agent', '').lower()
        
        suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan']
        
        for agent in suspicious_agents:
            if agent in user_agent:
                threats.append({
                    'threat_type': 'malicious_user_agent',
                    'severity': 'high',
                    'confidence': 0.9,
                    'description': f'Malicious user agent detected: {agent}',
                    'matched_pattern': agent,
                    'matched_field': 'user_agent',
                    'matched_value': log_entry.get('user_agent'),
                    'metadata': {
                        'detection_method': 'string_match',
                        'plugin_name': self.name
                    }
                })
        
        return threats
    
    def get_info(self) -> Dict[str, Any]:
        """Return plugin information."""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'type': 'detection',
            'patterns_count': len(self.patterns),
            'capabilities': ['url_analysis', 'user_agent_analysis']
        }
```

### **Advanced Detection Plugin**

More sophisticated detection with machine learning:

```python
# plugins/ml_detector.py
from src.plugin_system import DetectionPlugin
import joblib
import numpy as np
from typing import Dict, List, Any

class MLThreatDetector(DetectionPlugin):
    """Machine learning-based threat detection plugin."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.name = "ml_threat_detector"
        self.version = "2.0.0"
        
        # Load pre-trained model
        model_path = config.get('model_path', 'models/threat_detector.joblib')
        self.model = joblib.load(model_path)
        
        # Load feature extractor
        self.feature_extractor = self._init_feature_extractor()
        
        # Configuration
        self.threshold = config.get('threshold', 0.8)
        
    def detect(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """ML-based threat detection."""
        threats = []
        
        try:
            # Extract features
            features = self.feature_extractor.extract(log_entry)
            
            # Predict threat probability
            threat_prob = self.model.predict_proba([features])[0][1]
            
            if threat_prob >= self.threshold:
                # Get feature importance for explanation
                feature_importance = self._get_feature_importance(features)
                
                threats.append({
                    'threat_type': 'ml_detected_threat',
                    'severity': self._map_probability_to_severity(threat_prob),
                    'confidence': threat_prob,
                    'description': f'ML model detected threat (probability: {threat_prob:.3f})',
                    'metadata': {
                        'model_version': self.version,
                        'feature_importance': feature_importance,
                        'detection_method': 'machine_learning'
                    }
                })
                
        except Exception as e:
            # Log error but don't break the detection pipeline
            self.logger.error(f"ML detection error: {e}")
        
        return threats
    
    def _init_feature_extractor(self):
        """Initialize feature extraction pipeline."""
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.preprocessing import StandardScaler
        
        return FeatureExtractor()
    
    def _map_probability_to_severity(self, prob: float) -> str:
        """Map threat probability to severity level."""
        if prob >= 0.95:
            return 'critical'
        elif prob >= 0.9:
            return 'high'
        elif prob >= 0.8:
            return 'medium'
        else:
            return 'low'
```

______________________________________________________________________

## 🛡️ **Mitigation Plugins**

### **Basic Mitigation Plugin**

```python
# plugins/custom_mitigation.py
from src.plugin_system import MitigationPlugin
from typing import Dict, Any
import requests
import subprocess

class CustomMitigationPlugin(MitigationPlugin):
    """Custom mitigation strategy plugin."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.name = "custom_mitigation"
        self.version = "1.0.0"
        
        # Configuration
        self.api_endpoint = config.get('api_endpoint')
        self.api_token = config.get('api_token')
        self.timeout = config.get('timeout', 30)
        
    def can_handle(self, threat: Dict[str, Any]) -> bool:
        """Check if this plugin can handle the threat."""
        supported_types = ['custom_threat', 'brute_force', 'sql_injection']
        return threat.get('threat_type') in supported_types
    
    def mitigate(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Execute mitigation strategy."""
        result = {
            'action_taken': 'none',
            'success': False,
            'details': {},
            'timestamp': self._get_timestamp()
        }
        
        try:
            threat_type = threat.get('threat_type')
            source_ip = threat.get('source_ip')
            severity = threat.get('severity')
            
            # Choose mitigation strategy based on threat type
            if threat_type == 'brute_force':
                result = self._handle_brute_force(threat)
            elif threat_type == 'sql_injection':
                result = self._handle_sql_injection(threat)
            elif threat_type == 'custom_threat':
                result = self._handle_custom_threat(threat)
            
        except Exception as e:
            result['details']['error'] = str(e)
            self.logger.error(f"Mitigation error: {e}")
        
        return result
    
    def _handle_brute_force(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Handle brute force attacks."""
        source_ip = threat.get('source_ip')
        
        # Block IP for 1 hour
        success = self._block_ip(source_ip, duration=3600)
        
        return {
            'action_taken': 'ip_block',
            'success': success,
            'details': {
                'method': 'iptables',
                'duration': 3600,
                'target': source_ip
            }
        }
    
    def _handle_sql_injection(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Handle SQL injection attempts."""
        source_ip = threat.get('source_ip')
        
        # Immediate permanent block for SQL injection
        success = self._block_ip(source_ip, duration='permanent')
        
        # Also notify external security system
        external_response = self._notify_external_system(threat)
        
        return {
            'action_taken': 'permanent_block_and_notify',
            'success': success,
            'details': {
                'method': 'iptables',
                'duration': 'permanent',
                'target': source_ip,
                'external_notification': external_response
            }
        }
    
    def _block_ip(self, ip: str, duration: int = 3600) -> bool:
        """Block IP using iptables."""
        try:
            if duration == 'permanent':
                cmd = f"iptables -I INPUT -s {ip} -j DROP"
            else:
                # Use at command for temporary blocking
                cmd = f"echo 'iptables -D INPUT -s {ip} -j DROP' | at now + {duration} seconds"
                subprocess.run(f"iptables -I INPUT -s {ip} -j DROP", shell=True, check=True)
            
            subprocess.run(cmd, shell=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip}: {e}")
            return False
    
    def _notify_external_system(self, threat: Dict[str, Any]) -> bool:
        """Notify external security system."""
        if not self.api_endpoint:
            return False
            
        try:
            response = requests.post(
                f"{self.api_endpoint}/threats",
                json=threat,
                headers={'Authorization': f'Bearer {self.api_token}'},
                timeout=self.timeout
            )
            return response.status_code == 200
        except requests.RequestException as e:
            self.logger.error(f"Failed to notify external system: {e}")
            return False
```

______________________________________________________________________

## 📧 **Alert Plugins**

### **Custom Alert Channel Plugin**

```python
# plugins/custom_alert.py
from src.plugin_system import AlertPlugin
import requests
from typing import Dict, Any

class CustomAlertPlugin(AlertPlugin):
    """Custom alert channel plugin (e.g., for Microsoft Teams)."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.name = "teams_alert"
        self.webhook_url = config.get('webhook_url')
        self.timeout = config.get('timeout', 30)
        
    def send_alert(self, alert: Dict[str, Any]) -> bool:
        """Send alert to Microsoft Teams."""
        try:
            # Format message for Teams
            teams_message = self._format_teams_message(alert)
            
            response = requests.post(
                self.webhook_url,
                json=teams_message,
                timeout=self.timeout
            )
            
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Teams alert failed: {e}")
            return False
    
    def _format_teams_message(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Format alert for Teams webhook."""
        severity_colors = {
            'low': '28a745',      # Green
            'medium': 'ffc107',   # Yellow
            'high': 'fd7e14',     # Orange
            'critical': 'dc3545'  # Red
        }
        
        color = severity_colors.get(alert.get('severity', 'medium'), 'ffc107')
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": alert.get('title', 'Security Alert'),
            "sections": [{
                "activityTitle": alert.get('title', 'Security Alert'),
                "activitySubtitle": f"Severity: {alert.get('severity', 'Unknown')}",
                "facts": [
                    {"name": "Threat Type", "value": alert.get('threat_type', 'Unknown')},
                    {"name": "Source IP", "value": alert.get('source_ip', 'Unknown')},
                    {"name": "Time", "value": alert.get('timestamp', 'Unknown')},
                    {"name": "Description", "value": alert.get('message', 'No description')}
                ],
                "markdown": True
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "View Details",
                "targets": [{
                    "os": "default",
                    "uri": f"https://security-dashboard.company.com/alert/{alert.get('alert_id', '')}"
                }]
            }]
        }
```

______________________________________________________________________

## 📝 **Parser Plugins**

### **Custom Log Parser Plugin**

```python
# plugins/custom_parser.py
from src.plugin_system import ParserPlugin
import re
from datetime import datetime
from typing import Dict, Any, Optional

class CustomLogParser(ParserPlugin):
    """Custom log format parser plugin."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.name = "custom_log_parser"
        
        # Custom log format pattern
        self.log_pattern = re.compile(
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
            r'\[(?P<level>\w+)\] '
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) '
            r'"(?P<method>\w+) (?P<url>.*?) HTTP/.*?" '
            r'(?P<status>\d+) '
            r'(?P<size>\d+|-) '
            r'"(?P<referrer>.*?)" '
            r'"(?P<user_agent>.*?)"'
        )
        
    def can_parse(self, log_line: str) -> bool:
        """Check if this parser can handle the log line."""
        return bool(self.log_pattern.match(log_line))
    
    def parse(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Parse log line into structured data."""
        match = self.log_pattern.match(log_line)
        
        if not match:
            return None
        
        try:
            parsed_data = match.groupdict()
            
            # Convert and validate data types
            return {
                'timestamp': self._parse_timestamp(parsed_data['timestamp']),
                'level': parsed_data['level'],
                'ip': parsed_data['ip'],
                'method': parsed_data['method'],
                'url': parsed_data['url'],
                'status': int(parsed_data['status']),
                'size': self._parse_size(parsed_data['size']),
                'referrer': parsed_data['referrer'] if parsed_data['referrer'] != '-' else None,
                'user_agent': parsed_data['user_agent'],
                'raw_line': log_line
            }
            
        except (ValueError, KeyError) as e:
            self.logger.error(f"Failed to parse log line: {e}")
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime object."""
        return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
    
    def _parse_size(self, size_str: str) -> Optional[int]:
        """Parse response size."""
        return None if size_str == '-' else int(size_str)
```

______________________________________________________________________

## 🔧 **Plugin Configuration**

### **Plugin Registry Configuration**

Configure plugins in `config/plugins.yaml`:

```yaml
plugins:
  # Global plugin settings
  global:
    plugin_directories:
      - "plugins/"
      - "/etc/nginx-security/plugins/"
      - "/usr/local/lib/nginx-security/plugins/"
    
    # Plugin loading settings
    auto_discovery: true
    lazy_loading: true
    reload_on_change: true
    
    # Security settings
    sandbox_plugins: true
    max_execution_time: 30
    max_memory_usage: "100MB"
  
  # Detection plugins
  detection:
    custom_threat_detector:
      enabled: true
      module: "plugins.custom_detector"
      class: "CustomThreatDetector"
      priority: 10  # Lower number = higher priority
      config:
        patterns:
          - "admin\.php"
          - "wp-admin"
          - "phpmyadmin"
        severity: "medium"
        confidence_threshold: 0.7
    
    ml_threat_detector:
      enabled: true
      module: "plugins.ml_detector"
      class: "MLThreatDetector"
      priority: 5
      config:
        model_path: "models/threat_detector.joblib"
        threshold: 0.8
  
  # Mitigation plugins
  mitigation:
    custom_mitigation:
      enabled: true
      module: "plugins.custom_mitigation"
      class: "CustomMitigationPlugin"
      config:
        api_endpoint: "https://security-api.company.com"
        api_token: "${SECURITY_API_TOKEN}"
        timeout: 30
  
  # Alert plugins
  alerts:
    teams_alert:
      enabled: true
      module: "plugins.custom_alert"
      class: "CustomAlertPlugin"
      config:
        webhook_url: "${TEAMS_WEBHOOK_URL}"
        timeout: 30
  
  # Parser plugins
  parsers:
    custom_log_parser:
      enabled: true
      module: "plugins.custom_parser"
      class: "CustomLogParser"
      priority: 5
```

______________________________________________________________________

## 🧪 **Plugin Testing**

### **Unit Testing Framework**

Create comprehensive tests for your plugins:

```python
# tests/test_custom_detector.py
import unittest
from unittest.mock import Mock, patch
from plugins.custom_detector import CustomThreatDetector

class TestCustomThreatDetector(unittest.TestCase):
    """Test custom threat detector plugin."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'patterns': ['admin.php', 'wp-admin'],
            'severity': 'medium',
            'confidence_threshold': 0.7
        }
        self.detector = CustomThreatDetector(self.config)
    
    def test_detect_admin_access(self):
        """Test detection of admin page access."""
        log_entry = {
            'ip': '192.168.1.100',
            'url': '/admin.php?action=login',
            'method': 'POST',
            'status': 200,
            'user_agent': 'Mozilla/5.0'
        }
        
        threats = self.detector.detect(log_entry)
        
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]['threat_type'], 'custom_threat')
        self.assertEqual(threats[0]['severity'], 'medium')
        self.assertGreaterEqual(threats[0]['confidence'], 0.7)
    
    def test_no_detection_normal_request(self):
        """Test no detection for normal requests."""
        log_entry = {
            'ip': '192.168.1.100',
            'url': '/index.html',
            'method': 'GET',
            'status': 200,
            'user_agent': 'Mozilla/5.0'
        }
        
        threats = self.detector.detect(log_entry)
        
        self.assertEqual(len(threats), 0)
    
    def test_malicious_user_agent_detection(self):
        """Test detection of malicious user agents."""
        log_entry = {
            'ip': '192.168.1.100',
            'url': '/index.html',
            'method': 'GET',
            'status': 200,
            'user_agent': 'sqlmap/1.4.9'
        }
        
        threats = self.detector.detect(log_entry)
        
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]['threat_type'], 'malicious_user_agent')
        self.assertEqual(threats[0]['severity'], 'high')
    
    def test_confidence_calculation(self):
        """Test confidence score calculation."""
        log_entry = {
            'ip': '192.168.1.100',
            'url': '/admin.php',
            'method': 'POST',
            'status': 401,
            'user_agent': 'bot'
        }
        
        pattern = self.detector.compiled_patterns[0]
        confidence = self.detector._calculate_confidence(log_entry, pattern)
        
        # Should be high confidence due to 401 status, POST method, and bot user agent
        self.assertGreater(confidence, 0.8)

if __name__ == '__main__':
    unittest.main()
```

### **Integration Testing**

Test plugins within the full system:

```python
# tests/test_plugin_integration.py
import unittest
from src.plugin_system import PluginManager
from src.monitor_service import MonitorService

class TestPluginIntegration(unittest.TestCase):
    """Test plugin integration with main system."""
    
    def setUp(self):
        """Set up test environment."""
        self.plugin_manager = PluginManager('tests/test_plugins/')
        self.monitor = MonitorService('tests/test_config.yaml')
    
    def test_plugin_loading(self):
        """Test plugin discovery and loading."""
        plugins = self.plugin_manager.discover_plugins()
        
        self.assertGreater(len(plugins), 0)
        self.assertIn('custom_threat_detector', plugins)
    
    def test_detection_pipeline(self):
        """Test complete detection pipeline with plugins."""
        log_entry = {
            'ip': '192.168.1.100',
            'url': '/admin.php',
            'method': 'POST',
            'status': 401,
            'user_agent': 'Mozilla/5.0'
        }
        
        # Process through detection pipeline
        threats = self.monitor.process_log_entry(log_entry)
        
        # Should detect threat using custom plugin
        self.assertGreater(len(threats), 0)
        
        # Check that plugin was involved
        plugin_threats = [
            t for t in threats 
            if t.get('metadata', {}).get('plugin_name') == 'custom_threat_detector'
        ]
        self.assertGreater(len(plugin_threats), 0)
```

### **Performance Testing**

Test plugin performance:

```python
# tests/test_plugin_performance.py
import time
import unittest
from plugins.custom_detector import CustomThreatDetector

class TestPluginPerformance(unittest.TestCase):
    """Test plugin performance characteristics."""
    
    def setUp(self):
        """Set up performance test."""
        self.config = {
            'patterns': ['admin.php'] * 100,  # Many patterns
            'severity': 'medium',
            'confidence_threshold': 0.7
        }
        self.detector = CustomThreatDetector(self.config)
    
    def test_detection_performance(self):
        """Test detection performance with many patterns."""
        log_entry = {
            'ip': '192.168.1.100',
            'url': '/normal-page.html',
            'method': 'GET',
            'status': 200,
            'user_agent': 'Mozilla/5.0'
        }
        
        # Time detection process
        start_time = time.time()
        
        for _ in range(1000):
            threats = self.detector.detect(log_entry)
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 1000
        
        # Should complete detection in reasonable time
        self.assertLess(avg_time, 0.001)  # < 1ms average
    
    def test_memory_usage(self):
        """Test plugin memory usage."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Create many detector instances
        detectors = []
        for i in range(100):
            detectors.append(CustomThreatDetector(self.config))
        
        final_memory = process.memory_info().rss
        memory_per_instance = (final_memory - initial_memory) / 100
        
        # Should use reasonable memory per instance
        self.assertLess(memory_per_instance, 1024 * 1024)  # < 1MB per instance
```

______________________________________________________________________

## 📦 **Plugin Packaging and Distribution**

### **Plugin Package Structure**

Organize plugins for distribution:

```text
my_security_plugin/
├── setup.py
├── README.md
├── requirements.txt
├── my_security_plugin/
│   ├── __init__.py
│   ├── detector.py
│   ├── mitigation.py
│   └── config/
│       └── default_config.yaml
├── tests/
│   ├── __init__.py
│   ├── test_detector.py
│   └── test_mitigation.py
└── docs/
    ├── installation.md
    └── configuration.md
```

### **Plugin Setup Script**

```python
# setup.py
from setuptools import setup, find_packages

setup(
    name="my-security-plugin",
    version="1.0.0",
    description="Custom security detection and mitigation plugin",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "nginx-security-monitor>=2.0.0",
        "requests>=2.25.0",
        "scikit-learn>=1.0.0"
    ],
    entry_points={
        'nginx_security_plugins': [
            'my_detector = my_security_plugin.detector:MyDetectorPlugin',
            'my_mitigation = my_security_plugin.mitigation:MyMitigationPlugin'
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
)
```

### **Plugin Installation**

```bash
# Install from PyPI
pip install my-security-plugin

# Install from source
git clone https://github.com/AccessiTech/nginx-security-monitor.git
cd my-security-plugin
pip install -e .

# Install plugin dependencies
pip install -r requirements.txt
```

______________________________________________________________________

## 🔒 **Plugin Security**

### **Plugin Sandboxing**

Implement security measures for plugin execution:

```python
# src/plugin_security.py
import resource
import signal
import functools
from typing import Any, Callable

class PluginSandbox:
    """Security sandbox for plugin execution."""
    
    def __init__(self, max_memory: int = 100 * 1024 * 1024, max_time: int = 30):
        self.max_memory = max_memory  # 100MB
        self.max_time = max_time      # 30 seconds
    
    def timeout_handler(self, signum, frame):
        """Handle execution timeout."""
        raise TimeoutError("Plugin execution timed out")
    
    def limit_resources(self):
        """Set resource limits for plugin execution."""
        # Limit memory usage
        resource.setrlimit(resource.RLIMIT_AS, (self.max_memory, self.max_memory))
        
        # Limit CPU time
        resource.setrlimit(resource.RLIMIT_CPU, (self.max_time, self.max_time))
    
    def sandbox_execution(self, func: Callable) -> Callable:
        """Decorator to sandbox plugin execution."""
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Set up timeout
            signal.signal(signal.SIGALRM, self.timeout_handler)
            signal.alarm(self.max_time)
            
            try:
                # Limit resources in subprocess would be better
                # This is a simplified example
                result = func(*args, **kwargs)
                return result
            except TimeoutError:
                raise
            except Exception as e:
                # Log and re-raise
                raise
            finally:
                signal.alarm(0)  # Cancel alarm
        
        return wrapper
```

### **Plugin Validation**

Validate plugins before loading:

```python
# src/plugin_validator.py
import ast
import importlib.util
from typing import List, Dict, Any

class PluginValidator:
    """Validate plugin code for security issues."""
    
    DANGEROUS_IMPORTS = [
        'os', 'subprocess', 'sys', 'importlib',
        'exec', 'eval', '__import__'
    ]
    
    DANGEROUS_FUNCTIONS = [
        'exec', 'eval', 'compile', '__import__',
        'open', 'file', 'input', 'raw_input'
    ]
    
    def validate_plugin(self, plugin_path: str) -> Dict[str, Any]:
        """Validate plugin for security issues."""
        result = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'security_issues': []
        }
        
        try:
            with open(plugin_path, 'r') as f:
                code = f.read()
            
            # Parse AST
            tree = ast.parse(code)
            
            # Check for dangerous imports
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in self.DANGEROUS_IMPORTS:
                            result['security_issues'].append(
                                f"Dangerous import: {alias.name}"
                            )
                
                if isinstance(node, ast.Call):
                    if hasattr(node.func, 'id') and node.func.id in self.DANGEROUS_FUNCTIONS:
                        result['security_issues'].append(
                            f"Dangerous function call: {node.func.id}"
                        )
            
            # Set validity based on security issues
            if result['security_issues']:
                result['valid'] = False
            
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"Validation error: {e}")
        
        return result
```

______________________________________________________________________

## 📚 **Plugin Examples Repository**

### **Example Plugin Collection**

Create a collection of example plugins:

```bash
examples/
├── detectors/
│   ├── regex_detector.py          # Regex-based detection
│   ├── ml_detector.py             # Machine learning detection
│   ├── behavioral_detector.py     # Behavioral analysis
│   └── geolocation_detector.py    # Geographic analysis
├── mitigations/
│   ├── iptables_mitigation.py     # iptables integration
│   ├── cloudflare_mitigation.py   # Cloudflare API integration
│   ├── aws_waf_mitigation.py      # AWS WAF integration
│   └── rate_limit_mitigation.py   # Rate limiting
├── alerts/
│   ├── teams_alert.py             # Microsoft Teams
│   ├── pagerduty_alert.py         # PagerDuty integration
│   ├── opsgenie_alert.py          # Opsgenie integration
│   └── webhook_alert.py           # Generic webhook
└── parsers/
    ├── apache_parser.py           # Apache log format
    ├── iis_parser.py              # IIS log format
    ├── cloudflare_parser.py       # Cloudflare logs
    └── json_parser.py             # JSON log format
```

______________________________________________________________________

## 🔗 **Related Documentation**

- [API Reference](API_REFERENCE.md) - Plugin base classes and interfaces
- [Configuration Guide](CONFIGURATION.md) - Plugin configuration options
- [Pattern Detection](PATTERN_DETECTION.md) - Detection pattern concepts
- [Mitigation Strategies](MITIGATION_STRATEGIES.md) - Mitigation concepts
- [Integration Cookbook](INTEGRATION_COOKBOOK.md) - Integration examples

______________________________________________________________________

*This plugin development guide is part of the NGINX Security Monitor documentation. For updates and contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).*
