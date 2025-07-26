# 📖 API Reference - NGINX Security Monitor

## 🎯 **Overview**

This document provides comprehensive API documentation for all modules and classes in the
NGINX Security Monitor system. Each component is documented with its purpose, methods,
parameters, and usage examples.

## 📁 **Module Index**

| Module                 | Purpose                         | Key Classes           |
| ---------------------- | ------------------------------- | --------------------- |
| `monitor_service`      | Main service coordination       | `MonitorService`      |
| `log_parser`           | Log file parsing and processing | `LogParser`           |
| `pattern_detector`     | Threat pattern detection        | `PatternDetector`     |
| `alert_manager`        | Alert system management         | `AlertManager`        |
| `mitigation`           | Threat mitigation strategies    | `MitigationEngine`    |
| `security_coordinator` | Security orchestration          | `SecurityCoordinator` |
| `plugin_system`        | Plugin architecture             | `PluginManager`       |
| `crypto_utils`         | Encryption utilities            | `CryptoUtils`         |
| `network_security`     | Network-level security          | `NetworkSecurity`     |
| `service_protection`   | Service self-protection         | `ServiceProtection`   |

______________________________________________________________________

## 🔧 **Core Modules**

### **MonitorService** (`monitor_service.py`)

The main service class that coordinates all security monitoring activities.

#### **Class: MonitorService**

```python
class MonitorService:
    """Main monitoring service coordinator."""
    
    def __init__(self, config_path: str = None):
        """Initialize the monitoring service.
        
        Args:
            config_path (str): Path to configuration file
        """
```

#### **Methods:**

##### `start()`

Starts the monitoring service with all configured components.

```python
def start(self) -> None:
    """Start the monitoring service."""
```

**Example:**

```python
from nginx_security_monitor.monitor_service import MonitorService

monitor = MonitorService('/path/to/config.yaml')
monitor.start()
```

##### `stop()`

Gracefully stops the monitoring service.

```python
def stop(self) -> None:
    """Stop the monitoring service gracefully."""
```

##### `reload_config()`

Reloads configuration without stopping the service.

```python
def reload_config(self) -> bool:
    """Reload configuration.
    
    Returns:
        bool: True if reload successful, False otherwise
    """
```

______________________________________________________________________

### **LogParser** (`log_parser.py`)

Handles parsing and processing of various log file formats.

#### **Class: LogParser**

```python
class LogParser:
    """Log file parser with support for multiple formats."""
    
    def __init__(self, log_format: str = 'nginx'):
        """Initialize log parser.
        
        Args:
            log_format (str): Log format type ('nginx', 'apache', 'custom')
        """
```

#### **Methods:**

##### `parse_line(line: str)`

Parses a single log line into structured data.

```python
def parse_line(self, line: str) -> Dict[str, Any]:
    """Parse a single log line.
    
    Args:
        line (str): Raw log line
        
    Returns:
        Dict[str, Any]: Parsed log entry with fields:
            - timestamp: datetime object
            - ip: client IP address
            - method: HTTP method
            - url: requested URL
            - status: HTTP status code
            - user_agent: user agent string
            - additional fields based on log format
    """
```

**Example:**

```python
from nginx_security_monitor.log_parser import LogParser

parser = LogParser('nginx')
log_entry = parser.parse_line('192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET / HTTP/1.1" 200 1234')
print(log_entry['ip'])  # '192.168.1.1'
print(log_entry['status'])  # 200
```

##### `parse_file(file_path: str)`

Parses an entire log file.

```python
def parse_file(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
    """Parse entire log file.
    
    Args:
        file_path (str): Path to log file
        
    Yields:
        Dict[str, Any]: Parsed log entries
    """
```

______________________________________________________________________

### **PatternDetector** (`pattern_detector.py`)

Detects security threats using configurable patterns.

#### **Class: PatternDetector**

```python
class PatternDetector:
    """Threat pattern detection engine."""
    
    def __init__(self, patterns_config: str = None):
        """Initialize pattern detector.
        
        Args:
            patterns_config (str): Path to patterns configuration file
        """
```

#### **Methods:**

##### `detect_threats(log_entry: Dict)`

Analyzes a log entry for security threats.

```python
def detect_threats(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detect threats in log entry.
    
    Args:
        log_entry (Dict[str, Any]): Parsed log entry
        
    Returns:
        List[Dict[str, Any]]: List of detected threats with:
            - threat_type: type of threat detected
            - severity: threat severity level
            - description: human-readable description
            - confidence: detection confidence (0-1)
            - matched_pattern: pattern that triggered detection
    """
```

**Example:**

```python
from nginx_security_monitor.pattern_detector import PatternDetector

detector = PatternDetector('/path/to/patterns.json')
threats = detector.detect_threats({
    'ip': '192.168.1.100',
    'url': '/admin/login',
    'method': 'POST',
    'status': 401
})

for threat in threats:
    print(f"Threat: {threat['threat_type']} (Severity: {threat['severity']})")
```

##### `add_pattern(pattern: Dict)`

Adds a new detection pattern.

```python
def add_pattern(self, pattern: Dict[str, Any]) -> bool:
    """Add new detection pattern.
    
    Args:
        pattern (Dict[str, Any]): Pattern definition with:
            - name: pattern name
            - description: pattern description
            - conditions: detection conditions
            - severity: threat severity
            - enabled: whether pattern is active
            
    Returns:
        bool: True if pattern added successfully
    """
```

______________________________________________________________________

## 🚨 **Alert System**

### **AlertManager** (`alert_manager.py`)

Manages alert generation and delivery across multiple channels.

#### **Class: AlertManager**

```python
class AlertManager:
    """Alert management and delivery system."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize alert manager.
        
        Args:
            config (Dict[str, Any]): Alert configuration
        """
```

#### **Methods:**

##### `send_alert(alert: Dict)`

Sends an alert through configured channels.

```python
def send_alert(self, alert: Dict[str, Any]) -> bool:
    """Send alert through configured channels.
    
    Args:
        alert (Dict[str, Any]): Alert data with:
            - title: alert title
            - message: alert message
            - severity: alert severity level
            - timestamp: alert timestamp
            - source_ip: source IP if applicable
            - threat_type: type of threat
            - metadata: additional alert metadata
            
    Returns:
        bool: True if alert sent successfully
    """
```

**Example:**

```python
from nginx_security_monitor.alert_manager import AlertManager

alert_mgr = AlertManager({
    'email': {'enabled': True, 'smtp_server': 'localhost'},
    'sms': {'enabled': False}
})

alert_mgr.send_alert({
    'title': 'Brute Force Attack Detected',
    'message': 'Multiple failed login attempts from 192.168.1.100',
    'severity': 'high',
    'source_ip': '192.168.1.100',
    'threat_type': 'brute_force'
})
```

##### `register_channel(channel: AlertChannel)`

Registers a new alert channel.

```python
def register_channel(self, channel: 'AlertChannel') -> None:
    """Register new alert channel.
    
    Args:
        channel (AlertChannel): Alert channel implementation
    """
```

______________________________________________________________________

## 🛡️ **Security Components**

### **MitigationEngine** (`mitigation.py`)

Implements automated threat mitigation strategies.

#### **Class: MitigationEngine**

```python
class MitigationEngine:
    """Automated threat mitigation system."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize mitigation engine.
        
        Args:
            config (Dict[str, Any]): Mitigation configuration
        """
```

#### **Methods:**

##### `mitigate_threat(threat: Dict)`

Executes mitigation strategy for detected threat.

```python
def mitigate_threat(self, threat: Dict[str, Any]) -> Dict[str, Any]:
    """Execute mitigation for threat.
    
    Args:
        threat (Dict[str, Any]): Threat information
        
    Returns:
        Dict[str, Any]: Mitigation result with:
            - action_taken: description of mitigation action
            - success: whether mitigation was successful
            - details: additional mitigation details
    """
```

**Example:**

```python
from nginx_security_monitor.mitigation import MitigationEngine

mitigation = MitigationEngine({
    'auto_block': True,
    'block_duration': 3600,
    'fail2ban_integration': True
})

result = mitigation.mitigate_threat({
    'threat_type': 'brute_force',
    'source_ip': '192.168.1.100',
    'severity': 'high'
})

print(f"Action taken: {result['action_taken']}")
```

______________________________________________________________________

## 🔌 **Plugin System**

### **PluginManager** (`plugin_system.py`)

Manages dynamic loading and execution of security plugins.

#### **Class: PluginManager**

```python
class PluginManager:
    """Plugin management system."""
    
    def __init__(self, plugin_dir: str = None):
        """Initialize plugin manager.
        
        Args:
            plugin_dir (str): Directory containing plugins
        """
```

#### **Methods:**

##### `load_plugin(plugin_name: str)`

Loads a security plugin.

```python
def load_plugin(self, plugin_name: str) -> bool:
    """Load security plugin.
    
    Args:
        plugin_name (str): Name of plugin to load
        
    Returns:
        bool: True if plugin loaded successfully
    """
```

##### `execute_detection_plugins(log_entry: Dict)`

Executes all loaded detection plugins on a log entry.

```python
def execute_detection_plugins(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute detection plugins.
    
    Args:
        log_entry (Dict[str, Any]): Log entry to analyze
        
    Returns:
        List[Dict[str, Any]]: List of plugin detection results
    """
```

______________________________________________________________________

## 🔐 **Utility Modules**

### **CryptoUtils** (`crypto_utils.py`)

Provides encryption and decryption utilities for sensitive configuration data.

#### **Class: CryptoUtils**

```python
class CryptoUtils:
    """Cryptographic utilities for secure configuration."""
    
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> bytes:
        """Encrypt sensitive data.
        
        Args:
            data (str): Data to encrypt
            key (bytes): Encryption key
            
        Returns:
            bytes: Encrypted data
        """
```

#### **Methods:**

##### `generate_key()`

Generates a new encryption key.

```python
@staticmethod
def generate_key() -> bytes:
    """Generate new encryption key.
    
    Returns:
        bytes: Generated encryption key
    """
```

**Example:**

```python
from nginx_security_monitor.crypto_utils import CryptoUtils

# Generate encryption key
key = CryptoUtils.generate_key()

# Encrypt sensitive data
sensitive_data = "api_key_12345"
encrypted = CryptoUtils.encrypt_data(sensitive_data, key)

# Decrypt data
decrypted = CryptoUtils.decrypt_data(encrypted, key)
```

______________________________________________________________________

## 🌐 **Network Security**

### **NetworkSecurity** (`network_security.py`)

Handles network-level security monitoring and controls.

#### **Class: NetworkSecurity**

```python
class NetworkSecurity:
    """Network security monitoring and control."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize network security.
        
        Args:
            config (Dict[str, Any]): Network security configuration
        """
```

#### **Methods:**

##### `block_ip(ip_address: str, duration: int)`

Blocks an IP address for specified duration.

```python
def block_ip(self, ip_address: str, duration: int = 3600) -> bool:
    """Block IP address.
    
    Args:
        ip_address (str): IP address to block
        duration (int): Block duration in seconds
        
    Returns:
        bool: True if IP blocked successfully
    """
```

______________________________________________________________________

## 📊 **Data Types and Structures**

### **Common Data Structures**

#### **LogEntry**

```python
LogEntry = Dict[str, Any]
# Fields:
# - timestamp: datetime
# - ip: str
# - method: str
# - url: str
# - status: int
# - user_agent: str
# - referrer: str (optional)
# - response_size: int (optional)
```

#### **ThreatDetection**

```python
ThreatDetection = Dict[str, Any]
# Fields:
# - threat_type: str
# - severity: str ('low', 'medium', 'high', 'critical')
# - confidence: float (0.0-1.0)
# - description: str
# - matched_pattern: str
# - metadata: Dict[str, Any]
```

#### **AlertData**

```python
AlertData = Dict[str, Any]
# Fields:
# - title: str
# - message: str
# - severity: str
# - timestamp: datetime
# - source_ip: str (optional)
# - threat_type: str (optional)
# - metadata: Dict[str, Any]
```

______________________________________________________________________

## 🔧 **Configuration Interfaces**

### **Configuration Classes**

#### **MonitorConfig**

```python
@dataclass
class MonitorConfig:
    """Main monitoring configuration."""
    log_files: List[str]
    patterns_file: str
    alert_config: AlertConfig
    mitigation_config: MitigationConfig
    enable_encryption: bool = False
    plugin_directory: str = None
```

#### **AlertConfig**

```python
@dataclass
class AlertConfig:
    """Alert system configuration."""
    email_enabled: bool = False
    email_config: EmailConfig = None
    sms_enabled: bool = False
    sms_config: SmsConfig = None
    webhook_enabled: bool = False
    webhook_config: WebhookConfig = None
```

______________________________________________________________________

## 🚀 **Usage Examples**

### **Basic Monitoring Setup**

```python
from nginx_security_monitor.monitor_service import MonitorService
from nginx_security_monitor.log_parser import LogParser
from nginx_security_monitor.pattern_detector import PatternDetector
from nginx_security_monitor.alert_manager import AlertManager

# Initialize components
monitor = MonitorService('/etc/nginx-security/config.yaml')

# Start monitoring
monitor.start()

# The service will now:
# 1. Parse incoming log entries
# 2. Detect threats using configured patterns
# 3. Send alerts for detected threats
# 4. Execute mitigation strategies
```

### **Custom Plugin Development**

```python
from nginx_security_monitor.plugin_system import PluginManager, DetectionPlugin

class CustomThreatDetector(DetectionPlugin):
    """Custom threat detection plugin."""
    
    def detect(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Custom detection logic."""
        threats = []
        
        # Your custom detection logic here
        if self._is_suspicious(log_entry):
            threats.append({
                'threat_type': 'custom_threat',
                'severity': 'medium',
                'confidence': 0.8,
                'description': 'Custom threat detected'
            })
            
        return threats

# Load and use custom plugin
plugin_mgr = PluginManager()
plugin_mgr.register_plugin(CustomThreatDetector())
```

______________________________________________________________________

## 📝 **Error Handling**

### **Common Exceptions**

#### **ConfigurationError**

Raised when configuration is invalid or missing.

```python
class ConfigurationError(Exception):
    """Configuration-related error."""
    pass
```

#### **PatternError**

Raised when pattern detection encounters an error.

```python
class PatternError(Exception):
    """Pattern detection error."""
    pass
```

#### **AlertError**

Raised when alert delivery fails.

```python
class AlertError(Exception):
    """Alert delivery error."""
    pass
```

### **Error Handling Example**

```python
from nginx_security_monitor.monitor_service import MonitorService, ConfigurationError

try:
    monitor = MonitorService('/path/to/config.yaml')
    monitor.start()
except ConfigurationError as e:
    print(f"Configuration error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

______________________________________________________________________

## 🔗 **Related Documentation**

- [Configuration Guide](CONFIGURATION.md) - Detailed configuration options
- [Plugin Development](PLUGIN_DEVELOPMENT.md) - Creating custom plugins
- [Pattern Detection](PATTERN_DETECTION.md) - Understanding and customizing patterns
- [Alert Systems](ALERT_SYSTEMS.md) - Setting up alert channels
- [Integration Cookbook](INTEGRATION_COOKBOOK.md) - Integration examples

______________________________________________________________________

## 📊 **Version Compatibility**

| Component    | Minimum Version | Recommended Version |
| ------------ | --------------- | ------------------- |
| Python       | 3.8             | 3.11+               |
| PyYAML       | 5.4.0           | 6.0+                |
| cryptography | 3.4.0           | 41.0+               |
| requests     | 2.25.0          | 2.31+               |

______________________________________________________________________

*This API reference is maintained as part of the NGINX Security Monitor project.
For updates and contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).*
