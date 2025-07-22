# 🏗️ Architecture Guide - NGINX Security Monitor

## 🎯 **Overview**

The NGINX Security Monitor is a comprehensive, modular security monitoring system designed with
enterprise-grade architecture principles. This document provides detailed insight into the system's
architecture, design decisions, data flow, and extension points.

## 📊 **High-Level Architecture**

```text
┌─────────────────────────────────────────────────────────────────┐
│                     NGINX Security Monitor                     │
│                        Main Service                            │
└─────────────────────────┬───────────────────────────────────────┘
                          │
    ┌─────────────────────▼─────────────────────────┐
    │         Security Coordinator                  │
    │    (Central Orchestration & Control)          │
    └─────────────────────┬─────────────────────────┘
                          │
    ┌─────────────────────▼─────────────────────────┐
    │            Core Processing Layer              │
    │  ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │
    │  │   Log   │ │ Threat  │ │     Alert       │  │
    │  │Processor│ │Processor│ │    Manager      │  │
    │  └─────────┘ └─────────┘ └─────────────────┘  │
    └─────────────────────┬─────────────────────────┘
                          │
    ┌─────────────────────▼─────────────────────────┐
    │           Security Services Layer             │
    │  ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │
    │  │Pattern  │ │Security │ │   Service       │  │
    │  │Detector │ │Integr.  │ │  Protection     │  │
    │  └─────────┘ └─────────┘ └─────────────────┘  │
    └─────────────────────┬─────────────────────────┘
                          │
    ┌─────────────────────▼─────────────────────────┐
    │        Infrastructure & Security Layer        │
    │  ┌─────────┐ ┌─────────┐ ┌─────────────────┐  │
    │  │ Plugin  │ │ Crypto  │ │    Network      │  │
    │  │ System  │ │ Utils   │ │   Security      │  │
    │  └─────────┘ └─────────┘ └─────────────────┘  │
    └───────────────────────────────────────────────┘
```

## 🏢 **Component Architecture**

### **1. Core Service Layer**

#### **MonitorService** (`monitor_service.py`)

- **Purpose**: Main service entry point and lifecycle management
- **Responsibilities**:
  - Service initialization and configuration loading
  - Component orchestration and dependency injection
  - Signal handling for graceful shutdown
  - Backward compatibility for legacy integrations

#### **SecurityCoordinator** (`security_coordinator.py`)

- **Purpose**: Central orchestration hub for all security operations
- **Responsibilities**:
  - Monitoring lifecycle management
  - Coordination between core processors
  - Statistics collection and reporting
  - Error handling and recovery

### **2. Core Processing Layer**

#### **LogProcessor** (`log_processor.py`)

- **Purpose**: Log file reading and incremental processing
- **Key Features**:
  - Incremental log reading (tracks file position)
  - Log rotation detection and handling
  - Structured log parsing
  - Memory-efficient streaming processing

#### **ThreatProcessor** (`threat_processor.py`)

- **Purpose**: Threat detection coordination and enrichment
- **Key Features**:
  - Pattern detection orchestration
  - Threat enrichment with geolocation and metadata
  - Severity assessment algorithms
  - Mitigation strategy application

#### **AlertManager** (`alert_manager.py`)

- **Purpose**: Centralized alert generation and delivery
- **Key Features**:
  - Multi-channel alerting (email, SMS, webhooks)
  - Alert templating and formatting
  - Emergency alert prioritization
  - Alert throttling and deduplication

### **3. Security Services Layer**

#### **PatternDetector** (`pattern_detector.py`)

- **Purpose**: Threat pattern recognition and analysis
- **Detection Capabilities**:
  - SQL injection detection
  - Cross-site scripting (XSS) identification
  - Brute force attack recognition
  - DDoS pattern analysis
  - Directory traversal detection
  - Suspicious user agent identification

#### **SecurityIntegrationManager** (`security_integrations.py`)

- **Purpose**: External security tool integration hub
- **Supported Integrations**:
  - **fail2ban**: IP blocking and jail management
  - **OSSEC/Wazuh**: HIDS and SIEM integration
  - **Suricata**: Network IDS/IPS integration
  - **ModSecurity**: WAF integration
  - **Custom SIEM**: Webhook and API integrations

#### **ServiceProtection** (`service_protection.py`)

- **Purpose**: Self-protection mechanisms for the monitoring service
- **Protection Features**:
  - File integrity monitoring
  - Process integrity verification
  - Resource abuse detection
  - Network security controls
  - System hardening enforcement

### **4. Infrastructure & Security Layer**

#### **PluginSystem** (`plugin_system.py`)

- **Purpose**: Dynamic plugin loading and management
- **Plugin Types**:
  - Detection plugins for custom threat patterns
  - Mitigation plugins for custom response strategies
  - Alert plugins for custom notification channels
  - Parser plugins for custom log formats

#### **CryptoUtils** (`crypto_utils.py`)

- **Purpose**: Encryption and security utilities
- **Features**:
  - AES-256 encryption with PBKDF2 key derivation
  - Secure configuration management
  - Pattern obfuscation
  - Key rotation support

#### **NetworkSecurity** (`network_security.py`)

- **Purpose**: Network-level security controls
- **Features**:
  - IP access control and blocking
  - Firewall integration
  - Port security monitoring
  - DNS security validation

## 🔄 **Data Flow Architecture**

### **Primary Monitoring Flow**

```text
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   NGINX     │    │     Log     │    │   Threat    │
│   Logs      │───▶│  Processor  │───▶│  Processor  │
│   Files     │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
                                              │
┌─────────────┐    ┌─────────────┐           │
│   Alert     │    │   Pattern   │           │
│  Manager    │◄───│  Detector   │◄──────────┘
│             │    │             │
└─────────────┘    └─────────────┘
       │
       ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  External   │    │   Email/    │    │ Mitigation  │
│ Integrations│    │   SMS       │    │ Actions     │
│             │    │   Alerts    │    │             │
└─────────────┘    └─────────────┘    └─────────────┘
```

### **Security Integration Flow**

```text
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  fail2ban   │    │    OSSEC    │    │  Suricata   │
│    Logs     │    │    Logs     │    │    Logs     │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
               ┌─────────────────────┐
               │    Security         │
               │  Integration        │
               │    Manager          │
               └─────────────────────┘
                           │
                           ▼
               ┌─────────────────────┐
               │   Unified Threat    │
               │    Intelligence     │
               │     & Response      │
               └─────────────────────┘
```

## 🔒 **Security Architecture Principles**

### **1. Defense in Depth**

- **Multiple Detection Layers**: Application, network, and host-level monitoring
- **Redundant Controls**: Multiple tools providing overlapping coverage
- **Fail-Safe Defaults**: Secure-by-default configuration options

### **2. Zero-Trust Model**

- **Encrypted Configuration**: Sensitive data encrypted at rest
- **Plugin Sandboxing**: Isolated plugin execution environment
- **Service Self-Protection**: Continuous monitoring of service integrity

### **3. Principle of Least Privilege**

- **Dedicated Service User**: Runs with minimal required permissions
- **Systemd Hardening**: NoNewPrivileges, restricted filesystem access
- **Network Restrictions**: Limited network access requirements

### **4. Secure by Design**

- **Input Validation**: All inputs validated and sanitized
- **Safe Defaults**: Secure default configurations
- **Error Handling**: Fail securely without exposing sensitive information

## 📈 **Scalability Design Patterns**

### **1. Modular Architecture**

- **Component Isolation**: Each module has clear responsibilities
- **Loose Coupling**: Components communicate through well-defined interfaces
- **Plugin Extension**: Easy addition of new capabilities without core changes

### **2. Incremental Processing**

- **Streaming Log Processing**: Avoids loading entire log files into memory
- **State Management**: Tracks processing position for efficient restart
- **Batch Processing**: Processes log entries in configurable batches

### **3. Resource Management**

- **Configurable Intervals**: Adjustable monitoring frequency
- **Memory Efficiency**: Minimal memory footprint design
- **Resource Monitoring**: Built-in resource usage tracking

### **4. Horizontal Scaling Considerations**

- **Stateless Design**: Core processing logic is stateless
- **Shared Configuration**: Configuration can be centralized
- **Distributed Deployment**: Architecture supports multiple instances

## 🔧 **Extension Points and Customization**

### **1. Plugin Architecture**

```python
# Example Detection Plugin Interface
class DetectionPlugin:
    def detect(self, log_entry: dict) -> list:
        """Return list of detected threats"""
        pass
    
    def get_patterns(self) -> dict:
        """Return plugin-specific patterns"""
        pass
```

### **2. Custom Pattern Integration**

```json
{
  "custom_patterns": {
    "my_app_attack": {
      "description": "Application-specific attack pattern",
      "regex": "custom_pattern_here",
      "severity": "high",
      "mitigation": "custom_mitigation_plugin"
    }
  }
}
```

### **3. Integration Extension Points**

```python
# Example Integration Plugin
class CustomSIEMIntegration:
    def send_alert(self, threat_data: dict) -> bool:
        """Send alert to custom SIEM"""
        pass
    
    def get_threat_intel(self) -> list:
        """Retrieve threat intelligence"""
        pass
```

### **4. Alert Channel Extensions**

```python
# Example Custom Alert Channel
class SlackAlertPlugin:
    def send_alert(self, alert_data: dict) -> bool:
        """Send alert to Slack channel"""
        pass
```

## 🏗️ **Design Decisions and Rationale**

### **1. Modular Monolith Approach**

- **Rationale**: Balance between microservices complexity and monolithic simplicity
- **Benefits**: Easy deployment, efficient inter-component communication
- **Trade-offs**: Single point of failure, but simpler operational model

### **2. Configuration-Driven Architecture**

- **Rationale**: Maximum flexibility without code changes
- **Benefits**: Easy customization, environment-specific configurations
- **Implementation**: YAML-based configuration with validation

### **3. Plugin System Design**

- **Rationale**: Extensibility without modifying core code
- **Benefits**: Custom detection/mitigation without exposure in open source
- **Security**: Sandboxed execution environment

### **4. Multi-Integration Strategy**

- **Rationale**: Leverage existing security infrastructure
- **Benefits**: Enhanced coverage, reduced duplication
- **Challenges**: Coordination complexity, managed through central hub

## 🔍 **Performance Characteristics**

### **Resource Usage Patterns**

- **CPU**: Primarily pattern matching operations (regex-intensive)
- **Memory**: Minimal - streaming processing with small buffers
- **Disk I/O**: Read-heavy for log files, minimal writes for state
- **Network**: Periodic outbound for alerts and integrations

### **Scalability Metrics**

- **Log Processing**: ~10,000 entries/minute on modest hardware
- **Pattern Detection**: Concurrent processing of multiple patterns
- **Alert Delivery**: Asynchronous processing prevents blocking

### **Performance Optimization Features**

- **Configurable Check Intervals**: Balance between responsiveness and resource usage
- **Pattern Prioritization**: Process high-priority patterns first
- **Threshold-Based Processing**: Reduce false positives

## 🚀 **Deployment Architecture Patterns**

### **1. Single Node Deployment**

```text
┌─────────────────────────────────────┐
│           Production Server         │
│  ┌─────────────────────────────┐    │
│  │   NGINX Security Monitor   │    │
│  │         Service             │    │
│  └─────────────────────────────┘    │
│  ┌─────────────────────────────┐    │
│  │         NGINX               │    │
│  │       Web Server            │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

### **2. Distributed Monitoring**

```text
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Web       │    │   Web       │    │   Web       │
│  Server 1   │    │  Server 2   │    │  Server N   │
│             │    │             │    │             │
│ ┌─────────┐ │    │ ┌─────────┐ │    │ ┌─────────┐ │
│ │Monitor  │ │    │ │Monitor  │ │    │ │Monitor  │ │
│ │Instance │ │    │ │Instance │ │    │ │Instance │ │
│ └─────────┘ │    │ └─────────┘ │    │ └─────────┘ │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
               ┌─────────────────────┐
               │   Central Alert     │
               │     Manager         │
               └─────────────────────┘
```

### **3. Container Architecture**

```yaml
# Docker Compose Example
version: '3.8'
services:
  nginx-security-monitor:
    image: nginx-security-monitor:latest
    volumes:
      - /var/log/nginx:/var/log/nginx:ro
      - ./config:/etc/nginx-security-monitor
    environment:
      - MONITOR_CONFIG=/etc/nginx-security-monitor/settings.yaml
```

## 🔗 **Integration Architecture**

### **Security Tool Ecosystem**

```text
                ┌─────────────┐
                │   NGINX     │
                │  Security   │
                │  Monitor    │
                └─────┬───────┘
                      │
    ┌─────────────────┼─────────────────┐
    │                 │                 │
    ▼                 ▼                 ▼
┌─────────┐    ┌─────────────┐    ┌─────────┐
│fail2ban │    │ OSSEC/Wazuh │    │Suricata │
│         │    │             │    │         │
└─────────┘    └─────────────┘    └─────────┘
    │                 │                 │
    └─────────────────┼─────────────────┘
                      │
              ┌───────▼───────┐
              │  Unified      │
              │  Security     │
              │  Dashboard    │
              └───────────────┘
```

## 📋 **Configuration Architecture**

### **Configuration Hierarchy**

```text
/etc/nginx-security-monitor/
├── settings.yaml           # Main configuration
├── patterns.json          # Detection patterns
├── service-settings.yaml  # Service-specific settings
└── security/
    ├── encrypted-patterns.enc
    ├── custom-plugins/
    └── ssl-certificates/
```

### **Configuration Loading Priority**

1. Environment variables
1. Command-line arguments
1. Service-specific settings
1. Main settings file
1. Default values

## 🔧 **Extension and Customization Guide**

### **Adding Custom Detection Patterns**

```json
{
  "custom_patterns": {
    "my_application_attack": {
      "description": "Custom application attack",
      "regex": "attack_pattern_regex",
      "severity": "high",
      "threshold": 1,
      "mitigation": "custom_mitigation"
    }
  }
}
```

### **Creating Custom Mitigation Plugins**

```python
# /opt/nginx-security-monitor/custom_plugins/my_mitigation.py
def mitigate_threat(threat_data):
    """Custom mitigation logic"""
    # Implement custom response
    return {"action": "custom_block", "success": True}
```

### **Adding Custom Alert Channels**

```python
# Custom alert plugin
class CustomAlertChannel:
    def send_alert(self, alert_data):
        # Custom alert delivery logic
        pass
```

## 🔄 **Future Architecture Considerations**

### **Planned Enhancements**

- **Microservices Migration Path**: Gradual decomposition strategy
- **Container Orchestration**: Kubernetes deployment patterns
- **Event-Driven Architecture**: Async event processing
- **Machine Learning Integration**: AI-powered threat detection

### **Scalability Roadmap**

- **Horizontal Scaling**: Multi-instance coordination
- **Load Balancing**: Distribution strategies
- **High Availability**: Failover and redundancy
- **Performance Optimization**: Caching and indexing

## 📚 **Related Documentation**

- [Installation Guide](INSTALLATION.md) - Deployment and setup
- [Configuration Guide](CONFIGURATION.md) - Configuration options
- [Plugin Development](PLUGIN_DEVELOPMENT.md) - Creating custom plugins
- [Security Features](SECURITY_FEATURES.md) - Advanced security capabilities
- [Operations Guide](OPERATIONS_GUIDE.md) - Day-to-day operations
- [API Reference](API_REFERENCE.md) - Detailed API documentation

______________________________________________________________________

*This architecture guide provides a comprehensive view of the NGINX Security Monitor system design.
For technical implementation details, refer to the individual module documentation and API reference.*
