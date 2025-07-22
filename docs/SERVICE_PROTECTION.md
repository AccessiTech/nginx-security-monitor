# Service Protection and Hardening Guide

## Overview

The NGINX Security Monitor implements comprehensive self-protection mechanisms to defend against attacks targeting
the monitoring service itself. Since security tools are high-value targets,
we've implemented multiple layers of protection.

## Self-Protection Features

### 🛡️ **File Integrity Monitoring**

- Continuous monitoring of critical service files
- SHA-256 hash verification of source code and configuration
- Automatic detection of unauthorized modifications
- Emergency shutdown on critical file tampering

### 🔍 **Process Integrity Monitoring**

- Baseline process state verification
- Detection of process hijacking attempts
- Monitoring for suspicious child processes
- Protection against code injection

### 📊 **Resource Abuse Detection**

- CPU, memory, and disk usage monitoring
- Detection of resource exhaustion attacks
- Network connection monitoring
- Rate limiting for service operations

### 🌐 **Network Security Controls**

- IP-based access control
- Firewall integration with automatic IP blocking
- Port security monitoring
- DNS query analysis for compromise indicators

### 🔐 **System Hardening**

- File permission enforcement
- Environment variable security validation
- Service binding restrictions
- TLS/SSL configuration validation

## Threat Response Mechanisms

### **Critical Threats (Emergency Shutdown)**

- File tampering of core service files
- Process hijacking detection
- Service compromise indicators

### **High Threats (Immediate Alerts)**

- Suspicious child processes
- Firewall configuration issues
- High resource usage
- Permission violations

### **Medium/Low Threats (Monitoring)**

- Unexpected network connections
- DNS anomalies
- Configuration warnings

## Installation and Setup

### 1. **Install with Self-Protection**

````bash
# Standard installation
sudo ./install.sh

# Apply additional hardening
sudo ./harden.sh
```bash

### 2. **Configure Protection Settings**

Edit `/etc/nginx-security-monitor/settings.yaml`:

```yaml
# Self-protection configuration
security:
  self_check_interval: 300  # Check every 5 minutes
  
protection:
  resource_thresholds:
    cpu_percent: 80.0
    memory_percent: 80.0
    disk_usage_percent: 90.0
  
  emergency_shutdown:
    file_tampering: true
    process_hijacking: true

network_security:
  allowed_ips:
    - 127.0.0.1
    - ::1
    # Add your management IPs
  
  allowed_ports:
    - 22    # SSH
    - 80    # HTTP
    - 443   # HTTPS
    - 587   # SMTP TLS
# Add language identifier to code block at line 107
```yaml

### 3. **Enable Additional Monitoring**

```bash
# Install system monitoring tools
sudo apt-get install aide psutil

# Setup integrity monitoring
sudo aide --init
# Add language identifier to code block at line 117
```bash

## Attack Scenarios and Defenses

### **Scenario 1: Direct File Tampering**

**Attack**: Attacker modifies service files to disable monitoring or inject malicious code.

**Defense**:

- File integrity monitoring detects changes immediately
- Service performs emergency shutdown
- Critical alert sent to administrators
- System logs all file access attempts

### **Scenario 2: Process Injection/Hijacking**

**Attack**: Attacker attempts to inject code into the running service process.

**Defense**:

- Process integrity checks detect baseline deviations
- Monitoring for unexpected child processes
- Emergency shutdown on process hijacking detection
- Process memory protection via systemd hardening

### **Scenario 3: Resource Exhaustion (DoS)**

**Attack**: Flood the service with requests to consume all system resources.

**Defense**:

- Rate limiting on service operations
- Resource usage monitoring with automatic alerts
- CPU/memory/disk threshold enforcement
- Network connection monitoring and blocking

### **Scenario 4: Network-Based Attacks**

**Attack**: Network scanning, unauthorized access attempts, or C2 communication.

**Defense**:

- IP-based access control with automatic blocking
- Port security monitoring
- Firewall integration with custom rules
- DNS query analysis for compromise indicators

### **Scenario 5: Configuration Attacks**

**Attack**: Modify configuration to disable security features or redirect alerts.

**Defense**:

- Configuration file integrity monitoring
- Encrypted configuration sections
- File permission enforcement
- Backup and restoration capabilities

### **Scenario 6: Privilege Escalation**

**Attack**: Attempt to escalate privileges from the service account.

**Defense**:

- Systemd security restrictions (NoNewPrivileges, CapabilityBoundingSet)
- File system access restrictions
- Network namespace isolation
- System call filtering

## Monitoring and Alerting

### **Self-Protection Alerts**

The service sends different types of alerts based on threat severity:

#### **Emergency Alerts** (Critical Threats)

# Add language identifier to code block at line 195
```text
Subject: 🚨 CRITICAL: Security Monitor Service Under Attack
# Add language identifier to code block at line 197
```text

- Sent for file tampering, process hijacking
- Triggers emergency shutdown procedures
- Requires immediate investigation

#### **Service Threat Alerts** (High Threats)

# Add language identifier to code block at line 205
```text
Subject: ⚠️ Security Monitor Service Threats Detected  
# Add language identifier to code block at line 207
```text

- Sent for high-severity threats
- Service continues running but requires attention
- Detailed threat information provided

### **Log Files**

Monitor these logs for security events:

- `/var/log/nginx-security-monitor.log` - Main service log
- `/var/log/nginx-security-monitor/nginx-security-monitor-security.log` - Security events
- `/var/log/auth.log` - System authentication attempts
- `journalctl -u nginx-security-monitor` - Systemd service logs

## Best Practices

### **1. Regular Security Maintenance**

```bash
# Weekly security checks
sudo /usr/local/bin/nginx-security-monitor-security-check

# Monthly integrity verification
sudo aide --check

# Update and restart service monthly
sudo apt update && sudo apt upgrade
sudo systemctl restart nginx-security-monitor
````

### **2. Network Isolation**

- Run service on isolated network segment if possible
- Use firewall rules to restrict unnecessary network access
- Monitor outbound connections for anomalies

### **3. Backup and Recovery**

```bash
# Backup configuration and patterns
sudo cp -r /etc/nginx-security-monitor /backup/location/

# Backup custom plugins
sudo cp -r /opt/nginx-security-monitor/custom_plugins /backup/location/

# Test restoration procedures regularly
```

### **4. Access Control**

- Limit administrative access to service files
- Use strong authentication for system access
- Regularly audit user access and permissions
- Enable audit logging for file access

### **5. Monitoring Integration**

- Integrate alerts with your SIEM/monitoring system
- Set up automated response procedures
- Create runbooks for different threat scenarios
- Regular security assessments and penetration testing

## Troubleshooting

### **High CPU/Memory Usage**

```bash
# Check resource usage
top -p $(pgrep -f monitor_service.py)

# Adjust thresholds if needed
sudo nano /etc/nginx-security-monitor/settings.yaml

# Restart service
sudo systemctl restart nginx-security-monitor
```

### **False Positive Alerts**

```bash
# Check self-protection logs
sudo grep -i "self-protection" /var/log/nginx-security-monitor.log

# Adjust thresholds or whitelist IPs
sudo nano /etc/nginx-security-monitor/settings.yaml

# Update allowed IPs or ports as needed
```

### **Emergency Shutdown Recovery**

```bash
# Check why service shut down
sudo journalctl -u nginx-security-monitor --since "1 hour ago"

# Verify file integrity
sudo aide --check

# If files are clean, restart service
sudo systemctl start nginx-security-monitor
```

### **Firewall Issues**

```bash
# Check firewall rules
sudo iptables -L NGINX_MONITOR_CHAIN

# Remove problematic rules if needed
sudo iptables -D NGINX_MONITOR_CHAIN <rule_number>

# Reset firewall rules
sudo iptables -F NGINX_MONITOR_CHAIN
```

## Advanced Configuration

### **Custom Threat Response**

Create custom response plugins for specific threats:

```python
# File: /etc/nginx-security-monitor/plugins/custom_response.py
from plugin_system import MitigationPlugin

class CustomThreatResponsePlugin(MitigationPlugin):
    def mitigate(self, threat_info):
        if threat_info.get('type') == 'File Tampering':
            # Custom response for file tampering
            self.backup_system()
            self.isolate_network()
            self.notify_security_team()
        
        return {'status': 'custom_response_applied'}
```

### **Integration with External Security Tools**

```yaml
# Custom integrations
integrations:
  siem:
    enabled: true
    endpoint: "https://your-siem.com/api/alerts"
    api_key: "encrypted_api_key_here"
  
  waf:
    enabled: true
    api_endpoint: "https://your-waf.com/api/block"
    auto_block: true
```

This comprehensive self-protection system ensures that even if your NGINX Security Monitor is publicly available
or the source code is known, the actual security measures and the service itself
remain protected against sophisticated attacks.
