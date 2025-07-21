---
version: 1.0.0
last_updated: 2025-07-20
changelog:
  - version: 1.0.0
    date: 2025-07-20
    changes:
      - Initial comprehensive configuration guide
      - Added cross-references with CONFIGURATION_SYSTEM.md
      - Enhanced documentation structure and navigation
maintainers:
  - nginx-security-team
review_status: current
applies_to_versions: '>=1.0.0'
---

# ⚙️ Configuration Guide

Complete configuration reference for NGINX Security Monitor.

## 📚 Documentation Structure

This configuration documentation is split into two parts:

- This file (CONFIGURATION.md): Contains all available configuration options and their descriptions
- [Configuration System Guide](CONFIGURATION_SYSTEM.md): Details about the secure configuration system, programmatic usage, and advanced features

> **Important**: We recommend reading the [Configuration System Guide](CONFIGURATION_SYSTEM.md) first to understand the secure configuration system's features and best practices.

## 📁 **Configuration File Structure**

```
config/
├── settings.yaml          # Main configuration file
├── patterns.json          # Detection patterns
├── schema.yaml            # Configuration schema
└── service-settings.yaml  # Service-specific settings
```

### **Configuration Files Explained**

#### **`settings.yaml` - Main Configuration Template**

- **Purpose**: Comprehensive configuration reference and development template
- **Contains**: All available configuration options with detailed parameter sets
- **Values**: Static values and placeholders (e.g., `smtp.example.com`, `your_email@example.com`)
- **Use Case**: Development, testing, and as a reference for all available options
- **Security**: Contains example/placeholder values, not production-ready

#### **`service-settings.yaml` - Production Service Configuration**

- **Purpose**: Production-ready service configuration with security best practices
- **Contains**: Streamlined settings focused on runtime service operation
- **Values**: Environment variable references (e.g., `"${SMTP_SERVER}"`, `"${API_KEY}"`)
- **Use Case**: Production deployment with proper secret management
- **Security**: Built-in encryption support, obfuscation, and self-protection features

#### **When to Use Which File**

| Scenario                        | Recommended File        | Reason                                        |
| ------------------------------- | ----------------------- | --------------------------------------------- |
| Development/Testing             | `settings.yaml`         | Complete reference with all options           |
| Production Deployment           | `service-settings.yaml` | Security-focused with environment variables   |
| Configuration Reference         | `settings.yaml`         | Comprehensive documentation of all parameters |
| CI/CD Pipelines                 | `service-settings.yaml` | Environment variable support                  |
| Security-Sensitive Environments | `service-settings.yaml` | Built-in encryption and obfuscation           |

> **💡 Tip**: Start with `settings.yaml` for development, then migrate to `service-settings.yaml` for production deployment with proper environment variable configuration.

## 🔧 **Main Configuration (settings.yaml)**

### **Basic Structure**

```yaml
# NGINX Security Monitor Configuration
# This file controls all aspects of the monitoring service

# ============================================================================
# Core Settings
# ============================================================================
monitoring:
  enabled: true
  check_interval: 10  # seconds between log checks
  batch_size: 1000    # number of log entries to process at once
  
# ============================================================================  
# Log File Settings
# ============================================================================
logs:
  access_log: "/var/log/nginx/access.log"
  error_log: "/var/log/nginx/error.log"
  format: "combined"  # nginx log format
  encoding: "utf-8"
  
# ============================================================================
# Pattern Detection Settings  
# ============================================================================
detection:
  enabled_patterns:
    - sql_injection
    - xss_attacks
    - ddos_detection
    - brute_force
    - directory_traversal
    - suspicious_user_agents
  
  thresholds:
    failed_requests_per_minute: 50
    requests_per_ip_per_minute: 100
    error_rate_threshold: 0.1
    suspicious_user_agent_threshold: 5
  
  whitelist:
    ips:
      - "127.0.0.1"
      - "::1"
      - "192.168.1.0/24"
    user_agents:
      - "Googlebot"
      - "Bingbot"
    
# ============================================================================
# Alert Settings
# ============================================================================
alerts:
  enabled: true
  channels:
    - email
    - sms
  
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    username: "your_email@gmail.com"
    password: "<REPLACE_WITH_ENV_VARIABLE>"  # Use app passwords for Gmail
    from_address: "your_email@gmail.com"
    to_addresses:
      - "security@yourdomain.com"
      - "admin@yourdomain.com"
    
    templates:
      subject: "[SECURITY ALERT] {severity} - {attack_type} detected"
      body_format: "html"  # html or text
  
  sms:
    enabled: false
    provider: "twilio"  # twilio, aws_sns, custom
    # Add provider-specific settings here
    
# ============================================================================
# Mitigation Settings
# ============================================================================
mitigation:
  enabled: true
  auto_mitigation: false  # Set to true for automatic responses
  
  strategies:
    ip_blocking:
      enabled: true
      duration: 3600  # seconds to block IP
      max_attempts: 10
    
    rate_limiting:
      enabled: true
      requests_per_minute: 60
      burst_allowance: 10
      
# ============================================================================
# Logging Settings
# ============================================================================
logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "/var/log/nginx-security-monitor.log"
  max_size: "10MB"
  backup_count: 5
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  
# ============================================================================
# Storage Settings
# ============================================================================
storage:
  database:
    type: "sqlite"  # sqlite, postgresql, mysql
    path: "/var/lib/nginx-security-monitor/monitor.db"
    
  cache:
    type: "memory"  # memory, redis
    max_size: 1000
    ttl: 3600
    
# ============================================================================
# Security Settings
# ============================================================================
security:
  encryption:
    enabled: false
    key_file: "<REPLACE_WITH_ENV_VARIABLE>"
    
  plugin_security:
    enabled: true
    allowed_plugins_dir: "/etc/nginx-security-monitor/plugins"
    signature_verification: false
```

## 🎯 **Pattern Configuration (patterns.json)**

### **Basic Pattern Structure**

```json
{
  "patterns": {
    "sql_injection": {
      "enabled": true,
      "severity": "high",
      "description": "Detects SQL injection attempts",
      "patterns": [
        "(?i)(union.*select|select.*from|insert.*into|delete.*from)",
        "(?i)(or\\s+1=1|and\\s+1=1|'\\s*or\\s*')",
        "(?i)(exec\\s*\\(|sp_|xp_)"
      ],
      "threshold": 1,
      "window": 60
    },
    
    "xss_attacks": {
      "enabled": true,
      "severity": "medium",
      "description": "Cross-site scripting detection",
      "patterns": [
        "(?i)<script[^>]*>.*?</script>",
        "(?i)javascript:",
        "(?i)on(load|click|mouseover|error)\\s*="
      ],
      "threshold": 1,
      "window": 60
    },
    
    "ddos_detection": {
      "enabled": true,
      "severity": "high",
      "description": "DDoS and high-volume attacks",
      "type": "frequency",
      "threshold": 100,
      "window": 60,
      "per_ip": true
    },
    
    "brute_force": {
      "enabled": true,
      "severity": "medium",
      "description": "Brute force login attempts",
      "patterns": [
        "POST.*/(login|signin|auth)",
        "401.*Unauthorized",
        "403.*Forbidden"
      ],
      "threshold": 5,
      "window": 300,
      "per_ip": true
    }
  }
}
```

### **Custom Pattern Examples**

```json
{
  "custom_patterns": {
    "wordpress_attacks": {
      "enabled": true,
      "severity": "medium",
      "description": "WordPress-specific attacks",
      "patterns": [
        "/wp-admin/",
        "/wp-login.php",
        "/xmlrpc.php"
      ],
      "threshold": 10,
      "window": 300
    },
    
    "api_abuse": {
      "enabled": true,
      "severity": "low",
      "description": "API endpoint abuse",
      "patterns": [
        "/api/v[0-9]+/",
        "GET.*api.*key=",
        "POST.*api/auth"
      ],
      "threshold": 50,
      "window": 60
    }
  }
}
```

## 🌍 **Environment-Specific Configurations**

### **Development Environment**

```yaml
# config/dev-settings.yaml
monitoring:
  check_interval: 5
  batch_size: 100

logs:
  access_log: "./tests/sample_logs/access.log"
  error_log: "./tests/sample_logs/error.log"

detection:
  thresholds:
    failed_requests_per_minute: 10  # Lower threshold for testing
    
alerts:
  email:
    enabled: false  # Disable emails in dev
    
logging:
  level: "DEBUG"
  file: "./logs/dev-monitor.log"
```

### **Production Environment**

```yaml
# config/prod-settings.yaml
monitoring:
  check_interval: 10
  batch_size: 1000

logs:
  access_log: "/var/log/nginx/access.log"
  error_log: "/var/log/nginx/error.log"

detection:
  thresholds:
    failed_requests_per_minute: 100
    requests_per_ip_per_minute: 200
    
mitigation:
  auto_mitigation: true  # Enable automatic responses
  
security:
  encryption:
    enabled: true  # Enable encryption in production
    
logging:
  level: "INFO"
  file: "/var/log/nginx-security-monitor.log"
```

### **High-Volume Environment**

```yaml
# config/high-volume-settings.yaml
monitoring:
  check_interval: 5
  batch_size: 5000  # Process more entries at once
  worker_threads: 4  # Multiple processing threads

detection:
  thresholds:
    failed_requests_per_minute: 500
    requests_per_ip_per_minute: 1000
    
storage:
  database:
    type: "postgresql"  # Use PostgreSQL for better performance
    
  cache:
    type: "redis"  # Use Redis for caching
    max_size: 10000
```

## 🔒 **Security Best Practices**

### **Configuration File Security**

```bash
# Set proper permissions
sudo chmod 600 /etc/nginx-security-monitor/settings.yaml
sudo chown nginx-monitor:nginx-monitor /etc/nginx-security-monitor/settings.yaml

# Encrypt sensitive data
python encrypt_config.py --encrypt-file settings.yaml
```

### **Credential Management**

```yaml
# Use environment variables for sensitive data
alerts:
  email:
    username: "${EMAIL_USERNAME}"
    password: "${EMAIL_PASSWORD}"
    
# Or use external secret management
alerts:
  email:
    password_file: "/etc/nginx-security-monitor/secrets/email_password"
```

### **Network Security**

```yaml
# Restrict network access
security:
  network:
    bind_address: "127.0.0.1"  # Only localhost
    allowed_networks:
      - "192.168.1.0/24"
      - "10.0.0.0/8"
```

## 🧪 **Configuration Validation**

### **Validate Configuration**

````bash
## 🧪 **Configuration Validation**

### **Validate Configuration (Recommended)**
```bash
# Use the built-in configuration validator
./bin/validate-config config/settings.yaml

# Validate all configuration files at once
./bin/validate-config --all

# Include security and permission checks
./bin/validate-config --security-check --fix-permissions

# Verbose validation with detailed output
./bin/validate-config --verbose
````

### **Alternative Manual Validation**

```bash
# Check configuration syntax manually
python -c "
import yaml
with open('config/settings.yaml') as f:
    config = yaml.safe_load(f)
print('✅ Configuration is valid YAML')
"

# Test configuration with the application
python -m src.monitor_service --check-config

# Validate patterns
python -m src.pattern_detector --validate-patterns
```

### **Configuration Testing**

```bash
# Test alert configuration using CLI
./bin/test-alerts

# Test all alert channels
./bin/test-alerts --email --slack

# Manual alert testing (alternative)
python -m src.alert_manager --test-alerts

# Test log file access
python -m src.log_parser --test-access

# Test mitigation strategies
python -m src.mitigation --test-strategies
```

## 🔄 **Configuration Updates**

### **Hot Configuration Reload**

```bash
# Send SIGHUP to reload configuration
sudo systemctl reload nginx-security-monitor

# Or use management script
sudo ./nginx-security-monitor.sh reload
```

### **Configuration Backup**

```bash
# Backup current configuration
sudo cp /etc/nginx-security-monitor/settings.yaml \
       /etc/nginx-security-monitor/settings.yaml.backup.$(date +%Y%m%d)

# Automated backup script
#!/bin/bash
CONFIG_DIR="/etc/nginx-security-monitor"
BACKUP_DIR="/var/backups/nginx-security-monitor"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/config_backup_$DATE.tar.gz -C $CONFIG_DIR .
```

## 📋 **Configuration Reference Quick Guide**

### **Essential Settings for First Run**

```yaml
# Minimum configuration to get started
logs:
  access_log: "/path/to/nginx/access.log"
  
alerts:
  email:
    enabled: true
    smtp_server: "your-smtp-server"
    username: "your-email"
    password: "your-password"
    to_addresses: ["alert@yourdomain.com"]
    
logging:
  level: "INFO"
  file: "/var/log/nginx-security-monitor.log"
```

### **Performance Tuning**

```yaml
# For high-performance environments
monitoring:
  check_interval: 5     # Check more frequently
  batch_size: 2000      # Process more entries at once
  worker_threads: 4     # Use multiple threads

storage:
  cache:
    max_size: 5000      # Larger cache
    
detection:
  enabled_patterns:     # Only enable needed patterns
    - ddos_detection
    - brute_force
```

## 🆘 **Troubleshooting Configuration**

### **Common Issues**

**Issue: Configuration file not found**

```bash
# Check file location and permissions
ls -la /etc/nginx-security-monitor/settings.yaml
sudo chmod 644 /etc/nginx-security-monitor/settings.yaml
```

**Issue: Invalid YAML syntax**

```bash
# Validate YAML
python -c "import yaml; yaml.safe_load(open('settings.yaml'))"
```

**Issue: Email alerts not working**

```bash
# Test email configuration
python -m src.alert_manager --test-email
```

**Issue: Log files not accessible**

```bash
# Check permissions
sudo ls -la /var/log/nginx/
sudo usermod -a -G nginx nginx-monitor
```

## 📚 **Related Documentation**

- [INSTALLATION.md](INSTALLATION.md) - Installation guide
- [ALERT_SYSTEMS.md](ALERT_SYSTEMS.md) - Alert configuration details
- [PATTERN_DETECTION.md](PATTERN_DETECTION.md) - Pattern customization
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Problem resolution
