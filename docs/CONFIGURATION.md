______________________________________________________________________

version: 1.1.0
last_updated: 2025-08-01
changelog:

- version: 1.1.0
  date: 2025-08-01
  changes:
  - Updated configuration examples to match current schema format
  - Added documentation for built-in schema sections
  - Updated schema format clarification
  - Enhanced troubleshooting information
- version: 1.0.0
  date: 2025-07-20
  changes:
  - Initial comprehensive configuration guide
  - Added cross-references with CONFIGURATION_SYSTEM.md
  - Enhanced documentation structure and navigation
    maintainers:
- nginx-security-team
  review_status: current
  applies_to_versions: '>=1.1.0'

______________________________________________________________________

# ⚙️ Configuration Guide

Complete configuration reference for NGINX Security Monitor.

## 📚 Documentation Structure

This configuration documentation is split into two parts:

- This file (CONFIGURATION.md): Contains all available configuration options and their descriptions
- [Configuration System Guide](CONFIGURATION_SYSTEM.md): Details about the secure configuration
  system, programmatic usage, and advanced features

> **Important**: We recommend reading the [Configuration System Guide](CONFIGURATION_SYSTEM.md)
> first to understand the secure configuration system's features and best practices.

## 📁 **Configuration File Structure**

```text
config/
├── settings.yaml          # Main configuration file
├── patterns.json          # Detection patterns
├── schema.yml            # Configuration schema
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
  **Use Case**: Production deployment with proper secret management
  **Security**: Built-in encryption support, obfuscation, and self-protection features

#### **When to Use Which File**

| Scenario                        | Recommended File        | Reason                                        |
| ------------------------------- | ----------------------- | --------------------------------------------- |
| Development/Testing             | `settings.yaml`         | Complete reference with all options           |
| Production Deployment           | `service-settings.yaml` | Security-focused with environment variables   |
| Configuration Reference         | `settings.yaml`         | Comprehensive documentation of all parameters |
| CI/CD Pipelines                 | `service-settings.yaml` | Environment variable support                  |
| Security-Sensitive Environments | `service-settings.yaml` | Built-in encryption and obfuscation           |

> **💡 Tip**: Start with `settings.yaml` for development, then migrate to `service-settings.yaml`
> for production deployment with proper environment variable configuration.

## 🔧 **Main Configuration (settings.yaml)**

### **Basic Structure**

````yaml
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
# Monitoring Log Files
# ============================================================================
monitoring:
  log_files:
    - "/var/log/nginx/access.log"
    - "/var/log/nginx/error.log"
  check_interval: 30
  pattern_file: "patterns.json"

## 📁 **Log File Configuration**

### **Important Note on Log File Paths**

The NGINX Security Monitor requires proper configuration of log file paths to function correctly. 
The **correct** configuration path is `monitoring.log_files`:

```yaml
monitoring:
  log_files:
    - "/var/log/nginx/access.log"
    - "/var/log/nginx/error.log"
````

⚠️ **Common Mistake**: Using `log_files` at the root level instead of under `monitoring`
will result in no attacks being detected.

### **Verifying Log File Configuration**

To verify that your log file configuration is correct, you can run:

```bash
python3 -c "from nginx_security_monitor.config_manager import ConfigManager; print(ConfigManager().get('monitoring.log_files'))"
```

This should display a list of log file paths. If it returns an empty list (`[]`), your configuration is incorrect.# ============================================================================

# Pattern Detection Settings

# ============================================================================

```yaml
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
```

# ============================================================================

# Alert Settings

# ============================================================================

<!-- markdownlint-disable MD034 -->

```yaml
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
password: "<REPLACE_WITH_ENV_VARIABLE>" # Use app passwords for Gmail
from_address: "your_email@gmail.com"
to_addresses:
  - "security@yourdomain.com"
  - "admin@yourdomain.com"

templates:
  subject: "[SECURITY ALERT] {severity} - {attack_type} detected"
  body_format: "html"  # html or text

sms:
enabled: false
provider: "twilio" # twilio, aws_sns, custom
\# Add provider-specific settings here
```

<!-- markdownlint-enable MD034 -->

# ============================================================================

# Mitigation Settings

# ============================================================================

```yaml
mitigation:
enabled: true
auto_mitigation: false # Set to true for automatic responses

strategies:
ip_blocking:
enabled: true
duration: 3600 # seconds to block IP
max_attempts: 10

rate_limiting:
  enabled: true
  requests_per_minute: 60
  burst_allowance: 10
```

# ============================================================================

# Logging Settings

# ============================================================================

```yaml
logging:
level: "INFO" # DEBUG, INFO, WARNING, ERROR, CRITICAL
file: "/var/log/nginx-security-monitor.log"
max_size: "10MB"
backup_count: 5
format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

# ============================================================================

# Storage Settings

# ============================================================================

```yaml
storage:
database:
type: "sqlite" # sqlite, postgresql, mysql
path: "/var/lib/nginx-security-monitor/monitor.db"

cache:
type: "memory" # memory, redis
max_size: 1000
ttl: 3600
```

# ============================================================================

# Security Settings

# ============================================================================

```yaml
security:
encryption:
enabled: false
key_file: "\<REPLACE_WITH_ENV_VARIABLE>"

plugin_security:
enabled: true
allowed_plugins_dir: "/opt/nginx-security-monitor/plugins"
signature_verification: false

```

## 📋 **Configuration Schema (schema.yml)**

The NGINX Security Monitor uses a custom schema format for configuration validation and documentation.
This schema defines all available configuration options, their types, defaults, and constraints.

### **Schema Format**

The schema uses ConfigManager's custom format with special metadata keys:

```yaml
# schema.yml - ConfigManager Custom Format
service:
  __type: object
  check_interval:
    __type: integer
    __default: 60
    __range: [1, 3600]
    __description: "Interval between security checks in seconds"
    __env: "NGINX_MONITOR_CHECK_INTERVAL"
    __required: false
    __security_critical: true
    __min_secure: 30

logs:
  __type: object
  access_log:
    __type: string
    __default: "/var/log/nginx/access.log"
    __description: "Path to NGINX access log file"
    __env: "NGINX_MONITOR_ACCESS_LOG"

# Flexible sections allow arbitrary keys
encrypted_config:
  __type: dict
  __default: {}
  __description: "Encrypted configuration sections"
  __flexible: true  # Allows any keys under this section
```

### **Schema Metadata Keys**

| Key                   | Purpose                    | Example                                                   |
| --------------------- | -------------------------- | --------------------------------------------------------- |
| `__type`              | Data type validation       | `string`, `integer`, `boolean`, `array`, `object`, `dict` |
| `__default`           | Default value              | `60`, `"/var/log/nginx/access.log"`                       |
| `__range`             | Valid range for numbers    | `[1, 3600]`                                               |
| `__description`       | Human-readable description | `"Interval between checks"`                               |
| `__env`               | Environment variable name  | `"NGINX_MONITOR_CHECK_INTERVAL"`                          |
| `__required`          | Whether field is mandatory | `true`, `false` (default)                                 |
| `__security_critical` | Affects security settings  | `true`, `false`                                           |
| `__min_secure`        | Minimum secure value       | `30`                                                      |
| `__flexible`          | Allow arbitrary sub-keys   | `true` (for `encrypted_config`)                           |

### **Built-in Schema Fallback**

If `schema.yml` is missing or invalid, ConfigManager uses a comprehensive built-in schema that includes:

- **Core sections**: `service`, `logs`, `monitoring`, `security`
- **Alert sections**: `email_service`, `sms_service`
- **Detection sections**: `pattern_detection`, `mitigation`
- **Protection sections**: `service_protection`, `network_security`
- **Flexible sections**: `encrypted_config` (supports arbitrary keys)
- **Legacy compatibility**: `log_file_path` for backwards compatibility

### **Schema Validation**

The schema validates:

1. **Type checking**: Ensures values match expected types
1. **Range validation**: Numeric values within specified ranges
1. **Required fields**: Mandatory configuration options
1. **Security constraints**: Minimum secure values for critical settings
1. **Path validation**: Prevents path traversal attacks
1. **Command injection**: Blocks potentially dangerous command strings

### **Environment Variable Overrides**

Any schema field with an `__env` key can be overridden via environment variables:

```bash
# Override check interval
export NGINX_MONITOR_CHECK_INTERVAL=30

# Override log file path  
export NGINX_MONITOR_ACCESS_LOG="/custom/nginx/access.log"
```

> **Important**: Use ConfigManager's custom schema format, **not** JSON Schema format.
> The ConfigManager expects `__type`, `__default`, etc., not `type`, `default`.

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
sudo chmod 600 /opt/nginx-security-monitor/settings.yaml
sudo chown nginx-monitor:nginx-monitor /opt/nginx-security-monitor/settings.yaml

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
    password_file: "/opt/nginx-security-monitor/secrets/email_password"
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
sudo cp /opt/nginx-security-monitor/settings.yaml \
       /opt/nginx-security-monitor/settings.yaml.backup.$(date +%Y%m%d)

# Automated backup script
#!/bin/bash
CONFIG_DIR="/opt/nginx-security-monitor"
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

## 🔧 **Configuration Troubleshooting**

### **Common Configuration Issues**

1. **Empty log_files Configuration**

   - **Symptoms**: No attacks detected, security monitor logs show "No log files configured"
   - **Cause**: Incorrect configuration path or missing configuration
   - **Solution**: Ensure `monitoring.log_files` is correctly defined in settings.yaml

1. **Invalid Log File Paths**

   - **Symptoms**: Security monitor logs show "Could not access log file"
   - **Cause**: Log files don't exist or permissions are incorrect
   - **Solution**: Verify file paths and permissions, check container paths for Docker deployments

1. **Configuration Not Loaded**

   - **Symptoms**: Default values used instead of configured values
   - **Cause**: settings.yaml not found or not accessible
   - **Solution**: Verify settings.yaml location and permissions

### **Diagnostic Commands**

Use these commands to diagnose configuration issues:

<!-- markdownlint-disable MD013 -->

```bash
# Check if configuration is loaded correctly
python3 -c "from nginx_security_monitor.config_manager import ConfigManager; print('Config loaded:' if ConfigManager().is_loaded() else 'Config NOT loaded')"

# Check log file configuration
python3 -c "from nginx_security_monitor.config_manager import ConfigManager; print('Log files:', ConfigManager().get('monitoring.log_files'))"

# Check monitoring interval
python3 -c "from nginx_security_monitor.config_manager import ConfigManager; print('Check interval:', ConfigManager().get('monitoring.check_interval'))"
```

<!-- markdownlint-enable MD013 -->

### **Common Issues**

#### Issue: Configuration file not found

```bash
# Check file location and permissions
ls -la /opt/nginx-security-monitor/settings.yaml
sudo chmod 644 /opt/nginx-security-monitor/settings.yaml
```

#### Issue: Invalid YAML syntax

```bash
# Validate YAML
python -c "import yaml; yaml.safe_load(open('settings.yaml'))"
```

#### Issue: Email alerts not working

```bash
# Test email configuration
python -m src.alert_manager --test-email
```

#### Issue: Log files not accessible

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
