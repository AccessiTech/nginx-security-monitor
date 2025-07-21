# NGINX Security Monitor

## Overview

NGINX Security Monitor is a Python package designed to monitor NGINX logs for potential security threats. It analyzes log data to detect attack patterns, mitigates identified threats, and triggers alerts via email and SMS. This tool can run as a standalone script or as a Linux system service for continuous monitoring.

## Features

- Parses NGINX log files to extract structured data.
- Detects various attack patterns based on predefined criteria (SQL injection, XSS, DDoS, brute force, etc.).
- Real-time monitoring with incremental log parsing.
- Mitigates threats using appropriate tactics.
- Sends alerts through email and SMS when threats are detected.
- Runs as a Linux systemd service for production environments.
- Comprehensive logging and monitoring capabilities.
- **Advanced Security Features**: Encrypted pattern storage and custom plugin system to keep your specific detection rules and countermeasures private (see [Security Features](docs/SECURITY_FEATURES.md)).
- **Service Self-Protection**: Multi-layered protection against attacks targeting the monitoring service itself (see [Service Protection](docs/SERVICE_PROTECTION.md)).
- **Secure Configuration System**: Centralized configuration management with schema validation, security hardening, and environment variable overrides (see [Configuration System](docs/CONFIGURATION_SYSTEM.md)).
- **Security Framework Integrations**: Native integration with popular security tools like fail2ban, OSSEC/Wazuh, Suricata, and ModSecurity (see [Security Integrations](SECURITY_INTEGRATIONS.md)).
- **Comprehensive Testing**: 69 automated tests with 46% code coverage, including unit tests, integration tests, and mocking strategies (see [Testing Guide](TESTING.md)).

## Installation

### Quick Installation (Development/Testing)

For development and testing, it's recommended to use a virtual environment:

```bash
# Clone the repository
git clone https://github.com/AccessiTech/nginx-security-monitor.git
cd nginx-security-monitor

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Linux/macOS
# or on Windows: .venv\Scripts\activate

# Install all dependencies (core + development)
pip install -r requirements.txt

# For clean install (force reinstall all packages):
# pip install -r requirements.txt --force-reinstall

# Install in development mode (optional, for easier testing)
pip install -e .
```

**Note**: Always activate your virtual environment before running the application:

```bash
source .venv/bin/activate  # Linux/macOS
# or: .venv\Scripts\activate  # Windows
```

### Full Installation (Recommended for Production)

For Linux systems, use the automated installation script:

```bash
# Clone the repository
git clone https://github.com/AccessiTech/nginx-security-monitor.git
cd nginx-security-monitor

# Make installation script executable
chmod +x install.sh

# Run installation (requires root privileges)
sudo ./install.sh
```

This will:

- Create a dedicated system user and group
- Install Python dependencies in a virtual environment
- Copy files to `/opt/nginx-security-monitor`
- Create configuration files in `/etc/nginx-security-monitor`
- Install and configure the systemd service
- Set up log rotation
- Apply basic security hardening

### Installation Method Comparison

**You only need ONE installation method** - choose based on your use case:

| Feature                   | Quick Install           | Full Install          |
| ------------------------- | ----------------------- | --------------------- |
| **Purpose**               | Development/testing     | Production deployment |
| **Python Dependencies**   | ✅ Virtual environment  | ✅ Included           |
| **Virtual Environment**   | ✅ User-managed (.venv) | ✅ System-managed     |
| **System Service**        | ❌ None                 | ✅ Auto-created       |
| **Auto-start on boot**    | ❌ No                   | ✅ Yes                |
| **Security hardening**    | ❌ None                 | ✅ Applied            |
| **Dedicated system user** | ❌ Your user            | ✅ nginx-monitor      |
| **Continuous monitoring** | ❌ Manual execution     | ✅ 24/7 service       |
| **Production ready**      | ❌ Testing only         | ✅ Yes                |

**Use Quick Install when:**

- You're developing or testing the code
- You want to run scripts manually/occasionally
- You need an isolated Python environment for development
- You don't want system-level changes
- You're experimenting before production deployment

**Use Full Install when:**

- You want a production security monitoring service
- You need 24/7 automatic threat detection
- You want professional deployment with security best practices
- You want the service to survive reboots and run continuously

**Typical workflow:** Start with Quick Install for testing, then use Full Install for production deployment.

### Additional Security Hardening (Recommended)

For production environments, apply additional security hardening:

```bash
# Apply comprehensive security hardening
sudo ./harden.sh
```

This additional hardening includes:

- Advanced file permission restrictions
- Firewall rule configuration
- System integrity monitoring setup
- Attack surface reduction
- Service isolation enhancements

## Configuration

### Service Configuration

After installation, configure the service by editing:

```bash
sudo nano /etc/nginx-security-monitor/settings.yaml
```

Key configuration sections:

#### Email Alerts

```yaml
email_service:
  enabled: true
  smtp_server: smtp.gmail.com
  smtp_port: 587
  use_tls: true
  username: your_email@gmail.com
  password: your_app_password
  from_address: your_email@gmail.com
  to_address: security@yourdomain.com
```

#### Monitoring Settings

```yaml
monitoring:
  check_interval: 10  # seconds between log checks
  
log_file_path: /var/log/nginx/access.log
error_log_file_path: /var/log/nginx/error.log
```

#### Detection Thresholds

```yaml
patterns:
  thresholds:
    failed_requests_per_minute: 50
    requests_per_ip_per_minute: 100
    error_rate_threshold: 0.1
```

### Legacy Configuration

For standalone usage, configure these files:

- `config/patterns.json`: Define the attack patterns to be detected.
- `config/settings.yaml`: Set up your email and SMS service credentials, alert thresholds, and log file paths.

## Advanced Security Features (Optional)

For production environments where you want to keep your specific detection patterns and countermeasures private, the system supports:

### Security Framework Integrations

Leverage your existing security infrastructure with native integrations:

```bash
# Check available security framework integrations
python3 security_integrations_util.py check

# Test integrations
python3 security_integrations_util.py test
```

**Supported frameworks:**

- **fail2ban**: Automatic IP blocking and jail management
- **OSSEC/Wazuh**: Host intrusion detection and SIEM integration
- **Suricata**: Network intrusion detection/prevention
- **ModSecurity**: Web application firewall integration

See [Security Integrations](SECURITY_INTEGRATIONS.md) for complete setup guide.

### Encrypted Pattern Storage

Store your custom detection rules in encrypted files that only your system can decrypt:

```bash
# Install cryptography for encryption features
pip install cryptography

# Generate master key and create encrypted patterns
python3 encrypt_config.py interactive
```

### Custom Mitigation Plugins

Keep your actual countermeasures private with the plugin system:

```bash
# Create custom plugin template
python3 encrypt_config.py create-plugin

# Edit the generated plugin with your secret mitigation logic
# Place in /etc/nginx-security-monitor/plugins/
```

### Obfuscation Features

- Randomized detection timing to avoid predictable patterns
- Decoy log entries to confuse potential attackers analyzing your system
- Variable detection order to make reverse engineering harder

See [SECURITY_FEATURES.md](SECURITY_FEATURES.md) for complete documentation.

**Benefits for Open Source**: Your specific detection patterns and countermeasures remain private while still using the open-source framework.

Use the management script for easy service control:

```bash
# Make management script executable
chmod +x nginx-security-monitor.sh

# Start the service
sudo ./nginx-security-monitor.sh start

# Check service status
sudo ./nginx-security-monitor.sh status

# View live logs
sudo ./nginx-security-monitor.sh logs

# Edit configuration
sudo ./nginx-security-monitor.sh config

# Restart after configuration changes
sudo ./nginx-security-monitor.sh restart
```

### Systemd Commands

You can also use standard systemd commands:

```bash
# Enable service to start at boot
sudo systemctl enable nginx-security-monitor

# Start the service
sudo systemctl start nginx-security-monitor

# Check status
sudo systemctl status nginx-security-monitor

# View logs
sudo journalctl -u nginx-security-monitor -f
```

## Usage

### Command-Line Utilities

NGINX Security Monitor provides several command-line utilities in the `bin/` directory:

```bash
# Main CLI interface
./bin/nginx-security-monitor start config/settings.yaml
./bin/nginx-security-monitor status
./bin/nginx-security-monitor test --patterns

# Installation and validation
./bin/test-installation                 # Verify installation
./bin/validate-config --all            # Validate configuration

# Development setup
./bin/dev-setup                        # Setup dev environment

# Configuration encryption
./bin/encrypt-config interactive
./bin/encrypt-config encrypt-patterns

# Documentation generation
./bin/generate-docs
```

For complete CLI documentation, see:

- **[CLI Reference Guide](docs/CLI_REFERENCE.md)** - Comprehensive command-line reference (24 commands)
- **[Executable Utilities](bin/README.md)** - Detailed usage examples for each command
- **Quick Help**: Run `./bin/[command] --help` for usage information

### As a System Service (Recommended)

Once installed and configured, the service runs automatically and continuously monitors your NGINX logs. It will:

1. Monitor the configured log file for new entries
1. Detect security patterns in real-time
1. Send alerts when threats are detected
1. Apply configured mitigations

### Standalone Usage

To use the NGINX Security Monitor as a standalone script, ensure that you have the necessary permissions to access the log files.

Example usage:

```python
from src.log_parser import parse_logs
from src.pattern_detector import PatternDetector
from src.mitigation import mitigate_threat
from src.alerts.email_alert import send_email_alert
from src.alerts.sms_alert import send_sms_alert

# Parse logs
logs = parse_logs('path/to/nginx.log')

# Detect patterns
detector = PatternDetector()
detector.detect_patterns(logs)

# Mitigate threats and send alerts
for pattern in detector.get_detected_patterns():
    mitigate_threat(pattern)
    send_email_alert({'pattern': pattern})
    send_sms_alert({'pattern': pattern})
```

## Security Features

The service includes detection for:

- **SQL Injection**: Detects common SQL injection patterns in requests
- **XSS Attacks**: Identifies cross-site scripting attempts
- **DDoS Attempts**: Monitors request frequency per IP address
- **Brute Force Attacks**: Tracks failed login attempts
- **Directory Traversal**: Detects path traversal attempts
- **Suspicious User Agents**: Identifies known attack tools
- **Error Pattern Analysis**: Analyzes 404 patterns for scanning attempts

### Integration with Popular Security Tools

NGINX Security Monitor integrates seamlessly with:

- **🔥 fail2ban**: Automatic IP blocking and jail management
- **🛡️ OSSEC/Wazuh**: Host intrusion detection and SIEM correlation
- **🕵️ Suricata**: Network-based intrusion detection/prevention
- **🔒 ModSecurity**: Web application firewall integration

This provides defense-in-depth with coordinated threat response across multiple security layers.

## Monitoring and Logs

### Service Logs

- Service logs: `/var/log/nginx-security-monitor.log`
- System logs: `journalctl -u nginx-security-monitor`

### Log Rotation

Automatic log rotation is configured for:

- Daily rotation
- 30-day retention
- Compression of old logs

## Testing

The project includes comprehensive test coverage with **69 tests** achieving **46% code coverage**. All tests are currently passing.

### Quick Test Commands

```bash
# Activate virtual environment (if using)
source .venv/bin/activate

# Run all tests
pytest

# Run tests with coverage report
pytest --cov=src --cov-report=term-missing

# Run specific test file
pytest tests/test_pattern_detector.py
```

### Dependency Management

```bash
# Regular install
pip install -r requirements.txt

# Clean install (force reinstall all packages with latest compatible versions)
pip install -r requirements.txt --force-reinstall

# Install only core runtime dependencies
pip install pyyaml>=6.0 cryptography>=3.4.8 psutil>=5.8.0

# Using Makefile shortcuts
make install        # Regular install
make install-clean  # Clean install
make install-core   # Core dependencies only
```

### Test Coverage Overview

- **Pattern Detection**: 80% coverage (13 tests)
- **Plugin System**: 84% coverage (18 tests)
- **Log Parser**: 100% coverage (3 tests)
- **Crypto Utils**: 71% coverage (8 tests)
- **Security Integrations**: 60% coverage (13 tests)
- **Service Protection**: 70% coverage (12 tests)
- **Alert Systems**: 68% coverage (2 tests)

For detailed testing information, including advanced usage, test architecture, and contribution guidelines, see [TESTING.md](TESTING.md).

## Maintenance

### Updating the Service

```bash
# Update service code
sudo ./nginx-security-monitor.sh update
```

### Backup Configuration

```bash
# Configuration is automatically backed up when edited
sudo cp /etc/nginx-security-monitor/settings.yaml /path/to/backup/
```

### Uninstalling

```bash
sudo ./nginx-security-monitor.sh uninstall
```

## Troubleshooting

### Common Issues

1. **Service won't start**: Check configuration syntax and file permissions
1. **No alerts received**: Verify email configuration and network connectivity
1. **High CPU usage**: Adjust `check_interval` in configuration
1. **Permission denied**: Ensure service user has read access to NGINX logs

### Debug Mode

Enable debug logging in `/etc/nginx-security-monitor/settings.yaml`:

```yaml
logging:
  level: DEBUG
```

Then restart the service and check logs for detailed information.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## 📊 Project Metrics

*Auto-generated on 2025-07-20 15:44:28*

### 📁 Files

- **Total files**: 23,480
- **Python files**: 2,881
- **Documentation files**: 118
- **Test files**: 584

### 📚 Documentation

- **Documentation files**: 73
- **Total words**: 67,564

### 🧪 Testing

- **Test coverage**: 0.0%

______________________________________________________________________

*Metrics updated automatically by documentation generator*

### 📁 Files

- **Total files**: 22,844
- **Python files**: 2,693
- **Documentation files**: 93
- **Test files**: 483

### 📚 Documentation

- **Documentation files**: 58
- **Total words**: 66,562

### 🧪 Testing

- **Test coverage**: 0.0%

______________________________________________________________________

*Metrics updated automatically by documentation generator*

### 📁 Files

- **Total files**: 21,951
- **Python files**: 2,584
- **Documentation files**: 93
- **Test files**: 459

### 📚 Documentation

- **Documentation files**: 58
- **Total words**: 66,562

### 🧪 Testing

- **Test coverage**: 0.0%

______________________________________________________________________

*Metrics updated automatically by documentation generator*
