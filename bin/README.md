# Executable Utilities

This directory contains command-line utilities for NGINX Security Monitor.

## Available Commands

### `nginx-security-monitor`

Main CLI interface for the monitoring service.

```bash
# Start monitoring
./bin/nginx-security-monitor start config/settings.yaml

# Check status
./bin/nginx-security-monitor status

# Validate configuration
./bin/nginx-security-monitor config --validate config/settings.yaml

# Run pattern tests
./bin/nginx-security-monitor test --patterns
```

### `test-installation`

**NEW!** Post-installation verification suite that checks if everything is working correctly.

```bash
# Run full installation test
./bin/test-installation

# Quick essential tests only
./bin/test-installation --quick

# Verbose output for debugging
./bin/test-installation --verbose
```

### `validate-config`

**NEW!** Configuration file validator that checks syntax, required fields, and security settings.

```bash
# Validate specific config file
./bin/validate-config config/settings.yaml

# Validate all configuration files
./bin/validate-config --all

# Include security checks
./bin/validate-config --security-check --fix-permissions
```

### `dev-setup`

**NEW!** Automated development environment setup for contributors and developers.

```bash
# Full development setup
./bin/dev-setup

# Force recreate virtual environment
./bin/dev-setup --force

# Minimal setup (dependencies only)
./bin/dev-setup --minimal
```

### `encrypt-config`

Configuration encryption utility for securing sensitive settings.

```bash
# Interactive mode
./bin/encrypt-config interactive

# Encrypt custom patterns
./bin/encrypt-config encrypt-patterns

# Encrypt configuration section
./bin/encrypt-config encrypt-config

# Decrypt and view
./bin/encrypt-config decrypt
```

### `generate-docs`

Automated documentation generation and maintenance.

```bash
# Generate all documentation
./bin/generate-docs

# Generate with specific options
python3 ./bin/generate-docs --output-dir docs/
```

## 🚀 Operations & Deployment

### `deploy`

**NEW!** Production deployment automation that handles environment-specific deployment with proper security and service configuration.

```bash
# Deploy to production (requires root)
sudo ./bin/deploy production

# Deploy to staging environment
sudo ./bin/deploy staging

# Deploy for current user only
./bin/deploy testing --user

# Show what would be done (dry run)
./bin/deploy production --dry-run
```

**Features:**

- Environment-specific deployment (production/staging/testing)
- System user creation and security hardening
- Python virtual environment setup
- Configuration management
- systemd service creation
- Post-deployment validation

### `security-check`

**NEW!** Comprehensive security audit and validation tool for your deployment.

```bash
# Full security audit
./bin/security-check

# Quick security check
./bin/security-check --quick

# Check specific configuration file
./bin/security-check --config config/settings.yaml

# Fix permissions automatically
./bin/security-check --fix-permissions
```

### `health-check`

**NEW!** System health monitoring and diagnostics for operations teams.

```bash
# Complete health check
./bin/health-check

# Monitor mode (continuous)
./bin/health-check --monitor

# Check specific services only
./bin/health-check --services nginx,fail2ban

# Export metrics to file
./bin/health-check --export-metrics
```

### `quick-start`

**NEW!** Interactive setup wizard for new users and first-time configuration.

```bash
# Interactive setup wizard
./bin/quick-start

# Silent setup with defaults
./bin/quick-start --defaults

# Skip installation steps
./bin/quick-start --config-only
```

## 🧪 Development & Testing Tools

### `test-patterns`

**NEW!** Advanced pattern testing and validation tool for developers.

```bash
# Test all patterns with generated logs
./bin/test-patterns

# Test specific pattern
./bin/test-patterns --pattern sql_injection_basic --verbose

# Performance benchmark
./bin/test-patterns --benchmark --iterations 5000

# Generate test scenarios
./bin/test-patterns --generate-scenarios --output-dir test_logs/

# Test with custom logs
./bin/test-patterns --custom-logs /var/log/nginx/access.log --report results.json
```

### `test-alerts`

**NEW!** Comprehensive alert system testing and validation.

```bash
# Test all alert configurations
./bin/test-alerts

# Test email alerts only
./bin/test-alerts --email-only --verbose

# Dry run (validate without sending)
./bin/test-alerts --dry-run

# Test webhook alerts with report
./bin/test-alerts --webhook-only --report alert_test.json
```

### `debug-logs`

**NEW!** Advanced log analysis and debugging tool.

```bash
# Analyze log file
./bin/debug-logs /var/log/nginx/access.log

# Filter by IP and export
./bin/debug-logs access.log --ip 192.168.1.100 --export filtered.log

# Real-time monitoring
./bin/debug-logs access.log --monitor --patterns config/patterns.json

# Filter by time range and status
./bin/debug-logs access.log --time-start "2025-07-21 10:00" --status 404 403
```

### `generate-test-data`

**NEW!** Realistic test data generator for development and testing.

```bash
# Generate SQL injection attack scenario
./bin/generate-test-data --scenario sql_injection --output sql_attack.log

# Generate baseline legitimate traffic
./bin/generate-test-data --baseline --duration 24 --requests-per-hour 500

# Generate mixed traffic
./bin/generate-test-data --mixed --requests 10000 --attack-ratio 0.05

# Generate all scenarios
./bin/generate-test-data --all-scenarios --output-dir test_data/ --compress
```

## Usage in Virtual Environment

When using a virtual environment, you can add the bin directory to your PATH:

```bash
```

### `setup-integrations`

**NEW!** External service integration setup tool for fail2ban, OSSEC, Splunk, and other security tools.

```bash
# Interactive setup for all integrations
./bin/setup-integrations

# Setup specific integrations only
./bin/setup-integrations --services fail2ban,ossec

# Test existing integrations
./bin/setup-integrations --test

# List available integrations
./bin/setup-integrations --list
```

### `backup-config`

**NEW!** Configuration backup and archival tool for operational safety.

```bash
# Create configuration backup
./bin/backup-config

# Backup to specific location
./bin/backup-config --output /path/to/backup

# Include logs and keys in backup
./bin/backup-config --include-all

# Create encrypted backup
./bin/backup-config --encrypt
```

### `migrate-config`

**NEW!** Configuration migration tool for version upgrades and environment changes.

```bash
# Migrate configuration to new version
./bin/migrate-config --version 2.0

# Migrate from one environment to another
./bin/migrate-config --from staging --to production

# Validate migration (dry run)
./bin/migrate-config --validate --dry-run
```

### `generate-keys`

**NEW!** Encryption key and certificate generation tool for secure operations.

```bash
# Generate all security keys
./bin/generate-keys --all

# Generate specific key types
./bin/generate-keys --encryption --api --ssl

# Generate SSL certificate for domain
./bin/generate-keys --ssl --domain example.com

# List existing keys
./bin/generate-keys --list

# Rotate all keys
./bin/generate-keys --rotate
```

### `maintenance`

**NEW!** System maintenance and cleanup tool for operational health.

```bash
# Full system cleanup
./bin/maintenance cleanup --all

# Clean logs older than 7 days
./bin/maintenance cleanup --logs --days 7

# Run health check
./bin/maintenance health

# Optimize databases
./bin/maintenance optimize

# Preview cleanup actions
./bin/maintenance cleanup --dry-run --all
```

## Command Categories

### **🔧 Essential Operations**

- `test-installation` - Post-installation verification
- `validate-config` - Configuration validation
- `security-check` - Security audit
- `health-check` - System health monitoring
- `quick-start` - Rapid deployment wizard
- `deploy` - Production deployment

### **🛠️ Development Tools**

- `dev-setup` - Development environment setup
- `test-patterns` - Pattern testing
- `test-alerts` - Alert system testing
- `debug-logs` - Log analysis
- `generate-test-data` - Test data generation

### **⚙️ Advanced Features**

- `setup-integrations` - External service integration
- `backup-config` - Configuration backup
- `migrate-config` - Configuration migration
- `generate-keys` - Security key management
- `maintenance` - System maintenance

### **📚 Utilities**

- `nginx-security-monitor` - Main CLI interface
- `encrypt-config` - Configuration encryption
- `generate-docs` - Documentation generation

## Quick Start Examples

### For New Users

```bash
# 1. Verify installation
./bin/test-installation --quick

# 2. Setup development environment
./bin/dev-setup

# 3. Validate configuration
./bin/validate-config --all

# 4. Quick security check
./bin/security-check --quick

# 5. Start monitoring
./bin/quick-start
```

### For Administrators

```bash
# Health monitoring
./bin/health-check --monitor

# Security audit
./bin/security-check --full

# Setup integrations
./bin/setup-integrations

# Backup configurations
./bin/backup-config --include-all

# System maintenance
./bin/maintenance cleanup --all
```

### For Developers

```bash
# Setup dev environment
./bin/dev-setup

# Test patterns
./bin/test-patterns --all

# Generate test data
./bin/generate-test-data --attacks

# Debug logs
./bin/debug-logs --follow --errors
```

## Usage Tips

```bash
```

## Making Commands Globally Available

For system-wide installation:

```bash
# Create symlinks in /usr/local/bin (requires admin rights)
sudo ln -s "$PWD/bin/nginx-security-monitor" /usr/local/bin/
sudo ln -s "$PWD/bin/encrypt-config" /usr/local/bin/
sudo ln -s "$PWD/bin/generate-docs" /usr/local/bin/

# Or copy to user's local bin
mkdir -p ~/.local/bin
cp bin/* ~/.local/bin/
# Make sure ~/.local/bin is in your PATH
```

## Development

All utilities are designed to:

- Work from the project root directory
- Handle virtual environment paths correctly
- Provide clear error messages and help text
- Follow Unix command-line conventions
