# 🖥️ CLI Reference Guide

Complete reference for all NGINX Security Monitor command-line utilities.

## Overview

NGINX Security Monitor provides 24 command-line utilities in the `bin/` directory, organized by function:

- **[Operations](#operations-commands)**: Service management and monitoring
- **[Configuration](#configuration-commands)**: Settings and validation
- **[Development](#development-commands)**: Development and testing tools
- **[Security](#security-commands)**: Encryption and security features
- **[Maintenance](#maintenance-commands)**: Backup, updates, and cleanup
- **[Monitoring](#monitoring-commands)**: Health checks and diagnostics

All commands are located in the `bin/` directory and should be run from the project root.

______________________________________________________________________

## Operations Commands

### `nginx-security-monitor`

**Main CLI interface for the monitoring service.**

```bash
# Start monitoring with configuration
./bin/nginx-security-monitor start config/settings.yaml

# Check service status
./bin/nginx-security-monitor status

# Stop monitoring service
./bin/nginx-security-monitor stop

# Restart with new configuration
./bin/nginx-security-monitor restart config/settings.yaml

# Test patterns without starting service
./bin/nginx-security-monitor test --patterns

# Validate configuration before starting
./bin/nginx-security-monitor config --validate config/settings.yaml
```

**Options:**

- `--verbose`: Enable detailed logging
- `--dry-run`: Test configuration without starting service
- `--daemon`: Run as background daemon

### `health-check`

**Comprehensive system health monitoring.**

```bash
# Run all health checks
./bin/health-check

# Quick essential checks only
./bin/health-check --quick

# Check specific components
./bin/health-check --service --integrations --logs

# Output as JSON for monitoring systems
./bin/health-check --json
```

### `monitor-dashboard`

**Real-time monitoring dashboard.**

```bash
# Start web-based dashboard
./bin/monitor-dashboard

# Start on specific port
./bin/monitor-dashboard --port 8080

# Dashboard with authentication
./bin/monitor-dashboard --auth --password
```

______________________________________________________________________

## Configuration Commands

### `validate-config`

**Configuration file validator with security checks.**

```bash
# Validate specific configuration file
./bin/validate-config config/settings.yaml

# Validate all configuration files
./bin/validate-config --all

# Include security and permission checks
./bin/validate-config --security-check --fix-permissions

# Verbose validation with detailed output
./bin/validate-config --verbose
```

### `migrate-config`

**Configuration migration and upgrade utility.**

```bash
# Migrate from v1.x to v2.x configuration format
./bin/migrate-config --from-version 1.0 --to-version 2.0

# Backup current config before migration
./bin/migrate-config --backup --migrate

# Preview migration changes without applying
./bin/migrate-config --preview
```

### `setup-integrations`

**Configure external security tool integrations.**

```bash
# Interactive setup wizard
./bin/setup-integrations

# Setup specific integration
./bin/setup-integrations --tool fail2ban

# Test integration after setup
./bin/setup-integrations --test --tool fail2ban

# List available integrations
./bin/setup-integrations --list
```

______________________________________________________________________

## Development Commands

### `dev-setup`

**Development environment initialization.**

```bash
# Setup complete development environment
./bin/dev-setup

# Setup with specific Python version
./bin/dev-setup --python python3.9

# Skip optional development tools
./bin/dev-setup --minimal
```

### `test-installation`

**Post-installation verification suite.**

```bash
# Run full installation verification
./bin/test-installation

# Quick essential tests only
./bin/test-installation --quick

# Verbose output for troubleshooting
./bin/test-installation --verbose

# Test specific components
./bin/test-installation --config --patterns --integrations
```

### `test-patterns`

**Pattern testing and validation.**

```bash
# Test all detection patterns
./bin/test-patterns

# Test specific pattern file
./bin/test-patterns --file config/patterns.json

# Test with sample attack data
./bin/test-patterns --sample-data

# Benchmark pattern performance
./bin/test-patterns --benchmark
```

### `test-alerts`

**Alert system testing.**

```bash
# Test all alert channels
./bin/test-alerts

# Test specific alert type
./bin/test-alerts --email --slack

# Send test alert with custom message
./bin/test-alerts --message "Test alert from CLI"
```

### `debug-logs`

**Enhanced debugging and log analysis.**

```bash
# Follow logs with syntax highlighting
./bin/debug-logs --follow

# Show last 100 entries with filtering
./bin/debug-logs --lines 100 --filter ERROR

# Export debug information
./bin/debug-logs --export --output debug-$(date +%Y%m%d).tar.gz
```

______________________________________________________________________

## Security Commands

### `encrypt-config`

**Configuration encryption and security management.**

```bash
# Interactive encryption wizard
./bin/encrypt-config interactive

# Encrypt specific configuration section
./bin/encrypt-config encrypt --section alerts.email

# Encrypt custom patterns
./bin/encrypt-config encrypt-patterns

# Generate new encryption key
./bin/encrypt-config generate-key

# Rotate encryption keys
./bin/encrypt-config rotate-keys --backup
```

### `generate-keys`

**Cryptographic key generation and management.**

```bash
# Generate all required keys
./bin/generate-keys

# Generate specific key type
./bin/generate-keys --type master --output keys/master.key

# Generate keys with specific strength
./bin/generate-keys --strength 4096
```

### `security-check`

**Security audit and compliance checking.**

```bash
# Run full security audit
./bin/security-check

# Check file permissions only
./bin/security-check --permissions

# Compliance check for specific standard
./bin/security-check --compliance stig

# Generate security report
./bin/security-check --report --output security-audit.json
```

______________________________________________________________________

## Maintenance Commands

### `backup-config`

**Configuration and data backup utility.**

```bash
# Backup all configuration and data
./bin/backup-config

# Backup to specific location
./bin/backup-config --output /backup/nsm-$(date +%Y%m%d).tar.gz

# Incremental backup (changes only)
./bin/backup-config --incremental

# Backup with encryption
./bin/backup-config --encrypt --password
```

### `maintenance`

**System maintenance and cleanup.**

```bash
# Run routine maintenance tasks
./bin/maintenance

# Clean old logs and temporary files
./bin/maintenance --cleanup

# Optimize database and indexes
./bin/maintenance --optimize

# Schedule automatic maintenance
./bin/maintenance --schedule daily
```

### `auto-update`

**Automated update management.**

```bash
# Check for available updates
./bin/auto-update --check

# Download and install updates
./bin/auto-update --install

# Update to specific version
./bin/auto-update --version 2.1.0

# Automatic updates with backup
./bin/auto-update --auto --backup
```

______________________________________________________________________

## Monitoring Commands

### `benchmark`

**Performance testing and optimization.**

```bash
# Run performance benchmark
./bin/benchmark

# Benchmark specific components
./bin/benchmark --patterns --alerts --integrations

# Extended benchmark with load testing
./bin/benchmark --extended --duration 300

# Compare performance between versions
./bin/benchmark --compare --baseline v1.0.0
```

### `export-data`

**Data export and reporting.**

```bash
# Export all monitoring data
./bin/export-data

# Export specific date range
./bin/export-data --from 2024-01-01 --to 2024-01-31

# Export in specific format
./bin/export-data --format json --output data-export.json

# Export with filtering
./bin/export-data --severity high --threat-type sql_injection
```

### `import-rules`

**Import detection rules and patterns.**

```bash
# Import rules from file
./bin/import-rules --file rules.json

# Import from threat intelligence feed
./bin/import-rules --feed https://threat-intel.example.com/rules

# Import with validation
./bin/import-rules --validate --test

# Bulk import with mapping
./bin/import-rules --bulk --mapping-file rules-mapping.yaml
```

### `generate-test-data`

**Generate test data for development and testing.**

```bash
# Generate sample attack logs
./bin/generate-test-data

# Generate specific attack types
./bin/generate-test-data --attacks sql_injection,xss,brute_force

# Generate with custom volume
./bin/generate-test-data --volume 1000 --duration 1h

# Generate realistic traffic patterns
./bin/generate-test-data --realistic --baseline normal
```

______________________________________________________________________

## Common Usage Patterns

### Initial Setup

```bash
# 1. Setup development environment
./bin/dev-setup

# 2. Validate configuration
./bin/validate-config config/settings.yaml

# 3. Test installation
./bin/test-installation

# 4. Setup integrations
./bin/setup-integrations

# 5. Start monitoring
./bin/nginx-security-monitor start config/settings.yaml
```

### Daily Operations

```bash
# Check system health
./bin/health-check

# Review recent alerts
./bin/debug-logs --lines 50 --filter ALERT

# Backup configuration
./bin/backup-config --incremental

# Check for updates
./bin/auto-update --check
```

### Development Workflow

```bash
# Setup development environment
./bin/dev-setup

# Test new patterns
./bin/test-patterns --file new-patterns.json

# Validate configuration changes
./bin/validate-config --all

# Run installation tests
./bin/test-installation --verbose

# Generate documentation
./bin/generate-docs
```

### Security Maintenance

```bash
# Run security audit
./bin/security-check --report

# Rotate encryption keys
./bin/encrypt-config rotate-keys --backup

# Update threat intelligence
./bin/import-rules --feed https://threat-intel.example.com/rules

# Test alert channels
./bin/test-alerts
```

______________________________________________________________________

## Global Options

Most commands support these common options:

- `--help, -h`: Show command help and usage
- `--verbose, -v`: Enable verbose output
- `--quiet, -q`: Suppress non-essential output
- `--config, -c`: Specify custom configuration file
- `--dry-run`: Preview actions without executing
- `--json`: Output results in JSON format
- `--log-level`: Set logging level (DEBUG, INFO, WARNING, ERROR)

______________________________________________________________________

## Integration with Documentation

- **Installation Guide**: Use `./bin/test-installation` after setup
- **Configuration Guide**: Use `./bin/validate-config` for validation
- **Operations Guide**: Use `./bin/health-check` for monitoring
- **Security Guide**: Use `./bin/security-check` for audits
- **Troubleshooting**: Use `./bin/debug-logs` for diagnosis

______________________________________________________________________

## Getting Help

For detailed help on any command:

```bash
./bin/[command] --help
```

For comprehensive documentation:

```bash
./bin/generate-docs
```

See also:

- [bin/README.md](../bin/README.md) - Detailed command documentation
- [OPERATIONS_GUIDE.md](OPERATIONS_GUIDE.md) - Day-to-day operations
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Problem resolution
