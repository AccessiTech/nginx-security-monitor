______________________________________________________________________

version: 1.0.0
last_updated: 2025-07-20
changelog:

- version: 1.0.0
  date: 2025-07-20
  changes:
  - Initial configuration system documentation
  - Added integration with main configuration guide
  - Added security features documentation
    maintainers:
- nginx-security-team
  review_status: current
  applies_to_versions: '>=1.0.0'

______________________________________________________________________

# 🔐 NGINX Security Monitor Configuration System

This document provides instructions for using the secure configuration system for the NGINX Security Monitor.

> **Configuration Options**: For a complete list of available configuration options and their descriptions, see [CONFIGURATION.md](CONFIGURATION.md).

## Overview

The NGINX Security Monitor uses a centralized configuration system with the following features:

- **Schema-based validation**: All configuration options are defined in a schema with types, defaults, and constraints
- **Layered configuration**: Values can come from defaults, configuration files, or environment variables (in order of precedence)
- **Security hardening**: File permission checks, integrity verification, input sanitization, and lockdown mode
- **Secure storage**: Sensitive values are stored securely in memory
- **Environment variable overrides**: All options can be overridden with environment variables

## Quick Start

### Basic Usage

```python
from src.config_manager import ConfigManager

# Get the ConfigManager instance (singleton)
config = ConfigManager.get_instance()

# Get configuration values with fallbacks
log_file = config.get('service.log_file_path', '/var/log/nginx/access.log')
check_interval = config.get('service.check_interval', 60)

# Use the values
print(f"Monitoring {log_file} every {check_interval} seconds")
```

### Configuration Files

The default configuration file is `/etc/nginx-security-monitor/settings.yaml`. You can specify
a different path when initializing the ConfigManager:

```python
config = ConfigManager(config_path='/path/to/config.yaml')
```

### Environment Variables

All configuration options can be overridden with environment variables. The environment variable
names are defined in the schema. For example:

```bash
# Set the check interval to 30 seconds
export NGINX_MONITOR_CHECK_INTERVAL=30

# Set the log file path
export NGINX_MONITOR_LOG_FILE_PATH=/var/log/custom/nginx.log
```

## Migrating Hardcoded Values

A migration utility is provided to help identify and replace hardcoded values with ConfigManager references:

```bash
# Scan the src directory for hardcoded values
python config_migration.py

# Apply the suggested changes
python config_migration.py --apply
```

## Security Features

### Lockdown Mode

In lockdown mode, the ConfigManager uses ultra-conservative security settings and restricts access to sensitive values:

```python
# Initialize in lockdown mode
config = ConfigManager(lockdown_mode=True)

# Check if in lockdown mode
if config.is_in_lockdown_mode():
    # Take appropriate action
```

### Sensitive Values

Sensitive values (like passwords and API keys) are stored securely in memory:

```python
# This value is stored securely
api_key = config.get('security_integrations.suricata.api_key')
```

### File Security

The ConfigManager verifies file permissions and integrity:

```python
# Reload configuration (includes security checks)
config.reload_config()
```

## Configuration Schema

The full configuration schema is defined in `src/config_schema.py`. This schema defines:

- All available configuration options
- Default values
- Type constraints
- Value ranges
- Environment variable names
- Security criticality

## Example Usage

See `examples/config_usage_example.py` for a complete example of using the ConfigManager in a module.

## Best Practices

1. **Always use the ConfigManager**: Never hardcode values that should be configurable
1. **Provide fallbacks**: Always provide sensible fallbacks when getting configuration values
1. **Check lockdown mode**: Be prepared to handle lockdown mode for security-critical operations
1. **Don't log sensitive values**: Never log sensitive values, even in debug mode
1. **Validate inputs**: Even though the ConfigManager validates values, still validate inputs in your code

## Testing

Tests for the ConfigManager are in `tests/test_config_manager.py`. Run the tests with:

```bash
python -m unittest tests/test_config_manager.py
```
