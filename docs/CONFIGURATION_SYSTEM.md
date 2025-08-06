______________________________________________________________________

version: 1.1.0
last_updated: 2025-08-01
changelog:

- version: 1.1.0
  date: 2025-08-01
  changes:
  - Updated ConfigManager singleton pattern documentation
  - Added test isolation best practices
  - Documented flexible encrypted_config support
  - Clarified schema format (ConfigManager custom vs JSON Schema)
  - Added troubleshooting section for configuration issues
- version: 1.0.0
  date: 2025-07-20
  changes:
  - Initial configuration system documentation
  - Added integration with main configuration guide
  - Added security features documentation
    maintainers:
- nginx-security-team
  review_status: current
  applies_to_versions: '>=1.1.0'

______________________________________________________________________

# 🔐 NGINX Security Monitor Configuration System

This document provides instructions for using the secure configuration system for the NGINX Security Monitor.

> **Configuration Options**: For a complete list of available configuration options and their descriptions, see [CONFIGURATION.md](CONFIGURATION.md).

## Overview

The NGINX Security Monitor uses a centralized configuration system with the following features:

- **Schema-based validation**: All configuration options are defined in a custom schema format with types,
  defaults, and constraints
- **Layered configuration**: Values can come from defaults, configuration files, or environment variables (in order of precedence)
- **Security hardening**: File permission checks, integrity verification, input sanitization, and lockdown mode
- **Secure storage**: Sensitive values are stored securely in memory
- **Environment variable overrides**: All options can be overridden with environment variables
- **Singleton pattern**: ConfigManager uses a singleton pattern for consistent configuration access
- **Built-in fallback schema**: Comprehensive built-in schema ensures system works even when schema files are missing

## Quick Start

### Basic Usage

```python
from nginx_security_monitor.config_manager import ConfigManager

# Get the ConfigManager instance (singleton)
config = ConfigManager.get_instance()

# Get configuration values with fallbacks
log_file = config.get('service.log_file_path', '/var/log/nginx/access.log')
check_interval = config.get('service.check_interval', 60)

# Use the values
print(f"Monitoring {log_file} every {check_interval} seconds")
```

### Configuration Files

The default configuration file is `/opt/nginx-security-monitor/settings.yaml`. You can specify
a different path when getting the ConfigManager instance:

```python
# For production use
config = ConfigManager.get_instance(config_path='/path/to/config.yaml')

# For testing (specify both schema and config paths)
config = ConfigManager.get_instance(
    schema_path='/path/to/test_schema.yml',
    config_path='/path/to/test_config.yaml'
)
```

### Test Isolation

**Important for Testing**: The ConfigManager uses a singleton pattern, which can cause test isolation issues.
Always reset the singleton between tests:

```python
import unittest
from nginx_security_monitor.config_manager import ConfigManager

class MyTestCase(unittest.TestCase):
    def tearDown(self):
        """Clean up test fixtures and reset ConfigManager singleton."""
        # Reset ConfigManager singleton to ensure test isolation
        ConfigManager.reset_instance()
```

## Schema Format

### ConfigManager Custom Schema Format

The NGINX Security Monitor uses a **custom schema format**, not standard JSON Schema. This format uses special metadata keys:

```yaml
# ConfigManager custom format (CORRECT)
service:
  __type: object
  check_interval:
    __type: integer
    __default: 60
    __range: [1, 3600]
    __description: "Interval between security checks in seconds"
    __env: "NGINX_MONITOR_CHECK_INTERVAL"
```

**NOT** JSON Schema format:

```yaml
# JSON Schema format (INCORRECT for ConfigManager)
service:
  type: object
  properties:
    check_interval:
      type: integer
      default: 60
```

### Schema Metadata Keys

- `__type`: Data type (`string`, `integer`, `number`, `boolean`, `array`, `object`, `dict`)
- `__default`: Default value
- `__range`: Valid range for numeric values `[min, max]`
- `__description`: Human-readable description
- `__env`: Environment variable name for overrides
- `__required`: Whether field is required (default: false)
- `__security_critical`: Whether field affects security
- `__min_secure`: Minimum secure value for security-critical fields
- `__flexible`: Allow arbitrary keys (used for `encrypted_config`)

### Flexible Dictionary Support

Some configuration sections support arbitrary keys using the `__flexible` flag:

```yaml
encrypted_config:
  __type: dict
  __default: {}
  __description: "Encrypted configuration sections"
  __flexible: true  # Allow any keys under this section
```

This allows configurations like:

```yaml
encrypted_config:
  secret_section: "encrypted_data"
  api_keys: "encrypted_keys"
  custom_data: "encrypted_custom"
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
1. **Reset singleton in tests**: Always call `ConfigManager.reset_instance()` in test tearDown methods
1. **Use custom schema format**: Ensure schema files use ConfigManager's custom format with `__type`, `__default`, etc.

## Troubleshooting

### Configuration Validation Errors

If you see "Configuration validation failed" errors:

1. **Check schema format**: Ensure you're using ConfigManager's custom format, not JSON Schema
1. **Verify required fields**: Make sure all required configuration sections are present
1. **Check value ranges**: Ensure numeric values are within specified ranges
1. **Validate file permissions**: Configuration files should have proper permissions (0640)

### Test Failures Due to Singleton Issues

If tests fail with ConfigManager validation errors:

1. **Add singleton reset**: Include `ConfigManager.reset_instance()` in your test `tearDown()` method
1. **Check test isolation**: Ensure each test starts with a clean ConfigManager state
1. **Use proper test config**: Create test-specific configuration files with valid schemas

### Schema File Issues

If schema validation fails:

1. **Check schema.yml format**: Use `__type`, `__default`, not `type`, `default`
1. **Verify schema signature**: Ensure schema.yml.sig contains only the hash, not full sha256sum output
1. **Built-in fallback**: ConfigManager will use built-in schema if schema.yml is missing/invalid

### Environment Variable Overrides

Environment variables should match the `__env` keys defined in the schema:

```bash
# Correct
export NGINX_MONITOR_CHECK_INTERVAL=30

# Schema definition
check_interval:
  __type: integer
  __default: 60
  __env: "NGINX_MONITOR_CHECK_INTERVAL"
```

### Debug Configuration Loading

Enable debug logging to see configuration loading details:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

from nginx_security_monitor.config_manager import ConfigManager
config = ConfigManager.get_instance()
```

For more detailed troubleshooting, see [Installation Issues](./troubleshooting/installation-issues.md).

## Testing

Tests for the ConfigManager are in `tests/test_config_manager.py`. Run the tests with:

```bash
python -m unittest tests/test_config_manager.py
```
