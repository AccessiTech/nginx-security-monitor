# Configuration Troubleshooting Guide

This guide helps diagnose and resolve common configuration issues with the NGINX Security Monitor.

## Quick Diagnosis

### Test ConfigManager Loading

```python
import logging
logging.basicConfig(level=logging.DEBUG)

from nginx_security_monitor.config_manager import ConfigManager

# Reset singleton and test loading
ConfigManager.reset_instance()
config = ConfigManager.get_instance()
print("SUCCESS: ConfigManager loaded successfully")
```

If this fails, follow the troubleshooting steps below.

## Common Issues and Solutions

### 1. Configuration Validation Failed

**Symptoms:**

- Error: "Configuration validation failed with X errors"
- Monitor fails to start
- Tests fail with ConfigManager validation errors

**Common Causes & Solutions:**

#### Schema Format Issues

```bash
# Check if schema uses correct format
grep -A 5 "__type\|__default" schema.yml
```

**Fix:** Ensure schema uses ConfigManager format:

```yaml
# CORRECT - ConfigManager custom format
service:
  __type: object
  check_interval:
    __type: integer
    __default: 60

# INCORRECT - JSON Schema format  
service:
  type: object
  properties:
    check_interval:
      type: integer
      default: 60
```

#### Missing Configuration Sections

```bash
# Check which sections are missing
python -c "
from nginx_security_monitor.config_manager import ConfigManager
try:
    ConfigManager.reset_instance()
    config = ConfigManager.get_instance()
except Exception as e:
    print(f'Error: {e}')
"
```

**Fix:** Add missing sections to your configuration or use built-in schema fallback.

#### Value Range Issues

Common validation errors:

- `monitoring.check_interval` must be ≥ 1 (not 0)
- Numeric values outside specified ranges

**Fix:** Adjust values to be within valid ranges defined in schema.

### 2. Test Isolation Issues

**Symptoms:**

- Tests pass individually but fail when run together
- ConfigManager validation errors in test suite
- Inconsistent test results

**Cause:** ConfigManager singleton not reset between tests

**Fix:** Add to your test class:

```python
class MyTestCase(unittest.TestCase):
    def tearDown(self):
        """Clean up test fixtures."""
        # Reset ConfigManager singleton for test isolation
        from nginx_security_monitor.config_manager import ConfigManager
        ConfigManager.reset_instance()
```

### 3. Schema File Issues

**Symptoms:**

- Warning: "Schema integrity check failed"
- Falls back to built-in defaults
- Missing configuration options

**Diagnosis:**

```bash
# Check if schema file exists and has correct permissions
ls -la /opt/nginx-security-monitor/schema.yml
ls -la /opt/nginx-security-monitor/schema.yml.sig

# Check schema signature
cat /opt/nginx-security-monitor/schema.yml.sig
```

**Fix Schema Signature:**

```bash
cd /opt/nginx-security-monitor
sha256sum schema.yml | cut -d' ' -f1 > schema.yml.sig
```

### 4. Unknown Configuration Option Errors

**Symptoms:**

- Error: "Unknown configuration option: section.key"
- Configuration sections not recognized

**Causes & Solutions:**

#### Using Test-Only Configuration Sections

If using sections like `encrypted_config` with arbitrary keys:

**Fix:** Ensure schema supports flexible sections:

```yaml
encrypted_config:
  __type: dict
  __default: {}
  __flexible: true  # Allows arbitrary keys
```

#### Typos in Configuration Keys

**Fix:** Check spelling and case sensitivity of configuration keys.

#### Missing Schema Definitions

**Fix:** Add missing sections to schema.yml or rely on built-in schema fallback.

### 5. Environment Variable Issues

**Symptoms:**

- Environment variables not being applied
- Unexpected configuration values

**Diagnosis:**

```bash
# Check environment variables
env | grep NGINX_MONITOR

# Test specific variable
echo $NGINX_MONITOR_CHECK_INTERVAL
```

**Fix:** Ensure environment variable names match schema `__env` keys:

```yaml
check_interval:
  __type: integer
  __default: 60
  __env: "NGINX_MONITOR_CHECK_INTERVAL"  # Must match exactly
```

## Debug Configuration Loading

### Enable Debug Logging

```python
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s - %(name)s - %(message)s'
)

from nginx_security_monitor.config_manager import ConfigManager
ConfigManager.reset_instance()
config = ConfigManager.get_instance()
```

### Check Configuration Structure

```python
from nginx_security_monitor.config_manager import ConfigManager
config = ConfigManager.get_instance()

# Print configuration structure
print("Configuration structure:")
for key, value in config.config.items():
    if isinstance(value, dict):
        print(f"  {key}: {list(value.keys())}")
    else:
        print(f"  {key}: {type(value).__name__}")
```

### Validate Specific Configuration Path

```python
from nginx_security_monitor.config_manager import ConfigManager
config = ConfigManager.get_instance()

# Test specific configuration access
try:
    value = config.get('service.check_interval', 'NOT_FOUND')
    print(f"service.check_interval = {value}")
except Exception as e:
    print(f"Error accessing config: {e}")
```

## Emergency Fixes

### Lockdown Mode

If configuration is completely broken, use lockdown mode:

```python
from nginx_security_monitor.config_manager import ConfigManager
ConfigManager.reset_instance()
config = ConfigManager.get_instance(lockdown_mode=True)
```

### Reset to Defaults

To start fresh with built-in defaults:

```bash
# Temporarily move schema file
sudo mv /opt/nginx-security-monitor/schema.yml /opt/nginx-security-monitor/schema.yml.backup

# ConfigManager will use built-in schema
python -c "
from nginx_security_monitor.config_manager import ConfigManager
ConfigManager.reset_instance()
config = ConfigManager.get_instance()
print('Using built-in schema fallback')
"

# Restore schema when ready
sudo mv /opt/nginx-security-monitor/schema.yml.backup /opt/nginx-security-monitor/schema.yml
```

## Related Documentation

- [Configuration System Guide](../CONFIGURATION_SYSTEM.md) - Detailed ConfigManager usage
- [Configuration Reference](../CONFIGURATION.md) - All available options
- [Installation Guide](../INSTALLATION.md) - Initial setup
