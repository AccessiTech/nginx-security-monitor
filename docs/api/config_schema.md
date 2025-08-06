# config_schema

Configuration Schema for NGINX Security Monitor

This file defines the schema for all configurable options in the NGINX Security Monitor.
It is used by the ConfigManager for validation, type conversion, and documentation.

## Constants

### SCHEMA

**Value**: Complete configuration schema for the NGINX Security Monitor

```json
{
  "service": {
    "config_path": {
      "__type": "string",
      "__default": "/opt/nginx-security-monitor/settings.yaml",
      "__description": "Path to the configuration file",
      "__env": "NGINX_MONITOR_CONFIG_PATH"
    },
    "check_interval": {
      "__type": "integer",
      "__default": 60,
      "__range": [1, 3600],
      "__description": "Interval between security checks in seconds",
      "__env": "NGINX_MONITOR_CHECK_INTERVAL"
    }
  }
}
```

> **Note**: This is a truncated view of the schema. The complete schema includes all configuration
> sections for log processing, pattern detection, mitigation strategies, service protection,
> network security, crypto settings, plugin system, security integrations, and alert systems.

## Functions

### save_schema_to_file(schema_path = '/opt/nginx-security-monitor/schema.yml')

Save the schema to a YAML file.

Args:
schema_path: Path to save the schema to

**Parameters:**

- **schema_path** = '/opt/nginx-security-monitor/schema.yml'
