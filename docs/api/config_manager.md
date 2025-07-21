# config_manager

ConfigManager for NGINX Security Monitor

This module implements a secure configuration management system for the NGINX Security Monitor.
It provides centralized access to configuration with security hardening features.

## Classes

### SecureString

A string class that protects its contents in memory as much as possible.

#### Methods

##### get_value() -> str

Return the actual string value.

**Returns:**

- str

##### clear()

Securely clear the string value from memory.

### ConfigManager

A centralized configuration manager for the NGINX Security Monitor with security hardening.

This class handles loading, validating, and accessing configuration from:

- Default schema values
- Configuration files (YAML)
- Environment variables

Features:

- Schema-based validation
- Type conversion
- Environment variable override
- Nested configuration access
- Configuration reload
- Security hardening
- Configuration integrity verification
- Protection against injection attacks

#### Attributes

- **\_instance** (NoneType)

#### Methods

##### get_instance(cls, schema_path = None, config_path = None, lockdown_mode = False)

Get or create the singleton instance of ConfigManager.

**Parameters:**

- **cls**
- **schema_path** = None
- **config_path** = None
- **lockdown_mode** = False

##### create_config_signature(file_path: str)

Create a signature file for configuration integrity verification.

Args:
file_path: Path to the configuration file

**Parameters:**

- **file_path** (str)

##### get(path: str, default: Any = None) -> Any

Get configuration value by dot-notation path with secure handling.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')
default: Default value to return if path not found

Returns:
Configuration value or default

**Parameters:**

- **path** (str)
- **default** (Any) = None

**Returns:**

- Any

##### get_raw(path: str, default: Any = None) -> Any

Get raw configuration value without secure wrapping.
Only use when the actual value is needed for operations.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')
default: Default value to return if path not found

Returns:
Raw configuration value or default

**Parameters:**

- **path** (str)
- **default** (Any) = None

**Returns:**

- Any

##### set(path: str, value: Any)

Set configuration value by dot-notation path with audit logging.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')
value: Value to set

**Parameters:**

- **path** (str)
- **value** (Any)

##### reload()

Reload configuration from file and reapply environment overrides.

##### save(file_path: str = None)

Save current configuration to file.

Args:
file_path: Path to save configuration to (defaults to self.config_path)

**Parameters:**

- **file_path** (str) = None

##### get_schema_info(path: str) -> Dict

Get schema information for a configuration path.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')

Returns:
Schema information (type, default, description, etc.)

**Parameters:**

- **path** (str)

**Returns:**

- Dict

##### to_dict() -> Dict

Return the complete configuration as a dictionary.

Sensitive values are masked in the returned dictionary.

**Returns:**

- Dict

##### get_env_var_name(path: str) -> str

Get the corresponding environment variable name for a config path.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')

Returns:
Environment variable name or None if not defined

**Parameters:**

- **path** (str)

**Returns:**

- str

##### self_monitor() -> Dict

Monitor the configuration system for security issues.

Returns:
Dict with monitoring results

**Returns:**

- Dict

##### reload_config()

Reload configuration from the config file.

## Functions

##### get_value(self) -> str

Return the actual string value.

**Parameters:**

- **self**

**Returns:**

- str

##### clear(self)

Securely clear the string value from memory.

**Parameters:**

- **self**

##### get_instance(cls, schema_path = None, config_path = None, lockdown_mode = False)

Get or create the singleton instance of ConfigManager.

**Parameters:**

- **cls**
- **schema_path** = None
- **config_path** = None
- **lockdown_mode** = False

##### create_config_signature(self, file_path: str)

Create a signature file for configuration integrity verification.

Args:
file_path: Path to the configuration file

**Parameters:**

- **self**
- **file_path** (str)

##### get(self, path: str, default: Any = None) -> Any

Get configuration value by dot-notation path with secure handling.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')
default: Default value to return if path not found

Returns:
Configuration value or default

**Parameters:**

- **self**
- **path** (str)
- **default** (Any) = None

**Returns:**

- Any

##### get_raw(self, path: str, default: Any = None) -> Any

Get raw configuration value without secure wrapping.
Only use when the actual value is needed for operations.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')
default: Default value to return if path not found

Returns:
Raw configuration value or default

**Parameters:**

- **self**
- **path** (str)
- **default** (Any) = None

**Returns:**

- Any

##### set(self, path: str, value: Any)

Set configuration value by dot-notation path with audit logging.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')
value: Value to set

**Parameters:**

- **self**
- **path** (str)
- **value** (Any)

##### reload(self)

Reload configuration from file and reapply environment overrides.

**Parameters:**

- **self**

##### save(self, file_path: str = None)

Save current configuration to file.

Args:
file_path: Path to save configuration to (defaults to self.config_path)

**Parameters:**

- **self**
- **file_path** (str) = None

##### get_schema_info(self, path: str) -> Dict

Get schema information for a configuration path.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')

Returns:
Schema information (type, default, description, etc.)

**Parameters:**

- **self**
- **path** (str)

**Returns:**

- Dict

##### to_dict(self) -> Dict

Return the complete configuration as a dictionary.

Sensitive values are masked in the returned dictionary.

**Parameters:**

- **self**

**Returns:**

- Dict

##### get_env_var_name(self, path: str) -> str

Get the corresponding environment variable name for a config path.

Args:
path: Path to the configuration value (e.g., 'service.check_interval')

Returns:
Environment variable name or None if not defined

**Parameters:**

- **self**
- **path** (str)

**Returns:**

- str

##### self_monitor(self) -> Dict

Monitor the configuration system for security issues.

Returns:
Dict with monitoring results

**Parameters:**

- **self**

**Returns:**

- Dict

##### reload_config(self)

Reload configuration from the config file.

**Parameters:**

- **self**

##### scan_schema(schema, path = '')

**Parameters:**

- **schema**
- **path** = ''
