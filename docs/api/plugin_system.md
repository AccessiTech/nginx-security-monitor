# plugin_system

Plugin system for custom mitigation strategies.
Allows clients to implement their own secret countermeasures without exposing them in the public codebase.

## Classes

### MitigationPlugin

Abstract base class for mitigation plugins.

#### Methods

#### name() -> str

Return the name of this plugin.

**Returns:**

- str

#### threat_types() -> Any

Return list of threat types this plugin can handle.

**Returns:**

- Any

#### can_handle(threat_info: Any) -> bool

Return config.get('mitigation.strategies.ddos.enabled') if this plugin can handle the given threat.

**Parameters:**

- **threat_info** (Any)

**Returns:**

- bool

#### mitigate(threat_info: Any) -> Any

Apply mitigation for the threat.

Args:
threat_info: Dictionary containing threat details

Returns:
Dictionary with mitigation results

**Parameters:**

- **threat_info** (Any)

**Returns:**

- Any

#### get_priority() -> int

Return priority level (lower number = higher priority).

**Returns:**

- int

### PluginManager

Manages and executes mitigation plugins.

#### Methods

#### get_available_plugins() -> Any

Return list of available plugin names.

**Returns:**

- Any

#### execute_mitigation(threat_info: Any) -> Any

Execute appropriate mitigation plugins for a threat.

Args:
threat_info: Dictionary containing threat details

Returns:
List of mitigation results from all applicable plugins

**Parameters:**

- **threat_info** (Any)

**Returns:**

- Any

### DefaultIPBlockPlugin

Default IP blocking mitigation (example - replace with your own).

#### Methods

#### name() -> str

**Returns:**

- str

#### threat_types() -> Any

**Returns:**

- Any

#### can_handle(threat_info: Any) -> bool

**Parameters:**

- **threat_info** (Any)

**Returns:**

- bool

#### mitigate(threat_info: Any) -> Any

**Parameters:**

- **threat_info** (Any)

**Returns:**

- Any

### AlertOnlyPlugin

Plugin that only logs threats without taking action.

#### Methods

#### name() -> str

**Returns:**

- str

#### threat_types() -> Any

**Returns:**

- Any

#### can_handle(threat_info: Any) -> bool

**Parameters:**

- **threat_info** (Any)

**Returns:**

- bool

#### get_priority() -> int

**Returns:**

- int

#### mitigate(threat_info: Any) -> Any

**Parameters:**

- **threat_info** (Any)

**Returns:**

- Any

## Functions

### create_plugin_template(plugin_name: str, output_file: str)

Create a template for a custom plugin.

**Parameters:**

- **plugin_name** (str)
- **output_file** (str)

#### name(self) -> str

Return the name of this plugin.

**Parameters:**

- **self**

**Returns:**

- str

#### threat_types(self) -> Any

Return list of threat types this plugin can handle.

**Parameters:**

- **self**

**Returns:**

- Any

#### can_handle(self, threat_info: Any) -> bool

Return config.get('mitigation.strategies.ddos.enabled') if this plugin can handle the given threat.

**Parameters:**

- **self**
- **threat_info** (Any)

**Returns:**

- bool

#### mitigate(self, threat_info: Any) -> Any

Apply mitigation for the threat.

Args:
threat_info: Dictionary containing threat details

Returns:
Dictionary with mitigation results

**Parameters:**

- **self**
- **threat_info** (Any)

**Returns:**

- Any

#### get_priority(self) -> int

Return priority level (lower number = higher priority).

**Parameters:**

- **self**

**Returns:**

- int

#### get_available_plugins(self) -> Any

Return list of available plugin names.

**Parameters:**

- **self**

**Returns:**

- Any

#### execute_mitigation(self, threat_info: Any) -> Any

Execute appropriate mitigation plugins for a threat.

Args:
threat_info: Dictionary containing threat details

Returns:
List of mitigation results from all applicable plugins

**Parameters:**

- **self**
- **threat_info** (Any)

**Returns:**

- Any

#### name(self) -> str

**Parameters:**

- **self**

**Returns:**

- str

#### threat_types(self) -> Any

**Parameters:**

- **self**

**Returns:**

- Any

#### can_handle(self, threat_info: Any) -> bool

**Parameters:**

- **self**
- **threat_info** (Any)

**Returns:**

- bool

#### mitigate(self, threat_info: Any) -> Any

**Parameters:**

- **self**
- **threat_info** (Any)

**Returns:**

- Any

#### name(self) -> str

**Parameters:**

- **self**

**Returns:**

- str

#### threat_types(self) -> Any

**Parameters:**

- **self**

**Returns:**

- Any

#### can_handle(self, threat_info: Any) -> bool

**Parameters:**

- **self**
- **threat_info** (Any)

**Returns:**

- bool

#### get_priority(self) -> int

**Parameters:**

- **self**

**Returns:**

- int

#### mitigate(self, threat_info: Any) -> Any

**Parameters:**

- **self**
- **threat_info** (Any)

**Returns:**

- Any
