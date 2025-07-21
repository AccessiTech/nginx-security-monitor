# threat_processor

Threat Processor Module
Handles threat analysis and processing for the NGINX Security Monitor.

## Classes

### ThreatProcessor

Handles threat detection and processing functionality.

#### Methods

##### process_log_entries(log_entries: Any) -> Any

Process log entries for threats and return detected threats.

Args:
log_entries: List of parsed log entries

Returns:
list: List of detected threats

**Parameters:**

- **log_entries** (Any)

**Returns:**

- Any

##### get_threat_statistics() -> Any

Get statistics about processed threats.

Returns:
dict: Threat statistics

**Returns:**

- Any

## Functions

##### process_log_entries(self, log_entries: Any) -> Any

Process log entries for threats and return detected threats.

Args:
log_entries: List of parsed log entries

Returns:
list: List of detected threats

**Parameters:**

- **self**
- **log_entries** (Any)

**Returns:**

- Any

##### get_threat_statistics(self) -> Any

Get statistics about processed threats.

Returns:
dict: Threat statistics

**Parameters:**

- **self**

**Returns:**

- Any
