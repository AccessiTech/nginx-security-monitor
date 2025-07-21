# log_processor

Log Processor Module
Handles log file reading and parsing for the NGINX Security Monitor.

## Classes

### LogProcessor

Handles log file reading and parsing functionality.

#### Methods

##### get_new_log_entries(log_file_path)

Get only new log entries since last check.

Args:
log_file_path: Path to the log file

Returns:
list: List of parsed log entries

**Parameters:**

- **log_file_path**

##### parse_log_line(line)

Parse a single log line into structured data.

Args:
line: Raw log line string

Returns:
dict: Parsed log entry or None if parsing failed

**Parameters:**

- **line**

##### reset_processed_size()

Reset the last processed size counter.

##### get_processed_size()

Get the current processed size.

Returns:
int: Last processed file size

## Functions

##### get_new_log_entries(self, log_file_path)

Get only new log entries since last check.

Args:
log_file_path: Path to the log file

Returns:
list: List of parsed log entries

**Parameters:**

- **self**
- **log_file_path**

##### parse_log_line(self, line)

Parse a single log line into structured data.

Args:
line: Raw log line string

Returns:
dict: Parsed log entry or None if parsing failed

**Parameters:**

- **self**
- **line**

##### reset_processed_size(self)

Reset the last processed size counter.

**Parameters:**

- **self**

##### get_processed_size(self)

Get the current processed size.

Returns:
int: Last processed file size

**Parameters:**

- **self**
