# monitor_service

NGINX Security Monitor Service
Main entry point for running the monitor as a system service.

## Constants

### SECURITY_FEATURES_AVAILABLE

**Value**: `True`

### SECURITY_FEATURES_AVAILABLE

**Value**: `False`

## Classes

### NginxSecurityMonitor

Main service class for the NGINX Security Monitor.

#### Methods

##### load_config()

Load configuration from YAML file.

##### setup_logging()

Setup logging configuration.

##### signal_handler(signum, frame)

Handle shutdown signals gracefully.

**Parameters:**

- **signum**
- **frame**

##### run()

Main service entry point - delegates to security coordinator.

##### get_monitoring_status()

Get current monitoring status.

##### force_check()

Force an immediate security check.

##### get_new_log_entries(log_file_path)

Get new log entries - delegates to log processor with state sync.

**Parameters:**

- **log_file_path**

##### process_threats(detected_patterns)

Process threats - backward compatibility with test expectations.

**Parameters:**

- **detected_patterns**

## Functions

##### main()

Main entry point.

##### load_config(self)

Load configuration from YAML file.

**Parameters:**

- **self**

##### setup_logging(self)

Setup logging configuration.

**Parameters:**

- **self**

##### signal_handler(self, signum, frame)

Handle shutdown signals gracefully.

**Parameters:**

- **self**
- **signum**
- **frame**

##### run(self)

Main service entry point - delegates to security coordinator.

**Parameters:**

- **self**

##### get_monitoring_status(self)

Get current monitoring status.

**Parameters:**

- **self**

##### force_check(self)

Force an immediate security check.

**Parameters:**

- **self**

##### get_new_log_entries(self, log_file_path)

Get new log entries - delegates to log processor with state sync.

**Parameters:**

- **self**
- **log_file_path**

##### process_threats(self, detected_patterns)

Process threats - backward compatibility with test expectations.

**Parameters:**

- **self**
- **detected_patterns**
