# service_protection

Self-Protection Module for NGINX Security Monitor
Implements security measures to protect the monitoring service itself from attacks.

## Classes

### ServiceProtection

Protects the security monitor service from attacks.

#### Methods

### check_rate_limiting(operation_type, limit_per_minute = None)

Check if operation is within rate limits.

**Parameters:**

- **operation_type**
- **limit_per_minute** = None

### check_file_integrity()

Check if monitored files have been tampered with.

### check_process_integrity()

Check if the service process has been compromised.

### check_resource_abuse()

Check for resource exhaustion attacks.

### check_log_tampering(log_file_path)

Check for log file tampering attempts.

**Parameters:**

- **log_file_path**

### check_service_availability()

Check if the service is functioning correctly.

### perform_self_check()

Perform comprehensive self-protection check.

### emergency_shutdown(reason)

Emergency shutdown if service is compromised.

**Parameters:**

- **reason**

## Functions

### check_rate_limiting(self, operation_type, limit_per_minute = None)

Check if operation is within rate limits.

**Parameters:**

- **self**
- **operation_type**
- **limit_per_minute** = None

### check_file_integrity(self)

Check if monitored files have been tampered with.

**Parameters:**

- **self**

### check_process_integrity(self)

Check if the service process has been compromised.

**Parameters:**

- **self**

### check_resource_abuse(self)

Check for resource exhaustion attacks.

**Parameters:**

- **self**

### check_log_tampering(self, log_file_path)

Check for log file tampering attempts.

**Parameters:**

- **self**
- **log_file_path**

### check_service_availability(self)

Check if the service is functioning correctly.

**Parameters:**

- **self**

### perform_self_check(self)

Perform comprehensive self-protection check.

**Parameters:**

- **self**

### emergency_shutdown(self, reason)

Emergency shutdown if service is compromised.

**Parameters:**

- **self**
- **reason**
