# alert_manager

Alert Manager Module
Handles all alert generation and sending logic for the NGINX Security Monitor.

## Classes

### AlertManager

Manages all alert generation and sending functionality.

#### Methods

#### send_threat_alert(pattern, mitigation_results)

Send alerts for detected threats.

Args:
pattern: The detected threat pattern
mitigation_results: List of mitigation results

**Parameters:**

- **pattern**
- **mitigation_results**

#### send_emergency_alert(critical_threats)

Send emergency alert for critical service threats.

Args:
critical_threats: List of critical threat objects

**Parameters:**

- **critical_threats**

#### send_service_threat_alert(high_threats)

Send alert for high-severity service threats.

Args:
high_threats: List of high-severity threat objects

**Parameters:**

- **high_threats**

#### send_integration_alert(threats)

Send alert for threats detected by security integrations.

Args:
threats: List of threat objects from security integrations

**Parameters:**

- **threats**

## Functions

### send_threat_alert(self, pattern, mitigation_results)

Send alerts for detected threats.

Args:
pattern: The detected threat pattern
mitigation_results: List of mitigation results

**Parameters:**

- **self**
- **pattern**
- **mitigation_results**

#### send_emergency_alert(self, critical_threats)

Send emergency alert for critical service threats.

Args:
critical_threats: List of critical threat objects

**Parameters:**

- **self**
- **critical_threats**

#### send_service_threat_alert(self, high_threats)

Send alert for high-severity service threats.

Args:
high_threats: List of high-severity threat objects

**Parameters:**

- **self**
- **high_threats**

#### send_integration_alert(self, threats)

Send alert for threats detected by security integrations.

Args:
threats: List of threat objects from security integrations

**Parameters:**

- **self**
- **threats**
