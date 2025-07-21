# security_integrations

Security Framework Integrations for NGINX Security Monitor
Integrates with popular security frameworks and tools like fail2ban, OSSEC, Suricata, etc.

## Classes

### Fail2BanIntegration

Integration with fail2ban for jail monitoring and IP blocking.

#### Methods

##### is_available()

Check if fail2ban is available and running.

##### get_jail_status()

Get status of all fail2ban jails.

##### get_individual_jail_status(jail_name)

Get detailed status for a specific jail.

**Parameters:**

- **jail_name**

##### ban_ip(jail_name, ip_address)

Ban an IP address in a specific jail.

**Parameters:**

- **jail_name**
- **ip_address**

##### unban_ip(jail_name, ip_address)

Unban an IP address from a specific jail.

**Parameters:**

- **jail_name**
- **ip_address**

##### monitor_jail_files()

Monitor fail2ban jail configuration files for changes.

### OSSECIntegration

Integration with OSSEC HIDS (Host Intrusion Detection System).

#### Methods

##### is_available()

Check if OSSEC is available and running.

##### get_recent_alerts(hours = None)

Get OSSEC alerts from the last specified hours.

**Parameters:**

- **hours** = None

##### add_custom_rule(rule_content)

Add a custom OSSEC rule for NGINX monitoring.

**Parameters:**

- **rule_content**

### SuricataIntegration

Integration with Suricata IDS/IPS.

#### Methods

##### is_available()

Check if Suricata is available and running.

##### get_recent_alerts(hours = 1)

Get Suricata alerts from EVE JSON log.

**Parameters:**

- **hours** = 1

##### add_custom_rule(rule_content)

Add custom Suricata rule for NGINX monitoring.

**Parameters:**

- **rule_content**

### WazuhIntegration

Integration with Wazuh SIEM.

#### Methods

##### is_available()

Check if Wazuh agent is available and running.

##### send_custom_event(event_data)

Send custom event to Wazuh manager.

**Parameters:**

- **event_data**

### ModSecurityIntegration

Integration with ModSecurity WAF.

#### Methods

##### is_available()

Check if ModSecurity is available.

##### get_recent_blocks(hours = 1)

Get recent ModSecurity blocks.

**Parameters:**

- **hours** = 1

### SecurityIntegrationManager

Main manager for all security framework integrations.

#### Methods

##### get_integration_status()

Get status of all security integrations.

##### handle_threat_with_integrations(threat_info)

Handle a detected threat using available security integrations.

**Parameters:**

- **threat_info**

##### get_aggregated_threats(hours = 1)

Get aggregated threat information from all available sources.

**Parameters:**

- **hours** = 1

## Functions

##### is_available(self)

Check if fail2ban is available and running.

**Parameters:**

- **self**

##### get_jail_status(self)

Get status of all fail2ban jails.

**Parameters:**

- **self**

##### get_individual_jail_status(self, jail_name)

Get detailed status for a specific jail.

**Parameters:**

- **self**
- **jail_name**

##### ban_ip(self, jail_name, ip_address)

Ban an IP address in a specific jail.

**Parameters:**

- **self**
- **jail_name**
- **ip_address**

##### unban_ip(self, jail_name, ip_address)

Unban an IP address from a specific jail.

**Parameters:**

- **self**
- **jail_name**
- **ip_address**

##### monitor_jail_files(self)

Monitor fail2ban jail configuration files for changes.

**Parameters:**

- **self**

##### is_available(self)

Check if OSSEC is available and running.

**Parameters:**

- **self**

##### get_recent_alerts(self, hours = None)

Get OSSEC alerts from the last specified hours.

**Parameters:**

- **self**
- **hours** = None

##### add_custom_rule(self, rule_content)

Add a custom OSSEC rule for NGINX monitoring.

**Parameters:**

- **self**
- **rule_content**

##### is_available(self)

Check if Suricata is available and running.

**Parameters:**

- **self**

##### get_recent_alerts(self, hours = 1)

Get Suricata alerts from EVE JSON log.

**Parameters:**

- **self**
- **hours** = 1

##### add_custom_rule(self, rule_content)

Add custom Suricata rule for NGINX monitoring.

**Parameters:**

- **self**
- **rule_content**

##### is_available(self)

Check if Wazuh agent is available and running.

**Parameters:**

- **self**

##### send_custom_event(self, event_data)

Send custom event to Wazuh manager.

**Parameters:**

- **self**
- **event_data**

##### is_available(self)

Check if ModSecurity is available.

**Parameters:**

- **self**

##### get_recent_blocks(self, hours = 1)

Get recent ModSecurity blocks.

**Parameters:**

- **self**
- **hours** = 1

##### get_integration_status(self)

Get status of all security integrations.

**Parameters:**

- **self**

##### handle_threat_with_integrations(self, threat_info)

Handle a detected threat using available security integrations.

**Parameters:**

- **self**
- **threat_info**

##### get_aggregated_threats(self, hours = 1)

Get aggregated threat information from all available sources.

**Parameters:**

- **self**
- **hours** = 1
