# Security Framework Integrations

## Overview

The NGINX Security Monitor now supports integration with popular security frameworks and tools, providing a comprehensive defense-in-depth approach. This allows you to leverage existing security infrastructure while enhancing detection and response capabilities.

## Supported Security Frameworks

### 🔥 **fail2ban Integration**

- **Purpose**: IP blocking and jail management
- **Features**:
  - Monitor fail2ban jail status and banned IPs
  - Automatically ban IPs detected by NGINX Security Monitor
  - Check jail configuration for security best practices
  - Real-time jail status monitoring

**Setup Requirements:**

```bash
# Install fail2ban
sudo apt-get install fail2ban  # Ubuntu/Debian
sudo yum install fail2ban      # CentOS/RHEL

# Enable and start service
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

**Recommended NGINX Jails:**

- `nginx-http-auth` - Failed authentication attempts
- `nginx-noscript` - Script injection attempts
- `nginx-badbots` - Malicious bot detection
- `nginx-noproxy` - Proxy abuse prevention

### 🛡️ **OSSEC/Wazuh Integration**

- **Purpose**: Host Intrusion Detection System (HIDS)
- **Features**:
  - Monitor OSSEC/Wazuh alerts and events
  - Send custom events to Wazuh manager
  - Parse alert logs for threat intelligence
  - Custom rule integration

**Setup Requirements:**

```bash
# Install Wazuh agent (example for Ubuntu)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update
sudo apt-get install wazuh-agent
```

### 🕵️ **Suricata Integration**

- **Purpose**: Network Intrusion Detection/Prevention System (IDS/IPS)
- **Features**:
  - Parse Suricata EVE JSON logs
  - Monitor network-based attacks
  - Custom rule integration
  - Real-time alert processing

**Setup Requirements:**

```bash
# Install Suricata
sudo apt-get install suricata  # Ubuntu/Debian
sudo yum install suricata      # CentOS/RHEL

# Configure EVE JSON logging in /etc/suricata/suricata.yaml
```

### 🔒 **ModSecurity Integration**

- **Purpose**: Web Application Firewall (WAF)
- **Features**:
  - Parse ModSecurity audit logs
  - Monitor WAF blocks and alerts
  - Custom rule integration
  - Attack pattern analysis

**Setup Requirements:**

```bash
# Install ModSecurity (with NGINX)
sudo apt-get install libnginx-mod-security
# Configure ModSecurity rules and audit logging
```

## Configuration

### Basic Configuration

Add to your `service-settings.yaml`:

```yaml
security_integrations:
  # fail2ban integration
  fail2ban:
    enabled: true
    jail_files:
      - /etc/fail2ban/jail.local
      - /etc/fail2ban/jail.conf
      - /etc/fail2ban/jail.d/
    
  # OSSEC/Wazuh integration  
  ossec:
    enabled: true
    ossec_dir: /var/ossec
    
  # Suricata integration
  suricata:
    enabled: true
    suricata_log: /var/log/suricata/eve.json
    suricata_rules: /etc/suricata/rules/
    
  # Wazuh SIEM integration
  wazuh:
    enabled: true
    wazuh_dir: /var/ossec
    api_url: "https://your-wazuh-manager:55000"  # Optional
    api_user: "api_user"                         # Optional
    api_password: "<REPLACE_WITH_ENV_VARIABLE>"                 # Optional
    
  # ModSecurity integration
  modsecurity:
    enabled: true
    audit_log: /var/log/modsec_audit.log
    rules_dir: /etc/modsecurity/rules
```

## Usage

### Automatic Integration

Once configured, the security integrations work automatically:

1. **Threat Detection**: When NGINX Security Monitor detects a threat, it automatically:

   - Bans the IP in appropriate fail2ban jails
   - Sends events to OSSEC/Wazuh
   - Logs to integrated security tools

1. **Aggregated Monitoring**: The system periodically checks all integrated tools for:

   - Recent alerts and blocks
   - Active threats
   - Security tool status

1. **Unified Alerting**: Threats from all sources are aggregated and reported in unified alerts

### Manual Testing

Use the security integrations utility:

```bash
# Check which integrations are available
python3 security_integrations_util.py check

# Test integration functionality
python3 security_integrations_util.py test

# Setup specific integrations
python3 security_integrations_util.py setup-fail2ban
python3 security_integrations_util.py setup-ossec
```

## Integration Benefits

### 1. **Unified Threat Intelligence**

- Correlate threats across multiple security tools
- Single dashboard for all security events
- Comprehensive threat timeline

### 2. **Automated Response**

- Automatic IP blocking via fail2ban
- Cross-system threat sharing
- Coordinated incident response

### 3. **Enhanced Detection**

- Network-level detection (Suricata)
- Host-level monitoring (OSSEC/Wazuh)
- Application-level protection (ModSecurity)
- Log analysis (NGINX Security Monitor)

### 4. **Compliance and Reporting**

- Centralized security event logging
- Audit trail across all tools
- Compliance reporting support

## Example Scenarios

### Scenario 1: SQL Injection Attack

1. **ModSecurity** blocks the initial request
1. **NGINX Security Monitor** detects the pattern in logs
1. **fail2ban** bans the source IP
1. **Wazuh** receives the alert for SIEM correlation
1. **Unified alert** sent to administrators

### Scenario 2: Brute Force Attack

1. **NGINX Security Monitor** detects failed login patterns
1. **fail2ban** activates nginx-http-auth jail
1. **OSSEC** monitors authentication logs
1. **Suricata** detects network patterns
1. **Coordinated blocking** across all layers

### Scenario 3: Bot Attack

1. **Suricata** detects suspicious network traffic
1. **NGINX Security Monitor** identifies bot patterns
1. **ModSecurity** blocks malicious requests
1. **fail2ban** bans bot IP ranges
1. **Threat intelligence** shared across tools

## Custom Rules and Integration

### fail2ban Custom Jail

Create custom jails for NGINX Security Monitor:

```ini
# /etc/fail2ban/jail.d/nginx-security-monitor.conf
[nginx-security-monitor]
enabled = true
port = http,https
filter = nginx-security-monitor
logpath = /var/log/nginx-security-monitor.log
maxretry = 3
bantime = 3600
findtime = 600
```

### OSSEC Custom Rules

Add custom OSSEC rules for enhanced detection:

```xml
<!-- /var/ossec/rules/nginx_security_rules.xml -->
<group name="nginx_security">
  <rule id="100001" level="10">
    <if_sid>31151</if_sid>
    <match>NGINX_SECURITY_ALERT</match>
    <description>NGINX Security Monitor Alert</description>
    <group>web,attack,</group>
  </rule>
</group>
```

### Suricata Custom Rules

Create Suricata rules for specific threats:

```
# /etc/suricata/rules/nginx-security.rules
alert http any any -> any any (msg:"NGINX Security Monitor - SQL Injection"; 
  content:"UNION SELECT"; nocase; sid:1000001; rev:1;)
```

## Troubleshooting

### Common Issues

1. **Integration Not Available**

   ```bash
   # Check if service is running
   sudo systemctl status fail2ban
   sudo systemctl status suricata
   sudo systemctl status wazuh-agent
   ```

1. **Permission Issues**

   ```bash
   # Ensure nginx-monitor user can read log files
   sudo usermod -a -G adm nginx-monitor
   sudo chmod 644 /var/log/suricata/eve.json
   ```

1. **Log File Locations**

   - Check actual log file paths in your system
   - Update configuration with correct paths
   - Ensure log rotation doesn't break monitoring

### Debug Mode

Enable debug logging for integration troubleshooting:

```yaml
logging:
  level: DEBUG
  handlers:
    - type: file
      filename: /var/log/nginx-security-monitor-debug.log
```

## Security Considerations

### 1. **Log File Security**

- Restrict access to security tool logs
- Use proper file permissions (640 or 644)
- Regular log rotation and archival

### 2. **API Security**

- Use strong authentication for API integrations
- Encrypt API communications (TLS)
- Regular credential rotation

### 3. **Integration Monitoring**

- Monitor integration health
- Alert on integration failures
- Backup integration configurations

## Best Practices

### 1. **Tool Coordination**

- Avoid duplicate blocking rules
- Coordinate ban times across tools
- Use consistent IP whitelisting

### 2. **Performance**

- Monitor resource usage of integrated tools
- Use appropriate check intervals
- Implement rate limiting for integrations

### 3. **Maintenance**

- Regular updates of security tools
- Review and tune detection rules
- Monitor false positive rates

### 4. **Documentation**

- Document custom rules and configurations
- Maintain integration dependency maps
- Create runbooks for common scenarios

## Integration Roadmap

### Planned Integrations

- **CrowdStrike Falcon**: Endpoint protection
- **Splunk**: SIEM integration
- **ELK Stack**: Log analysis and visualization
- **Snort**: Additional IDS support
- **pfSense**: Firewall integration

The security framework integrations provide a powerful foundation for comprehensive security monitoring, enabling your NGINX Security Monitor to work seamlessly with your existing security infrastructure while providing enhanced threat detection and response capabilities.
