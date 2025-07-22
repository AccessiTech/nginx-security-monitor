# 🔗 Integration Cookbook - NGINX Security Monitor

## 🎯 **Overview**

This cookbook provides practical, real-world integration examples for the NGINX Security Monitor
with popular security tools, SIEM systems, cloud platforms, and enterprise services.
Each recipe includes complete configuration examples, troubleshooting tips, and best practices.

## 📚 **Integration Categories**

<!-- markdownlint-disable MD013 -->

| Category                      | Tools                                                         | Purpose                       |
| ----------------------------- | ------------------------------------------------------------- | ----------------------------- |
| **Intrusion Detection**       | fail2ban, OSSEC, Wazuh, Suricata                              | Block and detect threats      |
| **Web Application Firewalls** | ModSecurity, Cloudflare WAF, AWS WAF                          | Filter malicious requests     |
| **SIEM Platforms**            | Splunk, ELK Stack, QRadar, ArcSight                           | Centralized log analysis      |
| **Cloud Security**            | AWS Security Hub, Azure Sentinel, GCP Security Command Center | Cloud-native security         |
| **Monitoring & Alerting**     | Prometheus, Grafana, DataDog, New Relic                       | Metrics and visualization     |
| **Incident Response**         | PagerDuty, Opsgenie, ServiceNow, Jira                         | Automated incident management |
| **Threat Intelligence**       | VirusTotal, AbuseIPDB, OTX, MISP                              | Threat context and reputation |

<!-- markdownlint-enable MD013 -->

______________________________________________________________________

## 🚫 **fail2ban Integration**

### **Complete fail2ban Setup**

Configure fail2ban to work with NGINX Security Monitor:

#### **1. Install and Configure fail2ban**

````bash
```bash
# Install fail2ban
sudo apt-get install fail2ban

# Create custom configuration
sudo mkdir -p /etc/fail2ban/filter.d
sudo mkdir -p /etc/fail2ban/action.d
````

#### **2. Create Custom Filter**

```ini
# /etc/fail2ban/filter.d/nginx-security-monitor.conf
[Definition]

# Match NGINX Security Monitor threat detections
failregex = ^<HOST> .* ".*" [45]\d\d \d+.*THREAT_DETECTED.*$
            ^<HOST> .* ".*(\?|&)(.*=.*(\\\|'|;|<|>|\(|\)|,|union|select|insert|delete|drop|update|script).*).*" \d+ \d+.*$
            ^<HOST> .* "(GET|POST) .*(\.\./|\.\.\\\|etc/passwd|etc/shadow|proc/self/environ).*" \d+ \d+.*$
            ^<HOST> .* ".*(\bor\b|\band\b).*(\b1=1\b|\b'='|\bdrop\b|\bunion\b|\bselect\b).*" \d+ \d+.*$

# Ignore legitimate traffic
ignoreregex = ^<HOST> .* "GET /(favicon\.ico|robots\.txt|sitemap\.xml)" 200.*$
              ^<HOST> .* ".*Googlebot.*" 200.*$
              ^<HOST> .* ".*Bingbot.*" 200.*$
```

#### **3. Create Custom Actions**

```ini
# /etc/fail2ban/action.d/nginx-security-notify.conf
[Definition]

# Action to notify NGINX Security Monitor of ban
actionstart = 
actionstop = 
actioncheck = 
actionban = curl -X POST http://localhost:8080/api/bans \
           -H "Content-Type: application/json" \
           -d '{"ip":"<ip>","action":"ban","jail":"<name>","time":"<time>"}'
actionunban = curl -X POST http://localhost:8080/api/bans \
             -H "Content-Type: application/json" \
             -d '{"ip":"<ip>","action":"unban","jail":"<name>","time":"<time>"}'

[Init]
```

#### **4. Configure Jails**

```ini
# /etc/fail2ban/jail.d/nginx-security.conf
[nginx-security-brute-force]
enabled = true
filter = nginx-security-monitor
logpath = /var/log/nginx/access.log
maxretry = 5
findtime = 600
bantime = 3600
action = iptables-multiport[name=nginx-security, port="http,https", protocol=tcp]
         nginx-security-notify[name=nginx-security-brute-force]

[nginx-security-sql-injection]
enabled = true
filter = nginx-security-monitor
logpath = /var/log/nginx/access.log
maxretry = 1
findtime = 300
bantime = 86400
action = iptables-multiport[name=nginx-sql, port="http,https", protocol=tcp]
         nginx-security-notify[name=nginx-security-sql-injection]

[nginx-security-directory-traversal]
enabled = true
filter = nginx-security-monitor
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 7200
action = iptables-multiport[name=nginx-traversal, port="http,https", protocol=tcp]
         nginx-security-notify[name=nginx-security-directory-traversal]
```

#### **5. NGINX Security Monitor Configuration**

```yaml
# config/settings.yaml
integrations:
  fail2ban:
    enabled: true
    
    # Communication settings
    api_endpoint: "http://localhost:8080/api"
    webhook_endpoint: "/webhook/fail2ban"
    
    # Synchronization
    sync_bans: true
    sync_interval: 60  # seconds
    
    # Jail management
    managed_jails:
      - "nginx-security-brute-force"
      - "nginx-security-sql-injection" 
      - "nginx-security-directory-traversal"
    
    # Ban coordination
    coordinate_bans: true
    ban_duration_sync: true
    
    # Logging
    log_integration: true
    log_file: "/var/log/nginx-security/fail2ban-integration.log"
```

#### **6. Integration Code**

```python
# src/integrations/fail2ban_integration.py
import subprocess
import requests
import json
from typing import Dict, Any, List

class Fail2banIntegration:
    """Integration with fail2ban for coordinated threat response."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.api_endpoint = config.get('api_endpoint')
        self.managed_jails = config.get('managed_jails', [])
        
    def ban_ip(self, ip: str, jail: str = "nginx-security-brute-force") -> bool:
        """Ban IP address through fail2ban."""
        try:
            cmd = f"fail2ban-client set {jail} banip {ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self._log_action(f"Banned IP {ip} in jail {jail}")
                return True
            else:
                self._log_error(f"Failed to ban IP {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            self._log_error(f"Error banning IP {ip}: {e}")
            return False
    
    def unban_ip(self, ip: str, jail: str = "nginx-security-brute-force") -> bool:
        """Unban IP address through fail2ban."""
        try:
            cmd = f"fail2ban-client set {jail} unbanip {ip}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            return result.returncode == 0
            
        except Exception as e:
            self._log_error(f"Error unbanning IP {ip}: {e}")
            return False
    
    def get_banned_ips(self, jail: str = None) -> List[str]:
        """Get list of currently banned IPs."""
        try:
            if jail:
                cmd = f"fail2ban-client get {jail} banip"
            else:
                # Get banned IPs from all managed jails
                banned_ips = []
                for managed_jail in self.managed_jails:
                    cmd = f"fail2ban-client get {managed_jail} banip"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        banned_ips.extend(result.stdout.strip().split('\n'))
                return list(set(banned_ips))
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().split('\n')
            else:
                return []
                
        except Exception as e:
            self._log_error(f"Error getting banned IPs: {e}")
            return []
    
    def sync_bans_with_security_monitor(self):
        """Synchronize bans between fail2ban and security monitor."""
        try:
            # Get banned IPs from fail2ban
            fail2ban_bans = self.get_banned_ips()
            
            # Get banned IPs from security monitor
            response = requests.get(f"{self.api_endpoint}/bans")
            security_monitor_bans = response.json().get('banned_ips', [])
            
            # Sync differences
            for ip in fail2ban_bans:
                if ip not in security_monitor_bans:
                    self._notify_security_monitor_ban(ip)
            
            for ip in security_monitor_bans:
                if ip not in fail2ban_bans:
                    self.ban_ip(ip)
                    
        except Exception as e:
            self._log_error(f"Error syncing bans: {e}")
    
    def handle_webhook(self, webhook_data: Dict[str, Any]):
        """Handle webhook notifications from fail2ban."""
        action = webhook_data.get('action')
        ip = webhook_data.get('ip')
        jail = webhook_data.get('jail')
        
        if action == 'ban':
            self._handle_ban_notification(ip, jail)
        elif action == 'unban':
            self._handle_unban_notification(ip, jail)
```

______________________________________________________________________

## 🔍 **OSSEC/Wazuh Integration**

### **Complete OSSEC/Wazuh Setup**

#### **1. OSSEC Agent Configuration**

```xml
<!-- /var/ossec/etc/ossec.conf -->
<ossec_config>
  <!-- NGINX Security Monitor log monitoring -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/nginx-security/threats.log</location>
  </localfile>
  
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx-security/mitigation.log</location>
  </localfile>
  
  <!-- NGINX access logs -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  
  <!-- Active response configuration -->
  <command>
    <name>nginx-security-block</name>
    <executable>nginx-security-block.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  
  <active-response>
    <command>nginx-security-block</command>
    <location>local</location>
    <rules_id>100001,100002,100003</rules_id>
    <timeout>3600</timeout>
  </active-response>
</ossec_config>
```

#### **2. Custom OSSEC Rules**

```xml
<!-- /var/ossec/rules/local_rules.xml -->
<group name="nginx-security,">
  
  <!-- NGINX Security Monitor threat detection -->
  <rule id="100001" level="10">
    <decoded_as>json</decoded_as>
    <field name="threat_type">sql_injection</field>
    <description>SQL injection attempt detected by NGINX Security Monitor</description>
    <group>web,attack,sql_injection</group>
  </rule>
  
  <rule id="100002" level="8">
    <decoded_as>json</decoded_as>
    <field name="threat_type">brute_force</field>
    <description>Brute force attack detected by NGINX Security Monitor</description>
    <group>web,attack,brute_force</group>
  </rule>
  
  <rule id="100003" level="12">
    <decoded_as>json</decoded_as>
    <field name="threat_type">directory_traversal</field>
    <description>Directory traversal attempt detected by NGINX Security Monitor</description>
    <group>web,attack,directory_traversal</group>
  </rule>
  
  <!-- High severity threats -->
  <rule id="100004" level="15">
    <decoded_as>json</decoded_as>
    <field name="severity">critical</field>
    <description>Critical threat detected by NGINX Security Monitor</description>
    <group>web,attack,critical</group>
  </rule>
  
  <!-- Mitigation actions -->
  <rule id="100005" level="5">
    <match>Mitigation action: IP blocked</match>
    <description>IP address blocked by NGINX Security Monitor</description>
    <group>web,mitigation</group>
  </rule>
  
</group>
```

#### **3. Custom Decoders**

```xml
<!-- /var/ossec/etc/local_decoder.xml -->
<decoder name="nginx-security-json">
  <program_name>nginx-security</program_name>
  <type>json</type>
</decoder>

<decoder name="nginx-security-threat">
  <parent>nginx-security-json</parent>
  <field name="timestamp">\.timestamp</field>
  <field name="threat_type">\.threat_type</field>
  <field name="severity">\.severity</field>
  <field name="source_ip">\.source_ip</field>
  <field name="description">\.description</field>
  <field name="confidence">\.confidence</field>
</decoder>
```

#### **4. Active Response Script**

```bash
#!/bin/bash
# /var/ossec/active-response/bin/nginx-security-block.sh

LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`

# Read input from OSSEC
read INPUT_JSON
SRCIP=$(echo $INPUT_JSON | jq -r '.srcip')
ACTION=$(echo $INPUT_JSON | jq -r '.action')

# Log the action
echo "$(date) - OSSEC Active Response: $ACTION for IP $SRCIP" >> /var/log/nginx-security/ossec-integration.log

case "$ACTION" in
  add)
    # Block IP via NGINX Security Monitor API
    curl -X POST http://localhost:8080/api/mitigation/block \
         -H "Content-Type: application/json" \
         -d "{\"ip\":\"$SRCIP\",\"duration\":3600,\"source\":\"ossec\"}"
    
    # Also block via iptables as backup
    iptables -I INPUT -s $SRCIP -j DROP
    ;;
    
  delete)
    # Unblock IP via NGINX Security Monitor API
    curl -X POST http://localhost:8080/api/mitigation/unblock \
         -H "Content-Type: application/json" \
         -d "{\"ip\":\"$SRCIP\",\"source\":\"ossec\"}"
    
    # Remove iptables rule
    iptables -D INPUT -s $SRCIP -j DROP
    ;;
esac

exit 0
```

#### **5. Integration Configuration**

```yaml
# config/settings.yaml
integrations:
  ossec:
    enabled: true
    
    # OSSEC manager connection
    manager_host: "127.0.0.1"
    manager_port: 1514
    agent_id: "001"
    
    # Log forwarding
    forward_threats: true
    forward_mitigations: true
    log_format: "json"
    
    # Active response coordination
    active_response: true
    response_timeout: 60
    
    # Rule mapping
    rule_mapping:
      sql_injection: 100001
      brute_force: 100002
      directory_traversal: 100003
      critical_threat: 100004
```

______________________________________________________________________

## 🌊 **Suricata Integration**

### **Complete Suricata IDS Setup**

#### **1. Suricata Configuration**

```yaml
# /etc/suricata/suricata.yaml (relevant sections)
outputs:
  - eve-log:
      enabled: yes
      filetype: unix_dgram
      filename: /var/run/suricata/suricata-command.socket
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes
            metadata: yes
            http-body: yes
            http-body-printable: yes
        - http:
            extended: yes
        - dns
        - tls
        - files
        - smtp
        - flow

# Custom rules directory
rule-files:
  - nginx-security-monitor.rules
  - /etc/suricata/rules/custom.rules

# Performance tuning for web traffic
af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

#### **2. Custom Suricata Rules**

<!-- markdownlint-disable MD013 -->

```bash
# /etc/suricata/rules/nginx-security-monitor.rules

# SQL Injection Detection
alert http any any -> any any (msg:"NGINX-SEC SQL Injection Attempt"; flow:established,to_server; content:"union"; nocase; content:"select"; nocase; distance:0; within:100; classtype:web-application-attack; sid:2000001; rev:1;)

alert http any any -> any any (msg:"NGINX-SEC SQL Injection - DROP TABLE"; flow:established,to_server; content:"drop"; nocase; content:"table"; nocase; distance:0; within:50; classtype:web-application-attack; sid:2000002; rev:1;)

# XSS Detection
alert http any any -> any any (msg:"NGINX-SEC XSS Attempt - Script Tag"; flow:established,to_server; content:"<script"; nocase; classtype:web-application-attack; sid:2000003; rev:1;)

alert http any any -> any any (msg:"NGINX-SEC XSS Attempt - JavaScript URI"; flow:established,to_server; content:"javascript:"; nocase; classtype:web-application-attack; sid:2000004; rev:1;)

# Directory Traversal
alert http any any -> any any (msg:"NGINX-SEC Directory Traversal Attempt"; flow:established,to_server; content:"../"; classtype:web-application-attack; sid:2000005; rev:1;)

alert http any any -> any any (msg:"NGINX-SEC Sensitive File Access"; flow:established,to_server; content:"/etc/passwd"; classtype:web-application-attack; sid:2000006; rev:1;)

# Brute Force Detection (multiple requests to login)
alert http any any -> any any (msg:"NGINX-SEC Potential Brute Force - Login"; flow:established,to_server; content:"POST"; http_method; content:"/login"; http_uri; threshold: type both, track by_src, count 10, seconds 60; classtype:web-application-attack; sid:2000007; rev:1;)

# Suspicious User Agents
alert http any any -> any any (msg:"NGINX-SEC Malicious User Agent - SQLMap"; flow:established,to_server; content:"sqlmap"; http_user_agent; nocase; classtype:web-application-attack; sid:2000008; rev:1;)

alert http any any -> any any (msg:"NGINX-SEC Malicious User Agent - Nikto"; flow:established,to_server; content:"nikto"; http_user_agent; nocase; classtype:web-application-attack; sid:2000009; rev:1;)

# File Upload Attacks
alert http any any -> any any (msg:"NGINX-SEC Malicious File Upload - PHP"; flow:established,to_server; content:"Content-Type: application/x-php"; http_header; classtype:web-application-attack; sid:2000010; rev:1;)

# Command Injection
alert http any any -> any any (msg:"NGINX-SEC Command Injection Attempt"; flow:established,to_server; pcre:"/(\||;|`|\$\(|\$\{)/"; classtype:web-application-attack; sid:2000011; rev:1;)
```

<!-- markdownlint-enable MD013 -->

#### **3. Integration Code**

```python
# src/integrations/suricata_integration.py
import json
import socket
import threading
from typing import Dict, Any, Callable

class SuricataIntegration:
    """Integration with Suricata IDS for enhanced threat detection."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.socket_path = config.get('socket_path', '/var/run/suricata/suricata-command.socket')
        self.running = False
        self.callback = None
        
    def start_monitoring(self, alert_callback: Callable):
        """Start monitoring Suricata alerts."""
        self.callback = alert_callback
        self.running = True
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_alerts)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def _monitor_alerts(self):
        """Monitor Suricata EVE alerts."""
        try:
            # Connect to Suricata socket
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.bind(self.socket_path)
            sock.settimeout(1.0)
            
            while self.running:
                try:
                    data = sock.recv(65536)
                    alert_data = json.loads(data.decode('utf-8'))
                    
                    if alert_data.get('event_type') == 'alert':
                        self._process_suricata_alert(alert_data)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error processing Suricata alert: {e}")
                    
        except Exception as e:
            logger.error(f"Error connecting to Suricata: {e}")
    
    def _process_suricata_alert(self, alert_data: Dict[str, Any]):
        """Process Suricata alert and convert to security monitor format."""
        try:
            # Extract relevant information
            alert = alert_data.get('alert', {})
            flow = alert_data.get('flow', {})
            http = alert_data.get('http', {})
            
            # Convert to security monitor threat format
            threat = {
                'threat_type': self._map_suricata_category(alert.get('category', '')),
                'severity': self._map_suricata_severity(alert.get('severity', 3)),
                'confidence': 0.8,  # High confidence from Suricata
                'description': alert.get('signature', 'Suricata alert'),
                'source_ip': flow.get('src_ip', ''),
                'dest_ip': flow.get('dest_ip', ''),
                'source_port': flow.get('src_port', 0),
                'dest_port': flow.get('dest_port', 0),
                'protocol': flow.get('proto', ''),
                'metadata': {
                    'suricata_signature_id': alert.get('signature_id'),
                    'suricata_gid': alert.get('gid'),
                    'suricata_rev': alert.get('rev'),
                    'http_hostname': http.get('hostname', ''),
                    'http_url': http.get('url', ''),
                    'http_method': http.get('http_method', ''),
                    'http_user_agent': http.get('http_user_agent', ''),
                    'detection_source': 'suricata'
                }
            }
            
            # Send to callback if configured
            if self.callback:
                self.callback(threat)
                
        except Exception as e:
            logger.error(f"Error processing Suricata alert: {e}")
    
    def _map_suricata_category(self, category: str) -> str:
        """Map Suricata alert category to threat type."""
        mapping = {
            'web-application-attack': 'web_attack',
            'attempted-admin': 'admin_access',
            'attempted-user': 'user_access',
            'inappropriate-content': 'content_violation',
            'policy-violation': 'policy_violation',
            'trojan-activity': 'malware',
            'unsuccessful-user': 'failed_auth',
            'successful-admin': 'admin_success',
            'successful-user': 'user_success',
            'shellcode-detect': 'shellcode',
            'string-detect': 'string_match',
            'suspicious-filename-detect': 'suspicious_file',
            'suspicious-login': 'suspicious_auth',
            'system-call-detect': 'system_call',
            'tcp-connection': 'tcp_connection',
            'unusual-client-port-connection': 'unusual_connection',
            'network-scan': 'network_scan',
            'denial-of-service': 'dos_attack',
            'non-standard-protocol': 'protocol_violation',
            'protocol-command-decode': 'protocol_decode',
            'generic-protocol-command-decode': 'generic_protocol',
            'generic-icmp-event': 'icmp_event',
            'generic-ip-event': 'ip_event'
        }
        
        return mapping.get(category.lower(), 'unknown')
    
    def _map_suricata_severity(self, severity: int) -> str:
        """Map Suricata severity to security monitor severity."""
        if severity == 1:
            return 'critical'
        elif severity == 2:
            return 'high'
        elif severity == 3:
            return 'medium'
        else:
            return 'low'
    
    def send_command(self, command: str) -> Dict[str, Any]:
        """Send command to Suricata via unix socket."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect('/var/run/suricata/suricata-command.socket')
            
            # Send command
            sock.send(json.dumps({"command": command}).encode())
            
            # Receive response
            response = sock.recv(4096)
            sock.close()
            
            return json.loads(response.decode())
            
        except Exception as e:
            logger.error(f"Error sending Suricata command: {e}")
            return {"return": "NOK", "message": str(e)}
```

#### **4. Configuration Integration**

```yaml
# config/settings.yaml
integrations:
  suricata:
    enabled: true
    
    # Socket configuration
    socket_path: "/var/run/suricata/suricata-command.socket"
    eve_socket_path: "/var/run/suricata/suricata-eve.socket"
    
    # Alert processing
    process_alerts: true
    alert_threshold: "medium"
    
    # Rule management
    custom_rules_file: "/etc/suricata/rules/nginx-security-monitor.rules"
    auto_update_rules: true
    
    # Performance settings
    buffer_size: 65536
    timeout: 1.0
    
    # Correlation settings
    correlate_with_nginx_logs: true
    correlation_window: 300  # 5 minutes
```

______________________________________________________________________

## ☁️ **Cloud Platform Integrations**

### **AWS Security Hub Integration**

#### **1. AWS Security Hub Configuration**

```python
# src/integrations/aws_security_hub.py
import boto3
import json
from datetime import datetime
from typing import Dict, Any, List

class AWSSecurityHubIntegration:
    """Integration with AWS Security Hub for cloud-native security."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.region = config.get('region', 'us-east-1')
        self.account_id = config.get('account_id')
        self.product_arn = f"arn:aws:securityhub:{self.region}:{self.account_id}:product/{self.account_id}/nginx-security-monitor"
        
        # Initialize Security Hub client
        self.security_hub = boto3.client('securityhub', region_name=self.region)
        
    def send_finding(self, threat: Dict[str, Any]) -> bool:
        """Send threat as Security Hub finding."""
        try:
            finding = self._convert_threat_to_finding(threat)
            
            response = self.security_hub.batch_import_findings(
                Findings=[finding]
            )
            
            failed_count = response.get('FailedCount', 0)
            return failed_count == 0
            
        except Exception as e:
            logger.error(f"Failed to send finding to Security Hub: {e}")
            return False
    
    def _convert_threat_to_finding(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Convert threat to Security Hub finding format."""
        finding_id = f"nginx-security-{threat.get('source_ip', 'unknown')}-{int(datetime.now().timestamp())}"
        
        # Map severity
        severity_mapping = {
            'low': {'Label': 'LOW', 'Normalized': 25},
            'medium': {'Label': 'MEDIUM', 'Normalized': 50},
            'high': {'Label': 'HIGH', 'Normalized': 75},
            'critical': {'Label': 'CRITICAL', 'Normalized': 100}
        }
        
        severity = severity_mapping.get(threat.get('severity', 'medium'), {'Label': 'MEDIUM', 'Normalized': 50})
        
        finding = {
            'SchemaVersion': '2018-10-08',
            'Id': finding_id,
            'ProductArn': self.product_arn,
            'GeneratorId': 'nginx-security-monitor',
            'AwsAccountId': self.account_id,
            'Types': [self._get_finding_type(threat.get('threat_type', 'unknown'))],
            'FirstObservedAt': datetime.now().isoformat(),
            'LastObservedAt': datetime.now().isoformat(),
            'CreatedAt': datetime.now().isoformat(),
            'UpdatedAt': datetime.now().isoformat(),
            'Severity': severity,
            'Confidence': int(threat.get('confidence', 0.5) * 100),
            'Title': f"NGINX Security Threat: {threat.get('threat_type', 'Unknown')}",
            'Description': threat.get('description', 'Threat detected by NGINX Security Monitor'),
            'SourceUrl': f"https://console.aws.amazon.com/securityhub/home?region={self.region}#/findings",
            'Resources': [
                {
                    'Type': 'AwsEc2Instance',
                    'Id': f"arn:aws:ec2:{self.region}:{self.account_id}:instance/{self._get_instance_id()}",
                    'Region': self.region,
                    'Details': {
                        'AwsEc2Instance': {
                            'Type': 'web-server',
                            'ImageId': self._get_ami_id(),
                            'VpcId': self._get_vpc_id(),
                            'SubnetId': self._get_subnet_id()
                        }
                    }
                }
            ],
            'Network': {
                'Direction': 'IN',
                'Protocol': 'HTTP',
                'SourceIpV4': threat.get('source_ip', ''),
                'DestinationPort': 80
            },
            'RecordState': 'ACTIVE',
            'WorkflowState': 'NEW',
            'UserDefinedFields': {
                'ThreatType': threat.get('threat_type', 'unknown'),
                'DetectionConfidence': str(threat.get('confidence', 0.5)),
                'MitigationApplied': str(threat.get('mitigation_applied', False)),
                'NginxSecurityVersion': self._get_version()
            }
        }
        
        return finding
    
    def _get_finding_type(self, threat_type: str) -> str:
        """Map threat type to Security Hub finding type."""
        type_mapping = {
            'sql_injection': 'TTPs/Command and Control/SQL Injection',
            'xss': 'TTPs/Command and Control/Cross-Site Scripting',
            'brute_force': 'TTPs/Credential Access/Brute Force',
            'directory_traversal': 'TTPs/Discovery/System Information Discovery',
            'malicious_user_agent': 'TTPs/Defense Evasion/Masquerading',
            'dos_attack': 'TTPs/Impact/Network Denial of Service'
        }
        
        return type_mapping.get(threat_type, 'TTPs/Impact/Network Denial of Service')

    def create_custom_insight(self) -> bool:
        """Create custom Security Hub insight for NGINX threats."""
        try:
            insight = {
                'Name': 'NGINX Security Monitor Threats',
                'Filters': {
                    'ProductArn': [{'Value': self.product_arn, 'Comparison': 'EQUALS'}],
                    'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}]
                },
                'GroupByAttribute': 'Types'
            }
            
            response = self.security_hub.create_insight(**insight)
            return 'InsightArn' in response
            
        except Exception as e:
            logger.error(f"Failed to create Security Hub insight: {e}")
            return False
```

#### **2. Security Hub Configuration**

```yaml
# config/settings.yaml
integrations:
  aws_security_hub:
    enabled: true
    
    # AWS Configuration
    region: "us-east-1"
    account_id: "123456789012"
    
    # Finding configuration
    send_findings: true
    finding_threshold: "medium"
    batch_size: 100
    
    # Resource tagging
    resource_tags:
      Environment: "production"
      Application: "nginx-security-monitor"
      Owner: "security-team"
    
    # Custom insights
    create_insights: true
    insight_names:
      - "Top Threat Types"
      - "Most Targeted Resources"
      - "Geographic Distribution"
```

### **Azure Sentinel Integration**

#### **1. Azure Sentinel Configuration**

```python
# src/integrations/azure_sentinel.py
import requests
import json
import hashlib
import hmac
import base64
from datetime import datetime
from typing import Dict, Any, List

class AzureSentinelIntegration:
    """Integration with Azure Sentinel SIEM."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.workspace_id = config.get('workspace_id')
        self.shared_key = config.get('shared_key')
        self.log_type = config.get('log_type', 'NginxSecurityMonitor')
        
    def send_logs(self, threats: List[Dict[str, Any]]) -> bool:
        """Send threat logs to Azure Sentinel."""
        try:
            # Convert threats to JSON
            json_data = json.dumps(threats)
            
            # Build signature
            date_string = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            string_to_hash = f"POST\n{len(json_data)}\napplication/json\nx-ms-date:{date_string}\n/api/logs"
            bytes_to_hash = bytes(string_to_hash, 'utf-8')
            decoded_key = base64.b64decode(self.shared_key)
            encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
            authorization = f"SharedKey {self.workspace_id}:{encoded_hash}"
            
            # Build headers
            headers = {
                'content-type': 'application/json',
                'Authorization': authorization,
                'Log-Type': self.log_type,
                'x-ms-date': date_string
            }
            
            # Send to Azure Sentinel
            uri = f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            response = requests.post(uri, data=json_data, headers=headers)
            
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Failed to send logs to Azure Sentinel: {e}")
            return False
    
    def create_analytics_rule(self, rule_config: Dict[str, Any]) -> bool:
        """Create analytics rule in Azure Sentinel."""
        try:
            # This would use Azure REST API to create analytics rules
            # Implementation depends on Azure AD authentication
            pass
        except Exception as e:
            logger.error(f"Failed to create analytics rule: {e}")
            return False
```

______________________________________________________________________

## 📊 **SIEM Platform Integrations**

### **Splunk Integration**

#### **1. Splunk Universal Forwarder Setup**

```bash
# Install Splunk Universal Forwarder
wget -O splunkforwarder-8.2.0-e77ba4b7c37f-linux-2.6-amd64.deb \
'https://www.splunk.com/bin/splunk/DownloadActivityServlet?...'

sudo dpkg -i splunkforwarder-8.2.0-e77ba4b7c37f-linux-2.6-amd64.deb
```

#### **2. Splunk Configuration**

```ini
# /opt/splunkforwarder/etc/system/local/inputs.conf
[monitor:///var/log/nginx-security/threats.log]
disabled = false
sourcetype = nginx_security_threats
index = security

[monitor:///var/log/nginx-security/mitigation.log]
disabled = false
sourcetype = nginx_security_mitigation
index = security

[monitor:///var/log/nginx/access.log]
disabled = false
sourcetype = nginx_access
index = web

# HTTP Event Collector input
[http://nginx_security_hec]
token = your-hec-token-here
index = security
sourcetype = nginx_security_json
```

#### **3. Splunk Props Configuration**

```ini
# /opt/splunk/etc/system/local/props.conf
[nginx_security_threats]
KV_MODE = json
SHOULD_LINEMERGE = false
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S
TRUNCATE = 10000
category = Security

[nginx_security_mitigation]
EXTRACT-action = Mitigation action: (?<mitigation_action>.+)
EXTRACT-ip = IP (?<blocked_ip>\d+\.\d+\.\d+\.\d+)
EXTRACT-duration = duration (?<block_duration>\d+)
TIME_FORMAT = %Y-%m-%d %H:%M:%S
category = Security

[nginx_access]
REPORT-nginx_access = nginx_access_extractions
TIME_FORMAT = %d/%b/%Y:%H:%M:%S %z
```

#### **4. Splunk Searches and Dashboards**

```spl
# Saved Search: Top Threat Types (Last 24 Hours)
index=security sourcetype=nginx_security_threats
| stats count by threat_type
| sort -count
| head 10

# Saved Search: Geographic Distribution of Threats
index=security sourcetype=nginx_security_threats
| iplocation source_ip
| geostats count by Country

# Alert: Critical Threats
index=security sourcetype=nginx_security_threats severity=critical
| eval alert_time=_time
| table alert_time, threat_type, source_ip, description
| sort -alert_time

# Dashboard Query: Threat Timeline
index=security sourcetype=nginx_security_threats
| timechart span=1h count by threat_type
```

#### **5. Splunk Integration Code**

```python
# src/integrations/splunk_integration.py
import requests
import json
from typing import Dict, Any, List

class SplunkIntegration:
    """Integration with Splunk for centralized logging and analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.hec_url = config.get('hec_url')
        self.hec_token = config.get('hec_token')
        self.index = config.get('index', 'security')
        self.sourcetype = config.get('sourcetype', 'nginx_security_json')
        
    def send_event(self, threat: Dict[str, Any]) -> bool:
        """Send threat event to Splunk via HEC."""
        try:
            # Format event for Splunk
            event = {
                "time": int(datetime.now().timestamp()),
                "index": self.index,
                "sourcetype": self.sourcetype,
                "source": "nginx-security-monitor",
                "event": threat
            }
            
            headers = {
                'Authorization': f'Splunk {self.hec_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.hec_url}/services/collector/event",
                headers=headers,
                data=json.dumps(event),
                verify=False  # Set to True in production with proper certs
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Failed to send event to Splunk: {e}")
            return False
    
    def send_batch_events(self, threats: List[Dict[str, Any]]) -> bool:
        """Send multiple threat events to Splunk."""
        try:
            events = []
            for threat in threats:
                events.append({
                    "time": int(datetime.now().timestamp()),
                    "index": self.index,
                    "sourcetype": self.sourcetype,
                    "source": "nginx-security-monitor",
                    "event": threat
                })
            
            headers = {
                'Authorization': f'Splunk {self.hec_token}',
                'Content-Type': 'application/json'
            }
            
            # Send as batch
            batch_data = '\n'.join([json.dumps(event) for event in events])
            
            response = requests.post(
                f"{self.hec_url}/services/collector/event",
                headers=headers,
                data=batch_data,
                verify=False
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Failed to send batch events to Splunk: {e}")
            return False
```

______________________________________________________________________

## 🔗 **API Integration Examples**

### **Generic REST API Integration**

```python
# src/integrations/generic_api.py
import requests
import json
from typing import Dict, Any, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class GenericAPIIntegration:
    """Generic REST API integration for custom endpoints."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_url = config.get('base_url')
        self.api_key = config.get('api_key')
        self.timeout = config.get('timeout', 30)
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Default headers
        self.headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'NGINX-Security-Monitor/2.0'
        }
        
        if self.api_key:
            auth_header = config.get('auth_header', 'Authorization')
            auth_prefix = config.get('auth_prefix', 'Bearer')
            self.headers[auth_header] = f"{auth_prefix} {self.api_key}"
    
    def send_threat_data(self, threat: Dict[str, Any]) -> bool:
        """Send threat data to external API."""
        try:
            endpoint = self.config.get('threat_endpoint', '/api/threats')
            url = f"{self.base_url}{endpoint}"
            
            # Transform threat data if mapping is configured
            if 'field_mapping' in self.config:
                threat = self._map_fields(threat, self.config['field_mapping'])
            
            response = self.session.post(
                url,
                headers=self.headers,
                data=json.dumps(threat),
                timeout=self.timeout
            )
            
            response.raise_for_status()
            return True
            
        except Exception as e:
            logger.error(f"Failed to send threat data to API: {e}")
            return False
    
    def get_threat_intelligence(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get threat intelligence for IP address."""
        try:
            endpoint = self.config.get('intel_endpoint', '/api/intel/ip')
            url = f"{self.base_url}{endpoint}/{ip}"
            
            response = self.session.get(
                url,
                headers=self.headers,
                timeout=self.timeout
            )
            
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            logger.error(f"Failed to get threat intelligence: {e}")
            return None
    
    def _map_fields(self, data: Dict[str, Any], mapping: Dict[str, str]) -> Dict[str, Any]:
        """Map fields according to configuration."""
        mapped_data = {}
        
        for source_field, target_field in mapping.items():
            if source_field in data:
                mapped_data[target_field] = data[source_field]
        
        return mapped_data
```

______________________________________________________________________

## 🔗 **Related Documentation**

- [Configuration Guide](CONFIGURATION.md) - Integration configuration options
- [Alert Systems](ALERT_SYSTEMS.md) - Alert channel integrations
- [Mitigation Strategies](MITIGATION_STRATEGIES.md) - Mitigation tool integrations
- [Plugin Development](PLUGIN_DEVELOPMENT.md) - Creating custom integrations
- [API Reference](API_REFERENCE.md) - Integration APIs and interfaces

______________________________________________________________________

*This integration cookbook is part of the NGINX Security Monitor documentation. For updates and contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).*
