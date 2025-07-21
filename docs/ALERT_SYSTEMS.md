# 🚨 Alert Systems Guide - NGINX Security Monitor

## 🎯 **Overview**

The NGINX Security Monitor includes a comprehensive alert system that can notify you of security threats through multiple channels. This guide covers setting up, configuring, and customizing the alert system to meet your specific needs.

## 📧 **Supported Alert Channels**

| Channel     | Description                   | Use Case                                |
| ----------- | ----------------------------- | --------------------------------------- |
| **Email**   | SMTP-based email alerts       | General notifications, detailed reports |
| **SMS**     | Text message alerts           | Critical threats, immediate attention   |
| **Webhook** | HTTP POST to custom endpoints | Integration with external systems       |
| **Slack**   | Slack workspace notifications | Team collaboration                      |
| **Discord** | Discord channel notifications | Community monitoring                    |
| **Custom**  | Plugin-based custom channels  | Specialized integrations                |

______________________________________________________________________

## 🔧 **Email Alert Setup**

### **Basic Email Configuration**

Add email configuration to your `settings.yaml`:

```yaml
alerts:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    username: "your-email@gmail.com"
    password: "your-app-password"  # Use app password for Gmail
    from_address: "security-monitor@yourdomain.com"
    to_addresses:
      - "admin@yourdomain.com"
      - "security-team@yourdomain.com"
    
    # Alert filtering
    min_severity: "medium"  # Only send medium, high, critical alerts
    max_alerts_per_hour: 10  # Rate limiting
    
    # Email template settings
    subject_template: "[SECURITY] {threat_type} detected from {source_ip}"
    include_logs: true  # Include relevant log entries in email
    include_mitigation: true  # Include mitigation actions taken
```

### **Gmail Configuration**

For Gmail accounts, you'll need to:

1. **Enable 2-Factor Authentication**
1. **Generate App Password**:
   - Go to Google Account settings
   - Security → 2-Step Verification
   - App passwords → Generate password
   - Use this password in the configuration

```yaml
alerts:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    username: "your-email@gmail.com"
    password: "your-16-char-app-password"
    from_address: "your-email@gmail.com"
    to_addresses: ["admin@yourdomain.com"]
```

### **Microsoft Outlook/Office 365**

```yaml
alerts:
  email:
    enabled: true
    smtp_server: "smtp-mail.outlook.com"
    smtp_port: 587
    use_tls: true
    username: "your-email@outlook.com"
    password: "your-password"
    from_address: "your-email@outlook.com"
    to_addresses: ["admin@yourdomain.com"]
```

### **Custom SMTP Server**

```yaml
alerts:
  email:
    enabled: true
    smtp_server: "mail.yourdomain.com"
    smtp_port: 25
    use_tls: false
    use_ssl: false
    username: "security@yourdomain.com"
    password: "secure-password"
    from_address: "security-monitor@yourdomain.com"
    to_addresses: ["admin@yourdomain.com"]
```

______________________________________________________________________

## 📱 **SMS Alert Setup**

### **Twilio Integration**

```yaml
alerts:
  sms:
    enabled: true
    provider: "twilio"
    config:
      account_sid: "your-twilio-account-sid"
      auth_token: "your-twilio-auth-token"
      from_number: "+1234567890"  # Your Twilio phone number
      to_numbers:
        - "+1987654321"  # Admin phone number
        - "+1555123456"  # Security team number
    
    # SMS-specific settings
    min_severity: "high"  # Only high and critical alerts via SMS
    max_sms_per_hour: 5   # Strict rate limiting for SMS
    message_template: "SECURITY ALERT: {threat_type} from {source_ip}. Check email for details."
```

### **AWS SNS Integration**

```yaml
alerts:
  sms:
    enabled: true
    provider: "aws_sns"
    config:
      aws_access_key_id: "your-access-key"
      aws_secret_access_key: "your-secret-key"
      aws_region: "us-east-1"
      topic_arn: "arn:aws:sns:us-east-1:123456789012:security-alerts"
    
    min_severity: "high"
    max_sms_per_hour: 3
```

### **Setup Instructions for Twilio**

1. **Create Twilio Account**:

   - Sign up at [twilio.com](https://twilio.com)
   - Verify your phone number
   - Purchase a phone number

1. **Get Credentials**:

   - Account SID from Twilio Console
   - Auth Token from Twilio Console
   - Phone number you purchased

1. **Install Dependencies**:

   ```bash
   pip install twilio
   ```

1. **Test Configuration**:

   ```bash
   python -c "
   from src.alerts.sms_alert import SmsAlert
   sms = SmsAlert({'provider': 'twilio', 'config': {...}})
   sms.send_test_message()
   "
   ```

______________________________________________________________________

## 🪝 **Webhook Integration**

### **Basic Webhook Setup**

```yaml
alerts:
  webhook:
    enabled: true
    endpoints:
      - name: "security-system"
        url: "https://your-security-system.com/api/alerts"
        method: "POST"
        headers:
          Authorization: "Bearer your-api-token"
          Content-Type: "application/json"
        timeout: 30
        retry_count: 3
        
      - name: "backup-endpoint"
        url: "https://backup-system.com/alerts"
        method: "POST"
        headers:
          X-API-Key: "your-api-key"
        
    # Webhook payload template
    payload_template: |
      {
        "alert_id": "{alert_id}",
        "timestamp": "{timestamp}",
        "threat_type": "{threat_type}",
        "severity": "{severity}",
        "source_ip": "{source_ip}",
        "description": "{description}",
        "mitigation_taken": "{mitigation_taken}",
        "log_entries": {log_entries}
      }
```

### **Slack Integration**

```yaml
alerts:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    channel: "#security-alerts"
    username: "Security Monitor"
    icon_emoji: ":shield:"
    
    # Message formatting
    message_template: |
      :warning: *Security Alert*
      *Threat Type:* {threat_type}
      *Severity:* {severity}
      *Source IP:* {source_ip}
      *Time:* {timestamp}
      *Description:* {description}
      
      *Mitigation:* {mitigation_taken}
    
    min_severity: "medium"
```

### **Discord Integration**

```yaml
alerts:
  discord:
    enabled: true
    webhook_url: "https://discord.com/api/webhooks/YOUR/DISCORD/WEBHOOK"
    username: "Security Monitor"
    avatar_url: "https://your-domain.com/security-icon.png"
    
    # Discord embed formatting
    embed_template:
      title: "Security Alert: {threat_type}"
      description: "{description}"
      color: 15158332  # Red color for alerts
      fields:
        - name: "Source IP"
          value: "{source_ip}"
          inline: true
        - name: "Severity"
          value: "{severity}"
          inline: true
        - name: "Mitigation"
          value: "{mitigation_taken}"
          inline: false
```

______________________________________________________________________

## 🎨 **Alert Customization**

### **Alert Templates**

Create custom alert templates in `config/alert_templates.yaml`:

```yaml
templates:
  brute_force:
    email:
      subject: "BRUTE FORCE ATTACK: {failed_attempts} attempts from {source_ip}"
      body: |
        A brute force attack has been detected:
        
        Source IP: {source_ip}
        Failed Attempts: {failed_attempts}
        Target URLs: {target_urls}
        Time Range: {start_time} - {end_time}
        
        Mitigation Actions Taken:
        {mitigation_actions}
        
        Recent Log Entries:
        {log_entries}
    
    slack:
      message: |
        :rotating_light: *BRUTE FORCE ATTACK DETECTED*
        
        *Source:* {source_ip}
        *Attempts:* {failed_attempts}
        *Status:* {mitigation_status}
        
        <@channel> Security team please investigate.
  
  sql_injection:
    email:
      subject: "SQL INJECTION ATTEMPT from {source_ip}"
      body: |
        Potential SQL injection attack detected:
        
        Source IP: {source_ip}
        Target URL: {target_url}
        Injection Pattern: {injection_pattern}
        User Agent: {user_agent}
        
        Request Details:
        {request_details}
        
        Immediate Action: {mitigation_taken}
    
    sms:
      message: "SQL INJECTION from {source_ip} targeting {target_url}. Blocked: {blocked_status}"
```

### **Alert Severity Levels**

Configure different behaviors for each severity level:

```yaml
alert_behavior:
  critical:
    channels: ["email", "sms", "slack"]
    immediate: true
    escalation_delay: 300  # 5 minutes
    max_frequency: "1/hour"
    
  high:
    channels: ["email", "slack"]
    immediate: true
    max_frequency: "3/hour"
    
  medium:
    channels: ["email"]
    immediate: false
    batch_interval: 900  # 15 minutes
    max_frequency: "5/hour"
    
  low:
    channels: ["email"]
    immediate: false
    batch_interval: 3600  # 1 hour
    max_frequency: "2/hour"
```

______________________________________________________________________

## 🔄 **Alert Deduplication**

Prevent alert spam with smart deduplication:

```yaml
deduplication:
  enabled: true
  
  # Group similar alerts
  grouping_rules:
    - name: "same_ip_brute_force"
      condition: "threat_type == 'brute_force' and source_ip == previous.source_ip"
      window: 3600  # 1 hour
      action: "merge"
      
    - name: "sql_injection_pattern"
      condition: "threat_type == 'sql_injection' and pattern == previous.pattern"
      window: 1800  # 30 minutes
      action: "suppress"
  
  # Merge similar alerts into summary
  merge_template: |
    Multiple {threat_type} attempts detected:
    
    Total Events: {event_count}
    Time Range: {first_seen} - {last_seen}
    Source IPs: {unique_ips}
    
    Summary of Actions:
    {summary_actions}
```

______________________________________________________________________

## 📊 **Alert Testing**

### **Test Alert Delivery**

Use the built-in test commands:

```bash
# Test email alerts
python -m src.alerts.email_alert test --config config/settings.yaml

# Test SMS alerts
python -m src.alerts.sms_alert test --config config/settings.yaml

# Test all alert channels
python -m src.alert_manager test_all --config config/settings.yaml
```

### **Test Configuration Script**

Create a test script (`test_alerts.py`):

```python
#!/usr/bin/env python3
"""Test alert system configuration."""

from src.alert_manager import AlertManager
import yaml

def test_alerts():
    """Test all configured alert channels."""
    
    # Load configuration
    with open('config/settings.yaml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Initialize alert manager
    alert_mgr = AlertManager(config['alerts'])
    
    # Test alert
    test_alert = {
        'title': 'Test Alert - System Check',
        'message': 'This is a test alert to verify alert system configuration.',
        'severity': 'low',
        'threat_type': 'test',
        'source_ip': '127.0.0.1',
        'timestamp': datetime.now().isoformat()
    }
    
    # Send test alert
    try:
        result = alert_mgr.send_alert(test_alert)
        print(f"Test alert sent: {result}")
    except Exception as e:
        print(f"Alert test failed: {e}")

if __name__ == "__main__":
    test_alerts()
```

______________________________________________________________________

## 🔧 **Troubleshooting**

### **Common Email Issues**

#### **Authentication Errors**

```bash
# Check SMTP server connectivity
telnet smtp.gmail.com 587

# Test authentication
python -c "
import smtplib
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('your-email@gmail.com', 'your-app-password')
print('Authentication successful')
server.quit()
"
```

#### **Gmail App Password Issues**

1. Ensure 2FA is enabled
1. Generate new app password
1. Use app password, not regular password
1. Check for typos in configuration

#### **Corporate Firewall Issues**

```yaml
alerts:
  email:
    smtp_server: "internal-smtp.company.com"
    smtp_port: 25
    use_tls: false
    # May need to configure proxy settings
```

### **SMS Troubleshooting**

#### **Twilio Issues**

```python
# Test Twilio configuration
from twilio.rest import Client

client = Client("account_sid", "auth_token")
message = client.messages.create(
    body="Test message from Security Monitor",
    from_="+1234567890",
    to="+1987654321"
)
print(f"Message sent: {message.sid}")
```

#### **Rate Limiting**

Monitor your SMS usage to avoid rate limits:

```yaml
alerts:
  sms:
    rate_limiting:
      max_per_minute: 1
      max_per_hour: 10
      max_per_day: 50
    
    fallback_to_email: true  # Use email if SMS limit reached
```

### **Webhook Debugging**

#### **Test Webhook Endpoints**

```bash
# Test webhook connectivity
curl -X POST https://your-webhook-url.com/alerts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-token" \
  -d '{"test": "message"}'
```

#### **Webhook Timeout Issues**

```yaml
alerts:
  webhook:
    timeout: 30
    retry_count: 3
    retry_delay: 5
    
    # Async delivery for better performance
    async_delivery: true
```

______________________________________________________________________

## 📈 **Alert Analytics**

### **Monitor Alert Performance**

Track alert delivery metrics:

```yaml
analytics:
  enabled: true
  metrics:
    - alert_delivery_success_rate
    - alert_delivery_time
    - alert_frequency_by_type
    - channel_performance
  
  reporting:
    daily_summary: true
    weekly_report: true
    email_reports_to: ["admin@yourdomain.com"]
```

### **Alert Dashboard**

View alert statistics in the web interface:

```bash
# Start web interface
python -m src.web_interface --port 8080

# Access dashboard at http://localhost:8080/alerts
```

______________________________________________________________________

## 🔐 **Security Considerations**

### **Secure Credential Storage**

Store sensitive credentials securely:

```yaml
alerts:
  email:
    password: "${EMAIL_PASSWORD}"  # Use environment variable
    
  sms:
    config:
      auth_token: "${TWILIO_AUTH_TOKEN}"  # Use environment variable
```

Set environment variables:

```bash
export EMAIL_PASSWORD="your-secure-password"
export TWILIO_AUTH_TOKEN="your-twilio-token"
```

### **Encrypted Configuration**

Encrypt sensitive alert configuration:

```bash
# Encrypt alert configuration
python encrypt_config.py config/alert_config.yaml

# Use encrypted configuration
python -m src.monitor_service --encrypted-config config/alert_config.yaml.enc
```

______________________________________________________________________

## 🔗 **Integration Examples**

### **SIEM Integration**

Send alerts to SIEM systems:

```yaml
alerts:
  webhook:
    endpoints:
      - name: "splunk"
        url: "https://splunk.company.com:8088/services/collector"
        headers:
          Authorization: "Splunk your-hec-token"
        payload_template: |
          {
            "time": "{timestamp}",
            "source": "nginx-security-monitor",
            "sourcetype": "security_alert",
            "event": {
              "threat_type": "{threat_type}",
              "severity": "{severity}",
              "source_ip": "{source_ip}",
              "description": "{description}"
            }
          }
```

### **Ticket System Integration**

Create tickets for security incidents:

```yaml
alerts:
  webhook:
    endpoints:
      - name: "jira"
        url: "https://company.atlassian.net/rest/api/2/issue"
        headers:
          Authorization: "Basic base64-encoded-credentials"
          Content-Type: "application/json"
        payload_template: |
          {
            "fields": {
              "project": {"key": "SEC"},
              "summary": "Security Alert: {threat_type} from {source_ip}",
              "description": "{description}",
              "issuetype": {"name": "Bug"},
              "priority": {"name": "High"}
            }
          }
```

______________________________________________________________________

## 📚 **Related Documentation**

- [Configuration Guide](CONFIGURATION.md) - Alert configuration options
- [API Reference](API_REFERENCE.md) - AlertManager API documentation
- [Plugin Development](PLUGIN_DEVELOPMENT.md) - Creating custom alert channels
- [Integration Cookbook](INTEGRATION_COOKBOOK.md) - Integration examples

______________________________________________________________________

*This alert systems guide is part of the NGINX Security Monitor documentation. For updates and contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).*
