# 🚀 Quick Start Tutorial

Get NGINX Security Monitor up and running in 15 minutes with this step-by-step tutorial.

## 🎯 **What You'll Accomplish**

By the end of this tutorial, you'll have:

- ✅ NGINX Security Monitor installed and running
- ✅ Basic threat detection configured
- ✅ Email alerts set up
- ✅ Your first security event detected
- ✅ Understanding of next steps for customization

## ⏱️ **Time Required**: ~15 minutes

## 📋 **Prerequisites**

Before starting, ensure you have:

- A system with NGINX running and generating logs
- Python 3.8 or higher installed
- Access to NGINX log files (usually in `/var/log/nginx/`)
- An email account for receiving alerts

## 🚀 **Step 1: Quick Installation (3 minutes)**

### **Clone and Setup**

```bash
# Clone the repository
git clone https://github.com/AccessiTech/nginx-security-monitor.git
cd nginx-security-monitor

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# Windows users: .venv\Scripts\activate
```

### **Install Dependencies**

```bash
# Install everything you need
pip install -r requirements.txt
```

**Expected output:**

```text
Successfully installed cryptography-45.0.5 psutil-7.0.0 pyyaml-6.0.2 pytest-8.4.1 ...
```

## ⚙️ **Step 2: Basic Configuration (5 minutes)**

### **Configure Email Alerts**

```bash
# Copy the example configuration
cp config/settings.yaml config/my-settings.yaml

# Edit the configuration file
nano config/my-settings.yaml  # or use your preferred editor
```

**Update these essential settings:**

```yaml
# Edit these lines in config/my-settings.yaml
email_service:
  smtp_server: "smtp.gmail.com"          # Change to your SMTP server
  smtp_port: 587
  username: "your-email@gmail.com"       # Your email
  password: "<REPLACE_WITH_ENV_VARIABLE>"          # Your email password/app password
  api_key: "<REPLACE_WITH_ENV_VARIABLE>"
  from_address: "your-email@gmail.com"   # Your email
  to_address: "your-email@gmail.com"     # Where to send alerts

# Log file paths (update if different)
log_file_path: "/var/log/nginx/access.log"
error_log_file_path: "/var/log/nginx/error.log"
```

#### Alternative: Use service-settings.yaml for advanced features

```bash
# For more advanced configuration, copy the service template
cp config/service-settings.yaml config/my-service-settings.yaml
# Edit as needed for advanced features like security integrations
```

> **💡 Configuration Files Explained**: We provide two configuration templates:
>
> - **`settings.yaml`** - Development template with all options and example values
> - **`service-settings.yaml`** - Production-ready with environment variables and security features
>
> For this tutorial, we use `settings.yaml` for simplicity. For production deployment, use `service-settings.yaml`.
> See the [Configuration File Structure guide](CONFIGURATION.md) for detailed differences.

### **Test Configuration**

```bash
# Test if your configuration is valid
python3 -c "
import yaml
with open('config/my-settings.yaml') as f:
    config = yaml.safe_load(f)
print('✅ Configuration is valid!')
"
```

## **Environment Variables Setup**

### **Step 3: Create and Configure .env File**

```bash
# Create a .env file in the application directory
cp config/.env.example .env

# Edit the .env file
nano .env  # or use your preferred editor
```

**Example .env File:**

```env
# Application Secrets
SECRET_KEY=your_secret_key
DATABASE_URL=your_database_url

# Email Service Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-email-password
EMAIL_API_KEY=your-email-api-key

# Log File Paths
LOG_FILE_PATH=/var/log/nginx/access.log
ERROR_LOG_FILE_PATH=/var/log/nginx/error.log
```

### **Usage**

The application automatically loads environment variables from the `.env` file.
Ensure that sensitive information such as API keys, database URLs, and other credentials
are stored securely in this file. Avoid committing the `.env` file to version control
by adding it to `.gitignore`.

## 🔍 **Step 3: Test Basic Detection (2 minutes)**

### **Generate Some Test Traffic**

<!-- markdownlint-disable MD013 -->

```bash
# Create a test log file to verify detection works
echo '127.0.0.1 - - [19/Jul/2025:10:30:45 +0000] "GET /test?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 1234 "-" "TestBot/1.0"' > test_access.log

# Test the pattern detector directly
python3 -c "
from src.pattern_detector import PatternDetector
from src.log_parser import parse_logs

detector = PatternDetector()
logs = parse_logs('test_access.log')
threats = detector.detect_patterns(logs)
print(f'✅ Detected {len(threats)} potential threats!')
for threat in threats:
    print(f'  - {threat.get(\"type\", \"Unknown\")} threat detected')
"
```

<!-- markdownlint-enable MD013 -->

**Expected Output:**

```text
✅ Detected 1 potential threats!
  - sql_injection threat detected
```

## 🚨 **Step 4: Run Your First Detection (3 minutes)**

### **Start the Monitor**

```bash
# Run the monitor with your configuration
python3 -m src.monitor_service config/my-settings.yaml
```

**Expected output:**

```text
🚀 NGINX Security Monitor Starting...
📊 Loading configuration from config/my-settings.yaml
🔍 Pattern detection enabled
📧 Email alerts configured
✅ Monitor ready - watching /var/log/nginx/access.log
```

### **Generate a Test Alert**

Open another terminal and create a suspicious request:

<!-- markdownlint-disable MD013 -->

```bash
# If you have NGINX running locally, create a malicious request
curl "http://localhost/test?id=1' OR '1'='1" 2>/dev/null || echo "SQL injection test sent"

# Or add directly to your NGINX access log (if you have write permission)
echo '127.0.0.1 - - [19/Jul/2025:10:30:45 +0000] "GET /test?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 1234 "-" "curl/7.68.0"' | sudo tee -a /var/log/nginx/access.log
```

<!-- markdownlint-enable MD013 -->

### **Check for Alert**

You should see output like:

```text
🚨 THREAT DETECTED: SQL Injection attempt from 127.0.0.1
📧 Alert sent to your-email@gmail.com
```

## ✅ **Step 5: Verify Everything Works (2 minutes)**

### **Check Alert Reception**

- Check your email for a security alert
- Subject should be: `NGINX Security Alert: sql_injection`

### **View Detection Logs**

```bash
# Check the monitor logs (if logging to file is configured)
tail -f /var/log/nginx-security-monitor.log
```

### **Test Different Attack Types**

<!-- markdownlint-disable MD013 -->

```bash
# Test XSS detection
echo '127.0.0.1 - - [19/Jul/2025:10:31:00 +0000] "GET /test?msg=%3Cscript%3Ealert(%27xss%27)%3C/script%3E HTTP/1.1" 200 1234 "-" "curl/7.68.0"' | sudo tee -a /var/log/nginx/access.log

# Test suspicious user agent
echo '127.0.0.1 - - [19/Jul/2025:10:31:15 +0000] "GET / HTTP/1.1" 200 1234 "-" "sqlmap/1.0"' | sudo tee -a /var/log/nginx/access.log
```

<!-- markdownlint-enable MD013 -->

## 🎉 **Congratulations! You're Now Monitoring**

You now have NGINX Security Monitor:

- ✅ Detecting SQL injection attempts
- ✅ Identifying XSS attacks
- ✅ Spotting suspicious user agents
- ✅ Sending email alerts for threats
- ✅ Logging all security events

## 🔧 **Next Steps: Customize Your Setup**

### **1. Add More Detection Patterns**

```bash
# Edit patterns configuration
nano config/patterns.json

# Add custom patterns for your application
{
  "attack_patterns": {
    "wordpress_attacks": {
      "description": "WordPress-specific attacks",
      "regex": "(/wp-admin/|/wp-login\\.php|/xmlrpc\\.php)",
      "severity": "medium"
    }
  }
}
```

### **2. Set Up SMS Alerts** (Optional)

```yaml
# Add to config/my-settings.yaml
sms_service:
  enabled: true
  provider: "twilio"
  api_key: "your-twilio-auth-token"
  from_number: "+1234567890"
  to_number: "+1987654321"
```

### **3. Enable Production Deployment**

```bash
# For production use, install as system service
sudo ./install.sh

# Enable and start the service
sudo systemctl enable nginx-security-monitor
sudo systemctl start nginx-security-monitor

# Check service status
sudo systemctl status nginx-security-monitor
```

## 🔍 **Common First-Run Issues**

### **Issue: Can't read NGINX logs**

```bash
# Fix permissions - make sure you can read the log files
sudo chmod 644 /var/log/nginx/access.log
# Or run the monitor with appropriate permissions
sudo python3 -m src.monitor_service config/my-settings.yaml
```

### **Issue: Email alerts not working**

```bash
# Test email configuration
python3 -c "
import yaml
from src.alerts.email_alert import send_email_alert

with open('config/my-settings.yaml') as f:
    config = yaml.safe_load(f)

test_alert = {
    'subject': 'Test Alert',
    'body': 'This is a test email from NGINX Security Monitor',
    'pattern': {'type': 'test', 'severity': 'info'}
}

try:
    send_email_alert(test_alert)
    print('✅ Test email sent successfully')
except Exception as e:
    print(f'❌ Email test failed: {e}')
"
```

### **Issue: No threats detected**

```bash
# Verify pattern detection is working
python3 -c "
from src.pattern_detector import PatternDetector

detector = PatternDetector()
test_log = {
    'ip_address': '127.0.0.1',
    'request': \"GET /test?id=1' OR '1'='1 HTTP/1.1\",
    'status_code': '200'
}

threats = detector.detect_patterns([test_log])
print(f'Pattern detection test: {len(threats)} threats found')
"
```

### **Issue: Configuration errors**

```bash
# Validate your configuration
python3 -c "
import yaml
try:
    with open('config/my-settings.yaml') as f:
        config = yaml.safe_load(f)
    print('✅ Configuration is valid')
    
    # Check required fields
    required_fields = ['email_service', 'log_file_path']
    for field in required_fields:
        if field not in config:
            print(f'⚠️  Missing required field: {field}')
        else:
            print(f'✅ Found required field: {field}')
            
except Exception as e:
    print(f'❌ Configuration error: {e}')
"
```

## 📊 **Understanding Your First Alert**

When you receive your first email alert, it will contain:

**Subject**: `NGINX Security Alert: sql_injection`

**Body**:

```text
🚨 Security Threat Detected

Attack Type: sql_injection
Severity: HIGH
Source IP: 127.0.0.1
Timestamp: 2025-07-19 10:30:45
Request: GET /test?id=1' OR '1'='1 HTTP/1.1

Pattern Matched: (' OR 1=1;|--|\\bSELECT\\b|\\bINSERT\\b|\\bUPDATE\\b|\\bDELETE\\b)

Mitigation Applied: Default threat mitigation

Recommended Actions:
1. Review the source IP for suspicious activity
2. Consider blocking the IP if attacks continue
3. Check application logs for related activities
4. Review firewall rules and access controls
```

## 🚀 **You're Ready to Explore**

Now that you have the basics working, explore these advanced features:

- **[Pattern Detection Guide](PATTERN_DETECTION.md)** - Customize detection rules
- **[Alert Systems Guide](ALERT_SYSTEMS.md)** - Advanced notification setup
- **[Security Integrations](SECURITY_INTEGRATIONS.md)** - Connect with fail2ban, OSSEC, etc.
- **[Plugin Development](PLUGIN_DEVELOPMENT.md)** - Create custom detection plugins

## 🆘 **Need Help?**

- **Documentation**: Check the specific guides in this repository
- **Issues**: Report problems on [GitHub Issues](https://github.com/AccessiTech/nginx-security-monitor/issues)
- **Troubleshooting**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## 📈 **What's Next?**

1. **Run for 24 hours** and observe the alerts you receive
1. **Tune the detection thresholds** based on your traffic patterns
1. **Add custom patterns** for your specific application
1. **Set up integrations** with your existing security tools
1. **Consider production deployment** with the full installation
