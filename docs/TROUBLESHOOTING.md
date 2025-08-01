# 🔧 Troubleshooting Guide - NGINX Security Monitor

## 🎯 **Overview**

This comprehensive troubleshooting guide helps you diagnose and resolve common issues with the NGINX Security Monitor.
It includes step-by-step diagnostic procedures, solutions for typical problems,
and guidance for when to escalate issues.

**💡 Quick CLI Tools**: Use `./bin/health-check` and `./bin/debug-logs` for rapid diagnostics.

## 🚨 **Quick Diagnostic Checklist**

When experiencing issues, start with this quick checklist:

```bash
# 1. Run comprehensive health check (recommended)
./bin/health-check

# 2. Quick essential checks only
./bin/health-check --quick

# 3. Debug logs with filtering
./bin/debug-logs --follow --filter ERROR

# 4. Validate configuration
./bin/validate-config --all --security-check

# 5. Test installation integrity
./bin/test-installation --verbose
```

### **Manual Diagnostic Commands** (if CLI tools unavailable)

```bash
# Check service status
sudo systemctl status nginx-security-monitor

# Check recent logs
sudo journalctl -u nginx-security-monitor --lines=50

# Verify configuration manually
python3 -m src.config_validator /etc/nginx-security/settings.yaml

# Check resource usage
ps aux | grep nginx-security
free -h
df -h /var/log/nginx-security

# Test API connectivity
curl -I http://localhost:8080/health

# Check file permissions
ls -la /etc/nginx-security/
ls -la /var/log/nginx-security/
```

______________________________________________________________________

## 🔍 **Service Issues**

### **Service Won't Start**

#### **Symptoms:**

- `systemctl start nginx-security-monitor` fails
- Service shows "failed" status
- No processes visible

#### **Diagnostic Steps:**

```bash
# Check detailed status
sudo systemctl status nginx-security-monitor -l

# Check service logs
sudo journalctl -u nginx-security-monitor --since "10 minutes ago"

# Check systemd service file
sudo systemctl cat nginx-security-monitor

# Test manual start
cd /opt/nginx-security-monitor
sudo -u nginx-security python3 -m src.monitor_service --config /etc/nginx-security/settings.yaml --debug
```

#### **Common Causes and Solutions:**

##### **1. Configuration Errors**

```bash
# Validate configuration
python3 -m src.config_validator /etc/nginx-security/settings.yaml

# Common configuration issues:
# - Invalid YAML syntax
# - Missing required fields
# - Incorrect file paths
# - Invalid log format specifications
```

**Solution:**

```bash
# Check for YAML syntax errors
python3 -c "import yaml; yaml.safe_load(open('/etc/nginx-security/settings.yaml'))"

# Use configuration template
cp /opt/nginx-security-monitor/config/settings.yaml.example /etc/nginx-security/settings.yaml
```

##### **2. Permission Issues**

```bash
# Check file ownership
ls -la /etc/nginx-security/
ls -la /var/log/nginx-security/
ls -la /var/lib/nginx-security/

# Expected ownership: nginx-security:nginx-security
```

**Solution:**

```bash
# Fix ownership
sudo chown -R nginx-security:nginx-security /etc/nginx-security/
sudo chown -R nginx-security:nginx-security /var/log/nginx-security/
sudo chown -R nginx-security:nginx-security /var/lib/nginx-security/

# Fix permissions
sudo chmod 755 /var/log/nginx-security/
sudo chmod 640 /etc/nginx-security/*.yaml
sudo chmod 600 /etc/nginx-security/keys/* 2>/dev/null || true
```

##### **3. Missing Dependencies**

```bash
# Check Python dependencies
pip3 list | grep -E "(PyYAML|requests|cryptography)"

# Check system dependencies
which python3
python3 --version
```

**Solution:**

```bash
# Install missing dependencies
pip3 install -r /opt/nginx-security-monitor/requirements.txt

# For system packages
sudo apt-get update
sudo apt-get install python3 python3-pip python3-yaml
```

##### **4. Port Already in Use**

```bash
# Check if port is already in use
sudo netstat -tlnp | grep :8080
sudo lsof -i :8080
```

**Solution:**

```bash
# Change port in configuration
sudo nano /etc/nginx-security/settings.yaml
# Update web_interface: port: 8081

# Or stop conflicting service
sudo systemctl stop <conflicting-service>
```

### **Service Crashes Frequently**

#### **Symptoms:**

- Service starts but stops after a short time
- Frequent restart messages in logs
- High memory usage before crashes

#### **Diagnostic Steps:**

```bash
# Check crash logs
sudo journalctl -u nginx-security-monitor --since "1 hour ago" | grep -E "(failed|error|crash|killed)"

# Check system resources
free -h
df -h
sudo dmesg | tail -20

# Monitor service in real-time
sudo journalctl -u nginx-security-monitor -f
```

#### **Common Causes and Solutions:**

##### **1. Memory Leaks**

```bash
# Monitor memory usage
watch -n 5 'ps aux | grep nginx-security'

# Check for large log files
du -sh /var/log/nginx-security/*
```

**Solution:**

```bash
# Implement log rotation
sudo logrotate /etc/logrotate.d/nginx-security-monitor

# Adjust memory limits in systemd
sudo systemctl edit nginx-security-monitor
# Add:
# [Service]
# MemoryMax=512M
# MemoryAccounting=yes
```

##### **2. Unhandled Exceptions**

```bash
# Enable debug logging
sudo nano /etc/nginx-security/settings.yaml
# Set: logging: level: DEBUG

# Check detailed error logs
sudo tail -f /var/log/nginx-security/error.log
```

**Solution:**

```bash
# Update to latest version
sudo /opt/nginx-security-monitor/scripts/upgrade.sh latest

# Report bug with logs
# Submit issue to GitHub with error details
```

______________________________________________________________________

## 📊 **Performance Issues**

### **High CPU Usage**

#### **Symptoms:**

- System load average consistently high
- NGINX Security Monitor processes consuming excessive CPU
- Slow response times

#### **Diagnostic Steps:**

```bash
# Check CPU usage by process
top -p $(pgrep -d',' -f nginx-security)

# Profile CPU usage
sudo perf top -p $(pgrep nginx-security-monitor)

# Check for CPU-intensive patterns
sudo strace -p $(pgrep nginx-security-monitor) -c -f
```

#### **Solutions:**

##### **1. Optimize Pattern Detection**

```yaml
# /etc/nginx-security/settings.yaml
pattern_detection:
  # Reduce pattern complexity
  max_patterns_per_check: 50
  
  # Enable pattern caching
  pattern_cache:
    enabled: true
    max_size: 1000
    ttl: 300
  
  # Batch processing
  batch_size: 100
  batch_timeout: 5
```

##### **2. Reduce Log Processing Load**

```yaml
# Implement sampling for high-volume logs
log_processing:
  sampling:
    enabled: true
    rate: 0.1  # Process 10% of logs
    
  # Parallel processing
  workers: 4
  queue_size: 1000
```

##### **3. Optimize Regular Expressions**

```python
# scripts/optimize_patterns.py
#!/usr/bin/env python3
"""Optimize regex patterns for better performance."""

import re
import json
import time
from typing import List, Dict, Any

def benchmark_pattern(pattern: str, test_strings: List[str], iterations: int = 1000) -> float:
    """Benchmark regex pattern performance."""
    compiled_pattern = re.compile(pattern, re.IGNORECASE)
    
    start_time = time.time()
    for _ in range(iterations):
        for test_string in test_strings:
            compiled_pattern.search(test_string)
    end_time = time.time()
    
    return (end_time - start_time) / iterations

def optimize_patterns():
    """Identify and optimize slow patterns."""
    with open('/etc/nginx-security/patterns.json', 'r') as f:
        patterns = json.load(f)
    
    test_urls = [
        "/index.html",
        "/admin/login.php",
        "/search?q=test",
        "/api/users/1",
        "/../../../etc/passwd"
    ]
    
    slow_patterns = []
    
    for pattern_name, pattern_data in patterns.items():
        pattern = pattern_data.get('pattern', '')
        if pattern:
            execution_time = benchmark_pattern(pattern, test_urls)
            
            if execution_time > 0.001:  # 1ms threshold
                slow_patterns.append({
                    'name': pattern_name,
                    'pattern': pattern,
                    'execution_time': execution_time
                })
    
    # Sort by execution time
    slow_patterns.sort(key=lambda x: x['execution_time'], reverse=True)
    
    print("Slow patterns detected:")
    for pattern in slow_patterns[:10]:
        print(f"- {pattern['name']}: {pattern['execution_time']:.4f}s")
        print(f"  Pattern: {pattern['pattern'][:100]}")

if __name__ == "__main__":
    optimize_patterns()
```

### **High Memory Usage**

#### **Symptoms:**

- Increasing memory consumption over time
- System running out of memory
- OOM (Out of Memory) kills

#### **Diagnostic Steps:**

```bash
# Monitor memory usage
sudo pmap -x $(pgrep nginx-security-monitor)

# Check for memory leaks
valgrind --leak-check=full python3 -m src.monitor_service

# Memory profiling
python3 -m memory_profiler /opt/nginx-security-monitor/src/monitor_service.py
```

#### **Solutions:**

##### **1. Configure Memory Limits**

```yaml
# /etc/nginx-security/settings.yaml
performance:
  memory:
    max_cache_size: "256MB"
    log_buffer_size: "64MB"
    pattern_cache_size: "32MB"
    
  # Enable garbage collection
  garbage_collection:
    enabled: true
    threshold: 1000
    interval: 300
```

##### **2. Implement Memory Monitoring**

```python
# scripts/memory_monitor.py
#!/usr/bin/env python3
"""Monitor memory usage and detect leaks."""

import psutil
import time
import gc
from collections import deque

class MemoryMonitor:
    def __init__(self, process_name: str = "nginx-security-monitor"):
        self.process_name = process_name
        self.memory_history = deque(maxlen=100)
        
    def monitor_memory(self, duration: int = 300):
        """Monitor memory usage for specified duration."""
        for process in psutil.process_iter(['pid', 'name', 'memory_info']):
            if self.process_name in process.info['name']:
                pid = process.info['pid']
                
                for _ in range(duration):
                    try:
                        proc = psutil.Process(pid)
                        memory_mb = proc.memory_info().rss / 1024 / 1024
                        self.memory_history.append({
                            'timestamp': time.time(),
                            'memory_mb': memory_mb
                        })
                        
                        # Check for memory leak
                        if len(self.memory_history) >= 10:
                            recent_avg = sum(m['memory_mb'] for m in list(self.memory_history)[-10:]) / 10
                            old_avg = sum(m['memory_mb'] for m in list(self.memory_history)[:10]) / 10
                            
                            if recent_avg > old_avg * 1.5:  # 50% increase
                                print(f"WARNING: Potential memory leak detected!")
                                print(f"Old average: {old_avg:.2f}MB")
                                print(f"Recent average: {recent_avg:.2f}MB")
                        
                        time.sleep(1)
                        
                    except psutil.NoSuchProcess:
                        break

if __name__ == "__main__":
    monitor = MemoryMonitor()
    monitor.monitor_memory(300)  # Monitor for 5 minutes
```

______________________________________________________________________

## 🔧 **Configuration Issues**

### **Invalid Configuration**

#### **Symptoms:**

- Service fails to start with configuration errors
- Warning messages about configuration
- Features not working as expected

#### **Diagnostic Script:**

````python
# scripts/config_diagnostics.py
#!/usr/bin/env python3
"""Comprehensive configuration diagnostics."""

import yaml
import os
import json
import jsonschema
from typing import Dict, Any, List

class ConfigDiagnostics:
    def __init__(self, config_path: str):
        self.config_path = config_path
        
    def validate_yaml_syntax(self) -> Dict[str, Any]:
        """Validate YAML syntax."""
        try:
            with open(self.config_path, 'r') as f:
                yaml.safe_load(f)
            return {'valid': True, 'message': 'YAML syntax is valid'}
        except yaml.YAMLError as e:
            return {'valid': False, 'message': f'YAML syntax error: {e}'}
        except FileNotFoundError:
            return {'valid': False, 'message': f'Configuration file not found: {self.config_path}'}
    
    def validate_schema(self) -> Dict[str, Any]:
        """Validate configuration against schema."""
        schema = {
            "type": "object",
            "required": ["logging", "monitoring", "patterns"],
            "properties": {
                "logging": {
                    "type": "object",
                    "required": ["level", "file"],
**Note:** For correct production behavior and support, set the following environment variable before starting the service:
```sh
export NSM_ENV=production
````

```python
                "properties": {
                    "level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]},
                    "file": {"type": "string"}
                "required": ["log_files"],
                "properties": {
                    "log_files": {"type": "array", "items": {"type": "string"}}
                }
            },
                "properties": {
                    "file": {"type": "string"}
                }
            }
        }
    }
    
    try:
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        jsonschema.validate(config, schema)
        return {'valid': True, 'message': 'Configuration schema is valid'}
    except jsonschema.ValidationError as e:
        return {'valid': False, 'message': f'Schema validation error: {e.message}'}
    except Exception as e:
        return {'valid': False, 'message': f'Validation error: {e}'}

def check_file_paths(self) -> Dict[str, Any]:
    """Check if referenced files exist."""
    try:
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        return {'valid': False, 'message': f'Cannot load config: {e}'}
    
    issues = []
    
    # Check log files
    log_files = config.get('monitoring', {}).get('log_files', [])
    for log_file in log_files:
        if not os.path.exists(log_file):
            issues.append(f'Log file not found: {log_file}')
    
    # Check patterns file
    patterns_file = config.get('patterns', {}).get('file', '')
    if patterns_file and not os.path.exists(patterns_file):
        issues.append(f'Patterns file not found: {patterns_file}')
    
    # Check SSL certificates
    ssl_config = config.get('web_interface', {}).get('ssl', {})
    if ssl_config.get('enabled'):
        cert_file = ssl_config.get('cert_file')
        key_file = ssl_config.get('key_file')
        
        if cert_file and not os.path.exists(cert_file):
            issues.append(f'SSL certificate not found: {cert_file}')
        if key_file and not os.path.exists(key_file):
            issues.append(f'SSL key file not found: {key_file}')
    
    return {
        'valid': len(issues) == 0,
        'issues': issues,
        'message': f'Found {len(issues)} file path issues' if issues else 'All file paths are valid'
    }

def check_permissions(self) -> Dict[str, Any]:
    """Check file permissions."""
    try:
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        return {'valid': False, 'message': f'Cannot load config: {e}'}
    
    issues = []
    
    # Check log directory permissions
    log_files = config.get('monitoring', {}).get('log_files', [])
    for log_file in log_files:
        log_dir = os.path.dirname(log_file)
        if os.path.exists(log_dir):
            stat = os.stat(log_dir)
            if not (stat.st_mode & 0o200):  # Check write permission
                issues.append(f'No write permission for log directory: {log_dir}')
    
    # Check patterns file permissions
    patterns_file = config.get('patterns', {}).get('file', '')
    if patterns_file and os.path.exists(patterns_file):
        stat = os.stat(patterns_file)
        if not (stat.st_mode & 0o400):  # Check read permission
            issues.append(f'No read permission for patterns file: {patterns_file}')
    
    return {
        'valid': len(issues) == 0,
        'issues': issues,
        'message': f'Found {len(issues)} permission issues' if issues else 'All permissions are correct'
    }

def run_full_diagnostics(self) -> Dict[str, Any]:
    """Run all diagnostic checks."""
    results = {
        'config_file': self.config_path,
        'checks': {
            'yaml_syntax': self.validate_yaml_syntax(),
            'schema_validation': self.validate_schema(),
            'file_paths': self.check_file_paths(),
            'permissions': self.check_permissions()
        }
    }
    
    # Overall status
    all_valid = all(check['valid'] for check in results['checks'].values())
    results['overall_status'] = 'valid' if all_valid else 'invalid'
    
    return results
```

```python
if __name__ == "__main__":
import sys

config_file = sys.argv[1] if len(sys.argv) > 1 else '/etc/nginx-security/settings.yaml'

diagnostics = ConfigDiagnostics(config_file)
results = diagnostics.run_full_diagnostics()

print(json.dumps(results, indent=2))

if results['overall_status'] != 'valid':
    sys.exit(1)
```

### **Pattern Detection Issues**

#### **Symptoms:**

- Threats not being detected
- False positives
- Pattern loading errors

#### **Diagnostic Steps:**

```bash
# Test pattern loading
python3 -c "
from nginx_security_monitor.pattern_detector import PatternDetector
detector = PatternDetector('/etc/nginx-security/patterns.json')
print('Patterns loaded successfully')
print(f'Total patterns: {len(detector.patterns)}')
"

# Test specific pattern
python3 -c "
from nginx_security_monitor.pattern_detector import PatternDetector
detector = PatternDetector('/etc/nginx-security/patterns.json')
test_entry = {
    'ip': '192.168.1.100',
    'url': '/admin.php',
    'method': 'GET',
    'status': 200
}
threats = detector.detect_threats(test_entry)
print(f'Detected threats: {len(threats)}')
for threat in threats:
    print(f'- {threat[\"threat_type\"]}: {threat[\"description\"]}')
"
```

#### **Pattern Testing Tool:**

```python
# scripts/test_patterns.py
#!/usr/bin/env python3
"""Test pattern detection with sample data."""

import json
import sys
from nginx_security_monitor.pattern_detector import PatternDetector

def test_patterns():
    """Test patterns with various input scenarios."""
    
    # Load pattern detector
    try:
        detector = PatternDetector('/etc/nginx-security/patterns.json')
        print(f"Loaded {len(detector.patterns)} patterns")
    except Exception as e:
        print(f"Error loading patterns: {e}")
        return False
    
    # Test cases
    test_cases = [
        {
            'name': 'SQL Injection',
            'log_entry': {
                'ip': '192.168.1.100',
                'url': '/search?q=1\' OR \'1\'=\'1',
                'method': 'GET',
                'status': 200,
                'user_agent': 'Mozilla/5.0'
            },
            'expected_threats': ['sql_injection']
        },
        {
            'name': 'Admin Access',
            'log_entry': {
                'ip': '192.168.1.101',
                'url': '/admin/login.php',
                'method': 'POST',
                'status': 200,
                'user_agent': 'Mozilla/5.0'
            },
            'expected_threats': ['admin_access']
        },
        {
            'name': 'Directory Traversal',
            'log_entry': {
                'ip': '192.168.1.102',
                'url': '/../../../etc/passwd',
                'method': 'GET',
                'status': 404,
                'user_agent': 'curl/7.68.0'
            },
            'expected_threats': ['directory_traversal']
        },
        {
            'name': 'Normal Request',
            'log_entry': {
                'ip': '192.168.1.103',
                'url': '/index.html',
                'method': 'GET',
                'status': 200,
                'user_agent': 'Mozilla/5.0'
            },
            'expected_threats': []
        }
    ]
    
    results = []
    
    for test_case in test_cases:
        try:
            threats = detector.detect_threats(test_case['log_entry'])
            detected_types = [threat['threat_type'] for threat in threats]
            
            # Check if expected threats were detected
            expected = set(test_case['expected_threats'])
            detected = set(detected_types)
            
            success = expected == detected
            
            results.append({
                'test_name': test_case['name'],
                'success': success,
                'expected': list(expected),
                'detected': list(detected),
                'threats': threats
            })
            
            status = "PASS" if success else "FAIL"
            print(f"{status}: {test_case['name']}")
            if not success:
                print(f"  Expected: {expected}")
                print(f"  Detected: {detected}")
            
        except Exception as e:
            print(f"ERROR: {test_case['name']} - {e}")
            results.append({
                'test_name': test_case['name'],
                'success': False,
                'error': str(e)
            })
    
    # Summary
    passed = sum(1 for r in results if r.get('success', False))
    total = len(results)
    print(f"\nTest Results: {passed}/{total} passed")
    
    return passed == total

if __name__ == "__main__":
    success = test_patterns()
    sys.exit(0 if success else 1)
```

______________________________________________________________________

## 🌐 **Network and Connectivity Issues**

### **API Not Responding**

#### **Symptoms:**

- Web interface not accessible
- API endpoints timing out
- Connection refused errors

#### **Diagnostic Steps:**

```bash
# Check if service is listening
sudo netstat -tlnp | grep :8080
sudo ss -tlnp | grep :8080

# Test local connectivity
curl -v http://localhost:8080/health
curl -v http://127.0.0.1:8080/health

# Check firewall rules
sudo iptables -L | grep 8080
sudo ufw status | grep 8080

# Test from external host
telnet your-server-ip 8080
```

#### **Solutions:**

##### **1. Firewall Configuration**

```bash
# Allow traffic on the configured port
sudo ufw allow 8080/tcp
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# For systemd-resolved issues
sudo systemctl restart systemd-resolved
```

##### **2. Binding Issues**

```yaml
# /etc/nginx-security/settings.yaml
web_interface:
  host: "0.0.0.0"  # Listen on all interfaces
  port: 8080
  
  # Or bind to specific interface
  # host: "192.168.1.100"
```

##### **3. SSL/TLS Issues**

```bash
# Test SSL configuration
openssl s_client -connect localhost:8443 -servername localhost

# Check certificate validity
openssl x509 -in /etc/nginx-security/ssl/cert.pem -text -noout

# Verify certificate chain
openssl verify -CAfile /etc/nginx-security/ssl/ca.pem /etc/nginx-security/ssl/cert.pem
```

### **Log File Access Issues**

#### **Symptoms:**

- "Permission denied" errors in logs
- No threat detection activity
- Log parsing errors

#### **Diagnostic Steps:**

```bash
# Check log file permissions
ls -la /var/log/nginx/access.log
ls -la /var/log/nginx/error.log

# Test read access as service user
sudo -u nginx-security cat /var/log/nginx/access.log | head -5

# Check if log files are being written
sudo tail -f /var/log/nginx/access.log

# Verify log format
sudo tail -5 /var/log/nginx/access.log
```

#### **Solutions:**

```bash
# Add nginx-security user to adm group (for log access)
sudo usermod -a -G adm nginx-security

# Or create specific log sharing
sudo chmod 644 /var/log/nginx/access.log
sudo chmod 644 /var/log/nginx/error.log

# Set up log rotation with proper permissions
sudo nano /etc/logrotate.d/nginx
# Add: create 644 www-data adm
```

______________________________________________________________________

## 📧 **Alert and Integration Issues**

### **Email Alerts Not Working**

#### **Diagnostic Steps:**

```bash
# Test SMTP configuration
python3 -c "
import smtplib
from email.mime.text import MimeText

# Test SMTP connection
server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('your-email@gmail.com', 'your-password')
print('SMTP connection successful')
server.quit()
"

# Test email sending
python3 -m nginx_sercurity_monitor.email_alert test --config /etc/nginx-security/settings.yaml
```

#### **Common Issues and Solutions:**

##### **1. Authentication Errors**

```bash
# For Gmail, use app passwords instead of regular password
# Go to Google Account → Security → App passwords

# Update configuration
sudo nano /etc/nginx-security/settings.yaml
# alerts:
#   email:
#     password: "your-app-password"  # Not regular password
```

##### **2. SMTP Server Issues**

```yaml
# /etc/nginx-security/settings.yaml
alerts:
  email:
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    use_tls: true
    use_ssl: false  # Don't use both TLS and SSL
    timeout: 30
```

##### **3. Corporate Firewall**

```bash
# Test SMTP connectivity
telnet smtp.gmail.com 587
telnet smtp.gmail.com 465

# Check proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY

# Configure proxy if needed
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
```

### **Integration Failures**

#### **fail2ban Integration Issues**

```bash
# Check fail2ban status
sudo systemctl status fail2ban

# Test fail2ban communication
sudo fail2ban-client status
sudo fail2ban-client status nginx-security

# Check fail2ban logs
sudo journalctl -u fail2ban --since "1 hour ago"

# Test manual ban
sudo fail2ban-client set nginx-security banip 192.168.1.100
sudo fail2ban-client set nginx-security unbanip 192.168.1.100
```

#### **SIEM Integration Issues**

```bash
# Test Splunk HEC endpoint
curl -k "https://splunk-server:8088/services/collector/event" \
     -H "Authorization: Splunk your-hec-token" \
     -d '{"event": "test"}'

# Test syslog forwarding
logger -p local0.info "Test message from nginx-security-monitor"

# Check rsyslog configuration
sudo systemctl status rsyslog
sudo tail /var/log/syslog | grep nginx-security
```

______________________________________________________________________

## 🔧 **Debug Mode and Detailed Logging**

### **Enable Debug Mode**

```yaml
# /etc/nginx-security/settings.yaml
logging:
  level: "DEBUG"
  file: "/var/log/nginx-security/debug.log"
  
  # Detailed component logging
  components:
    pattern_detector: "DEBUG"
    alert_manager: "DEBUG"
    mitigation_engine: "DEBUG"
    log_processor: "DEBUG"
```

### **Debug Logging Script**

```python
# scripts/debug_logging.py
#!/usr/bin/env python3
"""Enable comprehensive debug logging."""

import logging
import sys
import time
from nginx_security_monitor.monitor_service import MonitorService

def setup_debug_logging():
    """Configure detailed debug logging."""
    
    # Create debug logger
    debug_logger = logging.getLogger('nginx_security_debug')
    debug_logger.setLevel(logging.DEBUG)
    
    # Create detailed formatter
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)8s | %(name)20s | %(funcName)15s:%(lineno)3d | %(message)s'
    )
    
    # File handler for debug logs
    file_handler = logging.FileHandler('/var/log/nginx-security/debug.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Console handler for immediate feedback
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    debug_logger.addHandler(file_handler)
    debug_logger.addHandler(console_handler)
    
    return debug_logger

def trace_execution():
    """Trace execution flow for debugging."""
    import trace
    
    # Create tracer
    tracer = trace.Trace(
        count=False, 
        trace=True,
        ignoredirs=['/usr/lib/python3']
    )
    
    # Run monitor service with tracing
    tracer.run('monitor = MonitorService("/etc/nginx-security/settings.yaml"); monitor.start()')

if __name__ == "__main__":
    logger = setup_debug_logging()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'trace':
        trace_execution()
    else:
        # Start with debug logging
        logger.info("Starting debug session")
        
        try:
            monitor = MonitorService("/etc/nginx-security/settings.yaml")
            monitor.start()
        except Exception as e:
            logger.exception(f"Error during execution: {e}")
```

______________________________________________________________________

## 📞 **Getting Help and Support**

### **Information to Gather Before Seeking Help**

```bash
#!/bin/bash
# scripts/gather_support_info.sh

echo "NGINX Security Monitor Support Information"
echo "========================================"

# System information
echo "System Information:"
echo "- OS: $(lsb_release -d | cut -f2)"
echo "- Kernel: $(uname -r)"
echo "- Architecture: $(uname -m)"
echo "- Python: $(python3 --version)"

# Service information
echo -e "\nService Status:"
systemctl status nginx-security-monitor --no-pager

# Version information
echo -e "\nVersion Information:"
cat /opt/nginx-security-monitor/VERSION 2>/dev/null || echo "Version file not found"

# Configuration validation
echo -e "\nConfiguration Status:"
python3 -m src.config_validator /etc/nginx-security/settings.yaml

# Recent logs
echo -e "\nRecent Logs (last 20 lines):"
tail -20 /var/log/nginx-security/error.log 2>/dev/null || echo "Error log not found"

# Resource usage
echo -e "\nResource Usage:"
ps aux | grep nginx-security | grep -v grep
free -h
df -h /var/log/nginx-security

# Network status
echo -e "\nNetwork Status:"
netstat -tlnp | grep nginx-security

echo -e "\nSupport information gathered. Please provide this output when requesting help."
```

### **Community Resources**

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive guides and API reference
- **Stack Overflow**: Tag questions with `nginx-security-monitor`
- **Community Forum**: Discussion and Q&A

### **Professional Support**

For production environments requiring guaranteed response times:

- **Enterprise Support**: 24/7 support with SLA
- **Consulting Services**: Implementation and optimization
- **Training**: Team training and best practices

______________________________________________________________________

## 🔗 **Related Documentation**

- [Operations Guide](OPERATIONS_GUIDE.md) - Day-to-day operations
- [Performance Tuning](./operations/performance-tuning.md) - Optimization strategies
- [Configuration Guide](CONFIGURATION.md) - Configuration options
- [Installation Guide](INSTALLATION.md) - Setup and installation
- [Integration Cookbook](INTEGRATION_COOKBOOK.md) - Integration examples

______________________________________________________________________

*This troubleshooting guide is part of the NGINX Security Monitor documentation. For updates and contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).*
