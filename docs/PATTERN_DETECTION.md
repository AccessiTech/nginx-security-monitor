# 🔍 Pattern Detection Guide

Comprehensive guide to understanding, customizing, and extending the pattern detection system in NGINX Security Monitor.

## 📋 **Overview**

The pattern detection system is the core of NGINX Security Monitor, analyzing NGINX log entries in real-time to identify potential security threats. It uses a combination of regex patterns, frequency analysis, and behavioral detection to identify various attack types.

## 🎯 **Built-in Detection Patterns**

### **SQL Injection Detection**

```json
{
  "sql_injection": {
    "enabled": true,
    "severity": "high",
    "description": "Detects SQL injection attempts",
    "patterns": [
      "(?i)(union.*select|select.*from|insert.*into|delete.*from)",
      "(?i)(or\\s+1=1|and\\s+1=1|'\\s*or\\s*')",
      "(?i)(exec\\s*\\(|sp_|xp_)",
      "(?i)(concat\\s*\\(|char\\s*\\(|ascii\\s*\\()",
      "(?i)(waitfor\\s+delay|benchmark\\s*\\()",
      "(?i)(information_schema|mysql\\.|sys\\.)"
    ],
    "threshold": 1,
    "window": 60,
    "action": "alert_and_log"
  }
}
```

**What it catches:**

- Classic SQL injection: `' OR '1'='1`
- UNION-based attacks: `UNION SELECT * FROM users`
- Blind SQL injection: `'; WAITFOR DELAY '00:00:05'--`
- Information gathering: `' AND (SELECT * FROM information_schema.tables)`

### **Cross-Site Scripting (XSS) Detection**

```json
{
  "xss_attacks": {
    "enabled": true,
    "severity": "medium",
    "description": "Cross-site scripting detection",
    "patterns": [
      "(?i)<script[^>]*>.*?</script>",
      "(?i)javascript:",
      "(?i)on(load|click|mouseover|error|focus)\\s*=",
      "(?i)(alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\()",
      "(?i)<iframe[^>]*src",
      "(?i)expression\\s*\\("
    ],
    "threshold": 1,
    "window": 60
  }
}
```

**What it catches:**

- Script tags: `<script>alert('xss')</script>`
- Event handlers: `<img onerror="alert('xss')" src=x>`
- JavaScript URLs: `<a href="javascript:alert('xss')">`
- CSS expressions: `style="expression(alert('xss'))"`

### **DDoS and High-Volume Attacks**

```json
{
  "ddos_detection": {
    "enabled": true,
    "severity": "high",
    "description": "DDoS and high-volume attacks",
    "type": "frequency",
    "threshold": 100,
    "window": 60,
    "per_ip": true,
    "sliding_window": true
  }
}
```

**What it catches:**

- Rapid requests from single IP
- Distributed high-volume attacks
- Resource exhaustion attempts
- Bot traffic spikes

### **Brute Force Detection**

```json
{
  "brute_force": {
    "enabled": true,
    "severity": "medium",
    "description": "Brute force login attempts",
    "patterns": [
      "POST.*/(login|signin|auth|wp-login)",
      "POST.*password=",
      "401.*Unauthorized",
      "403.*Forbidden"
    ],
    "threshold": 5,
    "window": 300,
    "per_ip": true
  }
}
```

**What it catches:**

- Multiple failed login attempts
- Password spraying attacks
- Credential stuffing
- Authentication bypass attempts

### **Directory Traversal Detection**

```json
{
  "directory_traversal": {
    "enabled": true,
    "severity": "medium",
    "description": "Path traversal and directory attacks",
    "patterns": [
      "(?i)(\\.\\./|\\.\\.\\\\)",
      "(?i)(/etc/passwd|/etc/shadow|/etc/hosts)",
      "(?i)(/proc/|/sys/|/dev/)",
      "(?i)(boot\\.ini|win\\.ini|system32)",
      "(?i)(%2e%2e%2f|%2e%2e\\\\|%c0%af)"
    ],
    "threshold": 1,
    "window": 60
  }
}
```

**What it catches:**

- Path traversal: `../../../etc/passwd`
- Windows traversal: `..\..\..\windows\system32`
- URL encoded traversal: `%2e%2e%2f`
- System file access attempts

### **Suspicious User Agents**

```json
{
  "suspicious_user_agents": {
    "enabled": true,
    "severity": "low",
    "description": "Detects suspicious or malicious user agents",
    "patterns": [
      "(?i)(sqlmap|nmap|nikto|dirb|gobuster)",
      "(?i)(burp|owasp|zap|w3af)",
      "(?i)(python-requests|curl|wget)(?!.*bot)",
      "(?i)(masscan|nessus|openvas)",
      "(?i)(bot|crawler|spider)(?!.*(google|bing|yahoo))"
    ],
    "threshold": 3,
    "window": 300
  }
}
```

**What it catches:**

- Security scanners: `sqlmap/1.0`, `Nikto/2.1`
- Penetration testing tools: `Burp Suite`, `OWASP ZAP`
- Automated scripts: `python-requests/2.0`
- Unknown bots and crawlers

## 🛠 **Creating Custom Patterns**

### **Basic Custom Pattern**

```json
{
  "custom_wordpress_attacks": {
    "enabled": true,
    "severity": "medium",
    "description": "WordPress-specific attack patterns",
    "patterns": [
      "/wp-admin/admin-ajax\\.php.*action=",
      "/wp-content/plugins/.*\\.php\\?",
      "/wp-includes/.*\\.(php|inc)\\?",
      "wp-config\\.php",
      "/xmlrpc\\.php.*POST"
    ],
    "threshold": 5,
    "window": 300,
    "per_ip": true
  }
}
```

### **Advanced Custom Pattern with Multiple Conditions**

```json
{
  "api_abuse_detection": {
    "enabled": true,
    "severity": "medium", 
    "description": "API endpoint abuse detection",
    "conditions": {
      "all_of": [
        {
          "pattern": "/api/v[0-9]+/",
          "field": "request_uri"
        },
        {
          "pattern": "(GET|POST|PUT|DELETE)",
          "field": "method"
        }
      ],
      "frequency": {
        "threshold": 50,
        "window": 60,
        "per_ip": true
      }
    },
    "whitelist": {
      "user_agents": ["MyApp/1.0", "InternalService/2.1"],
      "ips": ["192.168.1.100", "10.0.0.0/8"]
    }
  }
}
```

### **Time-Based Pattern Detection**

```json
{
  "off_hours_admin_access": {
    "enabled": true,
    "severity": "low",
    "description": "Administrative access during off-hours",
    "patterns": [
      "/admin/",
      "/dashboard/",
      "/management/"
    ],
    "time_conditions": {
      "excluded_hours": ["22:00-06:00"],
      "excluded_days": ["saturday", "sunday"],
      "timezone": "UTC"
    },
    "threshold": 1,
    "window": 3600
  }
}
```

## 🎛 **Pattern Configuration Options**

### **Basic Pattern Options**

```json
{
  "pattern_name": {
    "enabled": true,                    # Enable/disable pattern
    "severity": "high|medium|low",      # Alert severity level
    "description": "Human readable description",
    "patterns": ["regex1", "regex2"],   # List of regex patterns
    "threshold": 5,                     # Number of matches to trigger
    "window": 300,                      # Time window in seconds
    "per_ip": true,                     # Count per IP address
    "sliding_window": false,            # Use sliding vs fixed window
    "action": "alert_and_log"           # Action to take on match
  }
}
```

### **Advanced Detection Types**

**Frequency-Based Detection:**

```json
{
  "high_frequency_requests": {
    "type": "frequency",
    "threshold": 100,
    "window": 60,
    "per_ip": true,
    "baseline": {
      "enabled": true,
      "learning_period": 7200,  # 2 hours
      "deviation_threshold": 3.0
    }
  }
}
```

**Anomaly Detection:**

```json
{
  "unusual_response_sizes": {
    "type": "anomaly",
    "field": "response_size",
    "algorithm": "statistical",
    "parameters": {
      "window_size": 1000,
      "threshold": 2.5,
      "min_samples": 50
    }
  }
}
```

**Geographic Pattern Detection:**

```json
{
  "geographic_anomaly": {
    "type": "geographic",
    "description": "Detect access from unusual countries",
    "allowed_countries": ["US", "CA", "GB"],
    "suspicious_countries": ["CN", "RU", "KP"],
    "action": "alert_high_risk_countries"
  }
}
```

## 🔧 **Pattern Tuning and Optimization**

### **Threshold Tuning**

```bash
# Analyze pattern performance
python -m src.pattern_detector --analyze-patterns --days 7

# Output example:
# Pattern: sql_injection
#   True Positives: 45
#   False Positives: 2
#   Current Threshold: 1
#   Recommended Threshold: 1
#   Precision: 95.7%
```

### **Performance Optimization**

```json
{
  "optimized_pattern": {
    "patterns": [
      "(?i)(?:union.*select|select.*from)"  # Use non-capturing groups
    ],
    "compiled": true,                        # Pre-compile regex
    "multiline": false,                      # Disable multiline if not needed
    "cache_results": true,                   # Cache pattern matches
    "max_string_length": 2048               # Limit string processing
  }
}
```

### **Pattern Priority and Ordering**

```json
{
  "pattern_priorities": {
    "sql_injection": 100,        # Highest priority
    "xss_attacks": 90,
    "ddos_detection": 80,
    "brute_force": 70,
    "directory_traversal": 60,
    "suspicious_user_agents": 10  # Lowest priority
  }
}
```

## 🧪 **Testing Custom Patterns**

### **Pattern Validation Tool**

```bash
# Test a single pattern
python -m src.pattern_detector --test-pattern \
  --pattern "(?i)(union.*select)" \
  --test-string "GET /search?q=1' UNION SELECT * FROM users-- HTTP/1.1"

# Expected output:
# ✅ Pattern matched!
# Match: "UNION SELECT"
# Position: 19-31
```

### **Bulk Pattern Testing**

```bash
# Test all patterns against sample logs
python -m src.pattern_detector --validate-patterns \
  --config config/patterns.json \
  --test-logs tests/sample_logs/

# Generate test data
python scripts/generate_test_attacks.py --output test_attacks.log
```

### **Pattern Performance Benchmarking**

```bash
# Benchmark pattern performance
python -m src.pattern_detector --benchmark \
  --patterns config/patterns.json \
  --log-file /var/log/nginx/access.log \
  --duration 60

# Output:
# Pattern Performance Report:
# sql_injection: 1,234 checks/sec, 0.8ms avg
# xss_attacks: 2,456 checks/sec, 0.4ms avg
# ddos_detection: 5,678 checks/sec, 0.2ms avg
```

## 📊 **Pattern Analytics and Reporting**

### **Detection Statistics**

```bash
# Generate pattern effectiveness report
python -m src.analytics --pattern-report --days 30

# View detection trends
python -m src.analytics --trend-analysis --pattern sql_injection
```

### **False Positive Analysis**

```json
{
  "whitelist_rules": {
    "sql_injection_exceptions": {
      "patterns": ["(?i)(union.*select)"],
      "exceptions": [
        {
          "condition": "user_agent contains 'MyLegitimateApp'",
          "action": "ignore"
        },
        {
          "condition": "ip in ['192.168.1.100']",
          "action": "log_only"
        }
      ]
    }
  }
}
```

## 🔄 **Dynamic Pattern Updates**

### **Hot Pattern Reloading**

```bash
# Reload patterns without restarting service
sudo systemctl reload nginx-security-monitor

# Or via API
curl -X POST http://localhost:8080/api/reload-patterns \
  -H "Authorization: Bearer your-api-token"
```

### **Pattern A/B Testing**

```json
{
  "experimental_patterns": {
    "new_sql_injection_v2": {
      "enabled": true,
      "experimental": true,
      "rollout_percentage": 25,  # Only apply to 25% of traffic
      "patterns": ["improved_regex_here"],
      "compare_to": "sql_injection"
    }
  }
}
```

## 🚨 **Pattern-Specific Mitigation**

### **Pattern-Triggered Actions**

```json
{
  "sql_injection": {
    "patterns": ["(?i)(union.*select)"],
    "actions": {
      "immediate": [
        "log_detailed",
        "alert_security_team", 
        "block_ip_temporary"
      ],
      "escalation": {
        "threshold": 3,
        "window": 3600,
        "actions": ["block_ip_permanent", "alert_admin"]
      }
    }
  }
}
```

### **Adaptive Thresholds**

```json
{
  "adaptive_thresholds": {
    "enabled": true,
    "learning_period": 86400,  # 24 hours
    "patterns": {
      "brute_force": {
        "base_threshold": 5,
        "max_threshold": 20,
        "adaptation_rate": 0.1
      }
    }
  }
}
```

## 📚 **Best Practices for Pattern Development**

### **1. Pattern Design Principles**

- **Specific**: Minimize false positives
- **Efficient**: Use optimized regex patterns
- **Maintainable**: Clear descriptions and comments
- **Testable**: Include test cases

### **2. Regex Optimization Tips**

```javascript
// ❌ Inefficient
".*admin.*password.*"

// ✅ Efficient  
"admin[^\\s]*password|password[^\\s]*admin"

// ❌ Catastrophic backtracking risk
"(a+)+"

// ✅ Safe pattern
"a+"
```

### **3. Testing Strategy**

```bash
# 1. Unit test individual patterns
pytest tests/test_patterns.py::test_sql_injection_detection

# 2. Integration test with real logs
python -m src.pattern_detector --test-integration

# 3. Performance test under load
python -m src.load_test --pattern-stress-test

# 4. False positive analysis
python -m src.analytics --false-positive-report
```

## 🆘 **Troubleshooting Pattern Issues**

### **Common Issues and Solutions**

**Issue: Pattern not detecting attacks**

```bash
# Debug pattern matching
python -m src.pattern_detector --debug \
  --pattern sql_injection \
  --input "test string here"
```

**Issue: Too many false positives**

```bash
# Analyze false positives
python -m src.analytics --false-positive-analysis \
  --pattern sql_injection --days 7
```

**Issue: Poor performance**

```bash
# Profile pattern performance
python -m src.pattern_detector --profile \
  --config config/patterns.json
```

## 📖 **Related Documentation**

- [CONFIGURATION.md](CONFIGURATION.md) - Configuration guide
- [ALERT_SYSTEMS.md](ALERT_SYSTEMS.md) - Alert configuration
- [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) - Custom plugin development
- [API_REFERENCE.md](API_REFERENCE.md) - API documentation
