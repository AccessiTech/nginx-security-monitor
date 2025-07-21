# 🛡️ Mitigation Strategies Guide - NGINX Security Monitor

## 🎯 **Overview**

The NGINX Security Monitor includes a comprehensive mitigation engine that can automatically respond to detected threats. This guide covers configuring, customizing, and extending the automated mitigation capabilities to protect your web infrastructure.

## 🔧 **Mitigation Engine Architecture**

The mitigation system operates in multiple layers:

1. **Detection** → Threat patterns identified
1. **Analysis** → Threat severity and context assessed
1. **Decision** → Appropriate mitigation strategy selected
1. **Execution** → Mitigation actions implemented
1. **Monitoring** → Results tracked and logged
1. **Escalation** → Additional actions if needed

______________________________________________________________________

## ⚙️ **Built-in Mitigation Strategies**

### **1. IP Blocking**

Temporarily or permanently block malicious IP addresses.

```yaml
mitigation:
  ip_blocking:
    enabled: true
    
    # Automatic blocking rules
    auto_block:
      brute_force:
        threshold: 5  # Block after 5 failed attempts
        duration: 3600  # Block for 1 hour
        escalation: true  # Increase duration for repeat offenders
        
      sql_injection:
        threshold: 1  # Block immediately
        duration: 7200  # Block for 2 hours
        permanent_after: 3  # Permanent block after 3 incidents
        
      directory_traversal:
        threshold: 2
        duration: 1800  # 30 minutes
        
    # Block duration escalation
    escalation:
      enabled: true
      multiplier: 2  # Double duration each time
      max_duration: 86400  # Maximum 24 hours
      reset_after: 604800  # Reset escalation after 1 week
    
    # Whitelist protection
    whitelist:
      - "127.0.0.1"
      - "192.168.1.0/24"  # Local network
      - "10.0.0.0/8"      # Internal network
    
    # Integration with system tools
    methods:
      - "iptables"
      - "fail2ban"
      - "nginx_deny"
```

### **2. Rate Limiting**

Implement dynamic rate limiting based on threat patterns.

```yaml
mitigation:
  rate_limiting:
    enabled: true
    
    # Adaptive rate limits
    adaptive_limits:
      normal_traffic:
        requests_per_minute: 60
        burst_allowance: 10
        
      suspicious_behavior:
        requests_per_minute: 10
        burst_allowance: 2
        trigger_duration: 300  # 5 minutes
        
      under_attack:
        requests_per_minute: 5
        burst_allowance: 1
        trigger_duration: 900  # 15 minutes
    
    # Per-endpoint limits
    endpoint_limits:
      "/login":
        requests_per_minute: 5
        requests_per_hour: 20
        
      "/admin/*":
        requests_per_minute: 10
        requests_per_hour: 100
        
      "/api/*":
        requests_per_minute: 100
        requests_per_hour: 1000
    
    # Implementation methods
    methods:
      - "nginx_limit_req"
      - "application_layer"
```

### **3. Request Filtering**

Filter malicious requests based on patterns and content.

```yaml
mitigation:
  request_filtering:
    enabled: true
    
    # SQL injection protection
    sql_injection:
      block_patterns:
        - "union.*select"
        - "drop.*table"
        - "insert.*into"
        - "delete.*from"
      response_action: "block"  # or "sanitize"
      
    # XSS protection
    xss_protection:
      block_patterns:
        - "<script.*>"
        - "javascript:"
        - "on(load|error|click)="
      response_action: "sanitize"
      
    # Directory traversal protection
    directory_traversal:
      block_patterns:
        - "\\.\\./.*"
        - "/etc/passwd"
        - "/etc/shadow"
      response_action: "block"
      
    # File upload restrictions
    file_upload:
      allowed_extensions: [".jpg", ".png", ".pdf", ".doc"]
      max_file_size: "10MB"
      scan_for_malware: true
```

### **4. Geographic Blocking**

Block traffic from specific countries or regions.

```yaml
mitigation:
  geo_blocking:
    enabled: true
    
    # Country-based blocking
    blocked_countries:
      - "CN"  # China
      - "RU"  # Russia
      - "KP"  # North Korea
    
    # Allow specific countries only
    allowed_countries_only: false
    allowed_countries: []
    
    # Regional blocking
    blocked_regions:
      - "TOR"  # Tor exit nodes
      - "VPN"  # Known VPN providers
      - "PROXY"  # Open proxies
    
    # Exceptions
    whitelist_ips:
      - "203.0.113.0/24"  # Trusted partner network
```

### **5. User-Agent Filtering**

Block requests from malicious or automated user agents.

```yaml
mitigation:
  user_agent_filtering:
    enabled: true
    
    # Block known bad user agents
    blocked_user_agents:
      - "sqlmap"
      - "nikto"
      - "nmap"
      - "masscan"
      - "bot"
      - "crawler"
      - "spider"
    
    # Block empty or suspicious user agents
    block_empty_user_agent: true
    block_suspicious_patterns: true
    
    # Advanced patterns
    suspicious_patterns:
      - "^$"  # Empty user agent
      - "python-requests"  # Automated scripts
      - "curl"  # Command line tools
      - "wget"  # Download tools
    
    # Allow legitimate bots
    whitelist_user_agents:
      - "Googlebot"
      - "Bingbot"
      - "facebookexternalhit"
```

______________________________________________________________________

## 🔄 **Integration Methods**

### **iptables Integration**

Direct firewall integration for IP blocking:

```yaml
mitigation:
  iptables:
    enabled: true
    chain: "INPUT"
    target: "DROP"
    table: "filter"
    
    # Custom rules
    custom_rules:
      - rule: "-s {ip} -j LOG --log-prefix 'Security-Block: '"
        apply_before_block: true
      - rule: "-s {ip} -j DROP"
        
    # Rule management
    auto_cleanup: true
    cleanup_interval: 3600  # 1 hour
    max_rules: 1000
```

### **fail2ban Integration**

Integrate with fail2ban for advanced IP management:

```yaml
mitigation:
  fail2ban:
    enabled: true
    
    # Jail configuration
    jails:
      nginx-security:
        enabled: true
        port: "http,https"
        filter: "nginx-security"
        logpath: "/var/log/nginx/access.log"
        maxretry: 3
        bantime: 3600
        findtime: 600
        
    # Custom filters
    filters:
      nginx-security: |
        [Definition]
        failregex = ^<HOST> .* ".*" [45]\d\d \d+.*$
                   ^<HOST> .* "(GET|POST) .*(\?|&)(.*=.*(\\\|'|;|<|>|\(|\)|,|union|select|insert|delete|drop|update|script).*).*" \d+ \d+.*$
        ignoreregex =
```

### **NGINX Configuration Integration**

Automatically update NGINX configuration for blocking:

```yaml
mitigation:
  nginx_integration:
    enabled: true
    
    # Configuration files
    deny_file: "/etc/nginx/conf.d/security-deny.conf"
    limit_req_file: "/etc/nginx/conf.d/security-limits.conf"
    
    # Auto-reload NGINX after changes
    auto_reload: true
    reload_command: "nginx -s reload"
    
    # Template for deny rules
    deny_template: |
      # Security-generated deny rules
      # Updated: {timestamp}
      {%- for ip in blocked_ips %}
      deny {{ ip }};
      {%- endfor %}
    
    # Template for rate limiting
    limit_req_template: |
      # Security-generated rate limiting
      # Updated: {timestamp}
      limit_req_zone $binary_remote_addr zone=security:10m rate=1r/s;
      limit_req zone=security burst=5 nodelay;
```

______________________________________________________________________

## 🎯 **Custom Mitigation Strategies**

### **Creating Custom Mitigation Plugins**

Develop custom mitigation strategies for specific threats:

```python
# plugins/custom_mitigation.py
from src.mitigation import MitigationPlugin

class CustomMitigationPlugin(MitigationPlugin):
    """Custom mitigation strategy example."""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "custom_mitigation"
        
    def can_handle(self, threat):
        """Check if this plugin can handle the threat."""
        return threat.get('threat_type') == 'custom_threat'
        
    def mitigate(self, threat):
        """Execute custom mitigation logic."""
        result = {
            'action_taken': 'custom_action',
            'success': False,
            'details': {}
        }
        
        try:
            # Your custom mitigation logic here
            self._custom_mitigation_logic(threat)
            
            result['success'] = True
            result['details'] = {
                'method': 'custom',
                'target': threat.get('source_ip'),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            result['details']['error'] = str(e)
            
        return result
        
    def _custom_mitigation_logic(self, threat):
        """Implement your custom mitigation logic."""
        # Example: Send to external security system
        import requests
        
        response = requests.post(
            'https://security-system.com/api/block',
            json={
                'ip': threat.get('source_ip'),
                'reason': threat.get('description'),
                'duration': 3600
            },
            headers={'Authorization': 'Bearer your-api-token'}
        )
        
        if response.status_code != 200:
            raise Exception(f"External system error: {response.text}")
```

Register custom plugin:

```yaml
mitigation:
  plugins:
    custom_mitigation:
      enabled: true
      module: "plugins.custom_mitigation"
      class: "CustomMitigationPlugin"
      config:
        api_endpoint: "https://security-system.com/api"
        api_token: "your-api-token"
        timeout: 30
```

### **Conditional Mitigation Logic**

Implement complex conditional logic for mitigation decisions:

```yaml
mitigation:
  conditional_logic:
    enabled: true
    
    rules:
      # Rule 1: Severe threats get immediate permanent blocking
      - name: "severe_threat_immediate_block"
        condition: |
          threat_type in ['sql_injection', 'rce'] and 
          severity == 'critical'
        actions:
          - type: "ip_block"
            duration: "permanent"
          - type: "alert"
            priority: "urgent"
          - type: "log"
            level: "critical"
            
      # Rule 2: Repeated offenders get escalated blocking
      - name: "repeat_offender_escalation"
        condition: |
          incident_count >= 3 and 
          last_incident_age < 86400
        actions:
          - type: "ip_block"
            duration: 86400  # 24 hours
          - type: "geo_analysis"
          - type: "threat_intelligence_lookup"
          
      # Rule 3: Internal IPs get monitoring only
      - name: "internal_ip_monitoring"
        condition: |
          source_ip.startswith('192.168.') or 
          source_ip.startswith('10.')
        actions:
          - type: "monitor"
          - type: "alert"
            priority: "low"
```

______________________________________________________________________

## 📊 **Mitigation Analytics**

### **Track Mitigation Effectiveness**

Monitor how well your mitigation strategies are working:

```yaml
analytics:
  mitigation_tracking:
    enabled: true
    
    metrics:
      - "blocked_attacks_count"
      - "mitigation_success_rate"
      - "false_positive_rate"
      - "response_time"
      - "threat_reduction_percentage"
    
    reporting:
      daily_summary: true
      weekly_detailed_report: true
      monthly_trend_analysis: true
      
    storage:
      database: "sqlite:///analytics.db"
      retention_days: 90
```

### **A/B Testing Mitigation Strategies**

Test different mitigation approaches:

```yaml
mitigation:
  ab_testing:
    enabled: true
    
    experiments:
      - name: "blocking_vs_rate_limiting"
        traffic_split: 50  # 50% each strategy
        strategies:
          - "ip_blocking"
          - "rate_limiting"
        metrics: ["effectiveness", "false_positives"]
        duration_days: 7
        
      - name: "immediate_vs_graduated_response"
        traffic_split: 30  # 30% new strategy, 70% current
        strategies:
          - "graduated_response"
          - "immediate_block"
        metrics: ["user_experience", "threat_mitigation"]
        duration_days: 14
```

______________________________________________________________________

## 🚨 **Emergency Response Procedures**

### **Panic Mode**

Activate emergency protection during active attacks:

```yaml
mitigation:
  panic_mode:
    enabled: true
    
    # Automatic activation triggers
    auto_trigger:
      attacks_per_minute: 100
      unique_ips_per_minute: 50
      critical_threats_per_hour: 10
      
    # Emergency actions
    emergency_actions:
      - "block_all_non_whitelisted"
      - "enable_strict_rate_limiting"
      - "activate_geo_blocking"
      - "send_emergency_alerts"
      - "enable_detailed_logging"
    
    # Auto-recovery
    recovery:
      auto_disable_after: 3600  # 1 hour
      conditions:
        - "attack_rate_below_threshold"
        - "manual_approval"
```

Manual panic mode activation:

```bash
# Activate panic mode
python -m src.mitigation panic --activate

# Check panic mode status
python -m src.mitigation panic --status

# Deactivate panic mode
python -m src.mitigation panic --deactivate
```

### **Incident Response Integration**

Integrate with incident response procedures:

```yaml
mitigation:
  incident_response:
    enabled: true
    
    # Automatic incident creation
    create_incidents:
      severity_threshold: "high"
      auto_assign_team: "security-team"
      
    # Incident management system integration
    integration:
      system: "jira"
      endpoint: "https://company.atlassian.net/rest/api/2"
      credentials: "encrypted_credentials"
      
    # Escalation procedures
    escalation:
      - level: 1
        condition: "severity == 'medium'"
        notify: ["security-team@company.com"]
        
      - level: 2
        condition: "severity == 'high'"
        notify: ["security-team@company.com", "it-manager@company.com"]
        
      - level: 3
        condition: "severity == 'critical'"
        notify: ["all-hands@company.com"]
        actions: ["activate_panic_mode"]
```

______________________________________________________________________

## 🔒 **Security Considerations**

### **Preventing Mitigation Bypass**

Protect your mitigation system from being bypassed:

```yaml
mitigation:
  security:
    # Protect configuration files
    config_protection:
      file_permissions: "600"
      owner: "root"
      group: "security"
      
    # Rate limit mitigation system access
    api_protection:
      rate_limit: "10/minute"
      authentication_required: true
      
    # Monitor mitigation system health
    health_monitoring:
      check_interval: 60
      alert_on_failure: true
      auto_restart: true
      
    # Prevent IP spoofing
    ip_validation:
      check_reverse_dns: true
      validate_source_routing: true
      detect_proxy_headers: true
```

### **Mitigation Logging and Auditing**

Comprehensive logging for compliance and analysis:

```yaml
logging:
  mitigation_audit:
    enabled: true
    log_level: "INFO"
    log_file: "/var/log/nginx-security/mitigation.log"
    
    # What to log
    log_events:
      - "mitigation_triggered"
      - "mitigation_executed"
      - "mitigation_failed"
      - "whitelist_bypass"
      - "escalation_triggered"
      - "panic_mode_activated"
    
    # Log format
    format: |
      {timestamp} | {level} | {event_type} | {source_ip} | {threat_type} | 
      {action_taken} | {success} | {details}
    
    # Log rotation
    rotation:
      max_size: "100MB"
      backup_count: 10
      compress: true
```

______________________________________________________________________

## 🧪 **Testing Mitigation Strategies**

### **Controlled Testing Environment**

Set up a safe testing environment:

```yaml
testing:
  environment:
    enabled: true
    mode: "simulation"  # Don't actually block in test mode
    
    # Test traffic generation
    test_scenarios:
      - name: "brute_force_simulation"
        type: "brute_force"
        source_ips: ["192.168.100.1", "192.168.100.2"]
        duration: 300  # 5 minutes
        intensity: "medium"
        
      - name: "sql_injection_test"
        type: "sql_injection"
        source_ip: "192.168.100.10"
        payloads: ["union select", "drop table", "' or 1=1"]
    
    # Verification
    verify_mitigation:
      check_blocking: true
      check_alerts: true
      check_logs: true
      generate_report: true
```

### **Mitigation Testing Scripts**

```bash
#!/bin/bash
# test_mitigation.sh

echo "Testing NGINX Security Monitor Mitigation..."

# Test 1: Brute force detection and blocking
echo "Test 1: Brute force simulation"
for i in {1..10}; do
    curl -s -o /dev/null "http://localhost/login" \
         -d "username=admin&password=wrong$i" \
         -H "X-Forwarded-For: 192.168.100.1"
    sleep 1
done

# Test 2: SQL injection detection
echo "Test 2: SQL injection simulation"
curl -s -o /dev/null "http://localhost/search?q=1' OR '1'='1" \
     -H "X-Forwarded-For: 192.168.100.2"

# Test 3: Directory traversal
echo "Test 3: Directory traversal simulation"
curl -s -o /dev/null "http://localhost/../../../etc/passwd" \
     -H "X-Forwarded-For: 192.168.100.3"

echo "Mitigation tests completed. Check logs for results."
```

______________________________________________________________________

## 📚 **Performance Optimization**

### **Optimize Mitigation Performance**

Ensure mitigation doesn't impact legitimate traffic:

```yaml
performance:
  optimization:
    # Caching
    cache_decisions: true
    cache_duration: 300  # 5 minutes
    cache_size: 10000    # Number of cached decisions
    
    # Asynchronous processing
    async_mitigation: true
    worker_threads: 4
    queue_size: 1000
    
    # Database optimization
    database:
      connection_pool_size: 10
      query_timeout: 5
      bulk_operations: true
    
    # Memory management
    memory:
      max_memory_usage: "512MB"
      cleanup_interval: 3600
      gc_threshold: 1000
```

### **Load Testing**

Test mitigation system under load:

```bash
# Install testing tools
pip install locust

# Run load test
locust -f load_test.py --host=http://localhost
```

Load test script (`load_test.py`):

```python
from locust import HttpUser, task, between

class SecurityTestUser(HttpUser):
    wait_time = between(1, 3)
    
    @task(3)
    def normal_request(self):
        """Normal traffic simulation."""
        self.client.get("/")
        
    @task(1)
    def malicious_request(self):
        """Malicious traffic simulation."""
        self.client.get("/search?q=1' OR '1'='1")
        
    @task(1)
    def brute_force_attempt(self):
        """Brute force simulation."""
        self.client.post("/login", data={
            "username": "admin",
            "password": "wrong_password"
        })
```

______________________________________________________________________

## 🔗 **Related Documentation**

- [Pattern Detection](PATTERN_DETECTION.md) - Understanding threat detection
- [Alert Systems](ALERT_SYSTEMS.md) - Configuring alert notifications
- [Configuration Guide](CONFIGURATION.md) - Mitigation configuration options
- [Integration Cookbook](INTEGRATION_COOKBOOK.md) - Integration examples
- [API Reference](API_REFERENCE.md) - MitigationEngine API documentation

______________________________________________________________________

*This mitigation strategies guide is part of the NGINX Security Monitor documentation. For updates and contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).*
