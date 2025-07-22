# 🎯 Use Cases Guide - NGINX Security Monitor

## 📋 **Overview**

This guide presents real-world implementation scenarios for NGINX Security Monitor across different organization types,
scales, and requirements. Each use case includes detailed configuration examples, deployment strategies,
and best practices tailored to specific environments.

## 🏢 **Use Case 1: Small Business E-commerce Site**

### **Scenario**

A small online retailer with a WordPress-based e-commerce site running on a single server, handling ~1,000
visitors per day. Limited IT resources, needs simple but effective security monitoring.

### **Requirements**

- Basic attack detection (SQL injection, XSS, brute force)
- Email alerts to business owner
- Simple deployment and maintenance
- Cost-effective solution

### **Configuration**

#### **Basic Setup**

```yaml
# config/small-business-settings.yaml
monitoring:
  check_interval: 30  # Check every 30 seconds (moderate frequency)
  batch_size: 500

logs:
  access_log: "/var/log/nginx/access.log"
  error_log: "/var/log/nginx/error.log"

# Essential detection patterns for e-commerce
detection:
  enabled_patterns:
    - sql_injection       # Protect customer data
    - xss_attacks         # Protect user sessions
    - brute_force         # Protect admin login
    - directory_traversal # Protect system files
    - wordpress_attacks   # WordPress-specific protection
  thresholds:
    failed_requests_per_minute: 20
    requests_per_ip_per_minute: 60
    error_rate_threshold: 0.15

# Simple email alerting
alerts:
  enabled: true
  email:
    enabled: true
    to: "owner@example.com"
    smtp_server: "smtp.example.com"
    from_address: "security-monitor@example.com"
```

```yaml
# config/small-business-settings.yaml
monitoring:
  check_interval: 30
  batch_size: 500

logs:
  access_log: "/var/log/nginx/access.log"
  error_log: "/var/log/nginx/error.log"

detection:
  enabled_patterns:
    - sql_injection
    - xss_attacks
    - brute_force
    - directory_traversal
    - wordpress_attacks
  thresholds:
    failed_requests_per_minute: 20
    requests_per_ip_per_minute: 60
    error_rate_threshold: 0.15

alerts:
  enabled: true
  email:
    enabled: true
    to: "owner@example.com"
    smtp_server: "smtp.example.com"
    from_address: "security-monitor@example.com"
```

#### **WordPress-Specific Patterns**

```json
{
  "custom_patterns": {
    "wordpress_attacks": {
      "enabled": true,
      "severity": "medium",
      "description": "WordPress-specific attacks",
      "patterns": [
        "/wp-admin/admin-ajax.php",
        "/wp-login.php.*force",
        "/xmlrpc.php",
        "wp-config.php",
        "/wp-content/plugins/.*.php"
      ],
      "threshold": 5,
      "window": 300
    },
    "ecommerce_attacks": {
      "enabled": true,
      "severity": "high",
      "description": "E-commerce specific attacks",
      "patterns": [
        "/checkout.*script",
        "/payment.*union",
        "/cart.*drop.*table",
        "credit.*card.*number"
      ],
      "threshold": 1,
      "window": 60
    }
  }
}
```

```json
{
  "custom_patterns": {
    "wordpress_attacks": {
      "enabled": true,
      "severity": "medium",
      "description": "WordPress-specific attacks",
      "patterns": [
        "/wp-admin/admin-ajax.php",
        "/wp-login.php.*force",
        "/xmlrpc.php",
        "wp-config.php",
        "/wp-content/plugins/.*.php"
      ],
      "threshold": 5,
      "window": 300
    },
    "ecommerce_attacks": {
      "enabled": true,
      "severity": "high",
      "description": "E-commerce specific attacks",
      "patterns": [
        "/checkout.*script",
        "/payment.*union",
        "/cart.*drop.*table",
        "credit.*card.*number"
      ],
      "threshold": 1,
      "window": 60
    }
  }
}
```

#### **Deployment Strategy**

```bash
# Simple single-server deployment
sudo ./install.sh
sudo systemctl enable nginx-security-monitor
sudo systemctl start nginx-security-monitor

# Setup log rotation for cost efficiency
sudo tee /etc/logrotate.d/nginx-security-small-business << EOF
/var/log/nginx-security-monitor/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

______________________________________________________________________

## 🏢 **Use Case 2: Enterprise Multi-Site Deployment**

### **Scenario**

Large corporation with 50+ web applications across multiple data centers. Requires centralized security monitoring,
compliance reporting, and integration with existing security infrastructure.

### **Requirements**

- Centralized monitoring and alerting
- Integration with SIEM (Splunk/ELK)
- Compliance reporting (SOX, PCI-DSS)
- High availability and scalability
- Advanced threat detection

### **Architecture**

```text
┌─────────────────────────────────────────────────────────────┐
│                    Central Security Operations             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │    SIEM     │ │   Splunk    │ │   Incident Response │   │
│  │  Dashboard  │ │   Server    │ │     Platform        │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
└─────────────────────┬───────────────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    │                 │                 │
┌───▼────┐     ┌──────▼──────┐     ┌───▼────┐
│ Site A │     │   Site B    │     │ Site C │
│        │     │             │     │        │
│┌──────┐│     │┌──────────┐ │     │┌──────┐│
││Monitor││     ││ Monitor  │ │     ││Monitor││
││ Node ││     ││  Node    │ │     ││ Node ││
│└──────┘│     │└──────────┘ │     │└──────┘│
└────────┘     └─────────────┘     └────────┘
```

### **Configuration**

#### **Central Configuration Template**

```yaml
# config/enterprise-settings.yaml
monitoring:
  check_interval: 5  # High frequency for enterprise
  batch_size: 2000
  worker_threads: 4

logs:
  access_log: "/var/log/nginx/access.log"
  error_log: "/var/log/nginx/error.log"
  format: "json"  # Structured logging for SIEM

# Comprehensive threat detection
detection:
  enabled_patterns:
    - sql_injection
    - xss_attacks
    - ddos_detection
    - brute_force
    - directory_traversal
    - suspicious_user_agents
    - api_abuse
    - file_upload_attacks
  
  thresholds:
    failed_requests_per_minute: 100
    requests_per_ip_per_minute: 500
    error_rate_threshold: 0.05

# Multi-channel alerting
alerts:
  enabled: true
  channels:
    - email
    - sms
    - webhook
    - syslog
  
  email:
    enabled: true
    smtp_server: "smtp.enterprise.com"
    from_address: "security-monitor@enterprise.com"
    to_addresses:
      - "soc@enterprise.com"
      - "security-team@enterprise.com"
  
  webhook:
    enabled: true
    endpoints:
      - name: "splunk_hec"
        url: "https://splunk.enterprise.com:8088/services/collector/event"
        headers:
          Authorization: "Splunk ${SPLUNK_HEC_TOKEN}"
      - name: "incident_management"
        url: "https://incidents.enterprise.com/api/alerts"
        headers:
          X-API-Key: "${INCIDENT_API_KEY}"

# Advanced mitigation with enterprise tools
mitigation:
  enabled: true
  auto_mitigation: true
  strategies:
    ip_blocking:
      enabled: true
      duration: 3600
    
    firewall_integration:
      enabled: true
      endpoint: "https://firewall-api.enterprise.com"
    
    load_balancer_integration:
      enabled: true
      endpoint: "https://lb-api.enterprise.com"

# Security framework integrations
security_integrations:
  fail2ban:
    enabled: true
  
  ossec:
    enabled: true
    ossec_dir: "/var/ossec"
  
  splunk:
    enabled: true
    hec_endpoint: "https://splunk.enterprise.com:8088/services/collector"
    index: "security_events"

# Enhanced security features
security:
  encryption:
    enabled: true
    key_file: "/etc/nginx-security-monitor/enterprise.key"
  
  obfuscation:
    enabled: true
    timing_variance_percent: 30
  
  plugin_security:
    enabled: true
    signature_verification: true

# Compliance and auditing
compliance:
  enabled: true
  standards:
    - pci_dss
    - sox
    - iso27001
  
  reporting:
    generate_reports: true
    report_frequency: "daily"
    retention_days: 2555  # 7 years for compliance
```

```yaml
# config/enterprise-settings.yaml
monitoring:
  check_interval: 5
  batch_size: 2000
  worker_threads: 4

logs:
  access_log: "/var/log/nginx/access.log"
  error_log: "/var/log/nginx/error.log"
  format: "json"

detection:
  enabled_patterns:
    - sql_injection
    - xss_attacks
    - ddos_detection
    - brute_force
    - directory_traversal
    - suspicious_user_agents
    - api_abuse
    - file_upload_attacks
  thresholds:
    failed_requests_per_minute: 100
    requests_per_ip_per_minute: 500
    error_rate_threshold: 0.05

alerts:
  enabled: true
  channels:
    - email
    - sms
    - webhook
    - syslog
  email:
    enabled: true
    smtp_server: "smtp.enterprise.com"
    from_address: "security-monitor@enterprise.com"
    to_addresses:
      - "soc@enterprise.com"
      - "security-team@enterprise.com"
  webhook:
    enabled: true
    endpoints:
      - name: "splunk_hec"
        url: "https://splunk.enterprise.com:8088/services/collector/event"
        headers:
          Authorization: "Splunk ${SPLUNK_HEC_TOKEN}"
      - name: "incident_management"
        url: "https://incidents.enterprise.com/api/alerts"
        headers:
          X-API-Key: "${INCIDENT_API_KEY}"

mitigation:
  enabled: true
  auto_mitigation: true
  strategies:
    ip_blocking:
      enabled: true
      duration: 3600
    firewall_integration:
      enabled: true
      endpoint: "https://firewall-api.enterprise.com"
    load_balancer_integration:
      enabled: true
      endpoint: "https://lb-api.enterprise.com"

security_integrations:
  fail2ban:
    enabled: true
  ossec:
    enabled: true
    ossec_dir: "/var/ossec"
  splunk:
    enabled: true
    hec_endpoint: "https://splunk.enterprise.com:8088/services/collector"
    index: "security_events"

security:
  encryption:
    enabled: true
    key_file: "/etc/nginx-security-monitor/enterprise.key"
  obfuscation:
    enabled: true
    timing_variance_percent: 30
  plugin_security:
    enabled: true
    signature_verification: true

compliance:
  enabled: true
  standards:
    - pci_dss
    - sox
    - iso27001
  reporting:
    generate_reports: true
    report_frequency: "daily"
    retention_days: 2555
```

#### **Site-Specific Configurations**

```yaml
# config/site-a-overrides.yaml
site_identification:
  site_name: "production-east"
  environment: "production"
  datacenter: "us-east-1"

detection:
  thresholds:
    # Higher thresholds for high-traffic production site
    failed_requests_per_minute: 200
    requests_per_ip_per_minute: 1000

# Site-specific patterns for customer-facing apps
custom_patterns:
  customer_portal_attacks:
    patterns:
      - "/customer/account.*script"
      - "/api/customer.*injection"
    severity: "critical"
```

```yaml
# config/site-a-overrides.yaml
site_identification:
  site_name: "production-east"
  environment: "production"
  datacenter: "us-east-1"

detection:
  thresholds:
    failed_requests_per_minute: 200
    requests_per_ip_per_minute: 1000

custom_patterns:
  customer_portal_attacks:
    patterns:
      - "/customer/account.*script"
      - "/api/customer.*injection"
    severity: "critical"
```

#### **Deployment with Configuration Management**

```bash
# Ansible deployment playbook excerpt
- name: Deploy NGINX Security Monitor
  hosts: web_servers
  vars:
    monitor_version: "{{ enterprise_monitor_version }}"
    config_template: "enterprise-settings.yaml.j2"
  
  tasks:
    - name: Install monitor
      include_role:
        name: nginx_security_monitor
      vars:
        environment: "{{ site_environment }}"
        datacenter: "{{ ansible_datacenter }}"
    
    - name: Configure site-specific settings
      template:
        src: "{{ config_template }}"
        dest: "/etc/nginx-security-monitor/settings.yaml"
      notify: restart_monitor
```

______________________________________________________________________

## ☁️ **Use Case 3: Cloud-Native Microservices Architecture**

### **Scenario**

Tech startup running microservices on Kubernetes with containerized applications. Multiple API gateways,
service meshes, and dynamic scaling requirements.

### **Requirements**

- Container-native deployment
- Integration with Kubernetes monitoring
- API gateway protection
- Microservice-specific threat detection
- Auto-scaling compatibility

### **Architecture**

```yaml
# kubernetes/nginx-security-monitor-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-security-monitor
  namespace: security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx-security-monitor
  template:
    metadata:
      labels:
        app: nginx-security-monitor
    spec:
      containers:
      - name: monitor
        image: nginx-security-monitor:latest
        env:
        - name: CONFIG_PATH
          value: "/config/cloud-native-settings.yaml"
        - name: NGINX_MONITOR_KEY
          valueFrom:
            secretKeyRef:
              name: monitor-secrets
              key: encryption-key
        volumeMounts:
        - name: config
          mountPath: /config
        - name: nginx-logs
          mountPath: /var/log/nginx
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: monitor-config
      - name: nginx-logs
        persistentVolumeClaim:
          claimName: nginx-logs-pvc
```

```yaml
# kubernetes/nginx-security-monitor-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-security-monitor
  namespace: security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx-security-monitor
  template:
    metadata:
      labels:
        app: nginx-security-monitor
    spec:
      containers:
      - name: monitor
        image: nginx-security-monitor:latest
        env:
        - name: CONFIG_PATH
          value: "/config/cloud-native-settings.yaml"
        - name: NGINX_MONITOR_KEY
          valueFrom:
            secretKeyRef:
              name: monitor-secrets
              key: encryption-key
        volumeMounts:
        - name: config
          mountPath: /config
        - name: nginx-logs
          mountPath: /var/log/nginx
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: monitor-config
      - name: nginx-logs
        persistentVolumeClaim:
          claimName: nginx-logs-pvc
```

### **Configuration**

#### **Cloud-Native Settings**

```yaml
# config/cloud-native-settings.yaml
monitoring:
  check_interval: 10
  batch_size: 1000
  
logs:
  access_log: "/var/log/nginx/access.log"
  error_log: "/var/log/nginx/error.log"
  format: "json"  # JSON for structured logging

# Microservices-specific detection
detection:
  enabled_patterns:
    - api_abuse
    - rate_limiting_bypass
    - jwt_attacks
    - graphql_attacks
    - container_escape_attempts
  
  # Microservices patterns
  custom_patterns:
    api_gateway_attacks:
      patterns:
        - "/api/v[0-9]+/.*union.*select"
        - "Authorization:.*script"
        - "/graphql.*query.*{.*admin"
      severity: "high"
    
    service_mesh_attacks:
      patterns:
        - "X-Forwarded-For:.*127.0.0.1"
        - "X-Real-IP:.*localhost"
      severity: "medium"

# Cloud-native alerting
alerts:
  webhook:
    enabled: true
    endpoints:
      - name: "prometheus_alertmanager"
        url: "http://alertmanager.monitoring.svc.cluster.local:9093/api/v1/alerts"
      - name: "slack_webhook"
        url: "${SLACK_WEBHOOK_URL}"

# Kubernetes integration
kubernetes:
  enabled: true
  namespace: "security"
  pod_name: "${HOSTNAME}"
  
  # Service discovery
  service_discovery:
    enabled: true
    label_selector: "app=nginx"
  
  # Resource monitoring
  resource_monitoring:
    enabled: true
    metrics_endpoint: ":8080/metrics"

# Observability
observability:
  metrics:
    enabled: true
    prometheus_endpoint: ":9090/metrics"
  
  tracing:
    enabled: true
    jaeger_endpoint: "http://jaeger.tracing.svc.cluster.local:14268/api/traces"
  
  logging:
    structured: true
    format: "json"
    level: "info"
```

```yaml
# config/cloud-native-settings.yaml
monitoring:
  check_interval: 10
  batch_size: 1000

logs:
  access_log: "/var/log/nginx/access.log"
  error_log: "/var/log/nginx/error.log"
  format: "json"

detection:
  enabled_patterns:
    - api_abuse
    - rate_limiting_bypass
    - jwt_attacks
    - graphql_attacks
    - container_escape_attempts
  custom_patterns:
    api_gateway_attacks:
      patterns:
        - "/api/v[0-9]+/.*union.*select"
        - "Authorization:.*script"
        - "/graphql.*query.*{.*admin"
      severity: "high"
    service_mesh_attacks:
      patterns:
        - "X-Forwarded-For:.*127.0.0.1"
        - "X-Real-IP:.*localhost"
      severity: "medium"

alerts:
  webhook:
    enabled: true
    endpoints:
      - name: "prometheus_alertmanager"
        url: "http://alertmanager.monitoring.svc.cluster.local:9093/api/v1/alerts"
      - name: "slack_webhook"
        url: "${SLACK_WEBHOOK_URL}"


  enabled: true
  namespace: "security"
  pod_name: "${HOSTNAME}"
  service_discovery:
    enabled: true
    label_selector: "app=nginx"
  resource_monitoring:
    enabled: true
    metrics_endpoint: ":8080/metrics"

observability:
  metrics:
    enabled: true
    prometheus_endpoint: ":9090/metrics"
  tracing:
    enabled: true
    jaeger_endpoint: "http://jaeger.tracing.svc.cluster.local:14268/api/traces"
  logging:
    structured: true
    format: "json"
    level: "info"
```

#### **Service Monitor for Prometheus**

```yaml
# kubernetes/service-monitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: nginx-security-monitor
  namespace: security
spec:
  selector:
    matchLabels:
      app: nginx-security-monitor
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

```yaml
# kubernetes/service-monitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: nginx-security-monitor
  namespace: security
spec:
  selector:
    matchLabels:
      app: nginx-security-monitor
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

______________________________________________________________________

## 🏛️ **Use Case 4: Government/Compliance-Heavy Environment**

### **Scenario**

Government agency with strict compliance requirements (FedRAMP, FISMA), air-gapped networks, and extensive audit trails needed.

### **Requirements**

- FIPS 140-2 Level 2 compliance
- Extensive audit logging
- Air-gapped deployment capability
- Multi-level security classifications
- Immutable audit trails

### **Configuration**

#### **High-Security Configuration**

```yaml
# config/government-settings.yaml
# CLASSIFICATION: CONTROLLED UNCLASSIFIED INFORMATION (CUI)

monitoring:
  check_interval: 5  # Frequent monitoring for security
  batch_size: 1000
  
security:
  # FIPS compliance
  fips_mode: true
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    key_derivation: "PBKDF2-SHA256"
    key_file: "/etc/nginx-security-monitor/fips-key"
  
  # Enhanced integrity checking
  integrity:
    enabled: true
    hash_algorithm: "SHA-256"
    verify_frequency: 300  # Every 5 minutes
  
  # Audit trail configuration
  audit:
    enabled: true
    immutable_logs: true
    digital_signatures: true
    retention_years: 7
    
# Comprehensive threat detection
detection:
  enabled_patterns:
    - all_standard_patterns
    - advanced_persistent_threats
    - insider_threats
    - data_exfiltration
    - privilege_escalation
  
  thresholds:
    # Strict thresholds for government security
    failed_requests_per_minute: 10
    requests_per_ip_per_minute: 100
    error_rate_threshold: 0.01

# Multi-level alerting
alerts:
  classification_aware: true
  
  email:
    enabled: true
    encryption: "PGP"
    classification_header: true
    security_labels:
      - "CUI"
      - "CONFIDENTIAL"
  
  syslog:
    enabled: true
    facility: "LOG_AUTHPRIV"
    severity_mapping:
      low: "LOG_INFO"
      medium: "LOG_WARNING"
      high: "LOG_ERR"
      critical: "LOG_CRIT"

# Government-specific compliance
compliance:
  enabled: true
  frameworks:
    - fisma
    - fedramp
    - nist_800_53
    - cis_controls
  
  reporting:
    automated: true
    formats:
      - "SCAP"
      - "STIG"
      - "CIS-CAT"
    
  audit_requirements:
    log_integrity: true
    chain_of_custody: true
    time_synchronization: "ntp"
    access_control: "mandatory"

# Air-gapped deployment settings
air_gapped:
  enabled: true
  offline_updates: true
  pattern_updates:
    method: "manual"
    verification: "digital_signature"
```

```yaml
# config/government-settings.yaml
# CLASSIFICATION: CONTROLLED UNCLASSIFIED INFORMATION (CUI)
monitoring:
  check_interval: 5
  batch_size: 1000
security:
  fips_mode: true
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    key_derivation: "PBKDF2-SHA256"
    key_file: "/etc/nginx-security-monitor/fips-key"
  integrity:
    enabled: true
    hash_algorithm: "SHA-256"
    verify_frequency: 300
  audit:
    enabled: true
    immutable_logs: true
    digital_signatures: true
    retention_years: 7
detection:
  enabled_patterns:
    - all_standard_patterns
    - advanced_persistent_threats
    - insider_threats
    - data_exfiltration
    - privilege_escalation
  thresholds:
    failed_requests_per_minute: 10
    requests_per_ip_per_minute: 100
    error_rate_threshold: 0.01
alerts:
  classification_aware: true
  email:
    enabled: true
    encryption: "PGP"
    classification_header: true
    security_labels:
      - "CUI"
      - "CONFIDENTIAL"
  syslog:
    enabled: true
    facility: "LOG_AUTHPRIV"
    severity_mapping:
      low: "LOG_INFO"
      medium: "LOG_WARNING"
      high: "LOG_ERR"
      critical: "LOG_CRIT"
compliance:
  enabled: true
  frameworks:
    - fisma
    - fedramp
    - nist_800_53
    - cis_controls
  reporting:
    automated: true
    formats:
      - "SCAP"
      - "STIG"
      - "CIS-CAT"
  audit_requirements:
    log_integrity: true
    chain_of_custody: true
    time_synchronization: "ntp"
    access_control: "mandatory"
air_gapped:
  enabled: true
  offline_updates: true
  pattern_updates:
    method: "manual"
    verification: "digital_signature"
```

#### **STIG Compliance Script**

```bash
#!/bin/bash
# Apply STIG compliance for NGINX Security Monitor

# File permissions (RHEL-08-010590)
chmod 640 /etc/nginx-security-monitor/*.yaml
chown nginx-monitor:nginx-monitor /etc/nginx-security-monitor/*.yaml

# Audit logging (RHEL-08-030010)
echo "nginx-security-monitor" >> /etc/audit/rules.d/nginx-security.rules

# SELinux policy (RHEL-08-010370)
setsebool -P httpd_can_network_connect 1
semanage fcontext -a -t admin_home_t "/etc/nginx-security-monitor(/.*)?"
restorecon -R /etc/nginx-security-monitor

# FIPS mode verification (RHEL-08-010020)
if [ ! -f /proc/sys/crypto/fips_enabled ] || [ "$(cat /proc/sys/crypto/fips_enabled)" != "1" ]; then
    echo "WARNING: FIPS mode not enabled"
fi
```

______________________________________________________________________

## 🌐 **Use Case 5: Multi-Region CDN with Edge Security**

### **Scenario**

Global media company with CDN infrastructure across 15 regions, handling millions of requests daily with edge computing requirements.

### **Requirements**

- Edge-deployed security monitoring
- Global threat intelligence sharing
- Regional compliance variations
- High-performance edge processing
- Centralized threat correlation

### **Architecture**

```text
Global Threat Intelligence Center
            │
    ┌───────┼───────┐
    │       │       │
┌───▼───┐ ┌─▼─┐ ┌──▼──┐
│US-East│ │EU │ │APAC │
│       │ │   │ │     │
│┌─────┐│ │┌──┐│ │┌───┐│
││Edge ││ ││  ││ ││   ││
││Nodes││ ││  ││ ││   ││
│└─────┘│ │└──┘│ │└───┘│
└───────┘ └───┘ └─────┘
```

### **Configuration**

#### **Edge Node Configuration**

```yaml
# config/edge-settings.yaml
monitoring:
  check_interval: 1  # Very frequent for edge
  batch_size: 5000   # Large batches for performance
  edge_mode: true
  
performance:
  # Optimized for edge deployment
  memory_limit: "512MB"
  cpu_limit: "1.0"
  cache_size: 10000
  
  # Async processing for performance
  async_processing: true
  queue_size: 50000

# Edge-specific detection
detection:
  enabled_patterns:
    - ddos_detection    # Critical for CDN
    - bot_detection     # Prevent bot abuse
    - api_abuse        # Protect API endpoints
    - cache_poisoning  # CDN-specific attack
  
  # Performance-optimized thresholds
  thresholds:
    failed_requests_per_minute: 1000  # High volume tolerance
    requests_per_ip_per_minute: 10000
    error_rate_threshold: 0.02

# Regional threat intelligence
threat_intelligence:
  enabled: true
  
  sources:
    - name: "global_intel"
      endpoint: "https://threat-intel.company.com/api/v1/indicators"
      region: "global"
    
    - name: "regional_intel"
      endpoint: "https://threat-intel-${REGION}.company.com/api/v1/indicators"
      region: "${REGION}"
  
  sharing:
    enabled: true
    share_detected_threats: true
    anonymize_data: true

# Edge alerting (lightweight)
alerts:
  # Local alerting for immediate response
  local:
    enabled: true
    threshold_based: true
    
  # Central reporting (batched)
  central:
    enabled: true
    batch_interval: 300  # 5 minutes
    endpoint: "https://central-soc.company.com/api/alerts"

# Geographical compliance
compliance:
  region: "${REGION}"
  gdpr: true  # EU regions
  ccpa: true  # California
  local_data_residency: true
```

```yaml
# config/edge-settings.yaml
monitoring:
  check_interval: 1
  batch_size: 5000
  edge_mode: true
performance:
  memory_limit: "512MB"
  cpu_limit: "1.0"
  cache_size: 10000
  async_processing: true
  queue_size: 50000
detection:
  enabled_patterns:
    - ddos_detection
    - bot_detection
    - api_abuse
    - cache_poisoning
  thresholds:
    failed_requests_per_minute: 1000
    requests_per_ip_per_minute: 10000
    error_rate_threshold: 0.02
threat_intelligence:
  enabled: true
  sources:
    - name: "global_intel"
      endpoint: "https://threat-intel.company.com/api/v1/indicators"
      region: "global"
    - name: "regional_intel"
      endpoint: "https://threat-intel-${REGION}.company.com/api/v1/indicators"
      region: "${REGION}"
  sharing:
    enabled: true
    share_detected_threats: true
    anonymize_data: true
alerts:
  local:
    enabled: true
    threshold_based: true
  central:
    enabled: true
    batch_interval: 300
    endpoint: "https://central-soc.company.com/api/alerts"
compliance:
  region: "${REGION}"
  gdpr: true
  ccpa: true
  local_data_residency: true
```

#### **Central Correlation Engine**

```yaml
# config/central-correlation-settings.yaml
correlation:
  enabled: true
  
  # Global threat pattern correlation
  pattern_correlation:
    time_window: 3600  # 1 hour correlation window
    min_nodes: 3       # Minimum nodes reporting same pattern
    confidence_threshold: 0.8
  
  # Cross-region attack detection
  global_patterns:
    distributed_attack:
      description: "Coordinated attack across regions"
      criteria:
        - same_attack_signature: true
        - multiple_regions: ">= 3"
        - time_window: 1800
      
    campaign_tracking:
      description: "Sustained campaign tracking"
      criteria:
        - similar_patterns: true
        - duration: ">= 7200"
        - escalation: true

# Machine learning enhancement
machine_learning:
  enabled: true
  
  models:
    - name: "anomaly_detection"
      type: "isolation_forest"
      training_data: "7_days"
      
    - name: "attack_classification"
      type: "random_forest"
      features:
        - request_patterns
        - timing_analysis
        - geolocation_data
```

```yaml
# config/central-correlation-settings.yaml
correlation:
  enabled: true
  pattern_correlation:
    time_window: 3600
    min_nodes: 3
    confidence_threshold: 0.8
  global_patterns:
    distributed_attack:
      description: "Coordinated attack across regions"
      criteria:
        - same_attack_signature: true
        - multiple_regions: ">= 3"
        - time_window: 1800
    campaign_tracking:
      description: "Sustained campaign tracking"
      criteria:
        - similar_patterns: true
        - duration: ">= 7200"
        - escalation: true
machine_learning:
  enabled: true
  models:
    - name: "anomaly_detection"
      type: "isolation_forest"
      training_data: "7_days"
    - name: "attack_classification"
      type: "random_forest"
      features:
        - request_patterns
        - timing_analysis
        - geolocation_data
```

______________________________________________________________________

## 🏥 **Use Case 6: Healthcare HIPAA-Compliant Environment**

### **Scenario**

Healthcare provider with patient portal, EHR systems, and strict HIPAA compliance requirements
for protecting PHI (Protected Health Information).

### **Requirements**

- HIPAA compliance for all security monitoring
- PHI data protection and anonymization
- Audit trails for compliance reporting
- Integration with healthcare security frameworks
- Patient data breach prevention

### **Configuration**

#### **HIPAA-Compliant Settings**

```yaml
# config/healthcare-settings.yaml
# HIPAA Compliance Configuration

monitoring:
  check_interval: 10
  batch_size: 1000
  
# HIPAA-specific security
security:
  hipaa_mode: true
  
  # Data anonymization
  data_anonymization:
    enabled: true
    anonymize_phi: true
    hash_identifiers: true
    
  # Encryption at rest and in transit
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    transit_encryption: "TLS-1.3"
    
  # Access controls
  access_control:
    role_based: true
    minimum_necessary: true
    audit_access: true

# Healthcare-specific threat detection
detection:
  enabled_patterns:
    - phi_exposure       # Detect PHI in logs
    - hipaa_violations   # HIPAA-specific attacks
    - medical_record_access  # Unauthorized access
    - patient_data_exfiltration
  
  # Custom healthcare patterns
  custom_patterns:
    phi_detection:
      patterns:
        - "\\b\\d{3}-\\d{2}-\\d{4}\\b"  # SSN
        - "\\b\\d{10}\\b"               # Patient ID
        - "DOB.*\\d{2}/\\d{2}/\\d{4}"   # Date of birth
      severity: "critical"
      action: "immediate_alert"
    
    ehr_attacks:
      patterns:
        - "/ehr/patient.*union.*select"
        - "/portal/records.*script"
        - "/api/patient.*drop.*table"
      severity: "high"

# HIPAA audit requirements
audit:
  enabled: true
  hipaa_compliant: true
  
  requirements:
    - access_logs: true
    - modification_logs: true
    - disclosure_tracking: true
    - breach_documentation: true
    
  retention:
    audit_logs: "6_years"    # HIPAA requirement
    security_logs: "6_years"
    incident_reports: "6_years"

# Healthcare alerting
alerts:
  email:
    enabled: true
    encryption: "required"
    phi_scrubbing: true
    
  incident_management:
    enabled: true
    breach_notification: true
    notification_timeline: "60_seconds"  # HIPAA breach notification
    
  compliance_reporting:
    enabled: true
    automated_reports: true
    regulatory_notifications: true

# Business Associate Agreement (BAA) compliance
baa_compliance:
  enabled: true
  data_processing_agreement: true
  subcontractor_agreements: true
  breach_notification_procedures: true
```

```yaml
# config/healthcare-settings.yaml
# HIPAA Compliance Configuration
monitoring:
  check_interval: 10
  batch_size: 1000
security:
  hipaa_mode: true
  data_anonymization:
    enabled: true
    anonymize_phi: true
    hash_identifiers: true
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    transit_encryption: "TLS-1.3"
  access_control:
    role_based: true
    minimum_necessary: true
    audit_access: true
detection:
  enabled_patterns:
    - phi_exposure
    - hipaa_violations
    - medical_record_access
    - patient_data_exfiltration
  custom_patterns:
    phi_detection:
      patterns:
        - "\\b\\d{3}-\\d{2}-\\d{4}\\b"
        - "\\b\\d{10}\\b"
        - "DOB.*\\d{2}/\\d{2}/\\d{4}"
      severity: "critical"
      action: "immediate_alert"
    ehr_attacks:
      patterns:
        - "/ehr/patient.*union.*select"
        - "/portal/records.*script"
        - "/api/patient.*drop.*table"
      severity: "high"
audit:
  enabled: true
  hipaa_compliant: true
  requirements:
    - access_logs: true
    - modification_logs: true
    - disclosure_tracking: true
    - breach_documentation: true
  retention:
    audit_logs: "6_years"
    security_logs: "6_years"
    incident_reports: "6_years"
alerts:
  email:
    enabled: true
    encryption: "required"
    phi_scrubbing: true
  incident_management:
    enabled: true
    breach_notification: true
    notification_timeline: "60_seconds"
  compliance_reporting:
    enabled: true
    automated_reports: true
    regulatory_notifications: true
baa_compliance:
  enabled: true
  data_processing_agreement: true
  subcontractor_agreements: true
  breach_notification_procedures: true
```

______________________________________________________________________

## 📊 **Use Case Comparison Matrix**

| Feature                   | Small Business | Enterprise    | Cloud-Native | Government    | CDN/Edge     | Healthcare |
| ------------------------- | -------------- | ------------- | ------------ | ------------- | ------------ | ---------- |
| **Deployment Complexity** | Low            | High          | Medium       | High          | High         | Medium     |
| **Security Level**        | Basic          | Advanced      | Medium       | Maximum       | High         | High       |
| **Compliance**            | None           | SOX/PCI       | GDPR         | FISMA/FedRAMP | Regional     | HIPAA      |
| **Scalability**           | Single Node    | Multi-Site    | Auto-Scale   | Fixed         | Global       | Medium     |
| **Integration**           | Minimal        | Extensive     | Cloud-Native | Air-Gapped    | CDN-Specific | Healthcare |
| **Alerting**              | Email          | Multi-Channel | Webhooks     | Classified    | Edge/Central | Encrypted  |
| **Resource Usage**        | Low            | High          | Variable     | Medium        | Optimized    | Medium     |

## 🔧 **Implementation Guides**

### **Quick Deployment Script**

```bash
#!/bin/bash
# Universal deployment script with use case selection

read -p "Select use case [1-6]: 
1) Small Business
2) Enterprise  
3) Cloud-Native
4) Government
5) CDN/Edge
6) Healthcare
Choice: " use_case

case $use_case in
    1) CONFIG_TEMPLATE="small-business-settings.yaml" ;;
    2) CONFIG_TEMPLATE="enterprise-settings.yaml" ;;
    3) CONFIG_TEMPLATE="cloud-native-settings.yaml" ;;
    4) CONFIG_TEMPLATE="government-settings.yaml" ;;
    5) CONFIG_TEMPLATE="edge-settings.yaml" ;;
    6) CONFIG_TEMPLATE="healthcare-settings.yaml" ;;
    *) echo "Invalid choice"; exit 1 ;;
esac

echo "Deploying with $CONFIG_TEMPLATE..."
cp "config/templates/$CONFIG_TEMPLATE" "config/settings.yaml"
sudo ./install.sh
```

### **Migration Between Use Cases**

```bash
#!/bin/bash
# Migration script for changing use cases

OLD_CONFIG="$1"
NEW_CONFIG="$2"

# Backup current configuration
cp "$OLD_CONFIG" "$OLD_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"

# Migrate essential settings
python3 scripts/migrate_config.py --from "$OLD_CONFIG" --to "$NEW_CONFIG"

# Validate new configuration
python3 -m src.monitor_service --check-config "$NEW_CONFIG"

echo "Migration complete. Review $NEW_CONFIG before applying."
```

## 📚 **Related Documentation**

- [Installation Guide](INSTALLATION.md) - Detailed installation procedures
- [Configuration Guide](CONFIGURATION.md) - Complete configuration reference
- [Security Features](SECURITY_FEATURES.md) - Advanced security capabilities
- [Operations Guide](OPERATIONS_GUIDE.md) - Day-to-day operations
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions

______________________________________________________________________

*This use cases guide provides practical implementation examples for NGINX Security Monitor
across various organizational contexts. Each use case includes production-ready
configurations and deployment strategies.*
