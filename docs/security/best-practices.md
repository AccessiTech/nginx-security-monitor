# Security Best Practices

This guide provides comprehensive security recommendations for deploying and operating Nginx Security Monitor in production environments.

## Security Architecture Overview

Nginx Security Monitor implements multiple layers of security:

1. **Input Validation**: All log data and configuration inputs are validated
1. **Encryption**: Sensitive data encrypted at rest and in transit
1. **Access Control**: Role-based access control and least privilege principles
1. **Audit Logging**: Comprehensive security event logging
1. **Network Security**: Secure communication protocols and network segmentation

## Installation Security

### System Hardening

```bash
# Run the provided hardening script
sudo ./harden.sh

# This script configures:
# - Secure file permissions
# - User account restrictions
# - Network security settings
# - System auditing
```

### Secure Installation

```bash
# Install with security hardening
sudo ./install.sh --secure

# Verify security configuration
sudo ./scripts/security-audit.sh
```

### File System Security

```bash
# Set proper ownership and permissions
sudo chown -R nsm:nsm /etc/nginx-security-monitor/
sudo chmod 750 /etc/nginx-security-monitor/
sudo chmod 640 /etc/nginx-security-monitor/config/*.yaml
sudo chmod 600 /etc/nginx-security-monitor/keys/*

# Protect log directories
sudo chown nsm:adm /var/log/nginx-security-monitor/
sudo chmod 750 /var/log/nginx-security-monitor/
```

## Configuration Security

### Encryption Configuration

```yaml
# config/security.yaml
security:
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    key_file: "/etc/nginx-security-monitor/keys/encryption.key"
    rotate_interval: "30d"
    
  patterns:
    encrypt_storage: true
    integrity_check: true
    signature_validation: true

  communications:
    tls_version: "1.3"
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
    certificate_validation: true
```

### Key Management

```bash
# Generate encryption keys
python encrypt_config.py --generate-key --key-file /etc/nginx-security-monitor/keys/encryption.key

# Set secure permissions
sudo chown nsm:nsm /etc/nginx-security-monitor/keys/encryption.key
sudo chmod 600 /etc/nginx-security-monitor/keys/encryption.key

# Key rotation
python encrypt_config.py --rotate-key --backup-old-key
```

### Secure Configuration Templates

```yaml
# Production security configuration
security:
  authentication:
    required: true
    method: "certificate"  # or "token", "oauth2"
    certificate_file: "/etc/ssl/certs/nsm-client.crt"
    private_key_file: "/etc/ssl/private/nsm-client.key"
    
  authorization:
    rbac_enabled: true
    default_role: "readonly"
    admin_users:
      - "admin@example.com"
    
  audit:
    enabled: true
    log_file: "/var/log/nginx-security-monitor/audit.log"
    log_level: "INFO"
    include_patterns:
      - "config_change"
      - "access_denied"
      - "pattern_match"
      - "integration_error"
```

## Network Security

### TLS Configuration

```yaml
# Secure communication settings
integrations:
  webhooks:
    tls:
      verify_certificates: true
      min_version: "1.2"
      cipher_suites: "ECDHE-RSA-AES256-GCM-SHA384"
      
  email:
    smtp:
      starttls: true
      verify_certificates: true
      
  syslog:
    tls_enabled: true
    certificate_file: "/etc/ssl/certs/syslog-client.crt"
```

### Firewall Configuration

```bash
# UFW rules
sudo ufw allow from 192.168.1.0/24 to any port 8080
sudo ufw allow from 10.0.0.0/8 to any port 514
sudo ufw deny 8080
sudo ufw deny 514

# iptables rules
sudo iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### Network Segmentation

- **Management Network**: Configuration and monitoring access
- **Log Collection Network**: Nginx log data ingestion
- **Alert Network**: Outbound notifications and integrations
- **DMZ**: Public-facing monitoring interfaces (if needed)

## Access Control

### User Management

```bash
# Create dedicated service user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/nginx-security-monitor nsm

# Add user to required groups
sudo usermod -a -G adm,syslog nsm

# Lock user account for security
sudo passwd -l nsm
```

### Role-Based Access Control

```yaml
# RBAC configuration
authorization:
  roles:
    admin:
      permissions:
        - "config:read"
        - "config:write"
        - "patterns:read"
        - "patterns:write"
        - "alerts:read"
        - "audit:read"
        
    operator:
      permissions:
        - "config:read"
        - "patterns:read"
        - "alerts:read"
        
    readonly:
      permissions:
        - "status:read"
        - "metrics:read"
        
  users:
    "admin@example.com":
      role: "admin"
      certificate_dn: "CN=admin,O=Example Corp"
      
    "operator@example.com":
      role: "operator"
      certificate_dn: "CN=operator,O=Example Corp"
```

## Runtime Security

### Process Security

```bash
# Systemd security features
[Service]
User=nsm
Group=nsm
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/nginx-security-monitor
CapabilityBoundingSet=CAP_DAC_OVERRIDE
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
```

### Container Security

```dockerfile
# Secure Dockerfile practices
FROM python:3.9-slim

# Create non-root user
RUN groupadd -r nsm && useradd -r -g nsm nsm

# Set security options
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy and set permissions
COPY --chown=nsm:nsm . /app
WORKDIR /app

# Switch to non-root user
USER nsm

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8080/health')"
```

### Resource Limits

```yaml
# Resource constraints
limits:
  memory:
    max_usage: "512MB"
    warning_threshold: "80%"
    
  cpu:
    max_usage: "2 cores"
    priority: "normal"
    
  disk:
    log_rotation: "daily"
    max_log_size: "100MB"
    retention_days: 30
    
  network:
    max_connections: 100
    rate_limit: "1000/minute"
```

## Monitoring and Alerting

### Security Monitoring

```yaml
# Security monitoring configuration
monitoring:
  security_events:
    - "failed_authentication"
    - "unauthorized_access"
    - "configuration_change"
    - "pattern_tampering"
    - "integration_failure"
    
  thresholds:
    failed_auth_rate: 5  # per minute
    config_changes: 1    # per hour
    pattern_violations: 10  # per minute
    
  alerts:
    security_team: "security@example.com"
    escalation_time: "15m"
    severity_levels: ["critical", "high", "medium", "low"]
```

### Audit Logging

```yaml
# Comprehensive audit configuration
audit:
  enabled: true
  format: "json"
  include_metadata: true
  
  events:
    authentication:
      success: true
      failure: true
      
    authorization:
      granted: true
      denied: true
      
    configuration:
      read: false
      write: true
      delete: true
      
    patterns:
      match: true
      update: true
      
    integrations:
      connect: true
      error: true
```

## Incident Response

### Security Incident Procedures

1. **Detection and Analysis**

   - Monitor security alerts
   - Analyze threat indicators
   - Assess impact and scope

1. **Containment**

   - Isolate affected systems
   - Prevent further compromise
   - Preserve evidence

1. **Eradication and Recovery**

   - Remove threats
   - Restore systems
   - Implement additional controls

1. **Post-Incident Activities**

   - Document lessons learned
   - Update security controls
   - Conduct security review

### Emergency Response

```bash
# Emergency lockdown
sudo systemctl stop nginx-security-monitor
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP

# Forensic data collection
sudo tar -czf incident-$(date +%Y%m%d-%H%M%S).tar.gz \
  /var/log/nginx-security-monitor/ \
  /etc/nginx-security-monitor/config/ \
  /var/log/audit/

# System isolation
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP
```

## Compliance and Standards

### Security Frameworks

- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover
- **ISO 27001**: Information Security Management System
- **CIS Controls**: Critical Security Controls
- **OWASP**: Web Application Security

### Compliance Requirements

```yaml
# Compliance configuration
compliance:
  frameworks:
    - "SOC2"
    - "ISO27001"
    - "GDPR"
    - "HIPAA"
    
  controls:
    data_encryption: true
    access_logging: true
    user_authentication: true
    data_retention: "5 years"
    
  reporting:
    frequency: "monthly"
    format: "json"
    recipients:
      - "compliance@example.com"
      - "security@example.com"
```

## Security Testing

### Vulnerability Assessment

```bash
# Security scanning
nmap -sS -O target-server
nikto -h http://target-server:8080
sqlmap -u "http://target-server:8080/api/config"

# Dependency scanning
safety check
bandit -r src/

# Container scanning
docker scan nginx-security-monitor:latest
```

### Penetration Testing

```bash
# Test authentication bypass
curl -X POST http://target:8080/api/config \
  -H "Content-Type: application/json" \
  -d '{"test": "unauthorized"}'

# Test injection attacks
curl http://target:8080/api/search?q='; DROP TABLE patterns; --

# Test privilege escalation
curl -X PUT http://target:8080/api/users/admin \
  -H "Authorization: Bearer low-priv-token"
```

## Regular Security Tasks

### Daily Tasks

- Monitor security alerts
- Review audit logs
- Check system integrity
- Verify backup completion

### Weekly Tasks

- Review user access
- Update threat patterns
- Check certificate expiration
- Analyze security metrics

### Monthly Tasks

- Security patch updates
- Vulnerability assessments
- Access control review
- Incident response testing

### Quarterly Tasks

- Security architecture review
- Penetration testing
- Compliance audits
- Security training updates

## Emergency Contacts

```yaml
# Emergency contact configuration
emergency_contacts:
  security_team:
    email: "security@example.com"
    phone: "+1-555-SECURITY"
    escalation_time: "15 minutes"
    
  incident_response:
    email: "ir@example.com"
    phone: "+1-555-INCIDENT"
    24x7: true
    
  vendor_support:
    email: "support@nginx-security-monitor.com"
    phone: "+1-555-SUPPORT"
    hours: "business"
```

______________________________________________________________________

**Related Documentation:**

- [Security Features](../SECURITY_FEATURES.md)
- [Encryption Guide](../ENCRYPTION_GUIDE.md)
- [Configuration Guide](../CONFIGURATION.md)
- [Operations Guide](../OPERATIONS_GUIDE.md)
