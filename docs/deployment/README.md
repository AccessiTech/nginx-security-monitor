# Deployment Guide

This guide covers deploying Nginx Security Monitor across different environments
with security best practices and configuration templates.

## Overview

Nginx Security Monitor can be deployed in various configurations:

- **Development**: Local testing and development
- **Staging**: Pre-production testing environment
- **Production**: Live production monitoring
  **High Availability**: Multi-node production setup

## Quick Deployment

### Docker Deployment (Recommended)

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t nginx-security-monitor .
docker run -d --name nsm \
  -v /var/log/nginx:/var/log/nginx:ro \
  -v ./config:/app/config \
  nginx-security-monitor
```

### Systemd Service Deployment

```bash
# Install and configure
sudo ./install.sh

# Enable and start service
sudo systemctl enable nginx-security-monitor
sudo systemctl start nginx-security-monitor

# Check status
sudo systemctl status nginx-security-monitor
```

## Environment-Specific Guides

- [Development Environment](development.md)
- [Staging Environment](staging.md)

## Configuration Management

### Environment Variables

```bash
# Required variables
export NSM_CONFIG_PATH=/opt/nginx-security-monitor/config
export NSM_LOG_LEVEL=INFO
export NSM_NGINX_LOG_PATH=/var/log/nginx/access.log

# Optional variables
export NSM_ALERT_EMAIL=admin@example.com
export NSM_ENCRYPTION_KEY_PATH=/opt/nginx-security-monitor/keys/encryption.key
```

### Configuration Templates

Pre-configured templates are available in `config/templates/`:

- `development.yaml`: Local development settings
- `staging.yaml`: Staging environment configuration
- `production.yaml`: Production-ready configuration
- `high-availability.yaml`: Multi-node setup

## Security Considerations

### File Permissions

```bash
# Set secure permissions
sudo chown -R nsm:nsm /opt/nginx-security-monitor/
sudo chmod 600 /opt/nginx-security-monitor/config/*.yaml
sudo chmod 600 /opt/nginx-security-monitor/keys/*
```

### Network Security

- Configure firewall rules for monitoring ports
- Use TLS for external integrations
- Implement proper network segmentation
- Enable audit logging

### Access Control

- Run service with dedicated user account
- Implement proper RBAC for configuration access
- Use encrypted configuration storage
- Regular security audits

## Monitoring and Health Checks

### Health Check Endpoints

```bash
# Service health
curl http://localhost:8080/health

# Configuration status
curl http://localhost:8080/config/status

# Integration status
curl http://localhost:8080/integrations/status
```

### Monitoring Metrics

- Detection rate and accuracy
- Response time and latency
- Integration connectivity
- Resource utilization

## Backup and Recovery

### Configuration Backup

```bash
# Automated backup script
./scripts/backup-config.sh

# Manual backup
tar -czf nsm-config-$(date +%Y%m%d).tar.gz /opt/nginx-security-monitor/
```

### Disaster Recovery

1. **Prepare Recovery Environment**
1. **Restore Configuration Files**
1. **Verify Integration Connectivity**
1. **Test Detection Capabilities**
1. **Resume Monitoring**

See [Disaster Recovery Guide](../operations/disaster-recovery.md) for detailed procedures.

## Scaling and Performance

### Horizontal Scaling

- Load balancer configuration
- Shared configuration storage
- Distributed alerting
- Centralized logging

### Performance Tuning

- Log processing optimization
- Pattern matching efficiency
- Memory and CPU optimization
- Network throughput tuning

## Troubleshooting

### Common Deployment Issues

1. **Permission Errors**

   ```bash
   sudo chown -R nsm:nsm /var/log/nginx-security-monitor/
   ```

1. **Configuration Validation**

   ```bash
   python -m nginx_security_monitor.config validate
   ```

1. **Service Startup Issues**

   ```bash
   sudo journalctl -u nginx-security-monitor -f
   ```

### Log Analysis

```bash
# Service logs
tail -f /var/log/nginx-security-monitor/service.log

# Error logs
grep ERROR /var/log/nginx-security-monitor/error.log

# Debug information
export NSM_LOG_LEVEL=DEBUG
sudo systemctl restart nginx-security-monitor
```

## Migration Guide

### Upgrading from Previous Versions

1. **Backup Current Configuration**
1. **Review Migration Notes**
1. **Update Configuration Format**
1. **Test in Staging Environment**
1. **Deploy to Production**

### Configuration Migration

```bash
# Migrate configuration
python scripts/migrate-config.py --from-version 1.0 --to-version 2.0

# Validate migrated configuration
python -m nginx_security_monitor.config validate --config migrated-config.yaml
```

## Automation and CI/CD

### Automated Deployment

```yaml
# GitHub Actions example
name: Deploy to Production
on:
  push:
    tags: ['v*']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy to production
        run: |
          ansible-playbook deploy.yml -i production
```

### Infrastructure as Code

- Terraform configurations
- Ansible playbooks
- Kubernetes manifests
- Docker Compose files

## Support and Maintenance

### Regular Maintenance Tasks

- Configuration updates
- Pattern rule updates
- Security patches
- Performance monitoring
- Backup verification

### Support Channels

- **Documentation**: [docs/](../)
- **Issues**: GitHub Issues
- **Emergency**: Contact your system administrator

______________________________________________________________________

**Related Documentation:**

- [Installation Guide](../INSTALLATION.md)
- [Configuration Guide](../CONFIGURATION.md)
- [Operations Guide](../OPERATIONS_GUIDE.md)
- [Security Features](../SECURITY_FEATURES.md)
