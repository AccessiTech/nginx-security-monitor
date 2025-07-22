# Disaster Recovery Procedures

This guide provides comprehensive disaster recovery procedures for Nginx Security Monitor,
including backup strategies, recovery procedures, and incident response protocols.

## Overview

Disaster recovery (DR) for Nginx Security Monitor involves protecting and restoring:

- **Configuration data**: Settings, patterns, and encryption keys
- **Historical data**: Logs, alerts, and security events
- **System state**: Service configurations and integrations
- **Operational continuity**: Monitoring capabilities and alerting

## Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)

| Component       | RTO Target | RPO Target | Priority |
| --------------- | ---------- | ---------- | -------- |
| Core Monitoring | 15 minutes | 5 minutes  | Critical |
| Configuration   | 5 minutes  | 1 hour     | Critical |
| Historical Data | 4 hours    | 24 hours   | High     |
| Integrations    | 30 minutes | 1 hour     | High     |
| Reporting       | 24 hours   | 24 hours   | Medium   |

## Backup Strategies

### Automated Backup Configuration

```yaml
# backup configuration in config/backup.yaml
backup:
  enabled: true
  schedule: "0 2 * * *"  # Daily at 2 AM
  retention:
    daily: 7
    weekly: 4
    monthly: 12
    yearly: 3
    
  targets:
    configuration:
      enabled: true
      path: "/etc/nginx-security-monitor/"
      encryption: true
      
    logs:
      enabled: true
      path: "/var/log/nginx-security-monitor/"
      compression: true
      retention_days: 90
      
    database:
      enabled: true
      type: "full"
      compression: true
      
  destinations:
    - type: "s3"
      bucket: "nsm-backups"
      region: "us-east-1"
      encryption: "AES256"
      
    - type: "local"
      path: "/backup/nginx-security-monitor/"
      
    - type: "remote"
      host: "backup.example.com"
      path: "/backups/nsm/"
      method: "rsync"
```

### Backup Scripts

```bash
#!/bin/bash
# scripts/backup.sh - Automated backup script

set -euo pipefail

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/nginx-security-monitor"
CONFIG_DIR="/etc/nginx-security-monitor"
LOG_DIR="/var/log/nginx-security-monitor"
S3_BUCKET="nsm-backups"

# Create backup directory
mkdir -p "$BACKUP_DIR/$BACKUP_DATE"

# Backup configuration files
echo "Backing up configuration..."
tar -czf "$BACKUP_DIR/$BACKUP_DATE/config.tar.gz" \
    -C "$CONFIG_DIR" \
    --exclude="*.tmp" \
    --exclude="*.lock" \
    .

# Backup logs (compressed)
echo "Backing up logs..."
tar -czf "$BACKUP_DIR/$BACKUP_DATE/logs.tar.gz" \
    -C "$LOG_DIR" \
    --exclude="*.tmp" \
    .

# Backup database
echo "Backing up database..."
sqlite3 /var/lib/nginx-security-monitor/data.db ".backup '$BACKUP_DIR/$BACKUP_DATE/database.db'"

# Create backup manifest
cat > "$BACKUP_DIR/$BACKUP_DATE/manifest.json" << EOF
{
  "timestamp": "$(date -Iseconds)",
  "version": "$(python -m nginx_security_monitor --version)",
  "hostname": "$(hostname)",
  "files": {
    "config": "config.tar.gz",
    "logs": "logs.tar.gz",
    "database": "database.db"
  },
  "checksums": {
    "config": "$(sha256sum $BACKUP_DIR/$BACKUP_DATE/config.tar.gz | cut -d' ' -f1)",
    "logs": "$(sha256sum $BACKUP_DIR/$BACKUP_DATE/logs.tar.gz | cut -d' ' -f1)",
    "database": "$(sha256sum $BACKUP_DIR/$BACKUP_DATE/database.db | cut -d' ' -f1)"
  }
}
EOF

# Upload to S3 (if configured)
if command -v aws &> /dev/null; then
    echo "Uploading to S3..."
    aws s3 sync "$BACKUP_DIR/$BACKUP_DATE/" "s3://$S3_BUCKET/$BACKUP_DATE/" \
        --storage-class STANDARD_IA \
        --server-side-encryption AES256
fi

# Cleanup old backups (keep last 7 days locally)
find "$BACKUP_DIR" -type d -name "20*" -mtime +7 -exec rm -rf {} \;

echo "Backup completed: $BACKUP_DATE"
```

### Backup Validation Script

```bash
#!/bin/bash
# scripts/validate-backup.sh - Backup validation script

BACKUP_PATH="$1"

if [ -z "$BACKUP_PATH" ]; then
    echo "Usage: $0 <backup_path>"
    exit 1
fi

echo "Validating backup at: $BACKUP_PATH"

# Check manifest file
if [ ! -f "$BACKUP_PATH/manifest.json" ]; then
    echo "ERROR: Missing manifest.json"
    exit 1
fi

# Validate checksums
echo "Validating checksums..."
MANIFEST="$BACKUP_PATH/manifest.json"

for file in config.tar.gz logs.tar.gz database.db; do
    if [ -f "$BACKUP_PATH/$file" ]; then
        EXPECTED=$(jq -r ".checksums.${file%.*}" "$MANIFEST")
        ACTUAL=$(sha256sum "$BACKUP_PATH/$file" | cut -d' ' -f1)
        
        if [ "$EXPECTED" = "$ACTUAL" ]; then
            echo "✓ $file checksum valid"
        else
            echo "✗ $file checksum mismatch"
            exit 1
        fi
    else
        echo "✗ Missing file: $file"
        exit 1
    fi
done

# Test archive integrity
echo "Testing archive integrity..."
tar -tzf "$BACKUP_PATH/config.tar.gz" > /dev/null && echo "✓ config.tar.gz integrity OK"
tar -tzf "$BACKUP_PATH/logs.tar.gz" > /dev/null && echo "✓ logs.tar.gz integrity OK"

# Test database integrity
echo "Testing database integrity..."
sqlite3 "$BACKUP_PATH/database.db" "PRAGMA integrity_check;" | grep -q "ok" && echo "✓ database.db integrity OK"

echo "Backup validation completed successfully"
```

## Recovery Procedures

### Full System Recovery

```bash
#!/bin/bash
# scripts/disaster-recovery.sh - Full system recovery script

set -euo pipefail

BACKUP_PATH="$1"
RECOVERY_MODE="${2:-full}"  # full, config-only, data-only

if [ -z "$BACKUP_PATH" ]; then
    echo "Usage: $0 <backup_path> [recovery_mode]"
    exit 1
fi

echo "Starting disaster recovery from: $BACKUP_PATH"
echo "Recovery mode: $RECOVERY_MODE"

# Validate backup before proceeding
./scripts/validate-backup.sh "$BACKUP_PATH"

# Stop services
echo "Stopping nginx-security-monitor service..."
sudo systemctl stop nginx-security-monitor

# Backup current state (if exists)
if [ -d "/etc/nginx-security-monitor" ]; then
    echo "Backing up current state..."
    sudo mv /etc/nginx-security-monitor /etc/nginx-security-monitor.recovery-backup-$(date +%Y%m%d_%H%M%S)
fi

# Recovery based on mode
case "$RECOVERY_MODE" in
    "full"|"config-only")
        echo "Restoring configuration..."
        sudo mkdir -p /etc/nginx-security-monitor
        sudo tar -xzf "$BACKUP_PATH/config.tar.gz" -C /etc/nginx-security-monitor/
        sudo chown -R nsm:nsm /etc/nginx-security-monitor/
        sudo chmod -R 640 /etc/nginx-security-monitor/config/
        sudo chmod 600 /etc/nginx-security-monitor/keys/*
        ;;
esac

case "$RECOVERY_MODE" in
    "full"|"data-only")
        echo "Restoring database..."
        sudo mkdir -p /var/lib/nginx-security-monitor
        sudo cp "$BACKUP_PATH/database.db" /var/lib/nginx-security-monitor/data.db
        sudo chown nsm:nsm /var/lib/nginx-security-monitor/data.db
        sudo chmod 640 /var/lib/nginx-security-monitor/data.db
        
        echo "Restoring logs..."
        sudo mkdir -p /var/log/nginx-security-monitor
        sudo tar -xzf "$BACKUP_PATH/logs.tar.gz" -C /var/log/nginx-security-monitor/
        sudo chown -R nsm:adm /var/log/nginx-security-monitor/
        ;;
esac

# Validate configuration
echo "Validating configuration..."
python -m nginx_security_monitor.config validate

# Start services
echo "Starting nginx-security-monitor service..."
sudo systemctl start nginx-security-monitor

# Wait for service to be ready
echo "Waiting for service to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:8080/health > /dev/null; then
        echo "Service is ready"
        break
    fi
    sleep 2
done

# Run post-recovery validation
echo "Running post-recovery validation..."
./scripts/post-recovery-validation.sh

echo "Disaster recovery completed successfully"
```

### Configuration-Only Recovery

```bash
#!/bin/bash
# scripts/config-recovery.sh - Configuration-only recovery

BACKUP_PATH="$1"

echo "Performing configuration-only recovery..."

# Stop service temporarily
sudo systemctl stop nginx-security-monitor

# Restore configuration
sudo tar -xzf "$BACKUP_PATH/config.tar.gz" -C /etc/nginx-security-monitor/

# Validate configuration
python -m nginx_security_monitor.config validate

# Restart service
sudo systemctl start nginx-security-monitor

echo "Configuration recovery completed"
```

### Database Recovery

```bash
#!/bin/bash
# scripts/database-recovery.sh - Database recovery procedures

BACKUP_PATH="$1"
RECOVERY_TYPE="${2:-replace}"  # replace, merge

echo "Performing database recovery..."

case "$RECOVERY_TYPE" in
    "replace")
        echo "Replacing database..."
        sudo systemctl stop nginx-security-monitor
        sudo cp "$BACKUP_PATH/database.db" /var/lib/nginx-security-monitor/data.db
        sudo chown nsm:nsm /var/lib/nginx-security-monitor/data.db
        sudo systemctl start nginx-security-monitor
        ;;
        
    "merge")
        echo "Merging database..."
        # Create temporary database for merging
        sqlite3 /tmp/merged.db < scripts/sql/create_tables.sql
        
        # Import backup data
        sqlite3 /tmp/merged.db ".restore '$BACKUP_PATH/database.db'"
        
        # Merge with current data (implement merge logic)
        python scripts/merge-databases.py \
            --source /var/lib/nginx-security-monitor/data.db \
            --backup /tmp/merged.db \
            --output /var/lib/nginx-security-monitor/data.db.new
            
        sudo systemctl stop nginx-security-monitor
        sudo mv /var/lib/nginx-security-monitor/data.db.new /var/lib/nginx-security-monitor/data.db
        sudo chown nsm:nsm /var/lib/nginx-security-monitor/data.db
        sudo systemctl start nginx-security-monitor
        ;;
esac

echo "Database recovery completed"
```

## Post-Recovery Validation

<!-- markdownlint-disable MD013 -->

```bash
#!/bin/bash
# scripts/post-recovery-validation.sh - Post-recovery system validation

echo "Running post-recovery validation..."

# Test service health
echo "Testing service health..."
if ! curl -s http://localhost:8080/health | grep -q "healthy"; then
    echo "ERROR: Service health check failed"
    exit 1
fi
echo "✓ Service health OK"

# Test configuration loading
echo "Testing configuration..."
if ! python -c "from nginx_security_monitor.config import load_config; load_config()"; then
    echo "ERROR: Configuration loading failed"
    exit 1
fi
echo "✓ Configuration loading OK"

# Test pattern loading
echo "Testing pattern loading..."
if ! python -c "from nginx_security_monitor.patterns import load_patterns; load_patterns()"; then
    echo "ERROR: Pattern loading failed"
    exit 1
fi
echo "✓ Pattern loading OK"

# Test database connectivity
echo "Testing database..."
if ! python -c "from nginx_security_monitor.database import test_connection; test_connection()"; then
    echo "ERROR: Database connection failed"
    exit 1
fi
echo "✓ Database connection OK"

# Test integrations
echo "Testing integrations..."
python scripts/test-integrations.py --quick

# Generate test log entry
echo "Testing log processing..."
echo "$(date --iso-8601=seconds) 192.168.1.100 - - [$(date '+%d/%b/%Y:%H:%M:%S %z')] \"GET /test-recovery HTTP/1.1\" 200 1234" >> /var/log/nginx/access.log

# Wait for processing
sleep 5

# Check if test entry was processed
if ! grep -q "test-recovery" /var/log/nginx-security-monitor/processed.log; then
    echo "WARNING: Log processing test may have failed"
else
    echo "✓ Log processing OK"
fi

echo "Post-recovery validation completed"
```

<!-- markdownlint-enable MD013 -->

## High Availability and Failover

### Active-Passive Configuration

```yaml
# ha-config.yaml - High availability configuration
high_availability:
  mode: "active_passive"
  
  primary:
    hostname: "nsm-primary.example.com"
    ip: "192.168.1.10"
    priority: 100
    
  secondary:
    hostname: "nsm-secondary.example.com"
    ip: "192.168.1.11"
    priority: 90
    
  shared_storage:
    type: "nfs"
    mount_point: "/shared/nginx-security-monitor"
    
  failover:
    health_check_interval: 30
    failure_threshold: 3
    automatic_failover: true
    
  synchronization:
    config_sync: true
    log_sync: true
    database_replication: true
```

### Failover Script

```bash
#!/bin/bash
# scripts/failover.sh - Automatic failover script

ROLE="$1"  # primary or secondary
PEER_IP="$2"

case "$ROLE" in
    "primary")
        echo "Starting as primary node..."
        
        # Mount shared storage
        sudo mount -t nfs nfs-server:/shared/nsm /shared/nginx-security-monitor
        
        # Start service
        sudo systemctl start nginx-security-monitor
        
        # Monitor secondary
        while true; do
            if ! ping -c 1 "$PEER_IP" > /dev/null 2>&1; then
                echo "Secondary node unreachable - continuing as primary"
            fi
            sleep 30
        done
        ;;
        
    "secondary")
        echo "Starting as secondary node..."
        
        # Monitor primary
        while true; do
            if ! curl -s "http://$PEER_IP:8080/health" > /dev/null; then
                echo "Primary node failed - initiating failover"
                
                # Mount shared storage
                sudo mount -t nfs nfs-server:/shared/nsm /shared/nginx-security-monitor
                
                # Start service
                sudo systemctl start nginx-security-monitor
                
                # Update DNS/load balancer
                python scripts/update-dns.py --promote-secondary
                
                # Become primary
                exec "$0" primary "$PEER_IP"
            fi
            sleep 30
        done
        ;;
esac
```

## Data Protection and Compliance

### Encryption at Rest

```bash
# Setup encrypted backup storage
cryptsetup luksFormat /dev/sdb1
cryptsetup luksOpen /dev/sdb1 backup_storage
mkfs.ext4 /dev/mapper/backup_storage
mount /dev/mapper/backup_storage /backup/encrypted
```

### GDPR Compliance

```yaml
# GDPR compliance configuration
data_protection:
  gdpr:
    enabled: true
    
    data_retention:
      personal_data: "2 years"
      security_logs: "7 years"
      audit_logs: "10 years"
      
    data_anonymization:
      ip_addresses: true
      user_agents: false
      
    right_to_erasure:
      enabled: true
      verification_required: true
      
    data_export:
      formats: ["json", "csv"]
      encryption: true
```

## Incident Response Integration

### Security Incident Procedures

```bash
#!/bin/bash
# scripts/security-incident-response.sh

INCIDENT_TYPE="$1"
SEVERITY="$2"

echo "Security incident detected: $INCIDENT_TYPE (Severity: $SEVERITY)"

case "$SEVERITY" in
    "critical")
        # Immediate response
        echo "CRITICAL: Initiating emergency procedures"
        
        # Isolate system
        sudo iptables -P INPUT DROP
        sudo iptables -P FORWARD DROP
        
        # Preserve evidence
        ./scripts/preserve-evidence.sh
        
        # Notify security team
        curl -X POST "$SECURITY_WEBHOOK" \
            -H "Content-Type: application/json" \
            -d "{\"incident\": \"$INCIDENT_TYPE\", \"severity\": \"$SEVERITY\", \"timestamp\": \"$(date -Iseconds)\"}"
        ;;
        
    "high")
        # Enhanced monitoring
        echo "HIGH: Increasing monitoring and logging"
        
        # Enable debug logging
        sed -i 's/level: INFO/level: DEBUG/' /etc/nginx-security-monitor/config/settings.yaml
        sudo systemctl reload nginx-security-monitor
        
        # Backup current state
        ./scripts/backup.sh
        ;;
esac
```

## Testing and Drills

### Monthly DR Drill

```bash
#!/bin/bash
# scripts/dr-drill.sh - Monthly disaster recovery drill

echo "Starting DR drill: $(date)"

# Create test environment
./scripts/setup-test-environment.sh

# Simulate failure
./scripts/simulate-failure.sh --type random

# Perform recovery
./scripts/disaster-recovery.sh /backup/test-data/

# Validate recovery
./scripts/post-recovery-validation.sh

# Generate report
./scripts/generate-dr-report.sh --drill-date "$(date +%Y%m%d)"

echo "DR drill completed"
```

### Recovery Time Testing

```bash
#!/bin/bash
# scripts/rto-test.sh - Recovery Time Objective testing

START_TIME=$(date +%s)

# Simulate disaster
./scripts/simulate-disaster.sh

# Perform recovery
./scripts/disaster-recovery.sh /backup/latest/

# Measure recovery time
END_TIME=$(date +%s)
RECOVERY_TIME=$((END_TIME - START_TIME))

echo "Recovery completed in $RECOVERY_TIME seconds"

# Check if within RTO
if [ $RECOVERY_TIME -le 900 ]; then  # 15 minutes
    echo "✓ Recovery within RTO target"
else
    echo "✗ Recovery exceeded RTO target"
fi
```

## Documentation and Runbooks

### Emergency Contact List

```yaml
# Emergency contacts configuration
emergency_contacts:
  primary_oncall:
    name: "Primary On-Call Engineer"
    phone: "+1-555-PRIMARY"
    email: "oncall@example.com"
    
  security_team:
    name: "Security Incident Response"
    phone: "+1-555-SECURITY"
    email: "security@example.com"
    
  management:
    name: "IT Management"
    phone: "+1-555-MANAGER"
    email: "it-manager@example.com"
    
  vendors:
    cloud_provider:
      name: "AWS Support"
      phone: "+1-800-AWS-SUPPORT"
      case_priority: "urgent"
```

### Recovery Checklists

```markdown
## Critical System Failure Checklist

### Immediate Response (0-15 minutes)
- [ ] Confirm system failure
- [ ] Notify on-call team
- [ ] Assess impact scope
- [ ] Activate backup systems
- [ ] Preserve evidence

### Recovery Actions (15-60 minutes)
- [ ] Identify root cause
- [ ] Select recovery strategy
- [ ] Execute recovery procedure
- [ ] Validate system functionality
- [ ] Update status page

### Post-Recovery (1-24 hours)
- [ ] Complete system validation
- [ ] Document incident
- [ ] Conduct post-mortem
- [ ] Update procedures
- [ ] Test backup systems
```

______________________________________________________________________

**Related Documentation:**

- [Operations Guide](../OPERATIONS_GUIDE.md)
- [Security Best Practices](../security/best-practices.md)
- [Performance Tuning](performance-tuning.md)
- [Monitoring Guide](monitoring.md)
