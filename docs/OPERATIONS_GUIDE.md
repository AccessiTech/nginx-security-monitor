# 🔧 Operations Guide - NGINX Security Monitor

## 🎯 **Overview**

This guide covers day-to-day operations and maintenance of the NGINX Security Monitor in production environments. It
includes service monitoring, health checks, log management, backup procedures, and operational best practices for
maintaining a secure and reliable security monitoring infrastructure.

**💡 Quick CLI Reference**: For command-line operations, see the [CLI Reference Guide](CLI_REFERENCE.md).

## 🚀 **Service Management**

### **Command Line Interface**

Use the CLI utilities for routine operations:

```bash
# Start monitoring service
./bin/nginx-security-monitor start config/settings.yaml

# Check service status and health
./bin/health-check

# Monitor real-time dashboard
./bin/monitor-dashboard

# Validate configuration before changes
./bin/validate-config config/settings.yaml

# Test alert systems
./bin/test-alerts

# Run system maintenance
./bin/maintenance
```

### **Systemd Service Control**

The NGINX Security Monitor runs as a systemd service for reliable operation:

#### **Service Commands**

```bash
# Start the service
sudo systemctl start nginx-security-monitor

# Stop the service
sudo systemctl stop nginx-security-monitor

# Restart the service
sudo systemctl restart nginx-security-monitor

# Reload configuration without restart
sudo systemctl reload nginx-security-monitor

# Check service status
sudo systemctl status nginx-security-monitor

# Enable auto-start on boot
sudo systemctl enable nginx-security-monitor

# View service logs
sudo journalctl -u nginx-security-monitor -f

# View logs for specific time period
sudo journalctl -u nginx-security-monitor --since "2024-01-01" --until "2024-01-02"
```

#### **Service Configuration**

```ini
# /etc/systemd/system/nginx-security-monitor.service
[Unit]
Description=NGINX Security Monitor
After=network.target nginx.service
Wants=network.target

[Service]
Type=forking
User=nginx-security
Group=nginx-security
WorkingDirectory=/opt/nginx-security-monitor
ExecStart=/opt/nginx-security-monitor/nginx-security-monitor.sh start
ExecReload=/opt/nginx-security-monitor/nginx-security-monitor.sh reload
ExecStop=/opt/nginx-security-monitor/nginx-security-monitor.sh stop
PIDFile=/var/run/nginx-security-monitor.pid
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/nginx-security /var/lib/nginx-security /etc/nginx-security

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

### **Process Management**

#### **Multi-Process Architecture**

```bash
# Check running processes
ps aux | grep nginx-security

# Expected process tree:
# nginx-security-monitor (main process)
# ├── log-processor (worker)
# ├── pattern-detector (worker)
# ├── alert-manager (worker)
# ├── mitigation-engine (worker)
# └── web-interface (worker)

# Check process resource usage
top -p $(pgrep -d',' -f nginx-security)

# Monitor memory usage
ps -o pid,vsz,rss,comm -p $(pgrep -f nginx-security)
```

#### **Process Health Monitoring**

```python
# scripts/health_check.py
#!/usr/bin/env python3
"""Health check script for NGINX Security Monitor."""

import psutil
import requests
import json
import sys
import time
from typing import Dict, Any, List

class HealthChecker:
    """Comprehensive health check for security monitor."""
    
    def __init__(self, config_file: str = '/etc/nginx-security/health.yaml'):
        self.config = self._load_config(config_file)
        self.checks = {
            'process': self._check_processes,
            'memory': self._check_memory_usage,
            'disk': self._check_disk_space,
            'network': self._check_network_connectivity,
            'api': self._check_api_health,
            'database': self._check_database_connection,
            'log_processing': self._check_log_processing
        }
        
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks."""
        results = {
            'timestamp': time.time(),
            'overall_status': 'healthy',
            'checks': {}
        }
        
        for check_name, check_func in self.checks.items():
            try:
                check_result = check_func()
                results['checks'][check_name] = check_result
                
                if not check_result.get('healthy', False):
                    results['overall_status'] = 'unhealthy'
                    
            except Exception as e:
                results['checks'][check_name] = {
                    'healthy': False,
                    'error': str(e),
                    'status': 'check_failed'
                }
                results['overall_status'] = 'unhealthy'
        
        return results
    
    def _check_processes(self) -> Dict[str, Any]:
        """Check if all required processes are running."""
        required_processes = [
            'nginx-security-monitor',
            'log-processor',
            'pattern-detector',
            'alert-manager',
            'mitigation-engine'
        ]
        
        running_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            cmdline = ' '.join(proc.info['cmdline'] or [])
            for req_proc in required_processes:
                if req_proc in cmdline:
                    running_processes.append({
                        'name': req_proc,
                        'pid': proc.info['pid'],
                        'status': proc.status()
                    })
        
        missing_processes = [
            proc for proc in required_processes 
            if not any(rp['name'] == proc for rp in running_processes)
        ]
        
        return {
            'healthy': len(missing_processes) == 0,
            'running_processes': running_processes,
            'missing_processes': missing_processes,
            'total_processes': len(running_processes)
        }
    
    def _check_memory_usage(self) -> Dict[str, Any]:
        """Check memory usage of security monitor processes."""
        memory_threshold = self.config.get('memory_threshold_mb', 512)
        
        total_memory = 0
        process_memory = []
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            if 'nginx-security' in (proc.info['name'] or ''):
                mem_mb = proc.info['memory_info'].rss / 1024 / 1024
                total_memory += mem_mb
                process_memory.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'memory_mb': round(mem_mb, 2)
                })
        
        return {
            'healthy': total_memory < memory_threshold,
            'total_memory_mb': round(total_memory, 2),
            'threshold_mb': memory_threshold,
            'process_memory': process_memory
        }
    
    def _check_disk_space(self) -> Dict[str, Any]:
        """Check disk space for log directories."""
        paths_to_check = [
            '/var/log/nginx-security',
            '/var/lib/nginx-security',
            '/tmp'
        ]
        
        disk_usage = []
        all_healthy = True
        
        for path in paths_to_check:
            try:
                usage = psutil.disk_usage(path)
                used_percent = (usage.used / usage.total) * 100
                
                # Alert if over 80% full
                is_healthy = used_percent < 80
                all_healthy = all_healthy and is_healthy
                
                disk_usage.append({
                    'path': path,
                    'total_gb': round(usage.total / 1024**3, 2),
                    'used_gb': round(usage.used / 1024**3, 2),
                    'free_gb': round(usage.free / 1024**3, 2),
                    'used_percent': round(used_percent, 2),
                    'healthy': is_healthy
                })
            except Exception as e:
                disk_usage.append({
                    'path': path,
                    'error': str(e),
                    'healthy': False
                })
                all_healthy = False
        
        return {
            'healthy': all_healthy,
            'disk_usage': disk_usage
        }
    
    def _check_api_health(self) -> Dict[str, Any]:
        """Check API endpoint health."""
        api_url = self.config.get('api_url', 'http://localhost:8080')
        
        try:
            # Check health endpoint
            response = requests.get(f"{api_url}/health", timeout=10)
            
            if response.status_code == 200:
                health_data = response.json()
                return {
                    'healthy': health_data.get('status') == 'healthy',
                    'response_time_ms': response.elapsed.total_seconds() * 1000,
                    'api_version': health_data.get('version'),
                    'uptime_seconds': health_data.get('uptime')
                }
            else:
                return {
                    'healthy': False,
                    'error': f"HTTP {response.status_code}",
                    'response_text': response.text[:200]
                }
                
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e)
            }

if __name__ == "__main__":
    checker = HealthChecker()
    results = checker.run_all_checks()
    
    print(json.dumps(results, indent=2))
    
    # Exit with error code if unhealthy
    sys.exit(0 if results['overall_status'] == 'healthy' else 1)
```

### **Automated Health Monitoring**

#### **Monitoring Script Setup**

```bash
#!/bin/bash
# scripts/monitor_health.sh

HEALTH_CHECK_INTERVAL=60  # seconds
LOG_FILE="/var/log/nginx-security/health-monitor.log"
ALERT_THRESHOLD=3  # consecutive failures before alert

consecutive_failures=0

while true; do
    # Run health check
    if python3 /opt/nginx-security-monitor/scripts/health_check.py > /tmp/health_check.json 2>&1; then
        echo "$(date): Health check passed" >> "$LOG_FILE"
        consecutive_failures=0
    else
        consecutive_failures=$((consecutive_failures + 1))
        echo "$(date): Health check failed (attempt $consecutive_failures)" >> "$LOG_FILE"
        
        # Send alert if threshold reached
        if [ $consecutive_failures -ge $ALERT_THRESHOLD ]; then
            echo "$(date): Sending health alert after $consecutive_failures failures" >> "$LOG_FILE"
            
            # Send alert via configured channels
            python3 -m src.alert_manager send_alert \
                --type "system_health" \
                --severity "high" \
                --message "NGINX Security Monitor health check failed $consecutive_failures times" \
                --details "$(cat /tmp/health_check.json)"
            
            consecutive_failures=0  # Reset after sending alert
        fi
    fi
    
    sleep $HEALTH_CHECK_INTERVAL
done
```

#### **Cron-based Monitoring**

```bash
# Add to crontab
# Check health every 5 minutes
*/5 * * * * /opt/nginx-security-monitor/scripts/health_check.py >> /var/log/nginx-security/health.log 2>&1

# Daily health report
0 8 * * * /opt/nginx-security-monitor/scripts/daily_health_report.sh

# Weekly performance report
0 9 * * 1 /opt/nginx-security-monitor/scripts/weekly_performance_report.sh
```

______________________________________________________________________

## 📊 **Log Management**

### **Log File Structure**

```text
/var/log/nginx-security/
├── main.log                    # Main application log
├── threats.log                 # Detected threats
├── mitigation.log              # Mitigation actions
├── alerts.log                  # Alert delivery log
├── performance.log             # Performance metrics
├── integration.log             # External integration logs
├── error.log                   # Error logs
├── access.log                  # API access logs
├── audit.log                   # Security audit trail
└── archive/                    # Rotated log files
    ├── main.log.1.gz
    ├── threats.log.1.gz
    └── ...
```

### **Log Rotation Configuration**

```bash
# /etc/logrotate.d/nginx-security-monitor
/var/log/nginx-security/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 nginx-security nginx-security
    
    postrotate
        # Signal the service to reopen log files
        /bin/kill -USR1 $(cat /var/run/nginx-security-monitor.pid) 2>/dev/null || true
    endscript
}

# Separate configuration for high-volume logs
/var/log/nginx-security/threats.log
/var/log/nginx-security/mitigation.log {
    hourly
    missingok
    rotate 168  # Keep 7 days of hourly logs
    compress
    delaycompress
    notifempty
    create 644 nginx-security nginx-security
    
    postrotate
        /bin/kill -USR1 $(cat /var/run/nginx-security-monitor.pid) 2>/dev/null || true
    endscript
}
```

### **Log Analysis and Monitoring**

#### **Log Analysis Script**

```python
# scripts/log_analyzer.py
#!/usr/bin/env python3
"""Analyze NGINX Security Monitor logs for operational insights."""

import re
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, Any, List

class LogAnalyzer:
    """Analyze security monitor logs."""
    
    def __init__(self, log_dir: str = '/var/log/nginx-security'):
        self.log_dir = log_dir
        
    def analyze_threats(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze threat detection patterns."""
        threats_file = f"{self.log_dir}/threats.log"
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        threat_types = Counter()
        severity_counts = Counter()
        source_ips = Counter()
        hourly_counts = defaultdict(int)
        
        try:
            with open(threats_file, 'r') as f:
                for line in f:
                    try:
                        threat_data = json.loads(line.strip())
                        threat_time = datetime.fromisoformat(threat_data.get('timestamp', ''))
                        
                        if threat_time >= cutoff_time:
                            threat_types[threat_data.get('threat_type', 'unknown')] += 1
                            severity_counts[threat_data.get('severity', 'unknown')] += 1
                            source_ips[threat_data.get('source_ip', 'unknown')] += 1
                            
                            # Count by hour
                            hour_key = threat_time.strftime('%Y-%m-%d %H:00')
                            hourly_counts[hour_key] += 1
                            
                    except (json.JSONDecodeError, ValueError):
                        continue
                        
        except FileNotFoundError:
            return {'error': 'Threats log file not found'}
        
        return {
            'analysis_period_hours': hours,
            'total_threats': sum(threat_types.values()),
            'threat_types': dict(threat_types.most_common(10)),
            'severity_distribution': dict(severity_counts),
            'top_source_ips': dict(source_ips.most_common(10)),
            'hourly_distribution': dict(sorted(hourly_counts.items()))
        }
    
    def analyze_performance(self, hours: int = 24) -> Dict[str, Any]:
        """Analyze performance metrics."""
        perf_file = f"{self.log_dir}/performance.log"
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        response_times = []
        memory_usage = []
        cpu_usage = []
        
        try:
            with open(perf_file, 'r') as f:
                for line in f:
                    try:
                        perf_data = json.loads(line.strip())
                        perf_time = datetime.fromisoformat(perf_data.get('timestamp', ''))
                        
                        if perf_time >= cutoff_time:
                            if 'response_time_ms' in perf_data:
                                response_times.append(perf_data['response_time_ms'])
                            if 'memory_usage_mb' in perf_data:
                                memory_usage.append(perf_data['memory_usage_mb'])
                            if 'cpu_usage_percent' in perf_data:
                                cpu_usage.append(perf_data['cpu_usage_percent'])
                                
                    except (json.JSONDecodeError, ValueError):
                        continue
                        
        except FileNotFoundError:
            return {'error': 'Performance log file not found'}
        
        def calculate_stats(values: List[float]) -> Dict[str, float]:
            if not values:
                return {}
            return {
                'min': min(values),
                'max': max(values),
                'avg': sum(values) / len(values),
                'count': len(values)
            }
        
        return {
            'analysis_period_hours': hours,
            'response_times': calculate_stats(response_times),
            'memory_usage': calculate_stats(memory_usage),
            'cpu_usage': calculate_stats(cpu_usage)
        }
    
    def check_error_patterns(self, hours: int = 24) -> Dict[str, Any]:
        """Check for error patterns in logs."""
        error_file = f"{self.log_dir}/error.log"
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        error_types = Counter()
        error_modules = Counter()
        recent_errors = []
        
        try:
            with open(error_file, 'r') as f:
                for line in f:
                    # Parse log line (assuming standard format)
                    match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (.+)', line.strip())
                    if match:
                        timestamp_str, level, message = match.groups()
                        try:
                            log_time = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                            if log_time >= cutoff_time:
                                error_types[level] += 1
                                
                                # Extract module name if present
                                module_match = re.search(r'\[(\w+)\]', message)
                                if module_match:
                                    error_modules[module_match.group(1)] += 1
                                
                                # Keep recent critical errors
                                if level in ['ERROR', 'CRITICAL']:
                                    recent_errors.append({
                                        'timestamp': timestamp_str,
                                        'level': level,
                                        'message': message[:200]  # Truncate long messages
                                    })
                                    
                        except ValueError:
                            continue
                            
        except FileNotFoundError:
            return {'error': 'Error log file not found'}
        
        return {
            'analysis_period_hours': hours,
            'total_errors': sum(error_types.values()),
            'error_levels': dict(error_types),
            'error_modules': dict(error_modules.most_common(10)),
            'recent_critical_errors': recent_errors[-10:]  # Last 10 critical errors
        }

if __name__ == "__main__":
    import sys
    
    analyzer = LogAnalyzer()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'threats':
        results = analyzer.analyze_threats()
    elif len(sys.argv) > 1 and sys.argv[1] == 'performance':
        results = analyzer.analyze_performance()
    elif len(sys.argv) > 1 and sys.argv[1] == 'errors':
        results = analyzer.check_error_patterns()
    else:
        # Full analysis
        results = {
            'threats': analyzer.analyze_threats(),
            'performance': analyzer.analyze_performance(),
            'errors': analyzer.check_error_patterns()
        }
    
    print(json.dumps(results, indent=2))
```

______________________________________________________________________

## 💾 **Backup and Recovery**

### **Backup Strategy**

#### **Configuration Backup**

```bash
#!/bin/bash
# scripts/backup_config.sh

BACKUP_DIR="/var/backups/nginx-security"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/config_backup_$TIMESTAMP"

# Create backup directory
mkdir -p "$BACKUP_PATH"

# Backup configuration files
cp -r /etc/nginx-security/ "$BACKUP_PATH/"

# Backup custom patterns
cp -r /var/lib/nginx-security/patterns/ "$BACKUP_PATH/" 2>/dev/null || true

# Backup database (if using SQLite)
if [ -f /var/lib/nginx-security/database.db ]; then
    cp /var/lib/nginx-security/database.db "$BACKUP_PATH/"
fi

# Backup systemd service file
cp /etc/systemd/system/nginx-security-monitor.service "$BACKUP_PATH/"

# Create backup manifest
cat > "$BACKUP_PATH/manifest.txt" << EOF
NGINX Security Monitor Configuration Backup
Created: $(date)
Hostname: $(hostname)
Version: $(cat /opt/nginx-security-monitor/VERSION 2>/dev/null || echo "unknown")

Contents:
- Configuration files (/etc/nginx-security/)
- Custom patterns (/var/lib/nginx-security/patterns/)
- Database files
- Systemd service file
EOF

# Compress backup
tar -czf "$BACKUP_PATH.tar.gz" -C "$BACKUP_DIR" "config_backup_$TIMESTAMP"
rm -rf "$BACKUP_PATH"

# Keep only last 10 backups
ls -t "$BACKUP_DIR"/config_backup_*.tar.gz | tail -n +11 | xargs rm -f

echo "Configuration backup created: $BACKUP_PATH.tar.gz"
```

#### **Log Backup and Archival**

```bash
#!/bin/bash
# scripts/archive_logs.sh

LOG_DIR="/var/log/nginx-security"
ARCHIVE_DIR="/var/lib/nginx-security/log-archive"
DAYS_TO_KEEP=7

# Create archive directory
mkdir -p "$ARCHIVE_DIR"

# Find logs older than specified days
find "$LOG_DIR" -name "*.log.*" -mtime +$DAYS_TO_KEEP -type f | while read logfile; do
    # Get relative path
    rel_path=${logfile#$LOG_DIR/}
    
    # Create year/month directory structure
    file_date=$(stat -c %Y "$logfile")
    year_month=$(date -d "@$file_date" +%Y/%m)
    dest_dir="$ARCHIVE_DIR/$year_month"
    
    mkdir -p "$dest_dir"
    
    # Move and compress if not already compressed
    if [[ "$logfile" == *.gz ]]; then
        mv "$logfile" "$dest_dir/"
    else
        gzip -c "$logfile" > "$dest_dir/${rel_path}.gz"
        rm "$logfile"
    fi
done

# Archive very old logs to external storage (optional)
find "$ARCHIVE_DIR" -type f -mtime +90 | while read old_file; do
    # Upload to S3, move to tape, etc.
    # aws s3 cp "$old_file" s3://backup-bucket/nginx-security-logs/
    # rm "$old_file"
    echo "Old log archived: $old_file"
done

echo "Log archival completed"
```

### **Recovery Procedures**

#### **Configuration Recovery**

```bash
#!/bin/bash
# scripts/restore_config.sh

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file.tar.gz>"
    exit 1
fi

BACKUP_FILE="$1"
TEMP_DIR="/tmp/nginx-security-restore-$$"

# Verify backup file exists
if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Create temporary directory
mkdir -p "$TEMP_DIR"

# Extract backup
echo "Extracting backup..."
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

# Find the extracted directory
EXTRACTED_DIR=$(find "$TEMP_DIR" -name "config_backup_*" -type d | head -1)

if [ -z "$EXTRACTED_DIR" ]; then
    echo "Error: Invalid backup format"
    rm -rf "$TEMP_DIR"
    exit 1
fi

# Stop service
echo "Stopping NGINX Security Monitor..."
sudo systemctl stop nginx-security-monitor

# Backup current configuration
echo "Backing up current configuration..."
sudo cp -r /etc/nginx-security /etc/nginx-security.backup.$(date +%Y%m%d_%H%M%S)

# Restore configuration
echo "Restoring configuration..."
sudo cp -r "$EXTRACTED_DIR/nginx-security/"* /etc/nginx-security/

# Restore patterns if present
if [ -d "$EXTRACTED_DIR/patterns" ]; then
    sudo mkdir -p /var/lib/nginx-security/patterns
    sudo cp -r "$EXTRACTED_DIR/patterns/"* /var/lib/nginx-security/patterns/
fi

# Restore database if present
if [ -f "$EXTRACTED_DIR/database.db" ]; then
    sudo cp "$EXTRACTED_DIR/database.db" /var/lib/nginx-security/
fi

# Restore systemd service if present
if [ -f "$EXTRACTED_DIR/nginx-security-monitor.service" ]; then
    sudo cp "$EXTRACTED_DIR/nginx-security-monitor.service" /etc/systemd/system/
    sudo systemctl daemon-reload
fi

# Set proper permissions
sudo chown -R nginx-security:nginx-security /etc/nginx-security
sudo chown -R nginx-security:nginx-security /var/lib/nginx-security
sudo chmod -R 640 /etc/nginx-security/*.yaml
sudo chmod 600 /etc/nginx-security/keys/* 2>/dev/null || true

# Start service
echo "Starting NGINX Security Monitor..."
sudo systemctl start nginx-security-monitor

# Verify service started
sleep 5
if sudo systemctl is-active --quiet nginx-security-monitor; then
    echo "Configuration restored successfully!"
    echo "Service is running."
else
    echo "Warning: Service failed to start. Check logs:"
    sudo journalctl -u nginx-security-monitor --lines=20
fi

# Cleanup
rm -rf "$TEMP_DIR"
```

______________________________________________________________________

## 🔄 **Upgrade and Migration**

### **Version Upgrade Procedure**

#### **Pre-Upgrade Checklist**

```bash
#!/bin/bash
# scripts/pre_upgrade_check.sh

echo "NGINX Security Monitor Pre-Upgrade Checklist"
echo "============================================="

# Check current version
current_version=$(cat /opt/nginx-security-monitor/VERSION 2>/dev/null || echo "unknown")
echo "Current version: $current_version"

# Check service status
if systemctl is-active --quiet nginx-security-monitor; then
    echo "✓ Service is running"
else
    echo "✗ Service is not running"
fi

# Check disk space
free_space=$(df /opt/nginx-security-monitor --output=avail | tail -1)
if [ "$free_space" -gt 1048576 ]; then  # 1GB in KB
    echo "✓ Sufficient disk space available"
else
    echo "✗ Warning: Low disk space ($(($free_space / 1024))MB available)"
fi

# Check configuration validity
if python3 -m src.config_validator /etc/nginx-security/settings.yaml; then
    echo "✓ Configuration is valid"
else
    echo "✗ Configuration validation failed"
fi

# Check for custom plugins
if [ -d /opt/nginx-security-monitor/plugins ] && [ "$(ls -A /opt/nginx-security-monitor/plugins)" ]; then
    echo "! Custom plugins detected - review compatibility"
    ls /opt/nginx-security-monitor/plugins
fi

# Create pre-upgrade backup
echo "Creating pre-upgrade backup..."
/opt/nginx-security-monitor/scripts/backup_config.sh

echo "Pre-upgrade check completed."
```

#### **Upgrade Script**

```bash
#!/bin/bash
# scripts/upgrade.sh

set -e

NEW_VERSION="$1"
if [ -z "$NEW_VERSION" ]; then
    echo "Usage: $0 <new_version>"
    exit 1
fi

INSTALL_DIR="/opt/nginx-security-monitor"
BACKUP_DIR="/var/backups/nginx-security/upgrade-$(date +%Y%m%d_%H%M%S)"

echo "Upgrading NGINX Security Monitor to version $NEW_VERSION"

# Pre-upgrade checks
echo "Running pre-upgrade checks..."
$INSTALL_DIR/scripts/pre_upgrade_check.sh

# Create upgrade backup
echo "Creating upgrade backup..."
mkdir -p "$BACKUP_DIR"
cp -r "$INSTALL_DIR" "$BACKUP_DIR/nginx-security-monitor"
cp -r /etc/nginx-security "$BACKUP_DIR/"

# Download new version
echo "Downloading version $NEW_VERSION..."
cd /tmp
wget "https://github.com/nginx-security-monitor/releases/download/v$NEW_VERSION/nginx-security-monitor-$NEW_VERSION.tar.gz"
tar -xzf "nginx-security-monitor-$NEW_VERSION.tar.gz"

# Stop service
echo "Stopping service..."
systemctl stop nginx-security-monitor

# Install new version
echo "Installing new version..."
rsync -av "nginx-security-monitor-$NEW_VERSION/" "$INSTALL_DIR/"

# Run database migrations if needed
if [ -f "$INSTALL_DIR/scripts/migrate.py" ]; then
    echo "Running database migrations..."
    python3 "$INSTALL_DIR/scripts/migrate.py"
fi

# Update configuration if needed
if [ -f "$INSTALL_DIR/scripts/update_config.py" ]; then
    echo "Updating configuration..."
    python3 "$INSTALL_DIR/scripts/update_config.py" --version "$NEW_VERSION"
fi

# Install new dependencies
echo "Installing dependencies..."
pip install -r "$INSTALL_DIR/requirements.txt" --upgrade

# Update systemd service if changed
if ! cmp -s "$INSTALL_DIR/systemd/nginx-security-monitor.service" "/etc/systemd/system/nginx-security-monitor.service"; then
    echo "Updating systemd service..."
    cp "$INSTALL_DIR/systemd/nginx-security-monitor.service" /etc/systemd/system/
    systemctl daemon-reload
fi

# Set permissions
chown -R nginx-security:nginx-security "$INSTALL_DIR"
chmod +x "$INSTALL_DIR/nginx-security-monitor.sh"

# Start service
echo "Starting service..."
systemctl start nginx-security-monitor

# Verify upgrade
sleep 10
if systemctl is-active --quiet nginx-security-monitor; then
    new_version=$(cat "$INSTALL_DIR/VERSION")
    echo "Upgrade successful! New version: $new_version"
    
    # Test basic functionality
    echo "Testing basic functionality..."
    curl -s http://localhost:8080/health > /dev/null
    echo "Health check passed."
    
else
    echo "Upgrade failed! Service is not running."
    echo "Restoring from backup..."
    
    systemctl stop nginx-security-monitor
    rm -rf "$INSTALL_DIR"
    cp -r "$BACKUP_DIR/nginx-security-monitor" "$INSTALL_DIR"
    systemctl start nginx-security-monitor
    
    echo "Rollback completed. Check logs for details."
    exit 1
fi

# Cleanup
rm -rf "/tmp/nginx-security-monitor-$NEW_VERSION"
rm -f "/tmp/nginx-security-monitor-$NEW_VERSION.tar.gz"

echo "Upgrade completed successfully!"
```

______________________________________________________________________

## 📈 **Performance Monitoring**

### **Metrics Collection**

#### **System Metrics Script**

```python
# scripts/collect_metrics.py
#!/usr/bin/env python3
"""Collect performance metrics for NGINX Security Monitor."""

import psutil
import time
import json
import sqlite3
from datetime import datetime
from typing import Dict, Any

class MetricsCollector:
    """Collect and store performance metrics."""
    
    def __init__(self, db_path: str = '/var/lib/nginx-security/metrics.db'):
        self.db_path = db_path
        self._init_database()
        
    def _init_database(self):
        """Initialize metrics database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                timestamp INTEGER PRIMARY KEY,
                cpu_usage REAL,
                memory_usage REAL,
                disk_usage REAL,
                network_bytes_sent INTEGER,
                network_bytes_recv INTEGER,
                process_count INTEGER,
                response_time_avg REAL,
                threats_per_minute REAL,
                alerts_per_minute REAL
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system-level metrics."""
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        
        # Disk usage for log directory
        disk = psutil.disk_usage('/var/log/nginx-security')
        disk_percent = (disk.used / disk.total) * 100
        
        # Network stats
        network = psutil.net_io_counters()
        
        # Process count
        process_count = len([p for p in psutil.process_iter() if 'nginx-security' in p.name()])
        
        return {
            'timestamp': int(time.time()),
            'cpu_usage': cpu_percent,
            'memory_usage': memory_percent,
            'disk_usage': disk_percent,
            'network_bytes_sent': network.bytes_sent,
            'network_bytes_recv': network.bytes_recv,
            'process_count': process_count
        }
    
    def collect_application_metrics(self) -> Dict[str, Any]:
        """Collect application-specific metrics."""
        # This would integrate with the application's metrics endpoint
        try:
            import requests
            response = requests.get('http://localhost:8080/metrics', timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        
        return {
            'response_time_avg': 0,
            'threats_per_minute': 0,
            'alerts_per_minute': 0
        }
    
    def store_metrics(self, metrics: Dict[str, Any]):
        """Store metrics in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics.get('timestamp'),
            metrics.get('cpu_usage'),
            metrics.get('memory_usage'), 
            metrics.get('disk_usage'),
            metrics.get('network_bytes_sent'),
            metrics.get('network_bytes_recv'),
            metrics.get('process_count'),
            metrics.get('response_time_avg'),
            metrics.get('threats_per_minute'),
            metrics.get('alerts_per_minute')
        ))
        
        conn.commit()
        conn.close()
    
    def get_metrics_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get metrics summary for specified time period."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_time = int(time.time()) - (hours * 3600)
        
        cursor.execute('''
            SELECT 
                AVG(cpu_usage) as avg_cpu,
                MAX(cpu_usage) as max_cpu,
                AVG(memory_usage) as avg_memory,
                MAX(memory_usage) as max_memory,
                AVG(disk_usage) as avg_disk,
                MAX(disk_usage) as max_disk,
                AVG(response_time_avg) as avg_response_time,
                SUM(threats_per_minute) as total_threats,
                SUM(alerts_per_minute) as total_alerts,
                COUNT(*) as data_points
            FROM metrics 
            WHERE timestamp > ?
        ''', (cutoff_time,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'period_hours': hours,
                'avg_cpu_usage': round(result[0] or 0, 2),
                'max_cpu_usage': round(result[1] or 0, 2),
                'avg_memory_usage': round(result[2] or 0, 2),
                'max_memory_usage': round(result[3] or 0, 2),
                'avg_disk_usage': round(result[4] or 0, 2),
                'max_disk_usage': round(result[5] or 0, 2),
                'avg_response_time': round(result[6] or 0, 2),
                'total_threats': int(result[7] or 0),
                'total_alerts': int(result[8] or 0),
                'data_points': result[9]
            }
        
        return {}

if __name__ == "__main__":
    collector = MetricsCollector()
    
    # Collect current metrics
    system_metrics = collector.collect_system_metrics()
    app_metrics = collector.collect_application_metrics()
    
    # Combine metrics
    all_metrics = {**system_metrics, **app_metrics}
    
    # Store metrics
    collector.store_metrics(all_metrics)
    
    # Print current metrics
    print(json.dumps(all_metrics, indent=2))
```

### **Performance Alerting**

```yaml
# config/performance_alerts.yaml
performance_monitoring:
  enabled: true
  collection_interval: 60  # seconds
  
  thresholds:
    cpu_usage:
      warning: 70
      critical: 90
      
    memory_usage:
      warning: 80
      critical: 95
      
    disk_usage:
      warning: 80
      critical: 90
      
    response_time:
      warning: 1000  # ms
      critical: 5000
      
    error_rate:
      warning: 5    # percent
      critical: 10
  
  alerts:
    enabled: true
    cooldown_minutes: 15  # Minimum time between similar alerts
    channels: ["email", "slack"]
```

______________________________________________________________________

## 🔗 **Related Documentation**

- [Installation Guide](INSTALLATION.md) - Initial setup and installation
- [Configuration Guide](CONFIGURATION.md) - Configuration options
- [Troubleshooting Guide](TROUBLESHOOTING.md) - Problem resolution
- [Performance Tuning](./operations/performance-tuning.md) - Optimization strategies
- [Security Features](SECURITY_FEATURES.md) - Security considerations

______________________________________________________________________

*This operations guide is part of the NGINX Security Monitor documentation. For updates and contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).*
