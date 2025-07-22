# Common Issues and Solutions

This guide provides solutions to frequently encountered issues with Nginx Security Monitor,
organized by category with automated problem detection and troubleshooting decision trees.

## Quick Problem Detection

### Automated Diagnostic Script

```bash
#!/bin/bash
# scripts/diagnose_issues.py

#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import requests
from pathlib import Path
from typing import Dict, List, Tuple

class NSMDiagnostics:
    def __init__(self):
        self.issues = []
        self.config_path = "/etc/nginx-security-monitor"
        self.log_path = "/var/log/nginx-security-monitor"
        self.service_name = "nginx-security-monitor"
    
    def run_full_diagnostic(self) -> Dict:
        """Run complete diagnostic check"""
        print("🔍 Running Nginx Security Monitor diagnostics...")
        
        checks = [
            ("Service Status", self.check_service_status),
            ("Configuration", self.check_configuration),
            ("Log Files", self.check_log_files),
            ("Permissions", self.check_permissions),
            ("Network Connectivity", self.check_network),
            ("Dependencies", self.check_dependencies),
            ("Performance", self.check_performance),
            ("Integration Status", self.check_integrations)
        ]
        
        results = {}
        for check_name, check_func in checks:
            print(f"  Checking {check_name}...")
            try:
                result = check_func()
                results[check_name] = result
                if not result.get('status', True):
                    print(f"    ❌ {result.get('message', 'Failed')}")
                else:
                    print(f"    ✅ OK")
            except Exception as e:
                results[check_name] = {
                    'status': False,
                    'message': f"Check failed: {str(e)}",
                    'error': str(e)
                }
                print(f"    ❌ Error: {e}")
        
        return results
    
    def check_service_status(self) -> Dict:
        """Check if service is running and healthy"""
        try:
            # Check systemd status
            result = subprocess.run([
                "systemctl", "is-active", self.service_name
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                return {
                    'status': False,
                    'message': f"Service {self.service_name} is not active",
                    'systemctl_status': result.stdout.strip(),
                    'solution': 'service_not_running'
                }
            
            # Check health endpoint
            try:
                response = requests.get('http://localhost:8080/health', timeout=5)
                if response.status_code != 200:
                    return {
                        'status': False,
                        'message': f"Health check failed: HTTP {response.status_code}",
                        'solution': 'health_check_failed'
                    }
            except requests.exceptions.RequestException as e:
                return {
                    'status': False,
                    'message': f"Cannot connect to health endpoint: {e}",
                    'solution': 'health_endpoint_unreachable'
                }
            
            return {'status': True, 'message': 'Service is running and healthy'}
            
        except Exception as e:
            return {
                'status': False,
                'message': f"Failed to check service status: {e}",
                'solution': 'check_service_manually'
            }
    
    def check_configuration(self) -> Dict:
        """Check configuration files"""
        config_file = Path(self.config_path) / "config" / "settings.yaml"
        
        if not config_file.exists():
            return {
                'status': False,
                'message': f"Configuration file not found: {config_file}",
                'solution': 'missing_config_file'
            }
        
        try:
            # Test configuration loading
            result = subprocess.run([
                "python", "-m", "nginx_security_monitor.config", "validate",
                "--config", str(config_file)
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                return {
                    'status': False,
                    'message': f"Configuration validation failed: {result.stderr}",
                    'solution': 'invalid_configuration'
                }
            
            return {'status': True, 'message': 'Configuration is valid'}
            
        except Exception as e:
            return {
                'status': False,
                'message': f"Failed to validate configuration: {e}",
                'solution': 'config_validation_error'
            }
    
    def check_log_files(self) -> Dict:
        """Check log file access and disk space"""
        issues = []
        
        # Check log directory
        log_dir = Path(self.log_path)
        if not log_dir.exists():
            issues.append("Log directory does not exist")
        elif not os.access(log_dir, os.W_OK):
            issues.append("Log directory is not writable")
        
        # Check disk space
        try:
            result = subprocess.run([
                "df", "-h", str(log_dir)
            ], capture_output=True, text=True)
            
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                usage_line = lines[1].split()
                if len(usage_line) >= 5:
                    usage_percent = int(usage_line[4].rstrip('%'))
                    if usage_percent > 90:
                        issues.append(f"Disk usage is {usage_percent}% (critical)")
                    elif usage_percent > 80:
                        issues.append(f"Disk usage is {usage_percent}% (warning)")
        except:
            issues.append("Could not check disk space")
        
        # Check nginx log access
        nginx_log = Path("/var/log/nginx/access.log")
        if nginx_log.exists() and not os.access(nginx_log, os.R_OK):
            issues.append("Cannot read nginx access log")
        
        if issues:
            return {
                'status': False,
                'message': f"Log file issues: {', '.join(issues)}",
                'issues': issues,
                'solution': 'log_file_issues'
            }
        
        return {'status': True, 'message': 'Log files accessible'}
    
    def check_permissions(self) -> Dict:
        """Check file and directory permissions"""
        permission_checks = [
            (self.config_path, "nsm", "nsm", 0o750),
            (f"{self.config_path}/config", "nsm", "nsm", 0o750),
            (f"{self.config_path}/keys", "nsm", "nsm", 0o700),
            (self.log_path, "nsm", "adm", 0o750)
        ]
        
        issues = []
        for path, expected_user, expected_group, expected_mode in permission_checks:
            if not Path(path).exists():
                continue
                
            try:
                stat_info = os.stat(path)
                
                # Check ownership (simplified - would need pwd/grp modules for full check)
                actual_mode = stat_info.st_mode & 0o777
                if actual_mode != expected_mode:
                    issues.append(f"{path} has mode {oct(actual_mode)}, expected {oct(expected_mode)}")
                    
            except Exception as e:
                issues.append(f"Cannot check permissions for {path}: {e}")
        
        if issues:
            return {
                'status': False,
                'message': f"Permission issues: {', '.join(issues)}",
                'solution': 'fix_permissions'
            }
        
        return {'status': True, 'message': 'Permissions are correct'}
    
    def check_network(self) -> Dict:
        """Check network connectivity"""
        issues = []
        
        # Check if port 8080 is listening
        try:
            result = subprocess.run([
                "netstat", "-ln"
            ], capture_output=True, text=True)
            
            if ":8080" not in result.stdout:
                issues.append("Port 8080 is not listening")
        except:
            issues.append("Cannot check network ports")
        
        # Check external connectivity (if configured)
        external_endpoints = [
            "https://api.github.com",  # Example external endpoint
        ]
        
        for endpoint in external_endpoints:
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code != 200:
                    issues.append(f"Cannot reach {endpoint}")
            except:
                issues.append(f"Network connectivity issue with {endpoint}")
        
        if issues:
            return {
                'status': False,
                'message': f"Network issues: {', '.join(issues)}",
                'solution': 'network_connectivity_issues'
            }
        
        return {'status': True, 'message': 'Network connectivity OK'}
    
    def check_dependencies(self) -> Dict:
        """Check Python dependencies"""
        try:
            import nginx_security_monitor
            
            # Check key dependencies
            required_modules = [
                'yaml', 'requests', 'cryptography', 
                'prometheus_client', 'aiofiles'
            ]
            
            missing = []
            for module in required_modules:
                try:
                    __import__(module)
                except ImportError:
                    missing.append(module)
            
            if missing:
                return {
                    'status': False,
                    'message': f"Missing dependencies: {', '.join(missing)}",
                    'solution': 'install_dependencies'
                }
            
            return {'status': True, 'message': 'All dependencies available'}
            
        except ImportError:
            return {
                'status': False,
                'message': "nginx_security_monitor module not found",
                'solution': 'install_nsm_package'
            }
    
    def check_performance(self) -> Dict:
        """Check basic performance metrics"""
        try:
            # Check CPU usage
            result = subprocess.run([
                "ps", "aux"
            ], capture_output=True, text=True)
            
            nsm_processes = [line for line in result.stdout.split('\n') 
                           if 'nginx-security-monitor' in line]
            
            if nsm_processes:
                # Parse CPU usage (simplified)
                cpu_usage = float(nsm_processes[0].split()[2])
                if cpu_usage > 80:
                    return {
                        'status': False,
                        'message': f"High CPU usage: {cpu_usage}%",
                        'solution': 'high_cpu_usage'
                    }
            
            return {'status': True, 'message': 'Performance OK'}
            
        except Exception as e:
            return {
                'status': False,
                'message': f"Cannot check performance: {e}",
                'solution': 'performance_check_failed'
            }
    
    def check_integrations(self) -> Dict:
        """Check integration status"""
        try:
            response = requests.get('http://localhost:8080/integrations/status', timeout=5)
            if response.status_code == 200:
                status_data = response.json()
                
                failed_integrations = [
                    name for name, status in status_data.items() 
                    if not status.get('connected', False)
                ]
                
                if failed_integrations:
                    return {
                        'status': False,
                        'message': f"Failed integrations: {', '.join(failed_integrations)}",
                        'solution': 'integration_failures'
                    }
                
                return {'status': True, 'message': 'All integrations healthy'}
            else:
                return {
                    'status': False,
                    'message': f"Cannot get integration status: HTTP {response.status_code}",
                    'solution': 'integration_status_unavailable'
                }
                
        except Exception as e:
            return {
                'status': False,
                'message': f"Integration check failed: {e}",
                'solution': 'integration_check_error'
            }
    
    def get_solutions(self, diagnostic_results: Dict) -> Dict:
        """Get solutions for detected issues"""
        solutions = {
            'service_not_running': {
                'title': 'Service Not Running',
                'description': 'The nginx-security-monitor service is not active',
                'steps': [
                    'sudo systemctl start nginx-security-monitor',
                    'sudo systemctl enable nginx-security-monitor',
                    'Check logs: sudo journalctl -u nginx-security-monitor -f'
                ]
            },
            'health_check_failed': {
                'title': 'Health Check Failed',
                'description': 'Service is running but health endpoint returns error',
                'steps': [
                    'Check configuration: python -m nginx_security_monitor.config validate',
                    'Check logs: tail -f /var/log/nginx-security-monitor/app.log',
                    'Restart service: sudo systemctl restart nginx-security-monitor'
                ]
            },
            'missing_config_file': {
                'title': 'Missing Configuration File',
                'description': 'Configuration file not found',
                'steps': [
                    'Copy example config: cp config/settings.yaml.example /etc/nginx-security-monitor/config/settings.yaml',
                    'Edit configuration: sudo vim /etc/nginx-security-monitor/config/settings.yaml',
                    'Set proper permissions: sudo chown nsm:nsm /etc/nginx-security-monitor/config/settings.yaml'
                ]
            },
            'log_file_issues': {
                'title': 'Log File Access Issues',
                'description': 'Problems with log file access or disk space',
                'steps': [
                    'Create log directory: sudo mkdir -p /var/log/nginx-security-monitor',
                    'Fix permissions: sudo chown nsm:adm /var/log/nginx-security-monitor',
                    'Check disk space: df -h /var/log',
                    'Clean old logs: sudo find /var/log -name "*.log.*" -mtime +30 -delete'
                ]
            },
            'fix_permissions': {
                'title': 'Fix File Permissions',
                'description': 'Incorrect file or directory permissions',
                'steps': [
                    'Run permission fix script: sudo ./scripts/fix-permissions.sh',
                    'Or manually fix: sudo chown -R nsm:nsm /etc/nginx-security-monitor',
                    'Set directory permissions: sudo chmod 750 /etc/nginx-security-monitor',
                    'Set file permissions: sudo chmod 640 /etc/nginx-security-monitor/config/*.yaml'
                ]
            }
        }
        
        applicable_solutions = {}
        for check_name, result in diagnostic_results.items():
            if not result.get('status', True) and 'solution' in result:
                solution_key = result['solution']
                if solution_key in solutions:
                    applicable_solutions[solution_key] = solutions[solution_key]
        
        return applicable_solutions

def main():
    diagnostics = NSMDiagnostics()
    results = diagnostics.run_full_diagnostic()
    
    # Print summary
    print("\n" + "="*50)
    print("DIAGNOSTIC SUMMARY")
    print("="*50)
    
    failed_checks = [name for name, result in results.items() if not result.get('status', True)]
    
    if not failed_checks:
        print("✅ All checks passed!")
        sys.exit(0)
    else:
        print(f"❌ {len(failed_checks)} issue(s) detected:")
        for check in failed_checks:
            print(f"  - {check}: {results[check].get('message', 'Unknown error')}")
        
        # Show solutions
        solutions = diagnostics.get_solutions(results)
        if solutions:
            print("\n" + "="*50)
            print("RECOMMENDED SOLUTIONS")
            print("="*50)
            
            for solution_key, solution in solutions.items():
                print(f"\n🔧 {solution['title']}")
                print(f"   {solution['description']}")
                print("   Steps:")
                for step in solution['steps']:
                    print(f"   1. {step}")
        
        sys.exit(1)

if __name__ == "__main__":
    main()
```

## Issue Categories

### 1. Service and Startup Issues

#### Service Won't Start

**Symptoms:**

- `systemctl start nginx-security-monitor` fails
- Service shows "failed" status
- No response from health endpoint

**Common Causes & Solutions:**

```bash
# Check service status
sudo systemctl status nginx-security-monitor

# Check logs for errors
sudo journalctl -u nginx-security-monitor -n 50

# Common fixes:
# 1. Configuration errors
python -m nginx_security_monitor.config validate

# 2. Permission issues
sudo chown -R nsm:nsm /etc/nginx-security-monitor/
sudo chmod 640 /etc/nginx-security-monitor/config/*.yaml

# 3. Missing dependencies
pip install -r requirements.txt

# 4. Port conflicts
sudo lsof -i :8080
sudo systemctl stop conflicting-service
```

#### Service Starts But Crashes

**Symptoms:**

- Service starts then immediately stops
- Crash logs in journal
- Health endpoint unreachable

**Diagnostic Decision Tree:**

```text
Service Crashes
├── Check Configuration
│   ├── Invalid YAML → Fix syntax errors
│   ├── Missing files → Restore missing files
│   └── Invalid values → Correct configuration values
├── Check Dependencies
│   ├── Missing modules → pip install requirements
│   ├── Version conflicts → Update dependencies
│   └── System packages → Install system dependencies
├── Check Resources
│   ├── Out of memory → Increase memory limits
│   ├── No disk space → Clean up disk space
│   └── File limits → Increase ulimits
└── Check Logs
    ├── Python traceback → Fix code issues
    ├── Permission denied → Fix permissions
    └── Network errors → Check network config
```

### 2. Configuration Issues

#### Invalid Configuration Errors

**Error Messages:**

```text
ConfigurationError: Invalid pattern format in patterns.json
yaml.scanner.ScannerError: mapping values are not allowed here
FileNotFoundError: [Errno 2] No such file or directory: 'patterns.json'
```

**Solutions:**

```bash
# Validate configuration syntax
python -m nginx_security_monitor.config validate

# Check YAML syntax
python -c "import yaml; yaml.safe_load(open('config/settings.yaml'))"

# Validate JSON patterns
python -c "import json; json.load(open('config/patterns.json'))"

# Use configuration linter
./scripts/lint-config.sh

# Reset to default configuration
cp config/settings.yaml.example config/settings.yaml
```

#### Encryption Key Issues

**Symptoms:**

- Cannot decrypt patterns
- Invalid key format errors
- Permission denied accessing keys

**Solutions:**

```bash
# Generate new encryption key
python encrypt_config.py --generate-key

# Check key permissions
ls -la /etc/nginx-security-monitor/keys/
sudo chmod 600 /etc/nginx-security-monitor/keys/*

# Re-encrypt patterns with new key
python encrypt_config.py --encrypt-patterns --key-file /path/to/key

# Test key validity
python encrypt_config.py --test-key --key-file /path/to/key
```

### 3. Performance Issues

#### High CPU Usage

**Symptoms:**

- CPU usage > 80% consistently
- Slow response times
- Log processing delays

**Performance Troubleshooting Script:**

```python
#!/usr/bin/env python3
# scripts/performance_troubleshoot.py

import psutil
import time
import requests
import statistics
from typing import List, Dict

class PerformanceTroubleshooter:
    def __init__(self):
        self.process_name = "nginx-security-monitor"
        self.measurements = []
    
    def diagnose_performance(self) -> Dict:
        """Diagnose performance issues"""
        print("🔍 Diagnosing performance issues...")
        
        # Find NSM process
        nsm_process = self.find_nsm_process()
        if not nsm_process:
            return {"error": "NSM process not found"}
        
        # Collect metrics over time
        self.collect_metrics(nsm_process, duration=60)
        
        # Analyze results
        analysis = self.analyze_metrics()
        
        return {
            "process_info": {
                "pid": nsm_process.pid,
                "memory_mb": nsm_process.memory_info().rss / 1024 / 1024,
                "cpu_percent": nsm_process.cpu_percent()
            },
            "analysis": analysis,
            "recommendations": self.get_recommendations(analysis)
        }
    
    def find_nsm_process(self):
        """Find the NSM process"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if any('nginx-security-monitor' in str(item) for item in proc.info['cmdline']):
                    return psutil.Process(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None
    
    def collect_metrics(self, process, duration=60):
        """Collect performance metrics"""
        print(f"📊 Collecting metrics for {duration} seconds...")
        
        start_time = time.time()
        while time.time() - start_time < duration:
            try:
                # Process metrics
                cpu_percent = process.cpu_percent()
                memory_mb = process.memory_info().rss / 1024 / 1024
                
                # System metrics
                system_cpu = psutil.cpu_percent()
                system_memory = psutil.virtual_memory().percent
                
                # Application metrics
                try:
                    response = requests.get('http://localhost:8080/metrics', timeout=1)
                    app_metrics = self.parse_prometheus_metrics(response.text)
                except:
                    app_metrics = {}
                
                self.measurements.append({
                    'timestamp': time.time(),
                    'process_cpu': cpu_percent,
                    'process_memory': memory_mb,
                    'system_cpu': system_cpu,
                    'system_memory': system_memory,
                    'app_metrics': app_metrics
                })
                
                time.sleep(1)
                
            except psutil.NoSuchProcess:
                break
    
    def parse_prometheus_metrics(self, metrics_text: str) -> Dict:
        """Parse Prometheus metrics"""
        metrics = {}
        for line in metrics_text.split('\n'):
            if line.startswith('nsm_'):
                parts = line.split()
                if len(parts) >= 2:
                    metric_name = parts[0]
                    try:
                        metric_value = float(parts[1])
                        metrics[metric_name] = metric_value
                    except ValueError:
                        continue
        return metrics
    
    def analyze_metrics(self) -> Dict:
        """Analyze collected metrics"""
        if not self.measurements:
            return {"error": "No measurements collected"}
        
        # Extract time series
        cpu_usage = [m['process_cpu'] for m in self.measurements]
        memory_usage = [m['process_memory'] for m in self.measurements]
        
        analysis = {
            'cpu': {
                'avg': statistics.mean(cpu_usage),
                'max': max(cpu_usage),
                'p95': self.percentile(cpu_usage, 95)
            },
            'memory': {
                'avg': statistics.mean(memory_usage),
                'max': max(memory_usage),
                'trend': self.calculate_trend(memory_usage)
            },
            'issues': []
        }
        
        # Identify issues
        if analysis['cpu']['avg'] > 70:
            analysis['issues'].append('high_cpu_usage')
        
        if analysis['memory']['max'] > 1000:  # 1GB
            analysis['issues'].append('high_memory_usage')
        
        if analysis['memory']['trend'] > 0.1:  # Growing trend
            analysis['issues'].append('memory_leak')
        
        return analysis
    
    def percentile(self, data: List[float], p: int) -> float:
        """Calculate percentile"""
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * p / 100
        f = int(k)
        c = k - f
        if f == len(sorted_data) - 1:
            return sorted_data[f]
        return sorted_data[f] * (1 - c) + sorted_data[f + 1] * c
    
    def calculate_trend(self, data: List[float]) -> float:
        """Calculate trend (simple linear regression slope)"""
        if len(data) < 2:
            return 0.0
        
        n = len(data)
        x = list(range(n))
        x_mean = sum(x) / n
        y_mean = sum(data) / n
        
        numerator = sum((x[i] - x_mean) * (data[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        return numerator / denominator if denominator != 0 else 0.0
    
    def get_recommendations(self, analysis: Dict) -> List[str]:
        """Get performance recommendations"""
        recommendations = []
        
        if 'high_cpu_usage' in analysis.get('issues', []):
            recommendations.extend([
                "Consider increasing worker threads in configuration",
                "Profile pattern matching performance",
                "Check for inefficient regex patterns",
                "Consider using compiled patterns or hyperscan"
            ])
        
        if 'high_memory_usage' in analysis.get('issues', []):
            recommendations.extend([
                "Reduce queue sizes in async configuration",
                "Implement memory limits in configuration",
                "Check for large log files being held in memory",
                "Consider log rotation and cleanup"
            ])
        
        if 'memory_leak' in analysis.get('issues', []):
            recommendations.extend([
                "Monitor memory growth over longer period",
                "Check for unclosed file handles",
                "Review async coroutine cleanup",
                "Consider restarting service periodically"
            ])
        
        return recommendations

def main():
    troubleshooter = PerformanceTroubleshooter()
    results = troubleshooter.diagnose_performance()
    
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return
    
    print("\n📊 Performance Analysis Results:")
    print("=" * 40)
    
    analysis = results['analysis']
    print(f"CPU Usage: avg={analysis['cpu']['avg']:.1f}%, max={analysis['cpu']['max']:.1f}%")
    print(f"Memory Usage: avg={analysis['memory']['avg']:.1f}MB, max={analysis['memory']['max']:.1f}MB")
    
    if analysis['issues']:
        print(f"\n⚠️  Issues Detected: {', '.join(analysis['issues'])}")
        
        print("\n💡 Recommendations:")
        for rec in results['recommendations']:
            print(f"  • {rec}")
    else:
        print("\n✅ No performance issues detected")

if __name__ == "__main__":
    main()
```

#### Memory Leaks

**Symptoms:**

- Memory usage increases over time
- Eventually leads to OOM errors
- Service becomes unresponsive

**Detection & Solutions:**

```bash
# Monitor memory usage over time
python scripts/memory_monitor.py --duration 3600

# Check for memory leaks
valgrind --tool=massif python -m nginx_security_monitor

# Analyze memory usage
python scripts/analyze_memory.py --profile memory.prof

# Temporary fix: restart service periodically
sudo systemctl restart nginx-security-monitor

# Permanent fixes:
# 1. Update to latest version
# 2. Reduce queue sizes in config
# 3. Implement memory limits
# 4. Fix application code
```

### 4. Integration Issues

#### Failed External Integrations

**Common Integration Problems:**

```python
# Integration troubleshooting script
#!/usr/bin/env python3

class IntegrationTroubleshooter:
    def __init__(self):
        self.integrations = {
            'fail2ban': self.test_fail2ban,
            'ossec': self.test_ossec,
            'suricata': self.test_suricata,
            'webhook': self.test_webhook
        }
    
    def test_fail2ban(self):
        """Test fail2ban integration"""
        try:
            import subprocess
            result = subprocess.run(['fail2ban-client', 'status'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return {'status': 'ok', 'message': 'fail2ban is running'}
            else:
                return {'status': 'error', 'message': 'fail2ban not responding'}
        except FileNotFoundError:
            return {'status': 'error', 'message': 'fail2ban not installed'}
    
    def test_webhook(self):
        """Test webhook integration"""
        import requests
        webhook_url = "https://example.com/webhook"  # From config
        
        try:
            response = requests.post(webhook_url, 
                                   json={'test': True}, 
                                   timeout=10)
            if response.status_code == 200:
                return {'status': 'ok', 'message': 'Webhook responding'}
            else:
                return {'status': 'error', 
                       'message': f'Webhook returned {response.status_code}'}
        except requests.exceptions.RequestException as e:
            return {'status': 'error', 'message': f'Webhook unreachable: {e}'}
```

### 5. Log Processing Issues

#### Logs Not Being Processed

**Symptoms:**

- No threat detections despite suspicious activity
- Processing metrics show zero
- Log files exist but seem ignored

**Troubleshooting Decision Tree:**

```text
Logs Not Processed
├── Check File Permissions
│   ├── Cannot read nginx logs → Fix file permissions
│   ├── Cannot write to NSM logs → Fix directory permissions
│   └── SELinux blocking access → Configure SELinux
├── Check Configuration
│   ├── Wrong log path → Update config with correct path
│   ├── Invalid log format → Fix log format configuration
│   └── Disabled processing → Enable log processing
├── Check File Monitoring
│   ├── File not being watched → Check inotify limits
│   ├── Log rotation issues → Fix log rotation config
│   └── File handle leaks → Restart service
└── Check Processing Pipeline
    ├── Queue full → Increase queue size
    ├── Workers stuck → Restart workers
    └── Pattern errors → Fix pattern syntax
```

**Solutions:**

```bash
# Check log file access
sudo -u nsm cat /var/log/nginx/access.log | head -5

# Check inotify limits
cat /proc/sys/fs/inotify/max_user_watches
echo 'fs.inotify.max_user_watches = 65536' | sudo tee -a /etc/sysctl.conf

# Test log processing manually
python -c "
from nginx_security_monitor.log_processor import LogProcessor
processor = LogProcessor()
processor.process_line('192.168.1.1 - - [20/Jul/2025:10:00:00 +0000] \"GET /admin.php HTTP/1.1\" 200 1234')
"

# Check processing metrics
curl http://localhost:8080/metrics | grep nsm_log_entries_processed
```

## Automated Problem Resolution

### Self-Healing Script

```bash
#!/bin/bash
# scripts/self_heal.sh - Automated problem resolution

set -euo pipefail

LOGFILE="/var/log/nginx-security-monitor/self-heal.log"
LOCKFILE="/var/run/nsm-self-heal.lock"

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# Prevent concurrent execution
if [ -f "$LOCKFILE" ]; then
    log "Self-heal already running (lockfile exists)"
    exit 1
fi

touch "$LOCKFILE"
trap "rm -f $LOCKFILE" EXIT

log "Starting self-healing checks"

# Check 1: Service health
if ! curl -s http://localhost:8080/health > /dev/null; then
    log "Health check failed, attempting restart"
    sudo systemctl restart nginx-security-monitor
    sleep 10
    
    if curl -s http://localhost:8080/health > /dev/null; then
        log "Service restart successful"
    else
        log "Service restart failed, escalating"
        # Send alert to operations team
        ./scripts/send_alert.sh "critical" "NSM service restart failed"
    fi
fi

# Check 2: Disk space
DISK_USAGE=$(df /var/log | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    log "High disk usage detected: ${DISK_USAGE}%"
    
    # Clean old logs
    find /var/log/nginx-security-monitor -name "*.log.*" -mtime +7 -delete
    
    NEW_USAGE=$(df /var/log | tail -1 | awk '{print $5}' | sed 's/%//')
    log "Disk usage after cleanup: ${NEW_USAGE}%"
fi

# Check 3: Memory usage
MEMORY_USAGE=$(ps aux | grep nginx-security-monitor | grep -v grep | awk '{print $4}' | head -1)
if [ "${MEMORY_USAGE:-0}" -gt 80 ]; then
    log "High memory usage detected: ${MEMORY_USAGE}%"
    
    # Restart if memory usage is excessive
    sudo systemctl restart nginx-security-monitor
    log "Service restarted due to high memory usage"
fi

# Check 4: Configuration validity
if ! python -m nginx_security_monitor.config validate; then
    log "Configuration validation failed"
    
    # Restore backup configuration
    if [ -f "/etc/nginx-security-monitor/config/settings.yaml.backup" ]; then
        cp /etc/nginx-security-monitor/config/settings.yaml.backup \
           /etc/nginx-security-monitor/config/settings.yaml
        sudo systemctl restart nginx-security-monitor
        log "Restored backup configuration"
    fi
fi

log "Self-healing checks completed"
```

______________________________________________________________________

**Related Documentation:**

- [Operations Guide](../OPERATIONS_GUIDE.md)
- [Performance Tuning](../operations/performance-tuning.md)
- [Monitoring Guide](../operations/monitoring.md)
- [Disaster Recovery](../operations/disaster-recovery.md)
