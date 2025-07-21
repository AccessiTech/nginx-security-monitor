# Installation Issues

This guide addresses common problems encountered during installation and initial setup of Nginx Security Monitor.

## Pre-Installation Checklist

### System Requirements Verification

```bash
#!/bin/bash
# scripts/verify_requirements.sh

echo "🔍 Verifying system requirements for Nginx Security Monitor..."

# Check operating system
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "✅ Linux OS detected"
    
    # Check distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "   Distribution: $NAME $VERSION"
        
        case "$ID" in
            ubuntu|debian)
                if [[ "$VERSION_ID" < "18.04" ]] && [[ "$ID" == "ubuntu" ]]; then
                    echo "⚠️  Ubuntu 18.04+ recommended"
                elif [[ "$VERSION_ID" < "10" ]] && [[ "$ID" == "debian" ]]; then
                    echo "⚠️  Debian 10+ recommended"
                fi
                ;;
            centos|rhel)
                if [[ "${VERSION_ID%%.*}" -lt 7 ]]; then
                    echo "⚠️  CentOS/RHEL 7+ recommended"
                fi
                ;;
        esac
    fi
else
    echo "❌ Unsupported operating system: $OSTYPE"
    echo "   Linux is required for production use"
    exit 1
fi

# Check Python version
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    echo "✅ Python $PYTHON_VERSION detected"
    
    if [[ "$PYTHON_VERSION" < "3.8" ]]; then
        echo "❌ Python 3.8+ required, found $PYTHON_VERSION"
        exit 1
    fi
else
    echo "❌ Python 3 not found"
    echo "   Install with: sudo apt-get install python3 python3-pip"
    exit 1
fi

# Check available memory
MEMORY_GB=$(free -g | awk 'NR==2{printf "%.1f", $2/1}')
echo "✅ Available memory: ${MEMORY_GB}GB"

if (( $(echo "$MEMORY_GB < 1.0" | bc -l) )); then
    echo "⚠️  Minimum 1GB RAM recommended for production"
fi

# Check disk space
DISK_SPACE=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
echo "✅ Available disk space: ${DISK_SPACE}GB"

if [[ "$DISK_SPACE" -lt 10 ]]; then
    echo "⚠️  Minimum 10GB free space recommended"
fi

# Check required system packages
REQUIRED_PACKAGES=("curl" "wget" "git" "build-essential")
MISSING_PACKAGES=()

for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! command -v "$package" &> /dev/null; then
        MISSING_PACKAGES+=("$package")
    fi
done

if [ ${#MISSING_PACKAGES[@]} -eq 0 ]; then
    echo "✅ All required system packages available"
else
    echo "❌ Missing packages: ${MISSING_PACKAGES[*]}"
    echo "   Install with: sudo apt-get install ${MISSING_PACKAGES[*]}"
fi

# Check nginx installation
if command -v nginx &> /dev/null; then
    NGINX_VERSION=$(nginx -v 2>&1 | sed 's/.*nginx\///; s/ .*//')
    echo "✅ Nginx $NGINX_VERSION detected"
else
    echo "⚠️  Nginx not detected"
    echo "   NSM can monitor nginx logs without nginx being on the same system"
    echo "   but for local monitoring, install with: sudo apt-get install nginx"
fi

# Check systemd
if command -v systemctl &> /dev/null; then
    echo "✅ systemd available"
else
    echo "⚠️  systemd not available"
    echo "   Manual service management required"
fi

echo ""
echo "📋 System verification complete"
```

## Installation Method Issues

### pip Install Failures

#### Error: `No matching distribution found`

```bash
# Problem: Package not found in PyPI
# Solution 1: Use development installation
git clone https://github.com/nginx-security-monitor/nginx-security-monitor.git
cd nginx-security-monitor
pip install -e .

# Solution 2: Install from source
pip install git+https://github.com/nginx-security-monitor/nginx-security-monitor.git

# Solution 3: Check Python version compatibility
python3 --version
pip --version
```

#### Error: `Permission denied`

```bash
# Problem: Installing to system Python without sudo
# Solution 1: Use virtual environment (recommended)
python3 -m venv nsm-env
source nsm-env/bin/activate
pip install nginx-security-monitor

# Solution 2: User installation
pip install --user nginx-security-monitor

# Solution 3: System installation (not recommended)
sudo pip install nginx-security-monitor
```

#### Error: `Failed building wheel`

```bash
# Problem: Missing build dependencies
# Solution: Install build dependencies
sudo apt-get update
sudo apt-get install build-essential python3-dev python3-setuptools

# For CentOS/RHEL:
sudo yum groupinstall "Development Tools"
sudo yum install python3-devel

# Retry installation
pip install nginx-security-monitor
```

### Docker Installation Issues

#### Container Won't Start

```bash
# Check Docker logs
docker logs nginx-security-monitor

# Common issues:

# Issue 1: Port already in use
docker ps | grep 8080
sudo lsof -i :8080
# Kill conflicting process or change port

# Issue 2: Volume mount issues
ls -la /etc/nginx-security-monitor/
sudo chown -R 1000:1000 /etc/nginx-security-monitor/

# Issue 3: Memory limits
docker stats nginx-security-monitor
# Increase memory limit in docker-compose.yml

# Issue 4: Missing configuration
docker exec -it nginx-security-monitor ls /etc/nsm/
# Mount configuration directory properly
```

#### Docker Compose Failures

```yaml
# Common docker-compose.yml issues and fixes:

version: '3.8'
services:
  nginx-security-monitor:
    image: nginx-security-monitor:latest
    container_name: nsm
    ports:
      - "8080:8080"
    volumes:
      # Fix: Use absolute paths
      - /etc/nginx-security-monitor:/etc/nsm:ro
      - /var/log/nginx:/var/log/nginx:ro
      - /var/log/nsm:/var/log/nsm
    environment:
      # Fix: Set proper environment variables
      - NSM_CONFIG_PATH=/etc/nsm/config/settings.yaml
      - NSM_LOG_LEVEL=INFO
    # Fix: Add health check
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    # Fix: Add resource limits
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
    # Fix: Ensure proper startup order
    depends_on:
      - redis
    restart: unless-stopped
```

### Source Installation Issues

#### Git Clone Failures

```bash
# Issue: Permission denied (publickey)
# Solution: Use HTTPS instead of SSH
git clone https://github.com/nginx-security-monitor/nginx-security-monitor.git

# Issue: SSL verification failed
# Solution: Update certificates or bypass (not recommended)
git config --global http.sslverify false  # Temporary fix
sudo apt-get update && sudo apt-get install ca-certificates  # Proper fix

# Issue: Large repository size
# Solution: Shallow clone
git clone --depth 1 https://github.com/nginx-security-monitor/nginx-security-monitor.git
```

#### Build Failures

```bash
# Issue: setup.py errors
# Solution: Install setuptools and wheel
pip install --upgrade setuptools wheel

# Issue: Missing dependencies
# Solution: Install development dependencies
pip install -r dev-requirements.txt

# Issue: C extension compilation errors
# Solution: Install system dependencies
sudo apt-get install python3-dev libffi-dev libssl-dev

# For Alpine Linux:
apk add gcc musl-dev libffi-dev openssl-dev python3-dev
```

## Configuration Issues During Installation

### Configuration File Generation

```bash
#!/bin/bash
# scripts/generate_initial_config.sh

set -e

CONFIG_DIR="/etc/nginx-security-monitor"
CONFIG_FILE="$CONFIG_DIR/config/settings.yaml"
BACKUP_SUFFIX=".backup.$(date +%Y%m%d_%H%M%S)"

echo "🔧 Generating initial configuration..."

# Create configuration directory structure
sudo mkdir -p "$CONFIG_DIR"/{config,keys,patterns}
sudo mkdir -p /var/log/nginx-security-monitor

# Generate base configuration
sudo tee "$CONFIG_FILE" > /dev/null << 'EOF'
# Nginx Security Monitor Configuration
# Generated by installation script

# Service Configuration
service:
  host: "0.0.0.0"
  port: 8080
  workers: 2
  debug: false

# Logging Configuration
logging:
  level: "INFO"
  file: "/var/log/nginx-security-monitor/app.log"
  max_size: "10MB"
  backup_count: 5
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Nginx Log Sources
log_sources:
  - path: "/var/log/nginx/access.log"
    format: "combined"
    enabled: true
  - path: "/var/log/nginx/error.log"
    format: "error"
    enabled: true

# Pattern Detection
patterns:
  file: "/etc/nginx-security-monitor/config/patterns.json"
  encrypted: false
  update_interval: 300  # 5 minutes

# Threat Detection
detection:
  enabled: true
  sensitivity: "medium"  # low, medium, high
  whitelist:
    - "127.0.0.1"
    - "::1"

# Integrations
integrations:
  fail2ban:
    enabled: false
    socket_path: "/var/run/fail2ban/fail2ban.sock"
  
  webhook:
    enabled: false
    url: ""
    timeout: 10
    retries: 3
  
  email:
    enabled: false
    smtp_server: ""
    port: 587
    username: ""
    password: ""
    from_address: ""
    to_addresses: []

# Performance Settings
performance:
  max_queue_size: 10000
  batch_size: 100
  processing_interval: 1.0
  memory_limit: "512MB"

# Security Settings
security:
  api_key_required: false
  rate_limit:
    enabled: true
    requests_per_minute: 60
  
  encryption:
    algorithm: "AES-256-GCM"
    key_rotation_days: 90
EOF

# Generate default patterns
sudo tee "$CONFIG_DIR/config/patterns.json" > /dev/null << 'EOF'
{
  "version": "1.0",
  "patterns": {
    "sql_injection": {
      "description": "SQL injection attempts",
      "patterns": [
        "(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|delete\\s+from|drop\\s+table)",
        "(?i)('\\s*(or|and)\\s+'1'\\s*=\\s*'1)",
        "(?i)(0x[0-9a-f]+|char\\s*\\(|ascii\\s*\\()"
      ],
      "severity": "high",
      "action": "block"
    },
    "xss_attempt": {
      "description": "Cross-site scripting attempts",
      "patterns": [
        "(?i)(<script|javascript:|vbscript:|onload\\s*=|onerror\\s*=)",
        "(?i)(document\\.cookie|document\\.location|window\\.location)"
      ],
      "severity": "medium",
      "action": "log"
    },
    "directory_traversal": {
      "description": "Directory traversal attempts",
      "patterns": [
        "\\.\\./",
        "(?i)(etc/passwd|windows/system32|boot\\.ini)"
      ],
      "severity": "medium",
      "action": "block"
    },
    "brute_force": {
      "description": "Brute force login attempts",
      "patterns": [
        "(?i)(wp-login\\.php|admin|login|signin)"
      ],
      "severity": "low",
      "action": "monitor",
      "threshold": 10
    }
  }
}
EOF

# Set proper permissions
sudo chown -R nsm:nsm "$CONFIG_DIR" 2>/dev/null || {
    echo "⚠️  nsm user not found, setting root ownership"
    sudo chown -R root:root "$CONFIG_DIR"
}

sudo chmod 750 "$CONFIG_DIR"
sudo chmod 750 "$CONFIG_DIR/config"
sudo chmod 640 "$CONFIG_FILE"
sudo chmod 640 "$CONFIG_DIR/config/patterns.json"

# Create log directory
sudo mkdir -p /var/log/nginx-security-monitor
sudo chown nsm:adm /var/log/nginx-security-monitor 2>/dev/null || {
    sudo chown root:root /var/log/nginx-security-monitor
}
sudo chmod 750 /var/log/nginx-security-monitor

echo "✅ Configuration files generated successfully"
echo "📍 Configuration location: $CONFIG_FILE"
echo "📝 Edit the configuration to match your environment"
```

### User and Group Setup

```bash
#!/bin/bash
# scripts/setup_user.sh

# Create nsm user and group
if ! getent group nsm >/dev/null; then
    sudo groupadd --system nsm
    echo "✅ Created nsm group"
fi

if ! getent passwd nsm >/dev/null; then
    sudo useradd --system --gid nsm --home-dir /var/lib/nsm \
                 --shell /bin/false --comment "Nginx Security Monitor" nsm
    echo "✅ Created nsm user"
fi

# Add nsm user to required groups
sudo usermod -a -G adm nsm  # For log access
sudo usermod -a -G www-data nsm  # For nginx integration

# Create home directory
sudo mkdir -p /var/lib/nsm
sudo chown nsm:nsm /var/lib/nsm
sudo chmod 750 /var/lib/nsm

echo "✅ User and group setup complete"
```

## Service Installation Issues

### Systemd Service Creation

```bash
#!/bin/bash
# scripts/install_systemd_service.sh

SERVICE_FILE="/etc/systemd/system/nginx-security-monitor.service"

# Detect Python executable
PYTHON_EXEC=$(which python3)
NSM_EXEC=$(which nginx-security-monitor || echo "/usr/local/bin/nginx-security-monitor")

# Create systemd service file
sudo tee "$SERVICE_FILE" > /dev/null << EOF
[Unit]
Description=Nginx Security Monitor
Documentation=https://github.com/nginx-security-monitor/nginx-security-monitor
After=network.target nginx.service
Wants=network.target

[Service]
Type=exec
User=nsm
Group=nsm
ExecStart=$NSM_EXEC --config /etc/nginx-security-monitor/config/settings.yaml
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
Restart=on-failure
RestartSec=5
TimeoutStopSec=30

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/nginx-security-monitor /var/lib/nsm
ReadOnlyPaths=/var/log/nginx

# Environment
Environment=PYTHONPATH=/usr/local/lib/python3.8/site-packages
Environment=NSM_CONFIG_PATH=/etc/nginx-security-monitor/config/settings.yaml

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable nginx-security-monitor.service

echo "✅ Systemd service installed and enabled"
echo "🚀 Start with: sudo systemctl start nginx-security-monitor"
```

### Service Start Failures

```bash
# Diagnosis script for service issues
#!/bin/bash

echo "🔍 Diagnosing service startup issues..."

# Check service status
echo "Service Status:"
sudo systemctl status nginx-security-monitor.service --no-pager

# Check service logs
echo -e "\nRecent Logs:"
sudo journalctl -u nginx-security-monitor.service -n 20 --no-pager

# Check configuration
echo -e "\nConfiguration Test:"
if command -v nginx-security-monitor >/dev/null; then
    nginx-security-monitor --config /etc/nginx-security-monitor/config/settings.yaml --test-config
else
    python3 -m nginx_security_monitor.main --test-config
fi

# Check permissions
echo -e "\nPermission Check:"
ls -la /etc/nginx-security-monitor/
ls -la /var/log/nginx-security-monitor/

# Check dependencies
echo -e "\nDependency Check:"
python3 -c "import nginx_security_monitor; print('✅ NSM module importable')" || echo "❌ NSM module import failed"

# Check ports
echo -e "\nPort Check:"
sudo netstat -tlnp | grep :8080 || echo "Port 8080 not in use"

# Suggest solutions
echo -e "\n💡 Common Solutions:"
echo "1. Check configuration syntax: nginx-security-monitor --test-config"
echo "2. Fix permissions: sudo chown -R nsm:nsm /etc/nginx-security-monitor/"
echo "3. Check logs: sudo journalctl -u nginx-security-monitor -f"
echo "4. Restart service: sudo systemctl restart nginx-security-monitor"
```

## Post-Installation Verification

### Installation Test Suite

```python
#!/usr/bin/env python3
# scripts/test_installation.py

import os
import sys
import subprocess
import requests
import time
import yaml
import json
from pathlib import Path
from typing import Dict, List, Tuple

class InstallationTester:
    def __init__(self):
        self.test_results = []
        self.config_path = "/etc/nginx-security-monitor/config/settings.yaml"
        self.service_url = "http://localhost:8080"
    
    def run_all_tests(self) -> bool:
        """Run complete installation test suite"""
        print("🧪 Running installation test suite...")
        
        tests = [
            ("Configuration Files", self.test_configuration_files),
            ("Python Dependencies", self.test_python_dependencies),
            ("Service Status", self.test_service_status),
            ("API Endpoints", self.test_api_endpoints),
            ("Log Processing", self.test_log_processing),
            ("Pattern Loading", self.test_pattern_loading),
            ("Permissions", self.test_permissions),
            ("Integration Readiness", self.test_integration_readiness)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            print(f"\n🔍 Testing {test_name}...")
            try:
                result = test_func()
                if result:
                    print(f"   ✅ PASSED")
                    passed += 1
                else:
                    print(f"   ❌ FAILED")
                self.test_results.append((test_name, result))
            except Exception as e:
                print(f"   ❌ ERROR: {e}")
                self.test_results.append((test_name, False))
        
        print(f"\n📊 Test Results: {passed}/{total} tests passed")
        
        if passed == total:
            print("🎉 Installation verification successful!")
            return True
        else:
            print("⚠️  Some tests failed. Check the issues above.")
            self.print_failure_guidance()
            return False
    
    def test_configuration_files(self) -> bool:
        """Test configuration file existence and validity"""
        required_files = [
            "/etc/nginx-security-monitor/config/settings.yaml",
            "/etc/nginx-security-monitor/config/patterns.json"
        ]
        
        for file_path in required_files:
            if not Path(file_path).exists():
                print(f"     Missing: {file_path}")
                return False
        
        # Test YAML syntax
        try:
            with open(self.config_path, 'r') as f:
                yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"     Invalid YAML: {e}")
            return False
        
        # Test JSON syntax
        try:
            with open("/etc/nginx-security-monitor/config/patterns.json", 'r') as f:
                json.load(f)
        except json.JSONDecodeError as e:
            print(f"     Invalid JSON: {e}")
            return False
        
        return True
    
    def test_python_dependencies(self) -> bool:
        """Test Python module imports"""
        required_modules = [
            'nginx_security_monitor',
            'yaml', 'requests', 'aiofiles',
            'cryptography', 'prometheus_client'
        ]
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                print(f"     Missing module: {module}")
                return False
        
        return True
    
    def test_service_status(self) -> bool:
        """Test service running status"""
        try:
            result = subprocess.run([
                'systemctl', 'is-active', 'nginx-security-monitor'
            ], capture_output=True, text=True)
            
            if result.stdout.strip() != 'active':
                print(f"     Service not active: {result.stdout.strip()}")
                return False
            
            return True
            
        except subprocess.SubprocessError as e:
            print(f"     Cannot check service status: {e}")
            return False
    
    def test_api_endpoints(self) -> bool:
        """Test API endpoint availability"""
        endpoints = [
            ('/health', 200),
            ('/metrics', 200),
            ('/status', 200)
        ]
        
        for endpoint, expected_status in endpoints:
            try:
                response = requests.get(f"{self.service_url}{endpoint}", timeout=5)
                if response.status_code != expected_status:
                    print(f"     {endpoint}: HTTP {response.status_code}, expected {expected_status}")
                    return False
            except requests.exceptions.RequestException as e:
                print(f"     {endpoint}: Connection failed - {e}")
                return False
        
        return True
    
    def test_log_processing(self) -> bool:
        """Test log processing functionality"""
        try:
            # Test with sample log line
            response = requests.post(
                f"{self.service_url}/test/process-log",
                json={"log_line": '127.0.0.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 1234'},
                timeout=10
            )
            
            if response.status_code != 200:
                print(f"     Log processing test failed: HTTP {response.status_code}")
                return False
            
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"     Log processing test failed: {e}")
            return False
    
    def test_pattern_loading(self) -> bool:
        """Test pattern loading"""
        try:
            response = requests.get(f"{self.service_url}/patterns/status", timeout=5)
            if response.status_code != 200:
                return False
            
            data = response.json()
            if not data.get('loaded', False):
                print("     Patterns not loaded")
                return False
            
            pattern_count = data.get('count', 0)
            if pattern_count == 0:
                print("     No patterns loaded")
                return False
            
            print(f"     {pattern_count} patterns loaded")
            return True
            
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            print(f"     Pattern status check failed: {e}")
            return False
    
    def test_permissions(self) -> bool:
        """Test file and directory permissions"""
        permission_tests = [
            ("/etc/nginx-security-monitor", "nsm", 0o750),
            ("/var/log/nginx-security-monitor", "nsm", 0o750),
        ]
        
        for path, expected_owner, expected_mode in permission_tests:
            if not Path(path).exists():
                continue
            
            stat_info = os.stat(path)
            actual_mode = stat_info.st_mode & 0o777
            
            if actual_mode != expected_mode:
                print(f"     {path}: mode {oct(actual_mode)}, expected {oct(expected_mode)}")
                return False
        
        return True
    
    def test_integration_readiness(self) -> bool:
        """Test integration readiness"""
        try:
            response = requests.get(f"{self.service_url}/integrations/status", timeout=5)
            if response.status_code != 200:
                return False
            
            # Just verify the endpoint is available
            # Integration failures are expected if not configured
            return True
            
        except requests.exceptions.RequestException:
            print("     Integration status endpoint not available")
            return False
    
    def print_failure_guidance(self):
        """Print guidance for failed tests"""
        print("\n🔧 Troubleshooting Guidance:")
        
        failed_tests = [name for name, result in self.test_results if not result]
        
        guidance = {
            "Configuration Files": [
                "Run: python scripts/generate_initial_config.py",
                "Check file permissions: ls -la /etc/nginx-security-monitor/",
                "Validate syntax: python -m yaml /etc/nginx-security-monitor/config/settings.yaml"
            ],
            "Python Dependencies": [
                "Install dependencies: pip install -r requirements.txt",
                "Check Python path: python -c 'import sys; print(sys.path)'",
                "Use virtual environment: python -m venv venv && source venv/bin/activate"
            ],
            "Service Status": [
                "Start service: sudo systemctl start nginx-security-monitor",
                "Check logs: sudo journalctl -u nginx-security-monitor -f",
                "Check configuration: nginx-security-monitor --test-config"
            ],
            "API Endpoints": [
                "Check if service is running: sudo systemctl status nginx-security-monitor",
                "Check port binding: sudo netstat -tlnp | grep 8080",
                "Check firewall: sudo ufw status"
            ]
        }
        
        for test_name in failed_tests:
            if test_name in guidance:
                print(f"\n{test_name}:")
                for step in guidance[test_name]:
                    print(f"  • {step}")

def main():
    tester = InstallationTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
```

______________________________________________________________________

**Related Documentation:**

- [Installation Guide](../INSTALLATION.md)
- [Configuration Guide](../CONFIGURATION.md)
- [Getting Started](../getting-started.md)
- [Common Issues](common-issues.md)
