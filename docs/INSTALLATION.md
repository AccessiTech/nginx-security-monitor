# 🚀 Installation Guide

Complete installation guide for NGINX Security Monitor across different environments and platforms.

## 📋 **Prerequisites**

### **System Requirements**

- **Python**: 3.8 or higher
- **Operating System**: Linux (Ubuntu 18.04+, CentOS 7+), macOS 10.15+, Windows 10+
- **Memory**: Minimum 512MB RAM, Recommended 1GB+
- **Storage**: 100MB for application, additional space for logs
- **Network**: Internet access for dependency installation

### **Required Permissions**

- Read access to NGINX log files
- Write access to configuration directories
- Optional: systemd service management (for service installation)

## 🛠 **Installation Methods**

## Method 1: Development Installation (Recommended for Testing)

### **Step 1: Clone and Setup**

```bash
# Clone the repository
git clone https://github.com/AccessiTech/nginx-security-monitor.git
cd nginx-security-monitor

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# Windows: .venv\Scripts\activate
```

### **Step 2: Install Dependencies**

```bash
# Install all dependencies (core + development tools)
pip install -r requirements.txt

# For clean install (force reinstall):
pip install -r requirements.txt --force-reinstall

# Install only core dependencies:
pip install pyyaml>=6.0 cryptography>=3.4.8 psutil>=5.8.0
```

### **Step 3: Verify Installation**

```bash
# Use the built-in installation test utility
./bin/test-installation

# For verbose output during testing
./bin/test-installation --verbose

# Quick essential tests only
./bin/test-installation --quick

# Test core modules manually (alternative)
python -c "import src.log_parser; print('✅ Log parser loaded')"
python -c "import src.pattern_detector; print('✅ Pattern detector loaded')"
python -c "import src.alert_manager; print('✅ Alert manager loaded')"

# Run tests to verify everything works
pytest
```

## Method 2: Production Installation (System Service)

### **Step 1: System Preparation**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv git

# CentOS/RHEL
sudo yum install python3 python3-pip git
# or on newer versions:
sudo dnf install python3 python3-pip git

# Create system user
sudo useradd -r -s /bin/false -d /opt/nginx-security-monitor nginx-monitor
```

### **Step 2: Install Application**

```bash
# Clone to system location
sudo git clone https://github.com/AccessiTech/nginx-security-monitor.git /opt/nginx-security-monitor
cd /opt/nginx-security-monitor

# Create virtual environment
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt

# Set permissions
sudo chown -R nginx-monitor:nginx-monitor /opt/nginx-security-monitor
sudo chmod +x nginx-security-monitor.sh
```

### **Step 3: Configure System Service**

```bash
# Copy service file
sudo cp systemd/nginx-security-monitor.service /etc/systemd/system/

# Create configuration directory
sudo mkdir -p /etc/nginx-security-monitor
sudo cp config/*.yaml /etc/nginx-security-monitor/
sudo chown -R nginx-monitor:nginx-monitor /etc/nginx-security-monitor

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable nginx-security-monitor
sudo systemctl start nginx-security-monitor
```

## Method 3: Docker Installation

### **Step 1: Build Docker Image**

```bash
# Clone repository
git clone https://github.com/AccessiTech/nginx-security-monitor.git
cd nginx-security-monitor

# Build image
docker build -t nginx-security-monitor .
```

### **Step 2: Run Container**

```bash
# Create volume for configuration
docker volume create nginx-security-config

# Run container
docker run -d \
  --name nginx-security-monitor \
  -v nginx-security-config:/etc/nginx-security-monitor \
  -v /var/log/nginx:/var/log/nginx:ro \
  --restart unless-stopped \
  nginx-security-monitor
```

### **Step 3: Docker Compose (Recommended)**

```yaml
# docker-compose.yml
version: '3.8'
services:
  nginx-security-monitor:
    build: .
    container_name: nginx-security-monitor
    volumes:
      - ./config:/etc/nginx-security-monitor
      - /var/log/nginx:/var/log/nginx:ro
    environment:
      - LOG_LEVEL=INFO
    restart: unless-stopped
```

```bash
# Start with docker-compose
docker-compose up -d
```

## 🔧 **Platform-Specific Instructions**

### **Ubuntu 20.04/22.04**

```bash
# Install dependencies
sudo apt update
sudo apt install python3.9 python3.9-venv python3-pip git

# Follow Method 1 or 2 above
```

### **CentOS 8/RHEL 8**

```bash
# Enable Python 3.9
sudo dnf module enable python39
sudo dnf install python39 python39-pip git

# Follow Method 1 or 2 above
```

### **macOS**

```bash
# Install Python via Homebrew (recommended)
brew install python@3.9 git

# Follow Method 1 above
```

### **Windows 10/11**

```powershell
# Install Python from python.org or Microsoft Store
# Install Git from git-scm.com

# Clone repository
git clone https://github.com/AccessiTech/nginx-security-monitor.git
cd nginx-security-monitor

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## 🚨 **Troubleshooting Common Issues**

### **Issue: Permission Denied on NGINX Logs**

```bash
# Add user to nginx group
sudo usermod -a -G nginx $USER

# Or adjust log file permissions
sudo chmod 644 /var/log/nginx/*.log
```

### **Issue: Python Version Too Old**

```bash
# Ubuntu: Install newer Python
sudo apt install software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.9 python3.9-venv

# CentOS: Enable newer Python module
sudo dnf module enable python39
sudo dnf install python39
```

### **Issue: Dependencies Won't Install**

```bash
# Upgrade pip first
pip install --upgrade pip

# Install with no cache
pip install -r requirements.txt --no-cache-dir

# Install with force reinstall
pip install -r requirements.txt --force-reinstall
```

### **Issue: Service Won't Start**

```bash
# Check service status
sudo systemctl status nginx-security-monitor

# Check logs
sudo journalctl -u nginx-security-monitor -f

# Verify configuration
sudo /opt/nginx-security-monitor/.venv/bin/python -m src.monitor_service --check-config
```

## ✅ **Verification Steps**

### **Test Installation**

```bash
# Activate environment (if using Method 1)
source .venv/bin/activate

# Test core functionality
python -c "
from src.log_parser import parse_logs
from src.pattern_detector import PatternDetector
print('✅ Core modules working')
"

# Run test suite
pytest tests/ -v
```

### **Test Configuration**

```bash
# Validate configuration files
python -c "
import yaml
with open('config/settings.yaml') as f:
    config = yaml.safe_load(f)
print('✅ Configuration valid')
"
```

### **Test Log Access**

```bash
# Test NGINX log access
python -c "
import os
log_file = '/var/log/nginx/access.log'
if os.path.exists(log_file) and os.access(log_file, os.R_OK):
    print('✅ Can read NGINX logs')
else:
    print('❌ Cannot read NGINX logs')
"
```

## **Environment Variables Setup**

### **Step 4: Configure Environment Variables**

```bash
# Create a .env file in the application directory
cd /opt/nginx-security-monitor
sudo touch .env

# Add sensitive information to the .env file
sudo bash -c 'echo "SECRET_KEY=your_secret_key" >> .env'
sudo bash -c 'echo "DATABASE_URL=your_database_url" >> .env'

# Set permissions for the .env file
sudo chown nginx-monitor:nginx-monitor .env
sudo chmod 600 .env
```

### **Usage**

The application automatically loads environment variables from the `.env` file. Ensure that sensitive information such as API keys, database URLs, and other credentials are stored securely in this file. Avoid committing the `.env` file to version control by adding it to `.gitignore`.

## 📚 **Next Steps**

After successful installation:

1. **Configure the system**: See [CONFIGURATION.md](CONFIGURATION.md)
1. **Set up alerts**: See [ALERT_SYSTEMS.md](ALERT_SYSTEMS.md)
1. **Customize patterns**: See [PATTERN_DETECTION.md](PATTERN_DETECTION.md)
1. **Start monitoring**: See [QUICK_START_TUTORIAL.md](QUICK_START_TUTORIAL.md)

## 🆘 **Getting Help**

- **Documentation**: Check the relevant guide in the docs/ directory
- **Issues**: Report problems on GitHub Issues
- **Community**: Join discussions in GitHub Discussions
- **Support**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed help
