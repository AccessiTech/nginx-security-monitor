# Development Environment Deployment

This guide covers setting up Nginx Security Monitor for local development and testing.

## Quick Setup

### Prerequisites

- Python 3.8+
- Git
- Docker (optional, for containerized development)
- Nginx (for log generation testing)

### Installation

```bash
# Clone repository
git clone https://github.com/AccessiTech/nginx-security-monitor.git
cd nginx-security-monitor

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate    # Windows

# Install in development mode
pip install -e .
pip install -r dev-requirements.txt
```

## Configuration

### Development Configuration

```yaml
# config/development.yaml
service:
  name: "nginx-security-monitor-dev"
  environment: "development"
  debug: true

logging:
  level: DEBUG
  console: true
  file: ./logs/dev-monitor.log
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

monitoring:
  nginx_log_path: "./test-data/nginx-access.log"
  poll_interval: 1.0  # Faster polling for development
  
detection:
  patterns_file: "./config/patterns-dev.json"
  enabled_rules:
    - sql_injection
    - xss_attempts
    - brute_force
    - directory_traversal

alerts:
  console: true
  email:
    enabled: false  # Disable email in dev
  webhooks:
    enabled: false  # Disable webhooks in dev

integrations:
  fail2ban:
    enabled: false
  ossec:
    enabled: false
  suricata:
    enabled: false

security:
  encryption:
    enabled: false  # Simplify for development
  rate_limiting:
    enabled: true
    requests_per_minute: 1000  # Higher limit for testing
```

### Environment Variables

```bash
# .env file for development
NSM_CONFIG_PATH=./config/development.yaml
NSM_LOG_LEVEL=DEBUG
NSM_NGINX_LOG_PATH=./test-data/nginx-access.log
NSM_CONSOLE_OUTPUT=true
NSM_DEBUG_MODE=true
```

## Development Workflow

### 1. Start Development Server

```bash
# Activate virtual environment
source venv/bin/activate

# Start in development mode
python -m nginx_security_monitor --config config/development.yaml --debug

# Or use the development script
./scripts/dev-server.sh
```

### 2. Generate Test Data

```bash
# Create test log entries
python scripts/generate-test-logs.py --output test-data/nginx-access.log

# Generate various attack patterns
python scripts/generate-test-attacks.py --count 100 --output test-data/attack-logs.log
```

### 3. Hot Reload Development

```bash
# Install development dependencies
pip install watchdog

# Start with hot reload
python scripts/dev-watch.py

# This will automatically restart when files change
```

## Testing

### Unit Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories
python -m pytest tests/unit/ -v
python -m pytest tests/integration/ -v

# Run with coverage
python -m pytest --cov=src/nginx_security_monitor tests/ --cov-report=html
```

### Integration Testing

```bash
# Test with real log data
python -m pytest tests/integration/test_log_processing.py -v

# Test pattern detection
python -m pytest tests/integration/test_pattern_detection.py -v

# Test configuration loading
python -m pytest tests/integration/test_config.py -v
```

### Manual Testing

<!-- markdownlint-disable MD013 -->

```bash
# Test pattern detection manually
echo '192.168.1.100 - - [20/Jul/2025:10:15:30 +0000] "GET /admin.php?id=1 UNION SELECT * FROM users-- HTTP/1.1" 200 1234' >> test-data/nginx-access.log

# Check if detection works
tail -f logs/dev-monitor.log

# Test configuration validation
python -c "from nginx_security_monitor.config import load_config; print(load_config('./config/development.yaml'))"
```

<!-- markdownlint-enable MD013 -->

## Development Tools

### Code Quality Tools

```bash
# Install development tools
pip install black flake8 mypy pre-commit bandit

# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/

# Security scanning
bandit -r src/
```

### Pre-commit Hooks

```bash
# Install pre-commit hooks
pre-commit install

# Run manually
pre-commit run --all-files

# Update hooks
pre-commit autoupdate
```

### Debug Tools

```bash
# Enable debug logging
export NSM_LOG_LEVEL=DEBUG

# Profile performance
python -m cProfile -o profile.stats -m nginx_security_monitor

# Memory profiling
pip install memory_profiler
python -m memory_profiler scripts/profile-memory.py
```

## Docker Development

### Development Container

```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  nginx-security-monitor:
    build:
      context: .
      dockerfile: Dockerfile.dev
    volumes:
      - .:/app
      - ./config:/app/config
      - ./test-data:/app/test-data
      - ./logs:/app/logs
    environment:
      - NSM_CONFIG_PATH=/app/config/development.yaml
      - NSM_LOG_LEVEL=DEBUG
    ports:
      - "8080:8080"
    command: python -m nginx_security_monitor --config /app/config/development.yaml
```

```bash
# Start development container
docker-compose -f docker-compose.dev.yml up --build

# Shell into container
docker-compose -f docker-compose.dev.yml exec nginx-security-monitor bash
```

### Development Dockerfile

```dockerfile
# Dockerfile.dev
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt dev-requirements.txt ./
RUN pip install -r requirements.txt -r dev-requirements.txt

# Copy source code
COPY . .

# Install in development mode
RUN pip install -e .

# Create logs directory
RUN mkdir -p logs test-data

EXPOSE 8080

CMD ["python", "-m", "nginx_security_monitor"]
```

## IDE Configuration

### VS Code Configuration

```json
// .vscode/settings.json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.formatting.provider": "black",
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": ["tests/"],
  "files.exclude": {
    "**/__pycache__": true,
    "**/*.pyc": true,
    ".coverage": true,
    "htmlcov/": true
  }
}
```

```json
// .vscode/launch.json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug Nginx Security Monitor",
      "type": "python",
      "request": "launch",
      "module": "nginx_security_monitor",
      "args": ["--config", "config/development.yaml", "--debug"],
      "console": "integratedTerminal",
      "env": {
        "NSM_LOG_LEVEL": "DEBUG"
      }
    }
  ]
}
```

## Performance Monitoring

### Development Metrics

```bash
# Monitor resource usage
python scripts/monitor-resources.py

# Check detection performance
python scripts/benchmark-detection.py

# Memory usage tracking
python scripts/track-memory.py
```

### Profiling

```bash
# CPU profiling
python -m cProfile -o cpu.prof -m nginx_security_monitor
snakeviz cpu.prof

# Line profiling
pip install line_profiler
kernprof -l -v scripts/profile-detection.py
```

## Troubleshooting

### Common Issues

1. **Import Errors**

   ```bash
   # Ensure development installation
   pip install -e .
   ```

1. **Test Failures**

   ```bash
   # Clear pytest cache
   python -m pytest --cache-clear
   ```

1. **Permission Issues**

   ```bash
   # Fix log directory permissions
   mkdir -p logs
   chmod 755 logs
   ```

### Debug Information

```bash
# Check Python path
python -c "import sys; print('\n'.join(sys.path))"

# Verify installation
python -c "import nginx_security_monitor; print(nginx_security_monitor.__file__)"

# Check configuration
python -c "from nginx_security_monitor.config import load_config; print(load_config())"
```

## Next Steps

1. **Explore the codebase**: Start with `src/nginx_security_monitor/`
1. **Run the test suite**: `python -m pytest tests/ -v`
1. **Make your first change**: Edit a pattern in `config/patterns.json`
1. **Create a feature branch**: `git checkout -b feature/my-feature`

______________________________________________________________________

**Related Documentation:**

- [Getting Started Guide](../getting-started.md)
- [Testing Guide](../TESTING.md)
- [Configuration Guide](../CONFIGURATION.md)
- [Contributing Guidelines](../CONTRIBUTING.md)
