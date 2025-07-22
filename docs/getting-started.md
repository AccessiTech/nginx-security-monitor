# Getting Started for Developers

Welcome to the Nginx Security Monitor development environment! This guide will help you set up
your development environment, understand the codebase, and make your first contribution.

## Prerequisites

- Python 3.8 or higher
- Git
- Text editor or IDE (VS Code recommended)
- Basic knowledge of Python and security concepts

## Quick Setup

### 1. Clone and Setup Environment

```bash
# Clone the repository
git clone https://github.com/AccessiTech/nginx-security-monitor.git
cd nginx-security-monitor

# Use the automated development setup tool
./bin/dev-setup

# Or manual setup:
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r dev-requirements.txt
pip install -e .
```

### 2. Verify Installation

```bash
# Use the built-in installation test utility
./bin/test-installation --verbose

# Or run basic tests manually
python -m pytest tests/ -v

# Test the main module
python -c "import nginx_security_monitor; print('Installation successful!')"
```

### 3. Configuration Setup

```bash
# Copy example configuration
cp config/settings.yaml.example config/settings.yaml

# Validate configuration
./bin/validate-config config/settings.yaml

# Generate encryption key for secure pattern storage
./bin/encrypt-config --generate-key
```

## Development Workflow

### 1. Understanding the Architecture

The project follows a modular architecture:

```text
src/
├── nginx_security_monitor/
│   ├── core/           # Core monitoring engine
│   ├── detection/      # Threat detection modules
│   ├── mitigation/     # Response strategies
│   ├── integrations/   # External tool integrations
│   └── plugins/        # Plugin system
```

**Key Components:**

- **Core Engine**: Main monitoring loop and log processing
- **Pattern Detection**: Rule-based threat identification
- **Mitigation System**: Automated response mechanisms
- **Integration Layer**: External security tool connectivity
- **Plugin System**: Extensible custom rule engine

### 2. Making Changes

```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Make your changes
# Edit files in src/, tests/, or docs/

# Test your changes
./bin/test-patterns --file config/patterns.json
./bin/test-alerts --test-config

# Run comprehensive tests
./bin/test-installation --verbose

# Run linting and security checks
./bin/security-check --code-analysis

# Or manual checks:
python -m pytest tests/ -v
flake8 src/ tests/
black src/ tests/
bandit -r src/
```

### 3. Testing Your Changes

```bash
# Unit tests
python -m pytest tests/unit/ -v

# Integration tests
python -m pytest tests/integration/ -v

# Coverage report
python -m pytest --cov=src/nginx_security_monitor tests/

# Test specific component
python -m pytest tests/test_detection.py -v
```

## Common Development Tasks

### Adding New Threat Patterns

1. Edit `config/patterns.json`:

   ```json
   {
     "sql_injection": {
       "patterns": ["(?i)(union.*select|select.*from)", "(?i)(drop.*table|delete.*from)"],
       "severity": "high",
       "description": "SQL injection attempt detected"
     }
   }
   ```

1. Add corresponding tests in `tests/test_patterns.py`

1. Update documentation in `docs/PATTERN_DETECTION.md`

### Creating New Integrations

1. Create new file in `src/nginx_security_monitor/integrations/`
1. Implement the integration interface
1. Add configuration to `config/settings.yaml`
1. Write tests in `tests/integration/`
1. Document in `docs/SECURITY_INTEGRATIONS.md`

### Developing Plugins

See our comprehensive [Plugin Development Guide](PLUGIN_DEVELOPMENT.md) for detailed instructions.

## Debugging and Troubleshooting

### Enable Debug Logging

```bash
# Set environment variable
export NGINX_MONITOR_LOG_LEVEL=DEBUG

# Or modify config/settings.yaml
logging:
  level: DEBUG
  file: /var/log/nginx-security-monitor.log
```

### Common Issues

1. **Import Errors**: Ensure you've installed in development mode with `pip install -e .`
1. **Permission Errors**: Check file permissions on log files and config directories
1. **Test Failures**: Verify all dependencies are installed with `pip install -r dev-requirements.txt`

### Debug Tools

```bash
# Check configuration
python -c "from nginx_security_monitor.config import load_config; print(load_config())"

# Test pattern matching
python scripts/test_patterns.py --input-file sample.log

# Validate integrations
python scripts/validate_integrations.py
```

## Code Style and Standards

We follow PEP 8 with some modifications. Key points:

- Line length: 88 characters (Black default)
- Use type hints for all public functions
- Docstrings in Google style
- Import order: standard library, third-party, local

### Pre-commit Hooks

```bash
# Install pre-commit hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

## Documentation

- All public APIs must be documented
- Include code examples in docstrings
- Update relevant documentation files
- Add entries to the changelog

See our [Style Guide](STYLE_GUIDE.md) for detailed documentation standards.

## Getting Help

If you encounter issues during development:

1. Check the [troubleshooting guide](troubleshooting/common-issues.md)
1. Review existing [GitHub issues](https://github.com/AccessiTech/nginx-security-monitor/issues)
1. Join our [community discussions](https://github.com/AccessiTech/nginx-security-monitor/discussions)
1. Consult the [operations guide](OPERATIONS_GUIDE.md) for deployment issues

## Next Steps

1. **Explore the Codebase**: Start with `src/nginx_security_monitor/core/`
1. **Run Examples**: Check out `examples/` directory
1. **Read Documentation**: Review [ARCHITECTURE.md](ARCHITECTURE.md)
1. **Join Development**: See [CONTRIBUTING.md](CONTRIBUTING.md)

Happy coding! 🚀

______________________________________________________________________

**Related Documentation:**

- [Installation Guide](INSTALLATION.md)
- [Configuration Guide](CONFIGURATION.md)
- [Testing Guide](TESTING.md)
- [Plugin Development](PLUGIN_DEVELOPMENT.md)
- [Contributing Guidelines](CONTRIBUTING.md)
