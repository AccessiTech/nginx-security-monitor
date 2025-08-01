# Welcome to Nginx Security Monitor Documentation

Explore the comprehensive documentation for Nginx Security Monitor. This documentation is
organized to help you get started quickly and find the information you need.

## 🚀 Getting Started

**New to Nginx Security Monitor?** Start here:

- [Quick Start Tutorial](QUICK_START_TUTORIAL.md) - Get up and running in 5 minutes
- [Installation Guide](INSTALLATION.md) - Complete installation instructions
- [Getting Started for Developers](getting-started.md) - Development environment setup
- [Use Cases](USE_CASES.md) - Common use cases and scenarios

## 📋 Essential Documentation

### Configuration and Setup

- [Configuration Guide](CONFIGURATION.md) - Complete configuration reference
- [Deployment Guide](deployment/) - Environment-specific deployment instructions
- [Encryption Guide](ENCRYPTION_GUIDE.md) - Secure configuration practices

### Security Documentation

- [Security Best Practices](security/best-practices.md) - Production security guidelines
- [Security Features](SECURITY_FEATURES.md) - Built-in security capabilities
- [Security Integrations](SECURITY_INTEGRATIONS.md) - External security tool integration

### Operations and Monitoring

- [Operations Guide](OPERATIONS_GUIDE.md) - Day-to-day operations
- [Alert Systems](ALERT_SYSTEMS.md) - Notification and alerting
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions

## 🔧 Technical References

### Command Line Interface

- [CLI Reference](CLI_REFERENCE.md) - Complete command-line utilities guide (24 commands)
- [Executable Utilities](../bin/README.md) - Detailed command documentation with examples
- **Quick CLI Access**: All utilities are in `bin/` - run `./bin/[command] --help` for usage

### Development and Customization

- [API Reference](API_REFERENCE.md) - Complete API documentation
- [Architecture](ARCHITECTURE.md) - System architecture overview
- [Plugin Development](PLUGIN_DEVELOPMENT.md) - Creating custom plugins
- [Testing](TESTING.md) - Testing guidelines and procedures

### Detection and Response

- [Pattern Detection](PATTERN_DETECTION.md) - Threat detection patterns
- [Mitigation Strategies](MITIGATION_STRATEGIES.md) - Automated response strategies
- [Service Protection](SERVICE_PROTECTION.md) - Service hardening

## 📚 Advanced Topics

### Integration and Automation

- [Integration Cookbook](INTEGRATION_COOKBOOK.md) - Integration examples and recipes
- [Style Guide](STYLE_GUIDE.md) - Documentation and code style standards

### Contributing and Community

- [Contributing Guidelines](CONTRIBUTING.md) - How to contribute to the project
- [Code of Conduct](CODE_OF_CONDUCT.md) - Community guidelines
- [Testing Keys](TESTING_KEYS.md) - Test environment setup

## High-Level Overview

NGINX Security Monitor is a Python-based tool designed to monitor NGINX logs for potential security threats.
It provides real-time detection, mitigation, and alerting capabilities, making it ideal for production environments.
Key features include:

- **Threat Detection**: Identifies attack patterns such as SQL injection, XSS, DDoS, and brute force (see [Pattern Detection](PATTERN_DETECTION.md)).

- **Mitigation Strategies**: Applies countermeasures to neutralize threats (see [Mitigation Strategies](MITIGATION_STRATEGIES.md)).

- **Alerting System**: Sends notifications via email and SMS (see [Alert Systems](ALERT_SYSTEMS.md)).

- **System Integration**: Works seamlessly with tools like fail2ban, OSSEC/Wazuh, Suricata, and
  ModSecurity (see [Security Integrations](SECURITY_INTEGRATIONS.md)).

- **Advanced Security**: Includes encrypted pattern storage and a plugin system for custom rules (see [Security Features](SECURITY_FEATURES.md)).

- **Production-Ready**: Can run as a Linux systemd service with security hardening (see [Service Protection](SERVICE_PROTECTION.md)).

  > For full production security and system integration, set the following environment variable before starting the service:
  >
  > ```sh
  > export NSM_ENV=production
  > ```

For a complete list of topics, use the sidebar navigation.
