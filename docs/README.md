# 📚 Documentation Quick Reference

## Configuration & Setup

### Getting Started

- **[README.md](../README.md)** - Main project overview and quick setup
- **[Installation Guide](INSTALLATION.md)** - Detailed installation instructions
- **[Quick Start Tutorial](QUICK_START_TUTORIAL.md)** - Step-by-step tutorial

### Configuration

- **[Configuration Guide](CONFIGURATION.md)** - Complete reference of all configuration options
- **[Configuration System](CONFIGURATION_SYSTEM.md)** - Advanced ConfigManager usage and best practices
- **[Configuration Troubleshooting](troubleshooting/configuration-issues.md)** - Configuration issues and solutions

## Feature Documentation

### Security Features

- **[Security Features](SECURITY_FEATURES.md)** - Overview of security capabilities
- **[Security Integrations](SECURITY_INTEGRATIONS.md)** - Third-party security tool integration
- **[Encryption Guide](ENCRYPTION_GUIDE.md)** - Configuration encryption and key management

### Detection & Response

- **[Mitigation Strategies](MITIGATION_STRATEGIES.md)** - Automated response options
- **[Use Cases](USE_CASES.md)** - Real-world usage scenarios

## Troubleshooting & Operations

### Troubleshooting

- **[Configuration Issues](troubleshooting/configuration-issues.md)** - ⭐ **NEW** - ConfigManager and schema problems
- **[Installation Issues](troubleshooting/installation-issues.md)** - Setup and deployment problems

### Operations

- **[Operations Guide](OPERATIONS_GUIDE.md)** - Day-to-day operations and maintenance

## Developer Documentation

### Development

- **[Contributing](CONTRIBUTING.md)** - How to contribute to the project
- **[Style Guide](STYLE_GUIDE.md)** - Code style and conventions
- **[Integration Cookbook](INTEGRATION_COOKBOOK.md)** - Custom integrations

## Recent Updates (2025-08-01)

🎉 **Major Configuration System Improvements:**

- **Fixed all 26 failing tests** - ConfigManager now properly supports test isolation and comprehensive schema validation
- **Enhanced schema system** - Added support for flexible sections like `encrypted_config` with arbitrary keys
- **Improved documentation** - New troubleshooting guides and comprehensive configuration reference
- **Built-in schema fallback** - System works reliably even when schema files are missing
- **Test isolation** - ConfigManager singleton properly resets between tests

### Key Documentation Updates

1. **[Configuration Troubleshooting](troubleshooting/configuration-issues.md)** - Brand new guide for configuration issues
1. **[Configuration System](CONFIGURATION_SYSTEM.md)** - Singleton pattern, test isolation, and schema format
1. **[Configuration Guide](CONFIGURATION.md)** - Added comprehensive schema documentation section

> **For Configuration Issues**: Start with [Configuration Troubleshooting](troubleshooting/configuration-issues.md) -
> it covers 95% of common problems including test failures, validation errors, and schema issues.
