# Security Features Documentation

## Overview

The NGINX Security Monitor includes advanced security features to protect your custom detection patterns and
mitigation strategies from being exposed in the open-source codebase.
This allows you to keep your specific security measures private while still
benefiting from the open-source framework.

## Key Security Features

### 1. Encrypted Pattern Storage

- Store custom detection patterns in encrypted files
- Patterns are encrypted using AES-256 with PBKDF2 key derivation
- Only your system can decrypt and use your custom patterns

### 2. Plugin System for Custom Mitigations

- Keep your actual countermeasures private in custom plugins
- Plugin system loads your private mitigation strategies at runtime
- No need to expose your specific security responses in the public code

### 3. Obfuscation and Randomization

- Variable timing to avoid predictable detection patterns
- Randomized detection order to confuse attackers
- Decoy log entries to mask real analysis patterns

### 4. Encrypted Configuration Sections

- Encrypt sensitive configuration data (API keys, passwords, etc.)
- Configuration sections are decrypted at runtime only

## Setup Instructions

### 1. Install Cryptographic Dependencies

```bash
pip install cryptography
```

### 2. Generate Master Key

````bash
```bash
# Interactive encryption wizard
./bin/encrypt-config interactive
# or
export NGINX_MONITOR_KEY=$(python3 -c "from nginx_security_monitor.crypto_utils import generate_master_key; print(generate_master_key())")
````

**Important**: Save this key securely! You'll need it to decrypt your patterns.

### 3. Create Encrypted Patterns

Use the configuration utility to create encrypted pattern files:

```bash
./bin/encrypt-config encrypt-patterns
```

This will interactively help you create:

- Custom SQL injection patterns
- Custom XSS detection rules
- Custom attack signatures
- Custom thresholds

### 4. Create Custom Mitigation Plugins

```bash
python3 encrypt_config.py create-plugin
```

This creates a template for your custom mitigation strategy. Edit the template to implement your specific countermeasures:

```python
def mitigate(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
    """Your secret mitigation logic here"""
    ip_address = threat_info.get('ip')
    
    # Your custom mitigation code:
    # - Block IP in your firewall
    # - Call your WAF API
    # - Update your threat intelligence database
    # - Trigger custom alerting systems
    # - etc.
    
    return {
        'status': 'success',
        'action': 'custom_action_taken',
        'method': 'your_secret_method'
    }
```

### 5. Configure the Service

Update your configuration file:

```yaml
# Enable security features
security:
  encrypted_patterns_file: /opt/nginx-security-monitor/custom_patterns.enc
  obfuscation:
    enabled: true
    timing_variance_percent: 20
    add_decoy_entries: true
    randomize_pattern_order: true

# Plugin directories
plugins:
  directories:
    - /opt/nginx-security-monitor/plugins
    - /opt/nginx-security-monitor/custom_plugins
```

## Security Benefits

### For Open Source Projects

1. **Pattern Privacy**: Your specific detection rules remain secret
1. **Mitigation Privacy**: Your countermeasures are not visible to attackers
1. **Configuration Security**: Sensitive data is encrypted
1. **Timing Obfuscation**: Makes reverse engineering detection logic harder

### For Production Environments

> **Note:** The `NSM_ENV=production` flag is required for full security hardening and system integration.
> Set this environment variable in your production deployment scripts or shell before starting the service:
>
> ```sh
> export NSM_ENV=production
> ```

1. **Zero-Knowledge Architecture**: The open-source code doesn't contain your secrets
1. **Pluggable Security**: Easy to add custom mitigations without code changes
1. **Encrypted Storage**: Patterns and configurations are encrypted at rest
1. **Runtime Security**: Decryption only happens when needed

## Example: Creating Secret Patterns

```bash
# 1. Set your master key
export NGINX_MONITOR_KEY="your-secret-key-here"

# 2. Create encrypted patterns
python3 encrypt_config.py encrypt-patterns

# Example patterns you might add:
# - Custom SQL injection signatures specific to your application
# - Application-specific attack patterns
# - Custom bot detection rules
# - Proprietary threat intelligence indicators
```

## Example: Custom Plugin

```python
# File: /opt/nginx-security-monitor/plugins/my_secret_plugin.py

from plugin_system import MitigationPlugin
import requests

class MySecretMitigationPlugin(MitigationPlugin):
    @property
    def name(self):
        return "my_secret_mitigation"
    
    @property  
    def threat_types(self):
        return ["SQL Injection", "XSS Attack"]
    
    def can_handle(self, threat_info):
        return threat_info.get('severity') == 'HIGH'
    
    def mitigate(self, threat_info):
        ip = threat_info.get('ip')
        
        # Your secret mitigation - could be:
        # 1. Call to your proprietary WAF API
        # 2. Custom firewall rules
        # 3. Threat intelligence database updates
        # 4. Custom notification systems
        
        # Example: Block IP in cloud WAF
        response = requests.post(
            'https://your-waf-api.com/block',
            headers={'Authorization': 'Bearer your-secret-token'},
            json={'ip': ip, 'duration': 3600}
        )
        
        if response.status_code == 200:
            return {
                'status': 'success',
                'action': 'cloud_waf_block',
                'ip_address': ip
            }
        else:
            return {
                'status': 'error',
                'error': 'WAF API call failed'
            }
```

## Best Practices

### 1. Key Management

- Store master keys in environment variables or secure key management systems
- Use different keys for different environments (dev/staging/prod)
- Rotate keys periodically

### 2. Plugin Security

- Keep plugin files in secure directories with restricted permissions
- Don't commit plugin files to public repositories
- Use separate plugins for different threat types

### 3. Pattern Management

- Regularly update your encrypted patterns based on new threats
- Test patterns in a development environment first
- Keep backups of your encrypted pattern files

### 4. Monitoring

- Monitor plugin execution for errors
- Log mitigation actions (without revealing strategies)
- Regular security audits of your custom patterns

## Troubleshooting

### Common Issues

1. **"Decryption failed"**

   - Check that NGINX_MONITOR_KEY environment variable is set
   - Verify the master key is correct
   - Ensure the encrypted file is not corrupted

1. **"Plugin not found"**

   - Check plugin directory permissions
   - Verify plugin file syntax
   - Check service logs for plugin loading errors

1. **"Security features not available"**

   - Install cryptography: `pip install cryptography`
   - Restart the service after installation

### Debug Mode

Enable debug logging to troubleshoot security features:

```yaml
logging:
  level: DEBUG
```

Then check logs:

```bash
sudo journalctl -u nginx-security-monitor -f
```

## Migration from Basic Setup

If you're upgrading from the basic version:

1. Install cryptography dependency
1. Create master key
1. Migrate existing patterns to encrypted format
1. Create custom plugins for any manual mitigations
1. Update configuration
1. Restart service

The system is backward compatible - if no encrypted patterns or plugins are found,
it will use the default open-source detection methods.
