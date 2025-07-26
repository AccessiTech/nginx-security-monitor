# Testing Keys and Development Setup

## Overview

This guide provides information about test master keys and setup for development and testing of the
NGINX Security Monitor encryption utilities.

## Test Master Keys

### Quick Setup

For development and testing, use the standard test key:

```bash
export NGINX_MONITOR_KEY="test_key"
```

### Available Test Keys

| Key                                 | Usage           | Description                                                   |
| ----------------------------------- | --------------- | ------------------------------------------------------------- |
| `test_key`                          | **Most Common** | Used throughout test suite, recommended for development       |
| `default_test_key_for_testing_only` | **Fallback**    | Built-in fallback in `crypto_utils.py` when no env var is set |
| `test_key_1234567890123456`         | **Extended**    | 16+ character version for specific encryption tests           |

### When Prompted by Utilities

#### encrypt_config.py

When the utility prompts for a master key:

```text
Enter your master key: test_key
```

#### Development Scripts

Set environment variable before running:

```bash
export NGINX_MONITOR_KEY="test_key"
python encrypt_config.py encrypt-patterns
```

#### Testing

All automated tests use mocked keys via patching - no manual setup needed:

```bash
pytest tests/test_encrypt_config_util.py
pytest tests/test_crypto_utils_advanced.py
```

## Utility Coverage Status

### ✅ encrypt_config.py (91% Coverage)

- **Test Suite**: 23 comprehensive test cases
- **Coverage**: 205 statements, 18 missing (91%)
- **Master Key**: Required - use `test_key`
- **Features Tested**: Pattern encryption, config sections, plugin generation, CLI actions

### ✅ security_integrations_util.py (91% Coverage)

- **Test Suite**: 16 comprehensive test cases
- **Coverage**: 202 statements, 19 missing (91%)
- **Master Key**: Not required
- **Features Tested**: Fail2ban setup, OSSEC integration, service detection, configuration

## Security Notes

⚠️ **Important**: These keys are for development and testing only!

- ✅ **Safe for**: Local development, automated testing, CI/CD pipelines
- ❌ **Not for**: Production deployments, live security monitoring
- 🔒 **Production**: Use `generate_master_key()` function to create secure keys

## Integration with Test Suite

The test suite automatically handles key management:

```python
# In tests - keys are automatically mocked
@patch("os.environ.get", return_value="test_key")
def test_encryption_feature(self, mock_env):
    # Test logic here - uses mocked key
    pass
```

## Troubleshooting

### Common Issues

1. **"No master key set" error**:

   ```bash
   export NGINX_MONITOR_KEY="test_key"
   ```

1. **Permission denied on key file**:

   ```bash
   chmod 600 ~/.nginx-monitor/master.key
   ```

1. **Test failures with crypto errors**:

   - Ensure `cryptography` package is installed
   - Verify test environment has proper Python version (3.8+)

### Verification Commands

Test that encryption is working:

```bash
# Quick test
python -c "
import os
os.environ['NGINX_MONITOR_KEY'] = 'test_key'
from nginx_security_monitor.crypto_utils import CryptoUtils
crypto = CryptoUtils()
test_data = 'Hello, World!'
encrypted = crypto.encrypt_data(test_data)
decrypted = crypto.decrypt_data(encrypted)
print(f'Success: {test_data == decrypted}')
"
```

## Next Steps

1. **For Contributors**: Use `test_key` for all development work
1. **For Testing**: Run `pytest tests/test_*_util.py` to verify utility coverage
1. **For Production**: Generate secure keys with `encrypt_config.py` utility
1. **For Documentation**: Update this guide when adding new utilities

______________________________________________________________________

**Last Updated**: Coverage finalization - utility scripts now at 91% coverage each
**Test Suite Status**: 39 utility tests passing, comprehensive coverage achieved
