# crypto_utils

Cryptographic utilities for securing custom patterns and configurations.
This allows clients to keep their specific detection patterns and countermeasures private.

## Classes

### SecurityConfigManager

Manages encrypted configuration and pattern files.

#### Methods

##### encrypt_data(data)

Encrypt data (dict or string) and return base64 encoded result.

**Parameters:**

- **data**

##### decrypt_data(encrypted_data)

Decrypt base64 encoded data and return original dict/string.

**Parameters:**

- **encrypted_data**

##### encrypt_file(input_file, output_file)

Encrypt a file and save to output location.

**Parameters:**

- **input_file**
- **output_file**

##### decrypt_file(encrypted_file)

Decrypt a file and return contents.

**Parameters:**

- **encrypted_file**

### PatternObfuscator

Adds randomization and obfuscation to detection patterns.

#### Methods

##### randomize_check_interval(base_interval, variance_percent = 20)

Add randomness to check intervals to avoid predictable patterns.

**Parameters:**

- **base_interval**
- **variance_percent** = 20

##### obfuscate_pattern_order(patterns)

Randomize the order of pattern checking to avoid predictable detection.

**Parameters:**

- **patterns**

##### add_decoy_requests(log_entries, decoy_count = None)

Add fake log entries to make real patterns harder to identify.

**Parameters:**

- **log_entries**
- **decoy_count** = None

##### variable_delay(base_delay = 0.1, max_delay = 1.0)

Add variable delays to make timing analysis harder.

**Parameters:**

- **base_delay** = 0.1
- **max_delay** = 1.0

## Functions

##### generate_master_key()

Generate a secure random master key for encryption.

##### create_encrypted_pattern_file(patterns_dict, output_file, master_key_env = 'NGINX_MONITOR_KEY')

Helper function to create encrypted pattern files.

**Parameters:**

- **patterns_dict**
- **output_file**
- **master_key_env** = 'NGINX_MONITOR_KEY'

##### encrypt_data(self, data)

Encrypt data (dict or string) and return base64 encoded result.

**Parameters:**

- **self**
- **data**

##### decrypt_data(self, encrypted_data)

Decrypt base64 encoded data and return original dict/string.

**Parameters:**

- **self**
- **encrypted_data**

##### encrypt_file(self, input_file, output_file)

Encrypt a file and save to output location.

**Parameters:**

- **self**
- **input_file**
- **output_file**

##### decrypt_file(self, encrypted_file)

Decrypt a file and return contents.

**Parameters:**

- **self**
- **encrypted_file**

##### randomize_check_interval(self, base_interval, variance_percent = 20)

Add randomness to check intervals to avoid predictable patterns.

**Parameters:**

- **self**
- **base_interval**
- **variance_percent** = 20

##### obfuscate_pattern_order(self, patterns)

Randomize the order of pattern checking to avoid predictable detection.

**Parameters:**

- **self**
- **patterns**

##### add_decoy_requests(self, log_entries, decoy_count = None)

Add fake log entries to make real patterns harder to identify.

**Parameters:**

- **self**
- **log_entries**
- **decoy_count** = None

##### variable_delay(self, base_delay = 0.1, max_delay = 1.0)

Add variable delays to make timing analysis harder.

**Parameters:**

- **self**
- **base_delay** = 0.1
- **max_delay** = 1.0
