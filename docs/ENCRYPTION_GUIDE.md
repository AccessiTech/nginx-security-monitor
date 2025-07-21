# 🔐 Encryption Guide - NGINX Security Monitor

## 🎯 **Overview**

The NGINX Security Monitor includes comprehensive encryption capabilities to protect sensitive configuration data, pattern definitions, and communication channels. This guide covers implementing encrypted configurations, key management best practices, and security audit considerations.

## 🔑 **Encryption Architecture**

### **What Gets Encrypted**

| Component                  | Purpose                          | Encryption Method  |
| -------------------------- | -------------------------------- | ------------------ |
| **Configuration Files**    | Protect sensitive settings       | AES-256-GCM        |
| **Pattern Definitions**    | Secure custom detection patterns | AES-256-CBC        |
| **API Keys & Tokens**      | Protect third-party credentials  | Fernet (symmetric) |
| **Database Connections**   | Secure database credentials      | AES-256-GCM        |
| **Communication Channels** | Encrypt alert notifications      | TLS 1.3            |
| **Log Storage**            | Protect archived security logs   | ChaCha20-Poly1305  |

### **Encryption Layers**

1. **Configuration Encryption** → Protect sensitive config at rest
1. **Runtime Encryption** → Encrypt data in memory when possible
1. **Transport Encryption** → Secure all network communications
1. **Storage Encryption** → Encrypt logs and persistent data

______________________________________________________________________

## 🔧 **Setting Up Encrypted Configuration**

### **Initial Key Generation**

Generate encryption keys for your installation:

```bash
# Generate master encryption key
python -m src.crypto_utils generate_key --output keys/master.key

# Generate configuration-specific keys
python -m src.crypto_utils generate_key --output keys/config.key
python -m src.crypto_utils generate_key --output keys/patterns.key
python -m src.crypto_utils generate_key --output keys/database.key

# Set secure permissions
chmod 600 keys/*.key
chown root:security keys/*.key
```

### **Encrypt Configuration Files**

Encrypt your existing configuration:

```bash
# Encrypt main configuration
python encrypt_config.py config/settings.yaml --key keys/config.key --output config/settings.yaml.enc

# Encrypt pattern definitions
python encrypt_config.py config/patterns.json --key keys/patterns.key --output config/patterns.json.enc

# Encrypt service settings
python encrypt_config.py config/service-settings.yaml --key keys/config.key --output config/service-settings.yaml.enc
```

### **Configuration File Structure**

Encrypted configuration format:

```yaml
# config/encrypted_config.yaml
encryption:
  enabled: true
  version: "1.0"
  algorithm: "AES-256-GCM"
  key_file: "/etc/nginx-security/keys/config.key"
  
# Encrypted data blocks
database:
  # This section will be encrypted
  encrypted_data: |
    gAAAAABhZ2V5...encrypted_content...XvYmRl
    
alerts:
  email:
    # This section will be encrypted
    encrypted_data: |
      gAAAAABhZ3R5...encrypted_content...MmNvbm
      
api_keys:
  # All API keys encrypted
  encrypted_data: |
    gAAAAABhZ4V5...encrypted_content...Tm90ZX
```

______________________________________________________________________

## 🔐 **Key Management**

### **Key Storage Options**

#### **1. File-Based Key Storage**

```yaml
encryption:
  key_storage:
    type: "file"
    key_directory: "/etc/nginx-security/keys/"
    permissions: "600"
    owner: "root"
    group: "security"
    
    # Key files
    master_key: "master.key"
    config_key: "config.key"
    patterns_key: "patterns.key"
```

#### **2. Environment Variable Storage**

```yaml
encryption:
  key_storage:
    type: "environment"
    key_mapping:
      master_key: "NSM_MASTER_KEY"
      config_key: "NSM_CONFIG_KEY"
      patterns_key: "NSM_PATTERNS_KEY"
```

Set environment variables securely:

```bash
# Export keys (use secure methods in production)
export NSM_MASTER_KEY=$(cat keys/master.key | base64 -w 0)
export NSM_CONFIG_KEY=$(cat keys/config.key | base64 -w 0)
export NSM_PATTERNS_KEY=$(cat keys/patterns.key | base64 -w 0)
```

#### **3. Hardware Security Module (HSM)**

```yaml
encryption:
  key_storage:
    type: "hsm"
    hsm_config:
      provider: "pkcs11"
      library_path: "/usr/lib/libpkcs11.so"
      slot_id: 0
      pin: "${HSM_PIN}"
      
    key_labels:
      master_key: "nginx-security-master"
      config_key: "nginx-security-config"
      patterns_key: "nginx-security-patterns"
```

#### **4. Cloud Key Management**

##### **AWS KMS Integration**

```yaml
encryption:
  key_storage:
    type: "aws_kms"
    region: "us-east-1"
    key_ids:
      master_key: "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
      config_key: "arn:aws:kms:us-east-1:123456789012:key/87654321-4321-4321-4321-210987654321"
    
    # IAM role for KMS access
    iam_role: "nginx-security-kms-role"
```

##### **Azure Key Vault Integration**

```yaml
encryption:
  key_storage:
    type: "azure_keyvault"
    vault_url: "https://nginx-security-vault.vault.azure.net/"
    client_id: "${AZURE_CLIENT_ID}"
    client_secret: "${AZURE_CLIENT_SECRET}"
    tenant_id: "${AZURE_TENANT_ID}"
    
    key_names:
      master_key: "nginx-security-master"
      config_key: "nginx-security-config"
```

##### **Google Cloud KMS Integration**

```yaml
encryption:
  key_storage:
    type: "gcp_kms"
    project_id: "nginx-security-project"
    location: "global"
    key_ring: "nginx-security-ring"
    
    key_names:
      master_key: "master-key"
      config_key: "config-key"
```

______________________________________________________________________

## 🛡️ **Advanced Encryption Features**

### **Multi-Layer Encryption**

Implement defense in depth with multiple encryption layers:

```yaml
encryption:
  multi_layer:
    enabled: true
    
    layers:
      # Layer 1: Field-level encryption
      field_level:
        enabled: true
        algorithm: "AES-256-GCM"
        fields: ["password", "api_key", "token", "secret"]
        
      # Layer 2: Section-level encryption  
      section_level:
        enabled: true
        algorithm: "ChaCha20-Poly1305"
        sections: ["database", "alerts", "integrations"]
        
      # Layer 3: File-level encryption
      file_level:
        enabled: true
        algorithm: "AES-256-CBC"
        files: ["*.yaml", "*.json", "*.conf"]
```

### **Key Rotation**

Implement automatic key rotation:

```yaml
encryption:
  key_rotation:
    enabled: true
    
    schedule:
      config_keys: "monthly"      # Rotate monthly
      pattern_keys: "quarterly"   # Rotate quarterly
      master_key: "annually"      # Rotate annually
      
    rotation_window:
      start_time: "02:00"         # 2 AM
      duration: "1h"              # 1 hour window
      
    backup_old_keys: true
    backup_retention: "1y"        # Keep old keys for 1 year
    
    notification:
      before_rotation: "7d"       # Notify 7 days before
      after_rotation: true        # Notify after completion
      alert_channels: ["email", "slack"]
```

### **Key Derivation**

Use key derivation for specific purposes:

```yaml
encryption:
  key_derivation:
    enabled: true
    algorithm: "PBKDF2"
    iterations: 100000
    salt_length: 32
    
    # Derive specific keys from master key
    derived_keys:
      log_encryption: "log_encrypt_v1"
      api_signing: "api_sign_v1"
      session_tokens: "session_v1"
      
    # Custom derivation for different environments
    environment_specific:
      production: "prod_salt_2024"
      staging: "stage_salt_2024"
      development: "dev_salt_2024"
```

______________________________________________________________________

## 🔒 **Secure Pattern Storage**

### **Encrypted Pattern Definitions**

Protect your custom detection patterns:

```bash
# Create encrypted pattern file
python -m src.crypto_utils encrypt_patterns \
    --input config/patterns.json \
    --output config/patterns.json.enc \
    --key keys/patterns.key
```

Pattern encryption format:

```json
{
  "encryption_metadata": {
    "version": "1.0",
    "algorithm": "AES-256-GCM",
    "timestamp": "2024-07-19T10:30:00Z",
    "key_id": "patterns_key_v1"
  },
  "encrypted_patterns": {
    "sql_injection": "gAAAAABhZ2V5...encrypted_pattern_data...XvYmRl",
    "xss_detection": "gAAAAABhZ3R5...encrypted_pattern_data...MmNvbm",
    "brute_force": "gAAAAABhZ4V5...encrypted_pattern_data...Tm90ZX"
  }
}
```

### **Dynamic Pattern Decryption**

Load patterns securely at runtime:

```python
# src/encrypted_patterns.py
from src.crypto_utils import CryptoUtils
import json

class EncryptedPatternLoader:
    """Load and decrypt pattern definitions."""
    
    def __init__(self, pattern_file: str, key_file: str):
        self.pattern_file = pattern_file
        self.crypto = CryptoUtils()
        self.key = self._load_key(key_file)
        
    def load_patterns(self) -> dict:
        """Load and decrypt all patterns."""
        with open(self.pattern_file, 'r') as f:
            encrypted_data = json.load(f)
            
        patterns = {}
        for pattern_name, encrypted_pattern in encrypted_data['encrypted_patterns'].items():
            try:
                decrypted = self.crypto.decrypt_data(encrypted_pattern, self.key)
                patterns[pattern_name] = json.loads(decrypted)
            except Exception as e:
                logger.error(f"Failed to decrypt pattern {pattern_name}: {e}")
                
        return patterns
    
    def add_encrypted_pattern(self, name: str, pattern: dict) -> bool:
        """Add new encrypted pattern."""
        try:
            pattern_json = json.dumps(pattern)
            encrypted = self.crypto.encrypt_data(pattern_json, self.key)
            
            # Load existing patterns
            with open(self.pattern_file, 'r') as f:
                data = json.load(f)
            
            # Add new pattern
            data['encrypted_patterns'][name] = encrypted
            
            # Save updated file
            with open(self.pattern_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            return True
        except Exception as e:
            logger.error(f"Failed to add encrypted pattern: {e}")
            return False
```

______________________________________________________________________

## 🔐 **Database Encryption**

### **Connection String Encryption**

Encrypt database connection details:

```yaml
database:
  encryption:
    enabled: true
    algorithm: "AES-256-GCM"
    
  # Encrypted connection strings
  connections:
    primary:
      encrypted_data: |
        gAAAAABhZ2V5X3JlYWxseV9sb25nX2VuY3J5cHRlZF9kYXRhX2hlcmVf
        dGhhdF9jb250YWluc190aGVfZGF0YWJhc2VfY29ubmVjdGlvbl9zdHJp
        bmdfd2l0aF91c2VybmFtZV9hbmRfcGFzc3dvcmQ
        
    backup:
      encrypted_data: |
        gAAAAABhZ3R5X2Fub3RoZXJfbG9uZ19lbmNyeXB0ZWRfY29ubmVjdGlv
        bl9zdHJpbmdfZm9yX3RoZV9iYWNrdXBfZGF0YWJhc2Vfc2VydmVy
```

### **Encrypted Data Storage**

Encrypt sensitive data in database:

```python
# src/encrypted_storage.py
from src.crypto_utils import CryptoUtils
import json
from typing import Any, Dict

class EncryptedStorage:
    """Handle encrypted data storage in database."""
    
    def __init__(self, encryption_key: bytes):
        self.crypto = CryptoUtils()
        self.key = encryption_key
        
    def store_encrypted(self, table: str, data: Dict[str, Any]) -> bool:
        """Store encrypted data in database."""
        try:
            # Encrypt sensitive fields
            encrypted_data = {}
            for field, value in data.items():
                if self._is_sensitive_field(field):
                    encrypted_data[field] = self.crypto.encrypt_data(
                        json.dumps(value), self.key
                    ).decode('utf-8')
                else:
                    encrypted_data[field] = value
            
            # Store in database (implementation depends on your DB)
            return self._store_in_database(table, encrypted_data)
            
        except Exception as e:
            logger.error(f"Failed to store encrypted data: {e}")
            return False
    
    def retrieve_decrypted(self, table: str, record_id: str) -> Dict[str, Any]:
        """Retrieve and decrypt data from database."""
        try:
            # Get encrypted data from database
            encrypted_data = self._retrieve_from_database(table, record_id)
            
            # Decrypt sensitive fields
            decrypted_data = {}
            for field, value in encrypted_data.items():
                if self._is_sensitive_field(field):
                    decrypted = self.crypto.decrypt_data(
                        value.encode('utf-8'), self.key
                    )
                    decrypted_data[field] = json.loads(decrypted)
                else:
                    decrypted_data[field] = value
                    
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Failed to retrieve decrypted data: {e}")
            return {}
    
    def _is_sensitive_field(self, field: str) -> bool:
        """Check if field contains sensitive data."""
        sensitive_fields = [
            'password', 'token', 'key', 'secret', 'credential',
            'api_key', 'auth_token', 'private_key', 'certificate'
        ]
        return any(sensitive in field.lower() for sensitive in sensitive_fields)
```

______________________________________________________________________

## 🌐 **Transport Encryption**

### **TLS Configuration**

Secure all network communications:

```yaml
network:
  tls:
    enabled: true
    version: "1.3"  # Minimum TLS 1.3
    
    # Certificate configuration
    certificates:
      server_cert: "/etc/nginx-security/certs/server.crt"
      server_key: "/etc/nginx-security/certs/server.key"
      ca_cert: "/etc/nginx-security/certs/ca.crt"
      
    # Cipher suites (TLS 1.3)
    cipher_suites:
      - "TLS_AES_256_GCM_SHA384"
      - "TLS_CHACHA20_POLY1305_SHA256"
      - "TLS_AES_128_GCM_SHA256"
    
    # Perfect Forward Secrecy
    perfect_forward_secrecy: true
    
    # Certificate validation
    verify_certificates: true
    check_hostname: true
    
    # HSTS settings
    hsts:
      enabled: true
      max_age: 31536000  # 1 year
      include_subdomains: true
      preload: true
```

### **API Communication Encryption**

Encrypt API communications:

```yaml
api:
  encryption:
    enabled: true
    
    # Request/response encryption
    payload_encryption:
      algorithm: "AES-256-GCM"
      key_exchange: "ECDH-P384"
      
    # API key encryption
    api_key_encryption:
      enabled: true
      rotation_interval: "24h"
      
    # Message authentication
    message_auth:
      algorithm: "HMAC-SHA256"
      key_derivation: "HKDF"
```

______________________________________________________________________

## 🔄 **Key Rotation Procedures**

### **Automated Key Rotation**

Implement automated key rotation:

```python
# src/key_rotation.py
import os
import shutil
from datetime import datetime, timedelta
from src.crypto_utils import CryptoUtils

class KeyRotationManager:
    """Manage automatic key rotation."""
    
    def __init__(self, config: dict):
        self.config = config
        self.crypto = CryptoUtils()
        
    def rotate_keys(self) -> bool:
        """Perform key rotation."""
        try:
            # Generate new keys
            new_keys = self._generate_new_keys()
            
            # Re-encrypt data with new keys
            self._re_encrypt_data(new_keys)
            
            # Backup old keys
            self._backup_old_keys()
            
            # Deploy new keys
            self._deploy_new_keys(new_keys)
            
            # Update key metadata
            self._update_key_metadata()
            
            # Send rotation notification
            self._send_rotation_notification()
            
            return True
            
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            return False
    
    def _generate_new_keys(self) -> dict:
        """Generate new encryption keys."""
        new_keys = {}
        
        for key_name in self.config['keys_to_rotate']:
            new_keys[key_name] = self.crypto.generate_key()
            
        return new_keys
    
    def _re_encrypt_data(self, new_keys: dict):
        """Re-encrypt data with new keys."""
        for key_name, new_key in new_keys.items():
            old_key = self._load_old_key(key_name)
            
            # Re-encrypt configuration files
            for config_file in self._get_encrypted_files(key_name):
                self._re_encrypt_file(config_file, old_key, new_key)
    
    def _backup_old_keys(self):
        """Backup old keys before rotation."""
        backup_dir = f"/etc/nginx-security/key-backups/{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(backup_dir, exist_ok=True)
        
        for key_file in self._get_key_files():
            shutil.copy2(key_file, backup_dir)
    
    def schedule_rotation(self):
        """Schedule automatic key rotation."""
        import schedule
        
        # Schedule based on configuration
        rotation_schedule = self.config.get('rotation_schedule', {})
        
        for key_type, frequency in rotation_schedule.items():
            if frequency == 'daily':
                schedule.every().day.at("02:00").do(self.rotate_keys)
            elif frequency == 'weekly':
                schedule.every().week.do(self.rotate_keys)
            elif frequency == 'monthly':
                schedule.every().month.do(self.rotate_keys)
```

### **Manual Key Rotation**

Provide manual key rotation tools:

```bash
#!/bin/bash
# scripts/rotate_keys.sh

echo "Starting key rotation process..."

# Backup current keys
BACKUP_DIR="/etc/nginx-security/key-backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp /etc/nginx-security/keys/* "$BACKUP_DIR/"

# Generate new keys
python -m src.crypto_utils generate_key --output /tmp/new_master.key
python -m src.crypto_utils generate_key --output /tmp/new_config.key
python -m src.crypto_utils generate_key --output /tmp/new_patterns.key

# Re-encrypt configuration files
echo "Re-encrypting configuration files..."
python -m src.crypto_utils re_encrypt \
    --input config/settings.yaml.enc \
    --old-key keys/config.key \
    --new-key /tmp/new_config.key \
    --output config/settings.yaml.enc.new

# Verify new encryption
echo "Verifying new encryption..."
python -m src.crypto_utils verify \
    --file config/settings.yaml.enc.new \
    --key /tmp/new_config.key

# Deploy new keys (only if verification passes)
if [ $? -eq 0 ]; then
    echo "Deploying new keys..."
    mv /tmp/new_master.key keys/master.key
    mv /tmp/new_config.key keys/config.key
    mv /tmp/new_patterns.key keys/patterns.key
    mv config/settings.yaml.enc.new config/settings.yaml.enc
    
    # Set permissions
    chmod 600 keys/*.key
    chown root:security keys/*.key
    
    echo "Key rotation completed successfully!"
else
    echo "Key rotation failed - verification error"
    exit 1
fi
```

______________________________________________________________________

## 🔍 **Security Auditing**

### **Encryption Audit Trail**

Maintain comprehensive audit logs:

```yaml
auditing:
  encryption_events:
    enabled: true
    log_file: "/var/log/nginx-security/encryption.log"
    
    # Events to log
    events:
      - "key_generation"
      - "key_rotation"
      - "encryption_operation"
      - "decryption_operation"
      - "key_access"
      - "encryption_failure"
      
    # Log format
    format: |
      {timestamp} | {level} | {event_type} | {user} | {key_id} | 
      {operation} | {file} | {result} | {details}
    
    # Log rotation
    rotation:
      max_size: "100MB"
      backup_count: 10
      compress: true
      
    # Tamper protection
    tamper_protection:
      enabled: true
      signature_algorithm: "HMAC-SHA256"
      signature_key: "audit_signature_key"
```

### **Compliance Reporting**

Generate compliance reports:

```python
# src/compliance_reporter.py
from datetime import datetime, timedelta
import json

class ComplianceReporter:
    """Generate encryption compliance reports."""
    
    def __init__(self, config: dict):
        self.config = config
        
    def generate_encryption_report(self, period_days: int = 30) -> dict:
        """Generate encryption compliance report."""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=period_days)
        
        report = {
            'report_period': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'duration_days': period_days
            },
            'encryption_status': self._check_encryption_status(),
            'key_management': self._audit_key_management(),
            'compliance_checks': self._run_compliance_checks(),
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _check_encryption_status(self) -> dict:
        """Check current encryption status."""
        return {
            'config_files_encrypted': self._check_config_encryption(),
            'pattern_files_encrypted': self._check_pattern_encryption(),
            'database_encryption': self._check_database_encryption(),
            'transport_encryption': self._check_transport_encryption(),
            'key_storage_secure': self._check_key_storage()
        }
    
    def _run_compliance_checks(self) -> dict:
        """Run compliance checks."""
        checks = {
            'encryption_algorithms': self._check_approved_algorithms(),
            'key_length_compliance': self._check_key_lengths(),
            'key_rotation_compliance': self._check_key_rotation(),
            'access_control_compliance': self._check_access_controls(),
            'audit_trail_complete': self._check_audit_trail()
        }
        
        return {
            'total_checks': len(checks),
            'passed_checks': sum(1 for result in checks.values() if result['status'] == 'pass'),
            'failed_checks': sum(1 for result in checks.values() if result['status'] == 'fail'),
            'details': checks
        }
```

______________________________________________________________________

## 🚨 **Emergency Procedures**

### **Key Compromise Response**

Procedures for handling key compromise:

```bash
#!/bin/bash
# scripts/emergency_key_rotation.sh

echo "EMERGENCY KEY ROTATION - Key Compromise Detected"

# 1. Immediately disable compromised keys
echo "Disabling compromised keys..."
mv keys/compromised.key keys/compromised.key.disabled

# 2. Generate new emergency keys
echo "Generating emergency keys..."
python -m src.crypto_utils generate_key --output keys/emergency.key --strength high

# 3. Re-encrypt critical data immediately
echo "Re-encrypting critical data..."
for file in config/*.enc; do
    python -m src.crypto_utils emergency_re_encrypt \
        --file "$file" \
        --compromised-key keys/compromised.key.disabled \
        --new-key keys/emergency.key
done

# 4. Notify security team
echo "Notifying security team..."
python -m src.alert_manager send_alert \
    --type "security_incident" \
    --severity "critical" \
    --message "Encryption key compromise detected - emergency rotation completed"

# 5. Update access logs
echo "$(date): Emergency key rotation completed due to compromise" >> /var/log/nginx-security/emergency.log

echo "Emergency key rotation completed!"
```

### **Encryption Recovery**

Procedures for encryption failure recovery:

```python
# src/encryption_recovery.py
import os
import shutil
from typing import List, Dict, Any

class EncryptionRecovery:
    """Handle encryption failure recovery."""
    
    def __init__(self, config: dict):
        self.config = config
        self.backup_dir = config.get('backup_directory', '/var/backups/nginx-security')
        
    def recover_from_failure(self, failure_type: str) -> bool:
        """Recover from encryption failure."""
        try:
            if failure_type == "key_corruption":
                return self._recover_from_key_corruption()
            elif failure_type == "config_corruption":
                return self._recover_from_config_corruption()
            elif failure_type == "total_failure":
                return self._recover_from_total_failure()
            else:
                logger.error(f"Unknown failure type: {failure_type}")
                return False
                
        except Exception as e:
            logger.error(f"Recovery failed: {e}")
            return False
    
    def _recover_from_key_corruption(self) -> bool:
        """Recover from corrupted encryption keys."""
        # Find latest key backup
        latest_backup = self._find_latest_key_backup()
        
        if not latest_backup:
            logger.error("No key backup found for recovery")
            return False
        
        # Restore keys from backup
        self._restore_keys_from_backup(latest_backup)
        
        # Verify restored keys
        if self._verify_restored_keys():
            logger.info("Key recovery successful")
            return True
        else:
            logger.error("Key recovery failed verification")
            return False
    
    def create_recovery_point(self) -> str:
        """Create recovery point with current encryption state."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        recovery_point_dir = f"{self.backup_dir}/recovery_points/{timestamp}"
        
        os.makedirs(recovery_point_dir, exist_ok=True)
        
        # Backup keys
        shutil.copytree('keys/', f"{recovery_point_dir}/keys/")
        
        # Backup encrypted configs
        shutil.copytree('config/', f"{recovery_point_dir}/config/")
        
        # Create recovery metadata
        metadata = {
            'timestamp': timestamp,
            'encryption_version': self._get_encryption_version(),
            'key_ids': self._get_current_key_ids(),
            'config_files': self._get_encrypted_config_files()
        }
        
        with open(f"{recovery_point_dir}/metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return recovery_point_dir
```

______________________________________________________________________

## 📊 **Performance Considerations**

### **Encryption Performance Tuning**

Optimize encryption performance:

```yaml
performance:
  encryption:
    # Caching
    key_cache:
      enabled: true
      max_size: 100
      ttl: 3600  # 1 hour
      
    # Batch operations
    batch_encryption:
      enabled: true
      batch_size: 1000
      
    # Parallel processing
    parallel_operations:
      enabled: true
      worker_threads: 4
      
    # Hardware acceleration
    hardware_acceleration:
      aes_ni: true      # Intel AES-NI
      cryptodev: true   # Hardware crypto devices
      
    # Memory optimization
    memory_management:
      secure_memory: true
      zero_on_free: true
      memory_pool_size: "64MB"
```

### **Benchmark Encryption Performance**

```python
# scripts/benchmark_encryption.py
import time
import statistics
from src.crypto_utils import CryptoUtils

def benchmark_encryption_performance():
    """Benchmark encryption performance."""
    crypto = CryptoUtils()
    
    # Test data sizes
    test_sizes = [1024, 10240, 102400, 1048576]  # 1KB, 10KB, 100KB, 1MB
    
    results = {}
    
    for size in test_sizes:
        test_data = "A" * size
        key = crypto.generate_key()
        
        # Benchmark encryption
        encrypt_times = []
        for _ in range(100):
            start = time.time()
            encrypted = crypto.encrypt_data(test_data, key)
            encrypt_times.append(time.time() - start)
        
        # Benchmark decryption
        decrypt_times = []
        for _ in range(100):
            start = time.time()
            decrypted = crypto.decrypt_data(encrypted, key)
            decrypt_times.append(time.time() - start)
        
        results[f"{size}_bytes"] = {
            'encryption': {
                'avg_time': statistics.mean(encrypt_times),
                'min_time': min(encrypt_times),
                'max_time': max(encrypt_times),
                'throughput_mbps': (size / 1024 / 1024) / statistics.mean(encrypt_times)
            },
            'decryption': {
                'avg_time': statistics.mean(decrypt_times),
                'min_time': min(decrypt_times),
                'max_time': max(decrypt_times),
                'throughput_mbps': (size / 1024 / 1024) / statistics.mean(decrypt_times)
            }
        }
    
    return results

if __name__ == "__main__":
    results = benchmark_encryption_performance()
    print(json.dumps(results, indent=2))
```

______________________________________________________________________

## 🔗 **Related Documentation**

- [Configuration Guide](CONFIGURATION.md) - Encryption configuration options
- [Security Features](SECURITY_FEATURES.md) - Overall security architecture
- [Plugin Development](PLUGIN_DEVELOPMENT.md) - Securing custom plugins
- [Operations Guide](OPERATIONS_GUIDE.md) - Managing encrypted deployments
- [API Reference](API_REFERENCE.md) - CryptoUtils API documentation

______________________________________________________________________

*This encryption guide is part of the NGINX Security Monitor documentation. For updates and contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).*
