

# Re-export NginxSecurityMonitor for convenience

from .monitor_service import NginxSecurityMonitor

# Expose encrypt_config module functions for test compatibility
from .encrypt_config import (
    CRYPTO_AVAILABLE,
    create_plugin_template,
    decrypt_and_view,
    encrypt_config_section,
    encrypt_patterns_file,
    main as encrypt_config_main
)

# Expose network_security module classes for test compatibility
from .network_security import NetworkSecurity, SecurityHardening
