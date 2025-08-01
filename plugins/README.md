# Custom Plugins Directory

This directory contains custom mitigation plugins for NGINX Security Monitor.

## Plugin Development

### Creating a New Plugin

1. Create a new Python file following the naming convention: `your_plugin_name.py`
1. Implement the `MitigationPlugin` interface
1. Place it in this directory

### Plugin Template

```python
"""
Custom mitigation plugin: your_plugin_name
"""

import logging
from typing import Dict, Any, List
import sys
import os

# Add the src directory to the path


from nginx_security_monitor.plugin_system import MitigationPlugin
from nginx_security_monitor.config_manager import ConfigManager

class YourPluginNamePlugin(MitigationPlugin):
    """Custom mitigation plugin."""
    
    @property
    def name(self) -> str:
        return "your_plugin_name"
    
    @property
    def threat_types(self) -> List[str]:
        return ["SQL Injection", "XSS Attack"]
    
    def can_handle(self, threat_info: Dict[str, Any]) -> bool:
        return threat_info.get('type') in self.threat_types
    
    def get_priority(self) -> int:
        return 50
    
    def mitigate(self, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        # Your custom mitigation logic here
        pass
```

## Current Plugins

- **test_plugin.py** - Example plugin for testing custom mitigation strategies

## Security Considerations

- Plugins in this directory are loaded by the main application
- Ensure your plugins handle errors gracefully
- Use appropriate logging levels
- Validate all inputs in your mitigation logic
- Consider the security implications of any external API calls

## Plugin Discovery

The plugin system automatically discovers plugins in these directories:

- `plugins/` (this directory, for development)
- `/opt/nginx-security-monitor/plugins` (system-wide)
- `/opt/nginx-security-monitor/custom_plugins` (custom installations)
- `~/.nginx-security-monitor/plugins` (user-specific)

## Documentation

For complete plugin development documentation, see:

- [Plugin Development Guide](../docs/PLUGIN_DEVELOPMENT.md)
- [Architecture Documentation](../docs/ARCHITECTURE.md)
